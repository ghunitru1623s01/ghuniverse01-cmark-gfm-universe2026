"""Dependency-free support tools for the Copilot PVR triage skill."""

from __future__ import annotations

import argparse
import base64
import hashlib
import itertools
import json
import os
import re
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlencode

SIGNALS = ("has_file_references", "has_poc", "has_line_numbers")
RECOMMENDATIONS = {"high trust", "normal", "no history", "treat with skepticism"}
VERDICTS = {"CONFIRMED", "UNCONFIRMED", "INCONCLUSIVE"}
QUALITIES = {"High", "Medium", "Low"}


def validate_repo(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+", value):
        raise ValueError("Repository must be an owner/repo name on github.com.")
    if value.split("/")[1] in {".", ".."}:
        raise ValueError("Invalid repository name.")
    return value.lower()


def validate_ghsa(value: str) -> str:
    if not re.fullmatch(r"GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}", value, re.IGNORECASE):
        raise ValueError("Expected a valid GHSA identifier, such as GHSA-2345-6789-cfgh.")
    return "GHSA" + value[4:].lower()


def validate_signals(signals: dict) -> None:
    if not isinstance(signals, dict) or any(type(signals.get(name)) is not bool for name in SIGNALS):
        raise ValueError("All three quality signals must be explicit JSON booleans.")


def priority_score(severity: str, signals: dict) -> int:
    validate_signals(signals)
    severity_weight = {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(severity.lower(), 1)
    return severity_weight + sum(signals[name] for name in SIGNALS)


def fast_close_candidate(signals: dict, recommendation: str, prior_similar: bool) -> bool:
    validate_signals(signals)
    if recommendation not in RECOMMENDATIONS or type(prior_similar) is not bool:
        raise ValueError("Invalid reputation recommendation or prior-similar flag.")
    if recommendation == "high trust" or any(signals[name] for name in SIGNALS):
        return False
    return recommendation == "treat with skepticism" or prior_similar


class GitHubError(RuntimeError):
    def __init__(self, status: int | None):
        self.status = status
        super().__init__(f"GitHub read failed (HTTP {status or 'unknown'}). Check gh authentication and repository access.")


def github_get(path: str) -> dict | list:
    if not path.startswith("/repos/"):
        raise ValueError("Only repository API reads are supported.")
    result = subprocess.run(
        ["gh", "api", "--hostname", "github.com", "--method", "GET", path],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if result.returncode:
        status = re.search(r"HTTP (\d{3})", result.stderr)
        raise GitHubError(int(status.group(1)) if status else None)
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise ValueError("GitHub returned an invalid JSON response.") from error


def list_advisories(repo: str, state: str = "triage") -> list[dict]:
    repo = validate_repo(repo)
    if state not in {"triage", "draft", "published", "closed", "withdrawn"}:
        raise ValueError("Unsupported advisory state.")
    advisories = []
    for page in range(1, 51):
        query = urlencode({"state": state, "per_page": 100, "page": page})
        result = github_get(f"/repos/{repo}/security-advisories?{query}")
        if not isinstance(result, list):
            raise ValueError("Expected an advisory list; no partial inbox will be used.")
        advisories.extend(result)
        if len(result) < 100:
            return advisories
    raise ValueError("Inbox exceeds the 5000-advisory limit; refusing to return an incomplete queue.")


def decode_content(result: dict) -> str:
    if result.get("encoding") != "base64":
        raise ValueError("File is not available as inline base64 content; inspect it separately.")
    return base64.b64decode(result["content"]).decode("utf-8")


def security_policy(repo: str) -> dict:
    repo = validate_repo(repo)
    owner = repo.split("/")[0]
    paths = [
        f"/repos/{repo}/contents/SECURITY.md",
        f"/repos/{repo}/contents/.github/SECURITY.md",
        f"/repos/{repo}/contents/docs/SECURITY.md",
        f"/repos/{owner}/.github/contents/SECURITY.md",
    ]
    for path in paths:
        try:
            return {"path": path, "content": decode_content(github_get(path))}
        except GitHubError as error:
            if error.status != 404:
                raise
    return {"path": None, "content": "", "note": "No accessible policy found; a 404 can also mean insufficient access."}


def validate_sha(value: str) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[a-fA-F0-9]{40}", value):
        raise ValueError("Use a full 40-character commit SHA. Resolve branches or tags first.")
    return value.lower()


def resolve_ref(repo: str, ref: str) -> dict:
    result = github_get(f"/repos/{validate_repo(repo)}/commits/{quote(ref, safe='')}")
    return {"ref": ref, "sha": validate_sha(result["sha"])}


def resolve_version(repo: str, version: str) -> dict:
    repo = validate_repo(repo)
    if not version or re.search(r"[\s<>=*,|]", version):
        raise ValueError("Choose one concrete affected version, not a version range or an exclusive upper bound.")
    tags = [version, version[1:] if version.startswith("v") else f"v{version}"]
    for tag in tags:
        try:
            result = github_get(f"/repos/{repo}/git/ref/tags/{quote(tag, safe='')}")
        except GitHubError as error:
            if error.status == 404:
                continue
            raise
        target = result["object"]
        for _depth in range(8):
            if target["type"] == "commit":
                return {"tag": tag, "sha": validate_sha(target["sha"])}
            if target["type"] != "tag":
                break
            target = github_get(f"/repos/{repo}/git/tags/{validate_sha(target['sha'])}")["object"]
        raise ValueError("Tag does not resolve to a commit within eight dereferences.")
    raise ValueError(f"No exact tag for {version!r}. Do not substitute HEAD for the affected version.")


def read_source(repo: str, path: str, ref: str, start: int = 1, length: int = 150) -> dict:
    repo = validate_repo(repo)
    ref = validate_sha(ref)
    if not path or PurePosixPath(path).is_absolute() or ".." in path.split("/") or "\\" in path:
        raise ValueError("Source path must be a relative repository path without traversal.")
    if start < 1 or not 1 <= length <= 500:
        raise ValueError("Start must be positive and length must be between 1 and 500.")
    result = github_get(f"/repos/{repo}/contents/{quote(path, safe='/')}?{urlencode({'ref': ref})}")
    lines = decode_content(result).splitlines()
    if start > len(lines):
        raise ValueError(f"Start line exceeds file length ({len(lines)}).")
    return {
        "repo": repo,
        "path": path,
        "ref": ref,
        "total_lines": len(lines),
        "content": "\n".join(f"{number}: {line}" for number, line in enumerate(lines[start - 1:start - 1 + length], start)),
    }


def fingerprint(advisory: dict) -> dict:
    vulnerabilities = advisory.get("vulnerabilities") or []
    packages = set()
    versions = set()
    for vulnerability in vulnerabilities:
        package = vulnerability.get("package") or {}
        name = package.get("name") or ""
        if name:
            packages.add(f"{package.get('ecosystem') or ''}:{name}".lower())
        version = (vulnerability.get("vulnerable_version_range") or "").strip()
        if version:
            versions.add(version)
    files = set(re.findall(
        r"(?<![\w./])((?:[\w.-]+/)*[\w.-]+\.(?:py|js|ts|jsx|tsx|go|rs|rb|java|c|cpp|cc|h|hpp|cs|php|swift|kt|sh|yaml|yml|html|sql))\b",
        advisory.get("description") or "",
    ))
    summary = re.sub(r"[^a-z0-9 ]", "", (advisory.get("summary") or "").lower()).strip()
    return {
        "cwes": {entry["cwe_id"] for entry in advisory.get("cwes") or [] if entry.get("cwe_id")},
        "packages": packages,
        "versions": versions,
        "files": files,
        "summary": {summary} if summary else set(),
    }


def compare_advisories(advisories: list[dict]) -> dict:
    fingerprints = {validate_ghsa(entry["ghsa_id"]): fingerprint(entry) for entry in advisories}
    components = {identifier: {identifier} for identifier in fingerprints}
    matches = []
    for left_id, right_id in itertools.combinations(fingerprints, 2):
        left, right = fingerprints[left_id], fingerprints[right_id]
        overlap = {field: sorted(left[field] & right[field]) for field in left if left[field] & right[field]}
        if not overlap:
            continue
        if "packages" in overlap and any(field in overlap for field in ("cwes", "files", "versions")):
            level = "strong"
        elif "packages" in overlap or ("cwes" in overlap and "files" in overlap):
            level = "moderate"
        else:
            level = "weak"
        matches.append({"advisories": [left_id, right_id], "level": level, "overlap": overlap})
        if level == "strong":
            merged = components[left_id] | components[right_id]
            for identifier in merged:
                components[identifier] = merged
    clusters = sorted({tuple(sorted(group)) for group in components.values() if len(group) > 1})
    return {
        "clusters": [list(group) for group in clusters],
        "matches": matches,
        "singles": sorted(identifier for identifier, group in components.items() if len(group) == 1),
        "note": "Structural heuristics only. Version strings are compared literally, not as overlapping ranges. No match does not prove reports are distinct.",
    }


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


class ReportStore:
    def __init__(self, root: Path):
        self.root = root.expanduser().resolve()

    def directory(self, repo: str, ghsa: str | None = None) -> Path:
        parts = validate_repo(repo).split("/")
        if ghsa is not None:
            parts.append(validate_ghsa(ghsa))
        directory = self.root
        for part in parts:
            if directory.is_symlink():
                raise ValueError("Refusing a symlink inside the report store.")
            directory = directory / part
        if directory.is_symlink():
            raise ValueError("Refusing a symlink inside the report store.")
        return directory

    def file(self, directory: Path, name: str) -> Path:
        path = directory / name
        if path.is_symlink():
            raise ValueError("Refusing a symlinked report file.")
        return path

    def write(self, directory: Path, name: str, content: str) -> Path:
        path = self.file(directory, name)
        current = self.root
        current.mkdir(mode=0o700, parents=True, exist_ok=True)
        for part in directory.relative_to(self.root).parts:
            current = current / part
            if current.is_symlink():
                raise ValueError("Refusing a symlink inside the report store.")
            current.mkdir(mode=0o700, exist_ok=True)
        temporary = None
        try:
            with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=directory, delete=False) as output:
                temporary = Path(output.name)
                output.write(content)
            os.replace(temporary, path)
        finally:
            if temporary is not None:
                temporary.unlink(missing_ok=True)
        return path

    def write_json(self, directory: Path, name: str, value: dict | list) -> Path:
        return self.write(directory, name, json.dumps(value, indent=2) + "\n")

    def read_json(self, directory: Path, name: str) -> dict | list:
        return json.loads(self.file(directory, name).read_text(encoding="utf-8"))

    def source_repository(self, repo: str, ghsa: str) -> str:
        repo = validate_repo(repo)
        directory = self.directory(repo, ghsa)
        if not self.file(directory, "context.json").exists():
            return repo
        context = self.read_json(directory, "context.json")
        if context["repo"] != repo:
            raise ValueError("Stored source context belongs to a different advisory repository.")
        return validate_repo(context["source_repo"])

    def snapshot(self, repo: str, advisory: dict, policy: dict, *, source_repo: str | None = None) -> Path:
        repo = validate_repo(repo)
        source_repo = validate_repo(source_repo if source_repo is not None else repo)
        directory = self.directory(repo, advisory["ghsa_id"])
        self.write_json(directory, "advisory.json", advisory)
        self.write_json(directory, "policy.json", policy)
        self.write_json(directory, "context.json", {"repo": repo, "source_repo": source_repo})
        return directory

    def record(self, repo: str, ghsa: str, assessment: dict, report: str, response: str, *, source_repo: str | None = None) -> Path:
        repo, ghsa = validate_repo(repo), validate_ghsa(ghsa)
        directory = self.directory(repo, ghsa)
        snapshot = self.read_json(directory, "advisory.json")
        if validate_repo(assessment["repo"]) != repo or validate_ghsa(assessment["ghsa_id"]) != ghsa:
            raise ValueError("Assessment identity does not match the report directory.")
        expected_source = self.source_repository(repo, ghsa)
        if validate_repo(assessment.get("source_repo", repo)) != expected_source:
            raise ValueError("Assessment source_repo does not match the fetched source context.")
        if source_repo is not None and validate_repo(source_repo) != expected_source:
            raise ValueError("--source-repo does not match the fetched source context. Fetch and assess the intended source first.")
        if not assessment.get("source_updated_at") or assessment["source_updated_at"] != snapshot.get("updated_at"):
            raise ValueError("Assessment is stale or lacks the advisory's updated_at timestamp.")
        if assessment.get("verdict") not in VERDICTS or assessment.get("quality") not in QUALITIES:
            raise ValueError("Use a supported verdict and quality rating.")
        code_finding = assessment.get("code_finding")
        if "code_finding" in assessment and (not isinstance(code_finding, str) or code_finding not in VERDICTS):
            raise ValueError("Use a supported code-finding status.")
        validate_signals(assessment.get("quality_signals"))
        for field in ("ref_sha", "head_sha"):
            if assessment.get(field) is not None:
                validate_sha(assessment[field])
        evidence = assessment.get("evidence")
        if not isinstance(evidence, list) or any(not isinstance(item, str) or not item.strip() for item in evidence):
            raise ValueError("Evidence must be a list of nonempty citation strings.")
        conclusive = assessment["verdict"] != "INCONCLUSIVE" or code_finding in {"CONFIRMED", "UNCONFIRMED"}
        if conclusive and (not assessment.get("ref_sha") or not evidence):
            raise ValueError("A conclusive verdict or code finding requires pinned source evidence.")
        if assessment.get("patch_status") not in {"patched", "still_vulnerable", "could_not_determine"}:
            raise ValueError("Invalid patch status.")
        if assessment["patch_status"] != "could_not_determine" and not assessment.get("head_sha"):
            raise ValueError("Patch status requires a pinned HEAD revision.")
        reporter = assessment.get("reporter")
        if reporter is not None and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]*", reporter):
            raise ValueError("Reporter must be a GitHub login or null, not a display name.")
        if not report.strip() or not response.strip():
            raise ValueError("Both the triage report and response draft are required.")
        outcome = {**assessment, "repo": repo, "source_repo": expected_source, "ghsa_id": ghsa, "reporter": reporter.lower() if reporter else None}
        outcome.pop("reviewed", None)
        outcome["generated_at"] = utc_now()
        self.write(directory, "triage.md", report)
        self.write(directory, "response.md", response)
        self.write_json(directory, "assessment.json", outcome)
        return directory

    def bundle_hash(self, directory: Path) -> str:
        digest = hashlib.sha256()
        for name in ("assessment.json", "triage.md", "response.md"):
            content = self.file(directory, name).read_bytes()
            digest.update(name.encode() + b"\0" + str(len(content)).encode() + b"\0" + content)
        return digest.hexdigest()

    def review(self, repo: str, ghsa: str) -> Path:
        directory = self.directory(repo, ghsa)
        assessment = self.read_json(directory, "assessment.json")
        snapshot = self.read_json(directory, "advisory.json")
        if validate_repo(assessment.get("source_repo", repo)) != self.source_repository(repo, ghsa):
            raise ValueError("Source repository changed. Regenerate the assessment before reviewing it.")
        if assessment["source_updated_at"] != snapshot.get("updated_at"):
            raise ValueError("Refresh the assessment before reviewing a changed advisory.")
        return self.write_json(directory, "review.json", {"sha256": self.bundle_hash(directory), "reviewed_at": utc_now()})

    def records(self, repo: str) -> list[dict]:
        records = []
        for candidate in sorted(self.directory(repo).glob("GHSA-*")):
            directory = self.directory(repo, candidate.name)
            if not self.file(directory, "assessment.json").exists():
                continue
            record = self.read_json(directory, "assessment.json")
            if record["repo"] != validate_repo(repo) or record["ghsa_id"] != candidate.name:
                raise ValueError("Stored assessment has a mismatched repository or advisory ID.")
            review = self.read_json(directory, "review.json") if self.file(directory, "review.json").exists() else {}
            record["source_repo"] = validate_repo(record.get("source_repo", repo))
            source_matches = record["source_repo"] == self.source_repository(repo, candidate.name)
            record["reviewed"] = source_matches and review.get("sha256") == self.bundle_hash(directory)
            records.append(record)
        return records

    def similar(self, repo: str, ghsa: str, vuln_type: str, component: str, *, source_repo: str | None = None) -> list[dict]:
        source_repo = self.source_repository(repo, ghsa) if source_repo is None else validate_repo(source_repo)
        terms = [value.strip().casefold() for value in (vuln_type, component) if value.strip()]
        results = []
        for record in self.records(repo):
            if record["ghsa_id"] == validate_ghsa(ghsa) or record["source_repo"] != source_repo:
                continue
            directory = self.directory(repo, record["ghsa_id"])
            text = self.file(directory, "triage.md").read_text(encoding="utf-8")
            text += " " + record.get("vuln_type", "") + " " + record.get("affected_component", "")
            if any(term in text.casefold() for term in terms):
                results.append({key: record[key] for key in ("ghsa_id", "source_repo", "verdict", "quality", "reviewed")})
        return results

    def pending(self, repo: str) -> list[dict]:
        results = []
        for record in self.records(repo):
            directory = self.directory(repo, record["ghsa_id"])
            snapshot = self.read_json(directory, "advisory.json")
            if snapshot.get("state") != "triage":
                continue
            results.append({
                "ghsa_id": record["ghsa_id"], "verdict": record["verdict"],
                "source_repo": record["source_repo"],
                "reviewed": record["reviewed"],
                "stale": (record["source_updated_at"] != snapshot.get("updated_at")
                          or record["source_repo"] != self.source_repository(repo, record["ghsa_id"])),
                "directory": str(directory),
            })
        return results


def reporter_score(records: list[dict], login: str) -> dict:
    history = [record for record in records if login and record.get("reporter") == login.lower() and record.get("reviewed") is True]
    total = len(history)
    quality = {name: sum(record["quality"] == name for record in history) for name in QUALITIES}
    confirmed_pct = sum(record["verdict"] == "CONFIRMED" for record in history) / total if total else 0.0
    low_share = quality["Low"] / total if total else 0.0
    if not total:
        recommendation = "no history"
    elif confirmed_pct >= 0.6 and low_share <= 0.2:
        recommendation = "high trust"
    elif confirmed_pct <= 0.2 or low_share >= 0.5:
        recommendation = "treat with skepticism"
    else:
        recommendation = "normal"
    return {"login": login, "total_reports": total, "confirmed_pct": confirmed_pct, "quality_breakdown": quality, "recommendation": recommendation}


def rank_inbox(advisories: list[dict], signals: dict, records: list[dict], now: datetime | None = None, *, source_repo: str | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    source_repo = validate_repo(source_repo) if source_repo is not None else None
    previous = {record["ghsa_id"]: record for record in records}
    duplicates = compare_advisories(advisories)
    queue = []
    skipped = 0
    for advisory in advisories:
        ghsa = validate_ghsa(advisory["ghsa_id"])
        prior = previous.get(ghsa, {})
        same_source = source_repo is None or prior.get("source_repo", prior.get("repo")) == source_repo
        if same_source and advisory.get("updated_at") and prior.get("source_updated_at") == advisory["updated_at"]:
            skipped += 1
            continue
        quality_signals = signals.get(ghsa)
        priority = priority_score(advisory.get("severity") or "unknown", quality_signals)
        try:
            created = datetime.fromisoformat(advisory["created_at"].replace("Z", "+00:00"))
            if created.tzinfo is None:
                created = created.replace(tzinfo=timezone.utc)
            age = max(0, (now.date() - created.astimezone(timezone.utc).date()).days)
        except (KeyError, ValueError, AttributeError):
            created, age = datetime.max.replace(tzinfo=timezone.utc), None
        action = "Triage Immediately" if priority >= 5 else "Triage Soon" if priority >= 3 else "Triage"
        if priority <= 1:
            action = "Likely Low Quality -- Request Details"
        if any(ghsa in group for group in duplicates["clusters"]):
            action = "Likely Duplicate -- Triage Best"
        queue.append({
            "ghsa_id": ghsa, "summary": advisory.get("summary", ""),
            "severity": advisory.get("severity"), "priority": priority,
            "quality_signals": quality_signals, "age_days": age,
            "created_at": advisory.get("created_at"), "suggested_action": action,
            "_sort_created": created,
        })
    queue.sort(key=lambda entry: (-entry["priority"], entry["_sort_created"], entry["ghsa_id"]))
    for entry in queue:
        del entry["_sort_created"]
    return {"generated_at": now.isoformat(), "source_repo": source_repo, "queue": queue, "skipped": skipped, "duplicates": duplicates}


def command_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Read-only GitHub access and local records for the Copilot PVR triage skill.")
    parser.add_argument("--repo", type=validate_repo, required=True, help="Advisory owner/repo on github.com; also scopes local reports")
    parser.add_argument("--source-repo", type=validate_repo, help="Source owner/repo for code and revision reads; defaults to --repo")
    default_root = Path(os.environ.get("XDG_STATE_HOME") or Path.home() / ".local" / "state") / "pvr-triage"
    parser.add_argument("--data-dir", type=Path, default=Path(os.environ.get("PVR_REPORT_DIR") or default_root))
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("fetch", "status", "review"):
        commands.add_parser(name).add_argument("ghsa", type=validate_ghsa)
    commands.add_parser("policy")
    commands.add_parser("pending")
    commands.add_parser("compare")
    commands.add_parser("inbox").add_argument("--state", choices=("triage", "draft"), default="triage")
    resolve = commands.add_parser("resolve").add_mutually_exclusive_group(required=True)
    resolve.add_argument("--version")
    resolve.add_argument("--ref")
    source = commands.add_parser("source")
    source.add_argument("--path", required=True)
    source.add_argument("--ref", type=validate_sha, required=True)
    source.add_argument("--start", type=int, default=1)
    source.add_argument("--length", type=int, default=150)
    tree = commands.add_parser("tree")
    tree.add_argument("--ref", type=validate_sha, required=True)
    tree.add_argument("--contains", default="")
    score = commands.add_parser("score")
    score.add_argument("--severity", default="unknown")
    score.add_argument("--signals", type=Path, required=True)
    score.add_argument("--recommendation", choices=sorted(RECOMMENDATIONS), default="no history")
    score.add_argument("--prior-similar", action="store_true")
    commands.add_parser("rank").add_argument("--signals", type=Path, required=True)
    commands.add_parser("history").add_argument("--reporter", required=True)
    similar = commands.add_parser("similar")
    similar.add_argument("ghsa", type=validate_ghsa)
    similar.add_argument("--vuln-type", default="")
    similar.add_argument("--component", default="")
    record = commands.add_parser("record")
    record.add_argument("ghsa", type=validate_ghsa)
    for name in ("assessment", "report", "response"):
        record.add_argument(f"--{name}", type=Path, required=True)
    return parser


def run_command(args: argparse.Namespace) -> dict | list:
    store = ReportStore(args.data_dir)
    source_repo = args.source_repo or args.repo
    if args.command in {"fetch", "status"}:
        advisory = github_get(f"/repos/{args.repo}/security-advisories/{args.ghsa}")
        if advisory.get("ghsa_id") != args.ghsa:
            raise ValueError("GitHub response did not match the requested advisory.")
        if args.command == "status":
            return {key: advisory.get(key) for key in ("ghsa_id", "state", "updated_at", "html_url")}
        policy = security_policy(args.repo)
        if source_repo != args.repo:
            policy["source_policy"] = {"repo": source_repo, **security_policy(source_repo)}
        directory = store.snapshot(args.repo, advisory, policy, source_repo=source_repo)
        return {"repo": args.repo, "source_repo": source_repo, "directory": str(directory),
                "advisory": str(directory / "advisory.json"), "policy": str(directory / "policy.json"),
                "context": str(directory / "context.json")}
    if args.command == "inbox":
        advisories = list_advisories(args.repo, args.state)
        result = {"repo": args.repo, "source_repo": source_repo, "state": args.state, "fetched_at": utc_now(), "advisories": advisories}
        path = store.write_json(store.directory(args.repo), "inbox.json", result)
        return {"path": str(path), "count": len(advisories)}
    if args.command == "policy":
        return security_policy(args.repo)
    if args.command == "resolve":
        result = resolve_version(source_repo, args.version) if args.version else resolve_ref(source_repo, args.ref)
        return {"repo": source_repo, **result}
    if args.command == "source":
        return read_source(source_repo, args.path, args.ref, args.start, args.length)
    if args.command == "tree":
        result = github_get(f"/repos/{source_repo}/git/trees/{args.ref}?recursive=1")
        return {
            "repo": source_repo, "ref": args.ref, "truncated": result.get("truncated", False),
            "paths": [entry["path"] for entry in result["tree"] if entry["type"] == "blob" and args.contains.casefold() in entry["path"].casefold()],
        }
    if args.command == "score":
        signals = json.loads(args.signals.read_text(encoding="utf-8"))
        return {
            "priority": priority_score(args.severity, signals),
            "fast_close_candidate": fast_close_candidate(signals, args.recommendation, args.prior_similar),
            "note": "A shortcut candidate is not an invalidity verdict or authorization to close an advisory.",
        }
    if args.command in {"rank", "compare"}:
        directory = store.directory(args.repo)
        inbox = store.read_json(directory, "inbox.json")
        if inbox["repo"] != args.repo:
            raise ValueError("Inbox belongs to another repository.")
        if args.command == "compare":
            return compare_advisories(inbox["advisories"])
        signals = json.loads(args.signals.read_text(encoding="utf-8"))
        if not isinstance(signals, dict):
            raise ValueError("Queue signals must be a JSON object keyed by GHSA ID.")
        selected_source = args.source_repo or inbox.get("source_repo", args.repo)
        result = rank_inbox(inbox["advisories"], signals, store.records(args.repo), source_repo=selected_source)
        path = store.write_json(directory, "ranked.json", result)
        return {"path": str(path), "count": len(result["queue"]), "skipped": result["skipped"]}
    if args.command == "record":
        directory = store.directory(args.repo, args.ghsa)
        drafts = [
            store.file(directory, name)
            for source, name in (
                (args.assessment, "draft-assessment.json"),
                (args.report, "draft-triage.md"),
                (args.response, "draft-response.md"),
            )
            if source.name == name and source.parent.resolve() == directory
        ]
        directory = store.record(
            args.repo, args.ghsa,
            json.loads(args.assessment.read_text(encoding="utf-8")),
            args.report.read_text(encoding="utf-8"),
            args.response.read_text(encoding="utf-8"),
            source_repo=args.source_repo,
        )
        for draft in drafts:
            draft.unlink()
        return {"directory": str(directory), "reviewed": False}
    if args.command == "history":
        records = store.records(args.repo)
        return {"score": reporter_score(records, args.reporter), "records": [entry for entry in records if entry.get("reporter") == args.reporter.lower()]}
    if args.command == "similar":
        return store.similar(args.repo, args.ghsa, args.vuln_type, args.component, source_repo=args.source_repo)
    if args.command == "pending":
        return {"pending": store.pending(args.repo), "note": "Cached triage state only. Recheck live status for every advisory before preparing an action."}
    if args.command == "review":
        if not sys.stdin.isatty():
            raise ValueError("Review requires an interactive maintainer terminal; no piped or automatic approval is accepted.")
        directory = store.directory(args.repo, args.ghsa)
        phrase = f"review {args.repo} {args.ghsa}"
        print(f"Inspect assessment.json, triage.md, and response.md in {directory}.", file=sys.stderr)
        if input(f"After reviewing them, type '{phrase}': ") != phrase:
            raise ValueError("Review was not approved.")
        return {"review": str(store.review(args.repo, args.ghsa))}
    raise ValueError("Unknown command.")


def main(argv: list[str] | None = None) -> int:
    args = command_parser().parse_args(argv)
    try:
        print(json.dumps(run_command(args), indent=2))
        return 0
    except (GitHubError, OSError, ValueError, KeyError, TypeError, subprocess.TimeoutExpired) as error:
        print(f"PVR error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())