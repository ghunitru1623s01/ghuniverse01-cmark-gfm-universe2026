import base64
import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import tracemalloc
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import call, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import pvr


REPO = "acme/widget"
SOURCE_REPO = "upstream/widget"
GHSA = "GHSA-2345-6789-cfgh"
OTHER_GHSA = "GHSA-jmpq-rvwx-2345"
SHA = "a" * 40


def advisory(ghsa=GHSA, package="widget", cwe="CWE-22", description="Bug in src/upload.py"):
    return {
        "ghsa_id": ghsa,
        "summary": ghsa,
        "description": description,
        "severity": "high",
        "state": "triage",
        "created_at": "2026-09-01T00:00:00Z",
        "updated_at": "2026-09-01T00:00:00Z",
        "vulnerabilities": [{"package": {"ecosystem": "pip", "name": package}}],
        "cwes": [{"cwe_id": cwe}] if cwe else [],
    }


def assessment(repo=REPO, ghsa=GHSA):
    return {
        "repo": repo,
        "ghsa_id": ghsa,
        "reporter": "alice",
        "verdict": "CONFIRMED",
        "quality": "High",
        "vuln_type": "path traversal",
        "affected_component": "upload",
        "quality_signals": dict.fromkeys(pvr.SIGNALS, True),
        "ref_sha": SHA,
        "head_sha": SHA,
        "patch_status": "still_vulnerable",
        "evidence": [f"src/upload.py:2 at {SHA}"],
        "source_updated_at": "2026-09-01T00:00:00Z",
    }


def github_response(value, link=None):
    headers = "HTTP/2.0 200 OK\r\nContent-Type: application/json\r\n"
    if link is not None:
        headers += f"Link: {link}\r\n"
    return subprocess.CompletedProcess([], 0, headers + "\r\n" + json.dumps(value), "")


class ScoringTests(unittest.TestCase):
    def setUp(self):
        self.absent = {
            "has_file_references": False,
            "has_poc": False,
            "has_line_numbers": False,
        }

    def test_priority_uses_severity_and_three_evidence_signals(self):
        for severity, weight in [("critical", 4), ("high", 3), ("medium", 2), ("low", 1), ("unknown", 1)]:
            with self.subTest(severity=severity):
                self.assertEqual(pvr.priority_score(severity, self.absent), weight)
                self.assertEqual(pvr.priority_score(severity, dict.fromkeys(self.absent, True)), weight + 3)

    def test_incomplete_or_non_boolean_signals_are_not_assumed_absent(self):
        for signals in [{}, {**self.absent, "has_poc": "false"}, {**self.absent, "has_poc": 0}]:
            with self.subTest(signals=signals), self.assertRaises(ValueError):
                pvr.priority_score("high", signals)

    def test_fast_close_reputation_matrix(self):
        for reputation, prior, expected in [
            ("high trust", False, False),
            ("high trust", True, False),
            ("normal", False, False),
            ("normal", True, True),
            ("no history", False, False),
            ("no history", True, True),
            ("treat with skepticism", False, True),
            ("treat with skepticism", True, True),
        ]:
            with self.subTest(reputation=reputation, prior=prior):
                self.assertEqual(pvr.fast_close_candidate(self.absent, reputation, prior), expected)
                for signal in self.absent:
                    self.assertFalse(pvr.fast_close_candidate({**self.absent, signal: True}, reputation, prior))

    def test_unrecognised_reputation_fails_closed(self):
        with self.assertRaises(ValueError):
            pvr.fast_close_candidate(self.absent, "trusted", True)


class IdentifierTests(unittest.TestCase):
    def test_valid_identifiers_are_normalised(self):
        self.assertEqual(pvr.validate_repo("Kwstubbs/PVRTools"), "kwstubbs/pvrtools")
        self.assertEqual(pvr.validate_repo("github/.github"), "github/.github")
        self.assertEqual(pvr.validate_ghsa("ghsa-2345-6789-CFGH"), "GHSA-2345-6789-cfgh")

    def test_invalid_identifiers_are_rejected(self):
        for value in ["../repo", "owner/..", "owner/repo/extra", "owner/repo?state=closed", "--help", "owner/repo;id"]:
            with self.subTest(repo=value), self.assertRaises(ValueError):
                pvr.validate_repo(value)
        for value in ["../../../tmp", "GHSA-test", "GHSA-0000-0000-0000", "GHSA-2345-6789-cfgh/.."]:
            with self.subTest(ghsa=value), self.assertRaises(ValueError):
                pvr.validate_ghsa(value)


class GitHubReadTests(unittest.TestCase):
    def test_utf8_stdout_and_stderr_are_decoded_under_a_non_utf8_locale(self):
        description = "caf\u00e9 \u2014 \u6f22\u5b57"
        response = ("HTTP/2.0 200 OK\r\n\r\n" + json.dumps({"description": description}, ensure_ascii=False)).encode("utf-8")
        success = f"import sys; sys.stdout.buffer.write({response!r})"
        failure = f"import sys; sys.stderr.buffer.write({(description + ' secret-token (HTTP 403)').encode('utf-8')!r}); sys.exit(1)"
        driver = f"""import subprocess
import sys
sys.path.insert(0, {str(Path(pvr.__file__).parent)!r})
import pvr
original_run = subprocess.run
emitter = {success!r}
def fixture(command, **kwargs):
    return original_run([sys.executable, "-c", emitter], **kwargs)
pvr.subprocess.run = fixture
assert pvr.github_get("/repos/acme/widget")["description"] == {ascii(description)}
emitter = {failure!r}
try:
    pvr.github_get("/repos/acme/widget")
except pvr.GitHubError as error:
    assert error.status == 403
    assert "secret-token" not in str(error)
else:
    raise AssertionError("Expected the sanitized GitHub error")
"""
        environment = {**os.environ, "LC_ALL": "C", "LANG": "C", "PYTHONUTF8": "0", "PYTHONCOERCECLOCALE": "0"}
        result = subprocess.run(
            [sys.executable, "-c", driver], capture_output=True, text=True,
            encoding="utf-8", env=environment, timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_transport_is_get_only(self):
        result = github_response(advisory())
        with patch.object(pvr.subprocess, "run", return_value=result) as process:
            self.assertEqual(pvr.github_get("/repos/acme/widget/security-advisories/" + GHSA)["ghsa_id"], GHSA)
        command = process.call_args.args[0]
        self.assertEqual(command[command.index("--method") + 1], "GET")
        self.assertEqual(command[command.index("--hostname") + 1], "github.com")
        self.assertIn("--include", command)
        self.assertEqual(process.call_args.kwargs["encoding"], "utf-8")
        self.assertFalse(process.call_args.kwargs.get("shell", False))

    def test_invalid_http_and_json_responses_fail_explicitly(self):
        for output in ("{}", "HTTP/2.0 200 OK\nMalformed header\n\n{}", "HTTP/2.0 200 OK\n\n{"):
            with self.subTest(output=output):
                result = subprocess.CompletedProcess([], 0, output, "")
                with patch.object(pvr.subprocess, "run", return_value=result), self.assertRaises(ValueError):
                    pvr.github_get("/repos/acme/widget")

    def test_api_errors_do_not_echo_credentials_or_response_bodies(self):
        result = subprocess.CompletedProcess([], 1, "", "secret-token (HTTP 403)")
        with patch.object(pvr.subprocess, "run", return_value=result), self.assertRaises(pvr.GitHubError) as caught:
            pvr.github_get("/repos/acme/widget")
        self.assertEqual(caught.exception.status, 403)
        self.assertNotIn("secret-token", str(caught.exception))

    def test_inbox_paginates_and_preserves_descriptions_for_semantic_review(self):
        link = '<https://api.github.com/repositories/123/security-advisories?after=cursor%2F%2B%3D>; rel="next"'
        pages = [github_response([advisory()] * 100, link), github_response([advisory(OTHER_GHSA)])]
        with patch.object(pvr.subprocess, "run", side_effect=pages) as process:
            result = pvr.list_advisories(REPO, "triage")
        self.assertEqual(len(result), 101)
        self.assertEqual(result[-1]["ghsa_id"], OTHER_GHSA)
        self.assertEqual(result[-1]["description"], "Bug in src/upload.py")
        self.assertEqual([entry.args[0][-1] for entry in process.call_args_list], [
            f"/repos/{REPO}/security-advisories?state=triage&per_page=100",
            f"/repos/{REPO}/security-advisories?state=triage&per_page=100&after=cursor%2F%2B%3D",
        ])

    def test_inbox_follows_a_before_cursor_even_when_the_page_is_short(self):
        link = '<https://api.github.com/repos/acme/widget/security-advisories?before=previous>; rel="next"'
        with patch.object(pvr, "github_get_with_headers", side_effect=[
            ([advisory()], {"link": link}), ([advisory(OTHER_GHSA)], {}),
        ]) as api:
            self.assertEqual(len(pvr.list_advisories(REPO)), 2)
        self.assertEqual(api.call_args_list, [
            call(f"/repos/{REPO}/security-advisories?state=triage&per_page=100"),
            call(f"/repos/{REPO}/security-advisories?state=triage&per_page=100&before=previous"),
        ])

    def test_full_final_page_does_not_require_an_extra_request(self):
        with patch.object(pvr, "github_get_with_headers", return_value=([advisory()] * 100, {})) as api:
            self.assertEqual(len(pvr.list_advisories(REPO)), 100)
        self.assertEqual(api.call_count, 1)

    def test_inbox_accepts_exactly_5000_reports_only_when_pagination_is_complete(self):
        for complete in (False, True):
            pages = [
                ([advisory()] * 100, {
                    "link": f'<https://api.github.com/repositories/123/security-advisories?after={index}>; rel="next"',
                } if index < 50 or not complete else {})
                for index in range(1, 51)
            ]
            with self.subTest(complete=complete), patch.object(pvr, "github_get_with_headers", side_effect=pages) as api:
                if complete:
                    self.assertEqual(len(pvr.list_advisories(REPO)), 5000)
                else:
                    with self.assertRaisesRegex(ValueError, "50-page/5000-advisory limit"):
                        pvr.list_advisories(REPO)
                self.assertEqual(api.call_count, 50)

    def test_inbox_rejects_repeated_cursors(self):
        headers = {"link": '<https://api.github.com/repositories/123/security-advisories?after=repeated>; rel="next"'}
        with patch.object(pvr, "github_get_with_headers", return_value=([advisory()], headers)) as api:
            with self.assertRaisesRegex(ValueError, "repeated an advisory cursor"):
                pvr.list_advisories(REPO)
        self.assertEqual(api.call_count, 2)

    def test_inbox_rejects_invalid_next_links_without_requesting_them(self):
        for url in (
            "https://example.com/?after=cursor",
            "http://api.github.com/?after=cursor",
            "https://api.github.com/?page=2",
            "https://api.github.com/?after=one&after=two",
            "https://api.github.com/?after=one&before=two",
        ):
            with self.subTest(url=url):
                headers = {"link": f'<{url}>; rel="next"'}
                with patch.object(pvr, "github_get_with_headers", return_value=([advisory()], headers)) as api:
                    with self.assertRaisesRegex(ValueError, "invalid next-page advisory cursor"):
                        pvr.list_advisories(REPO)
                self.assertEqual(api.call_count, 1)

    def test_later_inbox_access_error_is_not_a_partial_success(self):
        headers = {"link": '<https://api.github.com/repositories/123/security-advisories?after=next>; rel="next"'}
        with patch.object(pvr, "github_get_with_headers", side_effect=[
            ([advisory()], headers), pvr.GitHubError(403),
        ]):
            with self.assertRaises(pvr.GitHubError):
                pvr.list_advisories(REPO)

    def test_inbox_requires_a_list_response(self):
        with patch.object(pvr, "github_get_with_headers", return_value=({}, {})):
            with self.assertRaisesRegex(ValueError, "Expected an advisory list"):
                pvr.list_advisories(REPO)

    def test_permission_error_is_not_an_empty_security_policy(self):
        with patch.object(pvr, "github_get", side_effect=pvr.GitHubError(403)), self.assertRaises(pvr.GitHubError):
            pvr.security_policy(REPO)

    def test_policy_fallback_decodes_content(self):
        content = base64.b64encode(b"# Security policy").decode()
        with patch.object(pvr, "github_get", side_effect=[pvr.GitHubError(404), {"encoding": "base64", "content": content}]):
            result = pvr.security_policy(REPO)
        self.assertEqual(result["content"], "# Security policy")
        self.assertEqual(result["path"], f"/repos/{REPO}/contents/SECURITY.md")

    def test_github_policy_takes_precedence_when_root_policy_also_exists(self):
        policies = {
            f"/repos/{REPO}/contents/.github/SECURITY.md": {"encoding": "base64", "content": base64.b64encode(b"GitHub policy").decode()},
            f"/repos/{REPO}/contents/SECURITY.md": {"encoding": "base64", "content": base64.b64encode(b"Root policy").decode()},
        }
        with patch.object(pvr, "github_get", side_effect=policies.__getitem__) as api:
            result = pvr.security_policy(REPO)
        self.assertEqual(result["content"], "GitHub policy")
        api.assert_called_once_with(f"/repos/{REPO}/contents/.github/SECURITY.md")

    def test_inherited_policy_is_checked_after_all_repository_locations(self):
        content = {"encoding": "base64", "content": base64.b64encode(b"Inherited policy").decode()}
        paths = [
            f"/repos/{REPO}/contents/.github/SECURITY.md",
            f"/repos/{REPO}/contents/SECURITY.md",
            f"/repos/{REPO}/contents/docs/SECURITY.md",
            "/repos/acme/.github/contents/.github/SECURITY.md",
            "/repos/acme/.github/contents/SECURITY.md",
            "/repos/acme/.github/contents/docs/SECURITY.md",
        ]
        for index in range(3, 6):
            with self.subTest(location=paths[index]):
                with patch.object(pvr, "github_get", side_effect=[pvr.GitHubError(404)] * index + [content]) as api:
                    result = pvr.security_policy(REPO)
                self.assertEqual(api.call_args_list, [call(path) for path in paths[:index + 1]])
                self.assertEqual(result["path"], paths[index])
                self.assertEqual(result["content"], "Inherited policy")

    def test_missing_policy_checks_all_six_locations(self):
        with patch.object(pvr, "github_get", side_effect=pvr.GitHubError(404)) as api:
            result = pvr.security_policy(REPO)
        self.assertEqual(api.call_count, 6)
        self.assertIsNone(result["path"])
        self.assertIn("No accessible policy", result["note"])

    def test_inherited_policy_permission_error_is_not_a_missing_policy(self):
        with patch.object(pvr, "github_get", side_effect=[pvr.GitHubError(404)] * 3 + [pvr.GitHubError(403)]):
            with self.assertRaises(pvr.GitHubError):
                pvr.security_policy(REPO)

    def test_version_dereferences_annotated_tag(self):
        with patch.object(pvr, "github_get", side_effect=[
            pvr.GitHubError(404),
            {"object": {"type": "tag", "sha": "b" * 40}},
            {"object": {"type": "commit", "sha": SHA}},
        ]):
            self.assertEqual(pvr.resolve_version(REPO, "1.2.3"), {"tag": "v1.2.3", "sha": SHA})

    def test_version_ranges_are_not_treated_as_affected_revisions(self):
        with self.assertRaises(ValueError):
            pvr.resolve_version(REPO, "< 1.2.3")

    def test_unresolved_version_never_falls_back_to_head(self):
        with patch.object(pvr, "github_get", side_effect=pvr.GitHubError(404)), self.assertRaises(ValueError):
            pvr.resolve_version(REPO, "1.2.3")

    def test_file_reads_are_numbered_and_pinned(self):
        content = base64.b64encode(b"first\nsecond\nthird\n").decode()
        with patch.object(pvr, "github_get", return_value={"encoding": "base64", "content": content}):
            result = pvr.read_source(REPO, "src/upload.py", SHA, 2, 2)
        self.assertEqual(result["ref"], SHA)
        self.assertEqual(result["content"], "2: second\n3: third")
        with self.assertRaises(ValueError):
            pvr.read_source(REPO, "../outside", SHA, 1, 10)
        with self.assertRaises(ValueError):
            pvr.read_source(REPO, "src/upload.py", "HEAD", 1, 10)

    def test_source_citations_ignore_non_newline_separators(self):
        first_line = "first\f\v\x1c\x1d\x1e\x85\u2028\u2029\rtail"
        content = base64.b64encode(f"{first_line}\nsecond\n".encode()).decode()
        with patch.object(pvr, "github_get", return_value={"encoding": "base64", "content": content}):
            result = pvr.read_source(REPO, "src/upload.py", SHA, 1, 2)
            selected = pvr.read_source(REPO, "src/upload.py", SHA, 2, 1)
        self.assertEqual(result["total_lines"], 2)
        self.assertEqual(result["content"], f"1: {first_line}\n2: second")
        self.assertEqual(selected["content"], "2: second")

    def test_source_handles_crlf_and_final_newlines_without_extra_lines(self):
        for source, lines in (
            ("first\nsecond", ["first", "second"]),
            ("first\nsecond\n", ["first", "second"]),
            ("first\r\nsecond\r\n", ["first", "second"]),
            ("first\n\n", ["first", ""]),
            ("\n", [""]),
        ):
            with self.subTest(source=source):
                content = base64.b64encode(source.encode()).decode()
                with patch.object(pvr, "github_get", return_value={"encoding": "base64", "content": content}):
                    result = pvr.read_source(REPO, "src/upload.py", SHA)
                self.assertEqual(result["total_lines"], len(lines))
                self.assertEqual(result["content"], "\n".join(f"{number}: {line}" for number, line in enumerate(lines, 1)))

    def test_empty_source_has_no_line_one(self):
        with patch.object(pvr, "github_get", return_value={"encoding": "base64", "content": ""}):
            with self.assertRaisesRegex(ValueError, "file length \\(0\\)"):
                pvr.read_source(REPO, "src/upload.py", SHA)

    def test_directory_source_returns_a_clear_cli_error(self):
        errors = io.StringIO()
        output = io.StringIO()
        with patch.object(pvr, "github_get", return_value=[{"type": "file", "path": "src/upload.py"}]):
            with contextlib.redirect_stderr(errors), contextlib.redirect_stdout(output):
                status = pvr.main(["--repo", REPO, "source", "--ref", SHA, "--path", "src"])
        self.assertEqual(status, 1)
        self.assertIn("PVR error:", errors.getvalue())
        self.assertIn("not a directory", errors.getvalue())
        self.assertIn("Use tree", errors.getvalue())
        self.assertNotIn("Traceback", errors.getvalue())
        self.assertEqual(output.getvalue(), "")


class DuplicateTests(unittest.TestCase):
    def test_pair_evidence_is_bounded_without_skipping_cluster_edges(self):
        third = "GHSA-2345-6789-jmpq"
        with patch.object(pvr, "MAX_RETAINED_MATCHES", 1):
            result = pvr.compare_advisories([advisory(identifier) for identifier in (GHSA, OTHER_GHSA, third)])
        self.assertEqual(result["clusters"], [sorted([GHSA, OTHER_GHSA, third])])
        self.assertEqual(len(result["matches"]), 1)
        self.assertEqual(result["total_matches"], 3)
        self.assertEqual(result["match_counts"], {"strong": 3, "moderate": 0, "weak": 0})
        self.assertEqual(result["omitted_matches"], 2)
        self.assertTrue(result["matches_truncated"])
        self.assertIn("omitted 2", result["note"])

    def test_same_package_pair_evidence_stays_within_memory_bound(self):
        alphabet = "23456789cfghjmpqrvwx"
        reports = [
            advisory(
                f"GHSA-2345-6789-{alphabet[index // len(alphabet)]}{alphabet[index % len(alphabet)]}cf",
                cwe="", description=f"Report {index}",
            )
            for index in range(256)
        ]
        tracemalloc.start()
        try:
            result = pvr.compare_advisories(reports)
            _current, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(len(result["matches"]), pvr.MAX_RETAINED_MATCHES)
        self.assertEqual(result["total_matches"], 32640)
        self.assertEqual(result["omitted_matches"], 32640 - pvr.MAX_RETAINED_MATCHES)
        self.assertEqual(result["match_counts"]["moderate"], 32640)
        self.assertEqual(result["clusters"], [])
        self.assertEqual(len(result["singles"]), 256)
        self.assertLess(peak, 8 * 1024 * 1024)

    def test_dense_clusters_do_not_repeatedly_reassign_existing_components(self):
        class CountedIdentifier(str):
            hashes = 0

            def __hash__(self):
                type(self).hashes += 1
                return super().__hash__()

        alphabet = "23456789cfghjmpqrvwx"
        for size in (32, 64):
            identifiers = [
                f"GHSA-2345-6789-{alphabet[index // len(alphabet)]}{alphabet[index % len(alphabet)]}cf"
                for index in range(size)
            ]
            validate = pvr.validate_ghsa
            CountedIdentifier.hashes = 0
            with self.subTest(size=size), patch.object(pvr, "validate_ghsa", side_effect=lambda value: CountedIdentifier(validate(value))):
                result = pvr.compare_advisories([advisory(identifier) for identifier in identifiers])
            self.assertEqual(result["clusters"], [sorted(identifiers)])
            total = size * (size - 1) // 2
            self.assertEqual(len(result["matches"]), min(total, pvr.MAX_RETAINED_MATCHES))
            self.assertEqual(result["total_matches"], total)
            self.assertTrue(all(match["level"] == "strong" for match in result["matches"]))
            self.assertEqual(result["singles"], [])
            self.assertLess(CountedIdentifier.hashes, 8 * size * size)

    def test_strong_matches_form_clusters(self):
        result = pvr.compare_advisories([advisory(), advisory(OTHER_GHSA)])
        self.assertEqual(result["clusters"], [[GHSA, OTHER_GHSA]])
        self.assertEqual(result["matches"][0]["level"], "strong")
        self.assertFalse(result["matches_truncated"])
        self.assertEqual(result["omitted_matches"], 0)

    def test_moderate_matches_are_visible_but_not_clustered(self):
        result = pvr.compare_advisories([
            advisory(cwe="", description="First"),
            advisory(OTHER_GHSA, cwe="", description="Second"),
        ])
        self.assertEqual(result["clusters"], [])
        self.assertEqual(result["matches"][0]["level"], "moderate")

    def test_empty_metadata_does_not_imply_duplicate(self):
        result = pvr.compare_advisories([
            {"ghsa_id": GHSA, "summary": "First", "cwes": None, "vulnerabilities": None},
            {"ghsa_id": OTHER_GHSA, "summary": "Second"},
        ])
        self.assertEqual(result["matches"], [])
        self.assertEqual(result["singles"], [GHSA, OTHER_GHSA])


class ReportStoreTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = pvr.ReportStore(Path(self.temporary.name) / "reports")
        self.store.snapshot(REPO, advisory(), {"content": ""})

    def save(self, outcome=None):
        return self.store.record(REPO, GHSA, outcome or assessment(), "# Triage\nCode evidence.", "Thank you for the report.")

    def test_refuted_security_scenario_preserves_supported_code_behavior(self):
        directory = self.save({**assessment(), "verdict": "UNCONFIRMED", "code_finding": "CONFIRMED"})
        stored = self.store.read_json(directory, "assessment.json")
        self.assertEqual(stored["verdict"], "UNCONFIRMED")
        self.assertEqual(stored["code_finding"], "CONFIRMED")
        self.assertEqual(self.store.pending(REPO)[0]["verdict"], "UNCONFIRMED")
        matches = self.store.similar(REPO, OTHER_GHSA, "path traversal", "upload")
        self.assertEqual(matches[0]["verdict"], "UNCONFIRMED")

    def test_similar_normalizes_null_optional_metadata_without_inventing_matches(self):
        for changes, expected in (
            ({"vuln_type": None}, 1),
            ({"affected_component": None}, 1),
            ({"vuln_type": None, "affected_component": None}, 0),
        ):
            with self.subTest(changes=changes):
                self.save({**assessment(), **changes})
                matches = self.store.similar(REPO, OTHER_GHSA, "path traversal", "upload")
                self.assertEqual(len(matches), expected)
                self.assertEqual(self.store.similar(REPO, OTHER_GHSA, "null", "None"), [])
                stored = self.store.read_json(self.store.directory(REPO, GHSA), "assessment.json")
                for field in changes:
                    self.assertIsNone(stored[field])

    def test_similar_still_searches_report_text_when_optional_metadata_is_null(self):
        self.store.record(
            REPO, GHSA, {**assessment(), "vuln_type": None, "affected_component": None},
            "# Triage\nUpload path traversal confirmed by source.", "Reply draft.",
        )
        matches = self.store.similar(REPO, OTHER_GHSA, "path traversal", "upload")
        self.assertEqual([match["ghsa_id"] for match in matches], [GHSA])

    def test_failed_bundle_publication_preserves_existing_outputs_and_review(self):
        directory = self.save()
        self.store.review(REPO, GHSA)
        originals = {name: (directory / name).read_bytes() for name in ("triage.md", "response.md", "assessment.json", "review.json")}
        replace = pvr.os.replace
        for failed_name in ("triage.md", "response.md", "assessment.json"):
            def fail_publication(source, destination):
                if Path(source).name == failed_name and Path(destination) == directory / failed_name:
                    raise OSError("Publication failed")
                return replace(source, destination)

            with self.subTest(failed_name=failed_name), patch.object(pvr.os, "replace", side_effect=fail_publication):
                with self.assertRaisesRegex(OSError, "Publication failed"):
                    self.store.record(REPO, GHSA, {**assessment(), "verdict": "UNCONFIRMED"}, "Refuting evidence.", "Rejection draft.")
            self.assertEqual({name: (directory / name).read_bytes() for name in originals}, originals)
            self.assertTrue(self.store.records(REPO)[0]["reviewed"])
            self.assertEqual(list(directory.glob(".record-*")), [])

    def test_staging_failure_preserves_existing_bundle(self):
        directory = self.save()
        original_hash = self.store.bundle_hash(directory)
        with patch.object(pvr.shutil, "copy2", side_effect=OSError("Backup failed")):
            with self.assertRaisesRegex(OSError, "Backup failed"):
                self.store.record(REPO, GHSA, assessment(), "New triage.", "New reply.")
        self.assertEqual(self.store.bundle_hash(directory), original_hash)
        self.assertEqual(list(directory.glob(".record-*")), [])

    def test_incomplete_rollback_reports_and_preserves_recovery_files(self):
        directory = self.save()
        old_response = (directory / "response.md").read_bytes()
        replace = pvr.os.replace

        def fail_publication_and_one_restore(source, destination):
            if Path(destination) == directory / "assessment.json" or Path(source).name == "response.md.previous":
                raise OSError("Filesystem failure")
            return replace(source, destination)

        with patch.object(pvr.os, "replace", side_effect=fail_publication_and_one_restore):
            with self.assertRaisesRegex(OSError, "rollback was incomplete for response.md.*Recovery files remain"):
                self.store.record(REPO, GHSA, assessment(), "New triage.", "New reply.")
        recovery = list(directory.glob(".record-*"))
        self.assertEqual(len(recovery), 1)
        self.assertEqual((recovery[0] / "response.md.previous").read_bytes(), old_response)
        self.assertEqual((directory / "triage.md").read_text(encoding="utf-8"), "# Triage\nCode evidence.")

    def test_confirmed_code_finding_does_not_promote_security_verdict(self):
        directory = self.save({**assessment(), "verdict": "INCONCLUSIVE", "code_finding": "CONFIRMED"})
        stored = self.store.read_json(directory, "assessment.json")
        self.assertEqual(stored["verdict"], "INCONCLUSIVE")
        self.assertEqual(stored["code_finding"], "CONFIRMED")
        self.assertEqual(self.store.pending(REPO)[0]["verdict"], "INCONCLUSIVE")
        self.assertEqual(self.store.similar(REPO, OTHER_GHSA, "path traversal", "upload")[0]["verdict"], "INCONCLUSIVE")
        self.store.review(REPO, GHSA)
        self.assertEqual(pvr.reporter_score(self.store.records(REPO), "alice")["confirmed_pct"], 0.0)

    def test_invalid_code_finding_statuses_are_rejected(self):
        for status in ("SUPPORTED", "confirmed", None, True, 1, [], {}):
            with self.subTest(status=status), self.assertRaisesRegex(ValueError, "code-finding status"):
                self.save({**assessment(), "code_finding": status})

    def test_conclusive_code_findings_require_pinned_evidence_even_when_security_is_inconclusive(self):
        for status in ("CONFIRMED", "UNCONFIRMED"):
            for missing in ({"ref_sha": None}, {"evidence": []}):
                with self.subTest(status=status, missing=missing), self.assertRaisesRegex(ValueError, "pinned source evidence"):
                    self.save({**assessment(), "verdict": "INCONCLUSIVE", "code_finding": status, **missing})

    def test_unverified_code_and_security_findings_can_remain_inconclusive(self):
        directory = self.save({
            **assessment(), "verdict": "INCONCLUSIVE", "code_finding": "INCONCLUSIVE",
            "ref_sha": None, "head_sha": None, "evidence": [], "patch_status": "could_not_determine",
        })
        stored = self.store.read_json(directory, "assessment.json")
        self.assertEqual(stored["verdict"], "INCONCLUSIVE")
        self.assertEqual(stored["code_finding"], "INCONCLUSIVE")

    def test_automatic_source_selection_evidence_is_saved_and_reviewed_with_bundle(self):
        self.store.snapshot(REPO, advisory(), {"content": ""}, source_repo=SOURCE_REPO)
        selection = {
            "method": "automatic",
            "reason": "Reporting policy identifies the upstream and the source path matches.",
            "evidence": [f"{REPO}/SECURITY.md links to {SOURCE_REPO}", f"{SOURCE_REPO}@{SHA}:src/upload.py:2"],
            "candidates": [{"repo": SOURCE_REPO, "result": "selected", "reason": "Identity and code match"}],
        }
        directory = self.save({**assessment(), "source_repo": SOURCE_REPO, "source_selection": selection})
        stored = self.store.read_json(directory, "assessment.json")
        self.assertEqual(stored["source_selection"], selection)
        self.assertEqual(stored["repo"], REPO)
        self.assertEqual(stored["source_repo"], SOURCE_REPO)
        self.store.review(REPO, GHSA)
        self.assertTrue(self.store.records(REPO)[0]["reviewed"])
        stored["source_selection"]["reason"] = "Revised source explanation"
        self.store.write_json(directory, "assessment.json", stored)
        self.assertFalse(self.store.records(REPO)[0]["reviewed"])

    def test_cross_repo_assessment_must_match_fetched_source(self):
        self.store.snapshot(REPO, advisory(), {"content": ""}, source_repo=SOURCE_REPO)
        for source_fields in [{}, {"source_repo": "different/widget"}, {"source_repo": None}]:
            with self.subTest(source_fields=source_fields), self.assertRaises(ValueError):
                self.save({**assessment(), **source_fields})
        directory = self.save({**assessment(), "source_repo": "Upstream/Widget"})
        outcome = json.loads((directory / "assessment.json").read_text(encoding="utf-8"))
        self.assertEqual(outcome["repo"], REPO)
        self.assertEqual(outcome["source_repo"], SOURCE_REPO)
        self.assertEqual(directory, self.store.root / "acme" / "widget" / GHSA)
        with self.assertRaises(ValueError):
            self.store.record(REPO, GHSA, outcome, "Report", "Reply", source_repo="different/widget")

    def test_source_change_invalidates_review_and_marks_pending_stale(self):
        self.save()
        self.store.review(REPO, GHSA)
        self.store.snapshot(REPO, advisory(), {"content": ""}, source_repo=SOURCE_REPO)
        self.assertFalse(self.store.records(REPO)[0]["reviewed"])
        self.assertTrue(self.store.pending(REPO)[0]["stale"])
        with self.assertRaises(ValueError):
            self.store.review(REPO, GHSA)
        self.save({**assessment(), "source_repo": SOURCE_REPO})
        self.store.review(REPO, GHSA)
        self.assertTrue(self.store.records(REPO)[0]["reviewed"])
        self.assertEqual(self.store.pending(REPO)[0]["source_repo"], SOURCE_REPO)

    def test_legacy_reports_default_to_advisory_repository_without_rewriting(self):
        directory = self.save()
        (directory / "context.json").unlink(missing_ok=True)
        outcome_path = directory / "assessment.json"
        outcome = json.loads(outcome_path.read_text(encoding="utf-8"))
        outcome.pop("source_repo", None)
        outcome_path.write_text(json.dumps(outcome), encoding="utf-8")
        before = outcome_path.read_bytes()
        self.store.review(REPO, GHSA)
        record = self.store.records(REPO)[0]
        self.assertEqual(record["source_repo"], REPO)
        self.assertNotIn("code_finding", record)
        self.assertTrue(record["reviewed"])
        self.assertEqual(outcome_path.read_bytes(), before)
        self.assertFalse((directory / "context.json").exists())

    def test_similar_reports_do_not_cross_source_repositories(self):
        self.store.snapshot(REPO, advisory(), {"content": ""}, source_repo=SOURCE_REPO)
        self.save({**assessment(), "source_repo": SOURCE_REPO})
        self.assertEqual(self.store.similar(REPO, OTHER_GHSA, "path traversal", "upload"), [])
        matches = self.store.similar(REPO, OTHER_GHSA, "path traversal", "upload", source_repo=SOURCE_REPO)
        self.assertEqual(matches[0]["ghsa_id"], GHSA)
        self.assertEqual(matches[0]["source_repo"], SOURCE_REPO)

    def test_private_reports_and_pending_items_are_repository_scoped(self):
        directory = self.save()
        self.assertEqual(directory, self.store.root / "acme" / "widget" / GHSA)
        self.assertEqual((directory / "triage.md").stat().st_mode & 0o777, 0o600)
        self.assertEqual(len(self.store.pending(REPO)), 1)
        self.assertEqual(self.store.pending("another/widget"), [])
        self.store.snapshot(REPO, {**advisory(), "state": "closed"}, {"content": ""})
        self.assertEqual(self.store.pending(REPO), [])

    def test_reputation_requires_review_and_edits_invalidate_review(self):
        directory = self.save()
        self.assertEqual(pvr.reporter_score(self.store.records(REPO), "alice")["recommendation"], "no history")
        self.store.review(REPO, GHSA)
        self.assertEqual(pvr.reporter_score(self.store.records(REPO), "alice")["recommendation"], "high trust")
        (directory / "response.md").write_text("Edited response", encoding="utf-8")
        self.assertFalse(self.store.records(REPO)[0]["reviewed"])
        self.save({**assessment(), "reporter": None})
        self.store.review(REPO, GHSA)
        self.assertEqual(pvr.reporter_score(self.store.records(REPO), "unknown")["total_reports"], 0)
        self.assertEqual(len(self.store.records(REPO)), 1)

    def test_invalid_or_stale_assessments_are_rejected(self):
        for changes in [
            {"repo": "another/widget"}, {"ghsa_id": OTHER_GHSA},
            {"source_updated_at": "2026-08-01T00:00:00Z"},
            {"ref_sha": None}, {"evidence": []}, {"verdict": "PROBABLY"},
        ]:
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.save({**assessment(), **changes})

    def test_similar_reports_exclude_self_and_other_repositories(self):
        self.save()
        self.assertEqual(self.store.similar(REPO, GHSA, "path traversal", "upload"), [])
        self.assertEqual(self.store.similar("another/widget", OTHER_GHSA, "path traversal", "upload"), [])
        self.assertEqual(self.store.similar(REPO, OTHER_GHSA, "path traversal", "upload")[0]["ghsa_id"], GHSA)

    def test_symlinked_repository_directory_is_rejected(self):
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        (self.store.root / "different").symlink_to(outside, target_is_directory=True)
        with self.assertRaises(ValueError):
            self.store.snapshot("different/widget", advisory(), {"content": ""})
        self.assertEqual(list(outside.iterdir()), [])


class RankingTests(unittest.TestCase):
    def test_rank_retains_complete_clusters_and_reports_omitted_pair_evidence(self):
        third = "GHSA-2345-6789-jmpq"
        identifiers = (GHSA, OTHER_GHSA, third)
        signals = {identifier: dict.fromkeys(pvr.SIGNALS, True) for identifier in identifiers}
        with patch.object(pvr, "MAX_RETAINED_MATCHES", 1):
            result = pvr.rank_inbox([advisory(identifier) for identifier in identifiers], signals, [])
        self.assertEqual(len(result["queue"]), 3)
        self.assertEqual(result["duplicates"]["clusters"], [sorted(identifiers)])
        self.assertEqual(result["duplicates"]["total_matches"], 3)
        self.assertEqual(result["duplicates"]["omitted_matches"], 2)

    def test_changed_source_repo_is_not_skipped_as_an_existing_assessment(self):
        signals = {GHSA: dict.fromkeys(pvr.SIGNALS, False)}
        old = assessment()
        self.assertEqual(pvr.rank_inbox([advisory()], signals, [old], source_repo=REPO)["skipped"], 1)
        self.assertEqual(pvr.rank_inbox([advisory()], signals, [old], source_repo=SOURCE_REPO)["skipped"], 0)
        current = {**old, "source_repo": SOURCE_REPO}
        self.assertEqual(pvr.rank_inbox([advisory()], signals, [current], source_repo=SOURCE_REPO)["skipped"], 1)

    def test_priority_age_and_staleness(self):
        first = advisory()
        second = {**advisory(OTHER_GHSA), "created_at": "2026-08-01T00:00:00Z"}
        signals = {identifier: dict.fromkeys(pvr.SIGNALS, False) for identifier in (GHSA, OTHER_GHSA)}
        now = datetime(2026, 9, 9, tzinfo=timezone.utc)
        result = pvr.rank_inbox([first, second], signals, [], now)
        self.assertEqual([entry["ghsa_id"] for entry in result["queue"]], [OTHER_GHSA, GHSA])
        self.assertEqual(result["queue"][0]["age_days"], 39)
        self.assertEqual(pvr.rank_inbox([first, second], signals, [assessment()], now)["skipped"], 1)
        stale = {**assessment(), "source_updated_at": "2026-08-01T00:00:00Z"}
        self.assertEqual(pvr.rank_inbox([first, second], signals, [stale], now)["skipped"], 0)


class RecordCommandTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.store = pvr.ReportStore(Path(self.temporary.name) / "reports")
        self.directory = self.store.snapshot(REPO, advisory(), {"content": ""})
        outcome = self.store.write_json(self.directory, "draft-assessment.json", assessment())
        report = self.store.write(self.directory, "draft-triage.md", "# Triage\nCode evidence.")
        response = self.store.write(self.directory, "draft-response.md", "Thank you for the report.")
        self.drafts = (outcome, report, response)
        self.options = ["--repo", REPO, "--data-dir", str(self.store.root),
                        "record", GHSA, "--assessment", str(outcome),
                        "--report", str(report), "--response", str(response)]
        self.args = pvr.command_parser().parse_args(self.options)

    def test_record_removes_drafts_after_saving_all_outputs(self):
        result = pvr.run_command(self.args)
        self.assertEqual(result, {"directory": str(self.directory), "reviewed": False})
        for draft in self.drafts:
            self.assertFalse(draft.exists())
        saved = self.store.read_json(self.directory, "assessment.json")
        self.assertEqual(saved, {**assessment(), "source_repo": REPO, "generated_at": saved["generated_at"]})
        self.assertIsInstance(saved["generated_at"], str)
        self.assertEqual((self.directory / "triage.md").read_text(encoding="utf-8"), "# Triage\nCode evidence.")
        self.assertEqual((self.directory / "response.md").read_text(encoding="utf-8"), "Thank you for the report.")
        self.assertFalse(self.store.records(REPO)[0]["reviewed"])
        self.assertEqual(len(self.store.pending(REPO)), 1)

    def test_record_retains_drafts_and_existing_bundle_on_validation_failure(self):
        self.store.record(REPO, GHSA, assessment(), "Existing triage.", "Existing reply.")
        previous_hash = self.store.bundle_hash(self.directory)
        self.store.write_json(self.directory, "draft-assessment.json",
                              {**assessment(), "source_updated_at": "2026-08-01T00:00:00Z"})
        with self.assertRaisesRegex(ValueError, "stale"):
            pvr.run_command(self.args)
        self.assertTrue(all(draft.exists() for draft in self.drafts))
        self.assertEqual(self.store.bundle_hash(self.directory), previous_hash)

    def test_record_retains_drafts_on_invalid_json(self):
        self.args.assessment.write_text("{", encoding="utf-8")
        with self.assertRaises(json.JSONDecodeError):
            pvr.run_command(self.args)
        self.assertTrue(all(draft.exists() for draft in self.drafts))
        self.assertFalse((self.directory / "assessment.json").exists())

    def test_record_retains_all_drafts_if_saving_the_assessment_fails(self):
        replace = pvr.os.replace

        def fail_assessment_publication(source, destination):
            if Path(destination) == self.directory / "assessment.json":
                raise OSError("Disk full")
            return replace(source, destination)

        with patch.object(pvr.os, "replace", side_effect=fail_assessment_publication):
            with self.assertRaisesRegex(OSError, "Disk full"):
                pvr.run_command(self.args)
        self.assertTrue(all(draft.exists() for draft in self.drafts))
        self.assertFalse((self.directory / "triage.md").exists())
        self.assertFalse((self.directory / "response.md").exists())
        self.assertFalse((self.directory / "assessment.json").exists())

    def test_record_retains_drafts_and_prior_bundle_if_replacement_fails(self):
        self.store.record(REPO, GHSA, assessment(), "Original triage.", "Original reply.")
        previous_hash = self.store.bundle_hash(self.directory)
        replace = pvr.os.replace

        def fail_assessment_publication(source, destination):
            if Path(source).name == "assessment.json" and Path(destination) == self.directory / "assessment.json":
                raise OSError("Replacement failed")
            return replace(source, destination)

        with patch.object(pvr.os, "replace", side_effect=fail_assessment_publication):
            with self.assertRaisesRegex(OSError, "Replacement failed"):
                pvr.run_command(self.args)
        self.assertTrue(all(draft.exists() for draft in self.drafts))
        self.assertEqual(self.store.bundle_hash(self.directory), previous_hash)

    def test_record_preserves_external_inputs_and_unused_bundle_drafts(self):
        external = Path(self.temporary.name) / "inputs"
        external.mkdir()
        for field in ("assessment", "report", "response"):
            source = getattr(self.args, field)
            target = external / source.name
            target.write_bytes(source.read_bytes())
            setattr(self.args, field, target)
        pvr.run_command(self.args)
        for field in ("assessment", "report", "response"):
            self.assertTrue(getattr(self.args, field).exists())
        self.assertTrue(all(draft.exists() for draft in self.drafts))

    def test_record_preserves_canonical_inputs(self):
        pvr.run_command(self.args)
        self.args.assessment = self.directory / "assessment.json"
        self.args.report = self.directory / "triage.md"
        self.args.response = self.directory / "response.md"
        pvr.run_command(self.args)
        self.assertTrue(self.args.assessment.exists())
        self.assertTrue(self.args.report.exists())
        self.assertTrue(self.args.response.exists())

    def test_record_rejects_symlinked_drafts_before_saving(self):
        external = Path(self.temporary.name) / "external-response.md"
        external.write_text("External reply.", encoding="utf-8")
        self.args.response.unlink()
        self.args.response.symlink_to(external)
        with self.assertRaisesRegex(ValueError, "symlinked report file"):
            pvr.run_command(self.args)
        self.assertTrue(self.args.response.is_symlink())
        self.assertEqual(external.read_text(encoding="utf-8"), "External reply.")
        self.assertFalse((self.directory / "assessment.json").exists())

    def test_record_reports_cleanup_errors_instead_of_returning_success(self):
        unlink = Path.unlink

        def deny_draft_cleanup(path, *args, **kwargs):
            if path == self.args.assessment:
                raise PermissionError("Draft cleanup denied.")
            return unlink(path, *args, **kwargs)

        errors = io.StringIO()
        with patch.object(Path, "unlink", autospec=True, side_effect=deny_draft_cleanup):
            with contextlib.redirect_stderr(errors):
                self.assertEqual(pvr.main(self.options), 1)
        self.assertIn("PVR error:", errors.getvalue())
        self.assertIn("Draft cleanup denied.", errors.getvalue())
        self.assertTrue(all(draft.exists() for draft in self.drafts))
        self.assertTrue((self.directory / "assessment.json").exists())


class CommandLineTests(unittest.TestCase):
    def test_output_root_precedence_is_explicit_option_then_environment_then_default(self):
        with patch.dict(pvr.os.environ, {"PVR_REPORT_DIR": "/tmp/pvr-env", "XDG_STATE_HOME": "/tmp/pvr-state"}):
            command = ["--repo", REPO, "pending"]
            self.assertEqual(pvr.command_parser().parse_args(command).data_dir, Path("/tmp/pvr-env"))
            explicit = ["--repo", REPO, "--data-dir", "./examples/pvr-triage", "pending"]
            self.assertEqual(pvr.command_parser().parse_args(explicit).data_dir, Path("./examples/pvr-triage"))
            with patch.dict(pvr.os.environ, {"PVR_REPORT_DIR": ""}):
                self.assertEqual(pvr.command_parser().parse_args(command).data_dir, Path("/tmp/pvr-state/pvr-triage"))

    def test_fetch_keeps_advisory_identity_and_both_policies(self):
        for source_options, source_repo in [([], REPO), (["--source-repo", SOURCE_REPO], SOURCE_REPO)]:
            payloads = {
                f"/repos/{REPO}/security-advisories/{GHSA}": advisory(),
                f"/repos/{REPO}/contents/.github/SECURITY.md": {"encoding": "base64", "content": base64.b64encode(b"Reporting policy").decode()},
                f"/repos/{SOURCE_REPO}/contents/.github/SECURITY.md": {"encoding": "base64", "content": base64.b64encode(b"Product policy").decode()},
            }
            with self.subTest(source_repo=source_repo), tempfile.TemporaryDirectory() as temporary:
                args = pvr.command_parser().parse_args(["--repo", REPO, *source_options, "--data-dir", temporary, "fetch", GHSA])
                with patch.object(pvr, "github_get", side_effect=lambda path: payloads[path]):
                    result = pvr.run_command(args)
                directory = Path(result["directory"])
                context = json.loads((directory / "context.json").read_text(encoding="utf-8"))
                self.assertEqual(context, {"repo": REPO, "source_repo": source_repo})
                self.assertEqual(result["source_repo"], source_repo)
                self.assertEqual(json.loads((directory / "advisory.json").read_text(encoding="utf-8")), advisory())
                policy = json.loads((directory / "policy.json").read_text(encoding="utf-8"))
                self.assertEqual(policy["content"], "Reporting policy")
                if source_repo != REPO:
                    self.assertEqual(policy["source_policy"]["repo"], SOURCE_REPO)
                    self.assertEqual(policy["source_policy"]["content"], "Product policy")
                else:
                    self.assertNotIn("source_policy", policy)

    def test_record_command_checks_source_override_against_snapshot(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = pvr.ReportStore(Path(temporary))
            directory = store.snapshot(REPO, advisory(), {"content": ""}, source_repo=SOURCE_REPO)
            outcome = store.write_json(directory, "draft.json", {**assessment(), "source_repo": SOURCE_REPO})
            report = store.write(directory, "draft.md", "Code evidence")
            response = store.write(directory, "reply.md", "Reply")
            options = ["--repo", REPO, "--source-repo", REPO, "--data-dir", temporary,
                       "record", GHSA, "--assessment", str(outcome), "--report", str(report), "--response", str(response)]
            with self.assertRaises(ValueError):
                pvr.run_command(pvr.command_parser().parse_args(options))
            self.assertFalse((directory / "assessment.json").exists())
            options[options.index("--source-repo") + 1] = SOURCE_REPO
            pvr.run_command(pvr.command_parser().parse_args(options))
            saved = store.read_json(directory, "assessment.json")
            self.assertEqual(saved["repo"], REPO)
            self.assertEqual(saved["source_repo"], SOURCE_REPO)
            self.assertTrue(all(path.exists() for path in (outcome, report, response)))

    def test_source_permission_error_does_not_fall_back_to_advisory_repo(self):
        args = pvr.command_parser().parse_args(["--repo", REPO, "--source-repo", SOURCE_REPO, "resolve", "--ref", "HEAD"])
        with patch.object(pvr, "github_get", side_effect=pvr.GitHubError(403)) as api:
            with self.assertRaises(pvr.GitHubError):
                pvr.run_command(args)
        api.assert_called_once_with(f"/repos/{SOURCE_REPO}/commits/HEAD")

    def test_rank_command_uses_cached_source_repo_unless_explicitly_overridden(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = pvr.ReportStore(Path(temporary))
            store.snapshot(REPO, advisory(), {"content": ""})
            store.record(REPO, GHSA, assessment(), "Report", "Reply")
            signals = store.write_json(store.directory(REPO), "signals.json", {GHSA: dict.fromkeys(pvr.SIGNALS, False)})
            options = ["--repo", REPO, "--data-dir", temporary]
            with patch.object(pvr, "github_get_with_headers", return_value=([advisory()], {})):
                pvr.run_command(pvr.command_parser().parse_args([*options, "--source-repo", SOURCE_REPO, "inbox"]))
            for override, expected_source, expected_skipped in [([], SOURCE_REPO, 0), (["--source-repo", REPO], REPO, 1)]:
                with self.subTest(source_repo=expected_source):
                    result = pvr.run_command(pvr.command_parser().parse_args([*options, *override, "rank", "--signals", str(signals)]))
                    ranked = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
                    self.assertEqual(ranked["source_repo"], expected_source)
                    self.assertEqual(ranked["skipped"], expected_skipped)

    def test_source_commands_use_explicit_source_repo_or_advisory_default(self):
        content = base64.b64encode(b"source evidence\n").decode()
        cases = [
            (["resolve", "--ref", "HEAD"], {"sha": SHA}, "/commits/HEAD"),
            (["resolve", "--version", "1.2.3"], {"object": {"type": "commit", "sha": SHA}}, "/git/ref/tags/1.2.3"),
            (["source", "--ref", SHA, "--path", "src/widget.py"], {"encoding": "base64", "content": content}, f"/contents/src/widget.py?ref={SHA}"),
            (["tree", "--ref", SHA], {"tree": [{"type": "blob", "path": "src/widget.py"}]}, f"/git/trees/{SHA}?recursive=1"),
        ]
        for source_options, expected_repo in [([], REPO), (["--source-repo", "Upstream/Widget"], SOURCE_REPO)]:
            for command, payload, endpoint in cases:
                with self.subTest(source_repo=expected_repo, command=command):
                    args = pvr.command_parser().parse_args(["--repo", REPO, *source_options, *command])
                    with patch.object(pvr, "github_get", return_value=payload) as api:
                        result = pvr.run_command(args)
                    self.assertIsInstance(result, dict)
                    api.assert_called_once_with(f"/repos/{expected_repo}{endpoint}")
                    if command[0] == "source":
                        self.assertEqual(result["repo"], expected_repo)
                        self.assertEqual(result["content"], "1: source evidence")

    def test_source_override_does_not_redirect_advisory_status_or_inbox(self):
        with tempfile.TemporaryDirectory() as temporary:
            options = ["--repo", REPO, "--source-repo", SOURCE_REPO, "--data-dir", temporary]
            with patch.object(pvr, "github_get", return_value=advisory()) as api:
                result = pvr.run_command(pvr.command_parser().parse_args([*options, "status", GHSA]))
            api.assert_called_once_with(f"/repos/{REPO}/security-advisories/{GHSA}")
            self.assertEqual(result["ghsa_id"], GHSA)
            with patch.object(pvr, "github_get_with_headers", return_value=([advisory()], {})) as api:
                result = pvr.run_command(pvr.command_parser().parse_args([*options, "inbox"]))
            api.assert_called_once_with(f"/repos/{REPO}/security-advisories?state=triage&per_page=100")
            inbox = json.loads(Path(result["path"]).read_text(encoding="utf-8"))
            self.assertEqual(inbox["repo"], REPO)
            self.assertEqual(inbox["advisories"][0]["ghsa_id"], GHSA)

    def test_invalid_source_repository_is_rejected_before_api_access(self):
        with contextlib.redirect_stderr(io.StringIO()), patch.object(pvr, "github_get") as api:
            with self.assertRaises(SystemExit) as caught:
                pvr.main(["--repo", REPO, "--source-repo", "owner/../other", "resolve", "--ref", "HEAD"])
        self.assertEqual(caught.exception.code, 2)
        api.assert_not_called()

    def test_help_is_runnable_without_authentication(self):
        script = Path(pvr.__file__)
        result = subprocess.run([sys.executable, str(script), "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0)
        self.assertIn("inbox", result.stdout)
        self.assertIn("Read-only", result.stdout)

    def test_score_command_works_offline(self):
        with tempfile.TemporaryDirectory() as temporary:
            signals = Path(temporary) / "signals.json"
            signals.write_text(json.dumps(dict.fromkeys(pvr.SIGNALS, False)), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                result = pvr.main(["--repo", REPO, "score", "--severity", "critical", "--signals", str(signals)])
            self.assertEqual(result, 0)
            self.assertEqual(json.loads(output.getvalue())["priority"], 4)
            self.assertFalse(json.loads(output.getvalue())["fast_close_candidate"])

    def test_review_refuses_noninteractive_approval(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(pvr.sys, "stdin", io.StringIO("review")):
            output = io.StringIO()
            with contextlib.redirect_stderr(output):
                result = pvr.main(["--repo", REPO, "--data-dir", temporary, "review", GHSA])
            self.assertEqual(result, 1)
            self.assertIn("interactive", output.getvalue())
            self.assertEqual(list(Path(temporary).iterdir()), [])


if __name__ == "__main__":
    unittest.main()