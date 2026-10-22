import base64
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

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
    def test_transport_is_get_only(self):
        result = subprocess.CompletedProcess([], 0, json.dumps(advisory()), "")
        with patch.object(pvr.subprocess, "run", return_value=result) as process:
            self.assertEqual(pvr.github_get("/repos/acme/widget/security-advisories/" + GHSA)["ghsa_id"], GHSA)
        command = process.call_args.args[0]
        self.assertEqual(command[command.index("--method") + 1], "GET")
        self.assertEqual(command[command.index("--hostname") + 1], "github.com")
        self.assertFalse(process.call_args.kwargs.get("shell", False))

    def test_api_errors_do_not_echo_credentials_or_response_bodies(self):
        result = subprocess.CompletedProcess([], 1, "", "secret-token (HTTP 403)")
        with patch.object(pvr.subprocess, "run", return_value=result), self.assertRaises(pvr.GitHubError) as caught:
            pvr.github_get("/repos/acme/widget")
        self.assertEqual(caught.exception.status, 403)
        self.assertNotIn("secret-token", str(caught.exception))

    def test_inbox_paginates_and_preserves_descriptions_for_semantic_review(self):
        pages = [[advisory()] * 100, [advisory(OTHER_GHSA)]]
        with patch.object(pvr, "github_get", side_effect=pages):
            result = pvr.list_advisories(REPO, "triage")
        self.assertEqual(len(result), 101)
        self.assertEqual(result[-1]["ghsa_id"], OTHER_GHSA)
        self.assertEqual(result[-1]["description"], "Bug in src/upload.py")

    def test_permission_error_is_not_an_empty_security_policy(self):
        with patch.object(pvr, "github_get", side_effect=pvr.GitHubError(403)), self.assertRaises(pvr.GitHubError):
            pvr.security_policy(REPO)

    def test_policy_fallback_decodes_content(self):
        content = base64.b64encode(b"# Security policy").decode()
        with patch.object(pvr, "github_get", side_effect=[pvr.GitHubError(404), {"encoding": "base64", "content": content}]):
            result = pvr.security_policy(REPO)
        self.assertEqual(result["content"], "# Security policy")
        self.assertIn(".github/SECURITY.md", result["path"])

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


class DuplicateTests(unittest.TestCase):
    def test_strong_matches_form_clusters(self):
        result = pvr.compare_advisories([advisory(), advisory(OTHER_GHSA)])
        self.assertEqual(result["clusters"], [[GHSA, OTHER_GHSA]])
        self.assertEqual(result["matches"][0]["level"], "strong")

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
        with patch.object(pvr.ReportStore, "write_json", side_effect=OSError("Disk full")):
            with self.assertRaisesRegex(OSError, "Disk full"):
                pvr.run_command(self.args)
        self.assertTrue(all(draft.exists() for draft in self.drafts))
        self.assertTrue((self.directory / "triage.md").exists())
        self.assertTrue((self.directory / "response.md").exists())
        self.assertFalse((self.directory / "assessment.json").exists())

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
    def test_fetch_keeps_advisory_identity_and_both_policies(self):
        for source_options, source_repo in [([], REPO), (["--source-repo", SOURCE_REPO], SOURCE_REPO)]:
            payloads = {
                f"/repos/{REPO}/security-advisories/{GHSA}": advisory(),
                f"/repos/{REPO}/contents/SECURITY.md": {"encoding": "base64", "content": base64.b64encode(b"Reporting policy").decode()},
                f"/repos/{SOURCE_REPO}/contents/SECURITY.md": {"encoding": "base64", "content": base64.b64encode(b"Product policy").decode()},
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
            with patch.object(pvr, "github_get", return_value=[advisory()]):
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
            with patch.object(pvr, "github_get", return_value=[advisory()]) as api:
                result = pvr.run_command(pvr.command_parser().parse_args([*options, "inbox"]))
            api.assert_called_once_with(f"/repos/{REPO}/security-advisories?state=triage&per_page=100&page=1")
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