import contextlib
import io
import json
import re
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

SKILL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_DIR / "scripts"))

import pvr


class SkillPackageTests(unittest.TestCase):
    def test_workshop_guide_paths_match_bundled_layout(self):
        root = SKILL_DIR.parents[2]
        document = (root / "README.md").read_text(encoding="utf-8")
        links = re.findall(r"\]\(\./([^\s)#]+)", document)
        self.assertTrue(links)
        for link in links:
            with self.subTest(link=link):
                self.assertTrue((root / link).exists())
        self.assertIn("copilot skill add ./PVRTools/skills", document)
        self.assertIn('PVR_REPORT_DIR="$PWD/PVRTools/examples/pvr-triage"', document)
        self.assertIn("--data-dir ./PVRTools/examples/pvr-triage", document)
        self.assertIn("PVRTools/examples/pvr-triage/<your-owner>/<your-repo>/", document)

    def test_frontmatter_matches_example_format_without_tool_preapproval(self):
        document = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        self.assertTrue(document.startswith("---\n"))
        metadata = yaml.safe_load(document.split("---", 2)[1])
        self.assertEqual(metadata["name"], SKILL_DIR.name)
        self.assertTrue(0 < len(metadata["description"]) <= 1024)
        self.assertIn("PVR", metadata["description"])
        self.assertEqual(metadata["data_classification"], "restricted")
        self.assertEqual(metadata["sandbox"], "codespace")
        self.assertNotIn("allowed-tools", metadata)
        self.assertLess(len(document.splitlines()), 500)

    def test_bundled_document_references_exist_and_are_portable(self):
        document = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        links = re.findall(r"\]\(\./([^\s)#]+)\)", document)
        self.assertTrue(links)
        for link in links:
            with self.subTest(link=link):
                path = (SKILL_DIR / link).resolve()
                self.assertTrue(path.is_relative_to(SKILL_DIR))
                self.assertTrue(path.is_file())
        self.assertNotIn("/workspaces/", document)

    def test_assessment_template_starts_inconclusive(self):
        example = json.loads((SKILL_DIR / "assets" / "assessment.example.json").read_text(encoding="utf-8"))
        self.assertEqual(example["source_repo"], example["repo"])
        pvr.validate_repo(example["source_repo"])
        self.assertEqual(example["source_selection"]["method"], "unresolved")
        self.assertEqual(example["source_selection"]["evidence"], [])
        self.assertEqual(example["verdict"], "INCONCLUSIVE")
        self.assertEqual(example["code_finding"], "INCONCLUSIVE")
        self.assertIsNone(example["ref_sha"])
        self.assertEqual(example["evidence"], [])
        pvr.validate_signals(example["quality_signals"])

    def test_report_template_separates_security_verdict_and_code_finding(self):
        document = (SKILL_DIR / "assets" / "report-template.md").read_text(encoding="utf-8")
        self.assertIn("**Verdict:**", document)
        self.assertIn("reported security vulnerability", document)
        self.assertIn("**Code finding:**", document)

    def test_automatic_source_discovery_instructions_are_bundled(self):
        document = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
        self.assertIn("(./references/source-discovery.md)", document)
        self.assertTrue((SKILL_DIR / "references" / "source-discovery.md").is_file())

    def test_cached_comparison_preserves_moderate_evidence(self):
        with tempfile.TemporaryDirectory() as temporary:
            store = pvr.ReportStore(Path(temporary))
            raw = [
                {"ghsa_id": "GHSA-2345-6789-cfgh", "summary": "First", "vulnerabilities": [{"package": {"name": "widget"}}]},
                {"ghsa_id": "GHSA-jmpq-rvwx-2345", "summary": "Second", "vulnerabilities": [{"package": {"name": "widget"}}]},
            ]
            store.write_json(store.directory("acme/widget"), "inbox.json", {"repo": "acme/widget", "advisories": raw})
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = pvr.main(["--repo", "acme/widget", "--data-dir", temporary, "compare"])
            self.assertEqual(status, 0)
            result = json.loads(output.getvalue())
            self.assertEqual(result["clusters"], [])
            self.assertEqual(result["matches"][0]["level"], "moderate")


if __name__ == "__main__":
    unittest.main()