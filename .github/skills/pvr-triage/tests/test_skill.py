import contextlib
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import yaml

SKILL_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SKILL_DIR / "scripts"))

import pvr


class SkillPackageTests(unittest.TestCase):
    def test_workshop_guide_paths_match_deployed_layout(self):
        root = next(parent for parent in SKILL_DIR.parents if (parent / "README.md").is_file())
        document = (root / "README.md").read_text(encoding="utf-8")
        links = [
            link for link in re.findall(r"\]\(([^\s)#]+)", document)
            if not link.startswith(("https://", "http://"))
        ]
        self.assertTrue(links)
        for link in links:
            with self.subTest(link=link):
                self.assertTrue((root / link).exists())
        registrations = re.findall(r"copilot skill add ([^\s`]+)", document)
        self.assertTrue(registrations)
        for path in registrations:
            self.assertEqual((root / path).resolve(), SKILL_DIR.parent)
        cli_commands = [line for line in document.splitlines() if "copilot -i " in line]
        self.assertTrue(cli_commands)
        output_roots = re.findall(r"--data-dir ([^\s'`]+)", document)
        self.assertTrue(output_roots)
        output_root = Path(output_roots[0])
        self.assertEqual(output_root, Path("workshop-results/advanced"))
        self.assertTrue(all(Path(path) == output_root for path in output_roots))
        self.assertIn(f"{output_root.as_posix()}/<your-owner>/<your-repo>/", document)
        self.assertIn("workshop-results/basic/GHSA-xxxx-xxxx-xxxx.md", document)
        self.assertIn("/share file ./workshop-results/basic/", document)
        for command in cli_commands:
            self.assertIn(f"--data-dir {output_roots[0]}", command)

    def test_generated_report_tree_is_ignored(self):
        root = next(parent for parent in SKILL_DIR.parents if (parent / "README.md").is_file())
        document = (root / "README.md").read_text(encoding="utf-8")
        output_root = Path(re.findall(r"--data-dir ([^\s'`]+)", document)[0])
        results_root = root / "workshop-results"
        self.assertEqual((results_root / ".gitignore").read_text(encoding="utf-8").splitlines(), ["*", "!.gitignore"])
        paths = [
            Path("workshop-results/basic/GHSA-2345-6789-cfgh.md"),
            Path("workshop-results/basic/GHSA-2345-6789-cfgh-session.md"),
            output_root / "example-owner/example-repo/inbox.json",
            output_root / "example-owner/example-repo/GHSA-2345-6789-cfgh/assessment.json",
        ]
        for path in paths:
            with self.subTest(path=path):
                result = subprocess.run(
                    ["git", "-C", str(root), "check-ignore", "--no-index", "--quiet", str(path)],
                    capture_output=True, text=True, encoding="utf-8", check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
        scaffold = subprocess.run(
            ["git", "-C", str(root), "check-ignore", "--no-index", "--quiet", "workshop-results/.gitignore"],
            capture_output=True, text=True, encoding="utf-8", check=False,
        )
        self.assertEqual(scaffold.returncode, 1, scaffold.stderr)

    def test_all_workflow_helper_examples_retain_the_selected_output_root(self):
        for name in ("SKILL.md", "references/source-discovery.md", "references/responses.md"):
            document = (SKILL_DIR / name).read_text(encoding="utf-8")
            commands = re.findall(r'^\s*python "\$PVR_HELPER".*$', document, re.MULTILINE)
            self.assertTrue(commands, name)
            for command in commands:
                with self.subTest(document=name, command=command):
                    self.assertIn('--data-dir "$DATA_DIR"', command)

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