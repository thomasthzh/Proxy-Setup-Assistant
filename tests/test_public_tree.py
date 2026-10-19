"""Release scanner tests use only constructed synthetic marker credentials."""

import contextlib
import io
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from tools import check_public_tree as checker


class TextScannerTests(unittest.TestCase):
    def test_private_keys_flagged_without_disclosing_content(self):
        marker = "TEST_ONLY_FAKE_PRIVATE_DATA"
        text = "\n" + "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" + marker
        findings = checker.scan_text("notes.txt", text)
        self.assertEqual(findings[0].line, 2)
        self.assertIn("private-key block", str(findings[0]))
        self.assertNotIn(marker, str(findings[0]))

    def test_provider_tokens_are_constructed_and_detected(self):
        for value in ("ghp_" + "A" * 36, "github_pat_" + "A" * 70,
                      "glpat-" + "A" * 20, "AKIA" + "A" * 16,
                      "xoxb-" + "1" * 12 + "-" + "A" * 24,
                      "AIza" + "A" * 35, "sk_live_" + "A" * 24,
                      "sk-proj-" + "A" * 50, "tskey-auth-" + "A" * 30):
            with self.subTest(prefix=value[:4]):
                findings = checker.scan_text("notes.txt", value)
                self.assertTrue(findings)
                self.assertNotIn(value, "\n".join(map(str, findings)))

    def test_literal_credentials_and_private_urls_flagged(self):
        value = "TEST_ONLY_" + "SYNTHETIC_CREDENTIAL_0123456789"
        for text in ('password = "' + value + '"', '"token": "' + value + '"',
                     "hy2_obfs: " + value, "https://vps.example.com/s/" + value,
                     "https://user:" + value + "@vps.example.com/"):
            with self.subTest(text_kind=text[:8]):
                self.assertTrue(checker.scan_text("notes.txt", text))

    def test_explicit_test_markers_allowed_only_in_tests(self):
        text = 'token = "TEST_ONLY_NOT_A_REAL_TOKEN_0123456789"'
        self.assertEqual(checker.scan_text("tests/test_renderer.py", text), [])
        self.assertTrue(checker.scan_text("example.py", text))
        self.assertTrue(checker.scan_text("tests/test_renderer.py", 'token = "' + "z" * 32 + '"'))

    def test_placeholders_expressions_and_reserved_ips_allowed(self):
        content = '\n'.join(('password = "<generated-by-server>"', 'token = "replace-with-a-token"',
                             'password = "{settings[secret]}"', 'address = "192.0.2.10"',
                             'server: "203.0.113.10"', 'host = "127.0.0.1"',
                             'address = "vps.example.com"', 'DOMESTIC_DNS = ("223.5.5.5",)',
                             'direct-dns-server = 223.5.5.5,119.29.29.29'))
        self.assertEqual(checker.scan_text("example.txt", content), [])

    def test_actual_global_deployment_ip_assignment_is_detected(self):
        # Construct a public resolver address as a synthetic deployment example.
        value = ".".join(["1"] * 4)
        self.assertTrue(checker.scan_text("example.txt", 'address = "' + value + '"'))


class TreeScannerTests(unittest.TestCase):
    def test_deployment_files_caught_and_untracked_files_not_read(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "README.md").write_text("Public documentation", encoding="utf-8")
            (root / "settings.json").write_text("{}", encoding="utf-8")
            (root / "private.key").write_text("TEST_ONLY_FAKE_PRIVATE_DATA", encoding="utf-8")
            self.assertEqual(checker.scan_paths(root, ["README.md"]), [])
            findings = checker.scan_paths(root, ["README.md", "settings.json", "private.key"])
            self.assertEqual({finding.path for finding in findings}, {"settings.json", "private.key"})

    def test_path_escape_and_missing_files_fail_closed(self):
        with tempfile.TemporaryDirectory() as directory:
            findings = checker.scan_paths(Path(directory), ["../sibling.txt", "missing.txt", "/absolute.txt"])
            self.assertEqual(len(findings), 3)

    def test_non_utf8_and_binary_files_require_review(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "binary.dat").write_bytes(b"\x00data")
            (root / "invalid.txt").write_bytes(b"\xff\xfe")
            self.assertEqual(len(checker.scan_paths(root, ["binary.dat", "invalid.txt"])), 2)

    def test_git_inventory_is_exact_root_and_cached_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            responses = [subprocess.CompletedProcess([], 0, str(root) + "\n"),
                         subprocess.CompletedProcess([], 0, b"README.md\x00tests/test_cli.py\x00"),
                         subprocess.CompletedProcess([], 0)]
            with patch.object(checker.subprocess, "run", side_effect=responses) as run:
                names = checker.tracked_files(root)
            self.assertEqual(names, ["README.md", "tests/test_cli.py"])
            self.assertEqual(run.call_args_list[1].args[0][-3:], ["ls-files", "--cached", "-z"])
            self.assertEqual(run.call_args_list[2].args[0][-4:], ["diff", "--quiet", "--ignore-submodules", "--"])

    def test_unstaged_changes_cannot_hide_a_staged_secret(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            responses = [subprocess.CompletedProcess([], 0, str(root) + "\n"),
                         subprocess.CompletedProcess([], 0, b"notes.txt\x00"),
                         subprocess.CalledProcessError(1, ["git", "diff", "--quiet"])]
            with patch.object(checker.subprocess, "run", side_effect=responses), self.assertRaises(subprocess.CalledProcessError):
                checker.tracked_files(root)

    def test_parent_git_repository_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "child"
            response = subprocess.CompletedProcess([], 0, str(Path(directory)) + "\n")
            with patch.object(checker.subprocess, "run", return_value=response) as run, self.assertRaises(ValueError):
                checker.tracked_files(root)
            self.assertEqual(run.call_count, 1)

    def test_empty_git_inventory_is_not_a_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            responses = [subprocess.CompletedProcess([], 0, str(root) + "\n"),
                         subprocess.CompletedProcess([], 0, b"")]
            with patch.object(checker.subprocess, "run", side_effect=responses), self.assertRaises(ValueError):
                checker.tracked_files(root)

    def test_main_reports_locations_without_matched_values(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            marker = "TEST_ONLY_SYNTHETIC_CREDENTIAL_0123456789"
            (root / "notes.txt").write_text('password = "' + marker + '"', encoding="utf-8")
            output = io.StringIO()
            with patch.object(checker, "tracked_files", return_value=["notes.txt"]), contextlib.redirect_stdout(output):
                self.assertEqual(checker.main(["--root", str(root), "--tracked"]), 1)
            self.assertIn("notes.txt:1:", output.getvalue())
            self.assertNotIn(marker, output.getvalue())


if __name__ == "__main__":
    unittest.main()
