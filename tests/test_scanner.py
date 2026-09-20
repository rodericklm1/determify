"""
test_scanner.py - Comprehensive Unit Tests for Determify.
"""

import os
import sys
import unittest
import tempfile
import subprocess
from pathlib import Path
from determify.scanner import scan_file, scan_targets

class TestDetermifyScanner(unittest.TestCase):

    def test_det01_date_math_detection(self):
        content = """
        def get_date():
            prompt = "What is today's date? Please calculate the date for tomorrow."
            return client.messages.create(model="claude-3-5-sonnet", messages=[{"role": "user", "content": prompt}])
        """
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        
        os.unlink(f.name)
        ids = [x["id"] for x in findings]
        self.assertIn("DET-01", ids)

    def test_det02_file_discovery_with_llm(self):
        content = """
        # Ask LLM if file exists in prompt
        prompt = "Does the file exist in the directory? List all files in dir."
        llm_call(prompt)
        """
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        
        os.unlink(f.name)
        ids = [x["id"] for x in findings]
        self.assertIn("DET-02", ids)

    def test_comment_not_flagged_as_false_positive(self):
        content = """
        # TODO: check if file exists using os.path.exists
        # We need to extract the frontmatter with yaml.safe_load
        def real_function():
            return True
        """
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        
        os.unlink(f.name)
        self.assertEqual(len(findings), 0)

    def test_det07_sdk_signatures(self):
        content = """
        response = openai.chat.completions.create(model="gpt-4o", messages=[{"role": "user", "content": "hi"}])
        res2 = anthropic.messages.create(model="claude-3-7-sonnet", max_tokens=100, messages=[])
        res3 = llm.complete("generate summary")
        """
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        
        os.unlink(f.name)
        ids = [x["id"] for x in findings]
        self.assertEqual(ids.count("DET-07"), 3)

    def test_clean_file_no_findings(self):
        content = """
        import os
        import datetime

        def clean_function():
            now = datetime.datetime.now()
            exists = os.path.exists("test.txt")
            return {"now": now, "exists": exists}
        """
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        
        os.unlink(f.name)
        self.assertEqual(len(findings), 0)

    def test_scan_targets_directory(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad_script.py"
            p.write_text("prompt = 'parse the json structure and extract the frontmatter'; llm_call(prompt)")
            
            scanned, findings = scan_targets([td])
            self.assertEqual(scanned, 1)
            self.assertGreaterEqual(len(findings), 1)
            self.assertEqual(findings[0]["id"], "DET-03")

    def test_cli_deep_requires_provider_flag(self):
        cmd = [sys.executable, "-m", "determify.cli", "--deep", "."]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).parent.parent)
        res = subprocess.run(cmd, env=env, capture_output=True, text=True)
        self.assertEqual(res.returncode, 2)
        self.assertIn("requires an explicit decision engine flag", res.stderr)

    def test_cli_fail_on_findings_exit_code(self):
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "bad_script.py"
            p.write_text("openai.chat.completions.create(model='gpt-4o', messages=[])")
            
            cmd = [sys.executable, "-m", "determify.cli", "--fail-on-findings", td]
            env = os.environ.copy()
            env["PYTHONPATH"] = str(Path(__file__).parent.parent)
            res = subprocess.run(cmd, env=env, capture_output=True, text=True)
            self.assertEqual(res.returncode, 1)

if __name__ == "__main__":
    unittest.main()
