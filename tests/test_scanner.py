"""
test_scanner.py - Unit tests for determify scanner and patterns.
"""

import os
import unittest
import tempfile
from pathlib import Path
from determify.scanner import scan_file, scan_targets

class TestDetermifyScanner(unittest.TestCase):

    def test_det01_date_math_detection(self):
        content = """
        def get_date():
            prompt = "What is today's date? Please calculate the date for tomorrow."
            return openai.chat.completions.create(model="gpt-4", messages=[{"role": "user", "content": prompt}])
        """
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        
        os.unlink(f.name)
        ids = [x["id"] for x in findings]
        self.assertTrue("DET-01" in ids or "DET-07" in ids)

    def test_det02_file_discovery(self):
        content = """
        # Ask LLM if file exists
        llm_call("Does the file exist in the directory? List all files in dir.")
        """
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        
        os.unlink(f.name)
        ids = [x["id"] for x in findings]
        self.assertIn("DET-02", ids)

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
            p.write_text("llm_call('parse the json structure and extract the frontmatter')")
            
            scanned, findings = scan_targets([td])
            self.assertEqual(scanned, 1)
            self.assertGreaterEqual(len(findings), 1)
            self.assertEqual(findings[0]["id"], "DET-03")

if __name__ == "__main__":
    unittest.main()
