"""
test_scanner.py - Comprehensive Unit Tests & Adversarial Stress Tests for Determify.
"""

import os
import sys
import re
import json
import time
import unittest
from unittest.mock import patch
import tempfile
import subprocess
from pathlib import Path
from determify.scanner import scan_file, scan_targets, read_source_file_safe
from determify.jev_evaluator import _post_json, get_api_key
from determify.patterns import PATTERNS, MAX_GAP, _cue

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

    # --- Red-Team Adversarial Tests ---

    def test_redos_prefix_bomb_budget(self):
        """Tests that a pathological prefix-bomb executes in <500ms and avoids ReDoS."""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("format date " * 15000)
            f.flush()
            t0 = time.perf_counter()
            scan_file(f.name)
            elapsed = time.perf_counter() - t0
        
        os.unlink(f.name)
        self.assertLess(elapsed, 0.5, f"ReDoS vulnerability detected: took {elapsed:.2f}s")

    def test_fifo_does_not_hang(self):
        """Tests that FIFOs / pipes are safely rejected without blocking."""
        with tempfile.TemporaryDirectory() as td:
            fifo_path = os.path.join(td, "pipe.py")
            try:
                os.mkfifo(fifo_path)
            except (AttributeError, OSError):
                return  # Skip if platform lacks mkfifo
            
            t0 = time.perf_counter()
            content = read_source_file_safe(fifo_path)
            elapsed = time.perf_counter() - t0
            
            self.assertEqual(content, "")
            self.assertLess(elapsed, 0.1, "FIFO read blocked the process")

    def test_file_scheme_ssrf_rejected(self):
        """Tests that file:// endpoints are refused to prevent LFI/SSRF."""
        with self.assertRaises(RuntimeError) as ctx:
            _post_json("file:///etc/passwd", {}, headers={}, timeout=1)
        self.assertIn("Refusing non-HTTP(S) endpoint", str(ctx.exception))

    def test_batching_preserves_findings(self):
        """A tree split across many small batches must find exactly what one pass finds."""
        with tempfile.TemporaryDirectory() as d:
            for i in range(8):
                with open(os.path.join(d, f"m{i}.py"), "w") as fh:
                    fh.write(
                        'prompt = "what is today\'s date"\n'
                        'client.messages.create(model="x", messages=[{"role":"user","content":prompt}])\n'
                    )
            unbudgeted_n, unbudgeted = scan_targets([d], batch_bytes=10**9, progress=False)
            batched_n, batched = scan_targets([d], batch_bytes=1, progress=False)

            self.assertEqual(unbudgeted_n, batched_n)
            self.assertEqual(
                {(f["file"], f["line"], f["id"]) for f in unbudgeted},
                {(f["file"], f["line"], f["id"]) for f in batched},
                "Batching changed the findings",
            )
            self.assertTrue(batched, "Expected findings from the fixture tree")

    def test_batching_keeps_oversized_file(self):
        """A single file larger than the budget is its own batch, never dropped."""
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "big.py")
            with open(p, "w") as fh:
                fh.write('prompt = "what is today\'s date"\n')
                fh.write("x = 1\n" * 50000)  # well over the 1 byte budget
            n, findings = scan_targets([d], batch_bytes=1, progress=False)
            self.assertEqual(n, 1, "Oversized file was skipped")
            self.assertTrue(any(f["id"] == "DET-01" for f in findings))

    def test_progress_goes_to_stderr_not_stdout(self):
        """--json output must stay pipeable; progress belongs on stderr.

        Files must exceed MIN_BATCH_BYTES so the run genuinely splits, otherwise
        the single-batch case correctly emits no chatter at all.
        """
        with tempfile.TemporaryDirectory() as d:
            for i in range(3):
                with open(os.path.join(d, f"m{i}.py"), "w") as fh:
                    fh.write("prompt = 'what is today\\'s date'\n")
                    fh.write("x = 1\n" * 120000)  # each file > MIN_BATCH_BYTES

            import io
            from contextlib import redirect_stdout, redirect_stderr
            out, err = io.StringIO(), io.StringIO()
            with redirect_stdout(out), redirect_stderr(err):
                scan_targets([d], batch_bytes=1_000_000, progress=True)

            self.assertEqual(out.getvalue(), "", "Progress leaked to stdout")
            self.assertIn("batch", err.getvalue(), "Expected per-batch progress on stderr")

    def test_progress_silent_for_single_batch(self):
        """A tree that fits one batch should not emit batch chatter."""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "m.py"), "w") as fh:
                fh.write("x = 1\n")

            import io
            from contextlib import redirect_stderr
            err = io.StringIO()
            with redirect_stderr(err):
                scan_targets([d], batch_bytes=10**9, progress=True)

            self.assertNotIn("batch", err.getvalue())

    def test_shipped_patterns_are_not_quadratic(self):
        self.assertEqual(MAX_GAP, 250)
        helper = _cue(r"what\s+is\s+today'?s\s+date")
        self.assertFalse(helper.flags & re.DOTALL)
        self.assertNotIn(".*?", helper.pattern)
        self.assertIn("{0,250}", helper.pattern)
        bomb = ("what is today's date " * 8000)
        t0 = time.perf_counter()
        self.assertIsNone(helper.search(bomb))
        self.assertLess(time.perf_counter() - t0, 0.5)
        for pattern in PATTERNS:
            self.assertFalse(pattern["regex"].flags & re.DOTALL, pattern["id"])
            self.assertNotIn(".*?", pattern["regex"].pattern, pattern["id"])

    def test_dev_zero_symlink_does_not_bomb(self):
        with tempfile.TemporaryDirectory() as td:
            link = os.path.join(td, "bomb.py")
            os.symlink("/dev/zero", link)
            t0 = time.perf_counter()
            content = read_source_file_safe(link)
            elapsed = time.perf_counter() - t0
            self.assertEqual(content, "")
            self.assertLess(elapsed, 0.5)
            t1 = time.perf_counter()
            scanned, findings = scan_targets([td], progress=False)
            self.assertEqual(scanned, 0)
            self.assertEqual(findings, [])
            self.assertLess(time.perf_counter() - t1, 0.5)

    def test_scan_targets_fifo_does_not_hang(self):
        with tempfile.TemporaryDirectory() as td:
            os.mkfifo(os.path.join(td, "pipe.py"))
            t0 = time.perf_counter()
            scanned, findings = scan_targets([td], progress=False)
            self.assertEqual(scanned, 0)
            self.assertEqual(findings, [])
            self.assertLess(time.perf_counter() - t0, 0.5, "FIFO in the tree blocked scan_targets")

    def test_oversize_file_not_read(self):
        from determify.scanner import MAX_FILE_BYTES
        with tempfile.NamedTemporaryFile("wb", suffix=".py", delete=False) as handle:
            handle.write(b"openai.chat.completions.create()\n")
            handle.write(b"x" * (MAX_FILE_BYTES + 1))
            name = handle.name
        try:
            self.assertEqual(read_source_file_safe(name), "")
            self.assertEqual(scan_file(name), [])
        finally:
            os.unlink(name)

    def test_symlink_secret_not_read_or_posted(self):
        posted = []

        def capture(payload, use_kev=False, env_file=None):
            posted.append(payload)
            return {"answers": {}}, "test"

        with tempfile.TemporaryDirectory() as td:
            secret = Path(td) / "secret.txt"
            secret.write_text(
                'openai.chat.completions.create(model="x", messages=[])\n'
                "SECRET_MARKER_DO_NOT_LEAK\n"
            )
            link = Path(td) / "innocent.py"
            link.symlink_to(secret)
            with patch("determify.deep_scanner.call_decision_endpoint", capture):
                scanned, findings = scan_targets([td], use_kev=True, deep_scan=True, progress=False)
                scanned_direct, findings_direct = scan_targets(
                    [str(link)], use_kev=True, deep_scan=True, progress=False
                )
            blob = json.dumps({"posted": posted, "findings": findings, "direct": findings_direct})
            self.assertNotIn("SECRET_MARKER_DO_NOT_LEAK", blob)
            self.assertEqual(scanned, 0)
            self.assertEqual(scanned_direct, 0)

    def test_env_symlink_not_read(self):
        with tempfile.TemporaryDirectory() as td:
            secret = Path(td) / "secret.env"
            secret.write_text("OPENROUTER_API_KEY=sk-FROM-SYMLINK\n")
            link = Path(td) / ".env"
            link.symlink_to(secret)
            old = os.environ.pop("OPENROUTER_API_KEY", None)
            try:
                self.assertIsNone(get_api_key(env_file=str(link)))
            finally:
                if old is not None:
                    os.environ["OPENROUTER_API_KEY"] = old

    def test_redirect_does_not_forward_authorization(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        seen = {"redir_hits": 0, "steal_hits": 0, "steal_auth": None}

        class Handler(BaseHTTPRequestHandler):
            def _drain(self):
                length = int(self.headers.get("Content-Length", "0") or 0)
                if length:
                    self.rfile.read(length)

            def do_POST(self):
                self._drain()
                if self.path == "/redir":
                    seen["redir_hits"] += 1
                    port = self.server.server_address[1]
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{port}/steal")
                    self.end_headers()
                    return
                self.send_response(404)
                self.end_headers()

            def do_GET(self):
                if self.path == "/steal":
                    seen["steal_hits"] += 1
                    seen["steal_auth"] = self.headers.get("Authorization")
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"{}")
                    return
                self.send_response(404)
                self.end_headers()

            def log_message(self, format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(RuntimeError) as ctx:
                _post_json(
                    f"http://127.0.0.1:{server.server_address[1]}/redir",
                    {"probe": True},
                    headers={"Authorization": "Bearer sk-TEST-LEAK-TOKEN", "Content-Type": "application/json"},
                    timeout=3,
                )
            self.assertIn("refusing", str(ctx.exception).lower())
            self.assertEqual(seen["redir_hits"], 1)
            self.assertEqual(seen["steal_hits"], 0)
            self.assertIsNone(seen["steal_auth"])
        finally:
            server.shutdown()
            server.server_close()

    def test_cross_origin_redirect_refused(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0") or 0)
                if length:
                    self.rfile.read(length)
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:9/steal")
                self.end_headers()

            def log_message(self, format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with self.assertRaises(RuntimeError) as ctx:
                _post_json(
                    f"http://127.0.0.1:{server.server_address[1]}/redir",
                    {"probe": True},
                    headers={"Authorization": "Bearer sk-TEST-LEAK-TOKEN", "Content-Type": "application/json"},
                    timeout=3,
                )
            self.assertIn("refusing", str(ctx.exception).lower())
        finally:
            server.shutdown()
            server.server_close()

    def _cli(self, args, extra_env=None):
        cmd = [sys.executable, "-m", "determify.cli", *args]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).parent.parent)
        env.pop("OPENROUTER_API_KEY", None)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=20)

    def test_kev_dead_endpoint_fails_closed(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "bad.py").write_text(
                'openai.chat.completions.create(model="gpt-4o", messages=[])\n'
            )
            res = self._cli(["--kev", "--no-progress", td], {"KEV_ENDPOINT": "http://127.0.0.1:1/v1/systemone"})
            self.assertEqual(res.returncode, 2, res.stderr)
            self.assertNotIn("Clean", res.stdout)
            self.assertIn("failed closed", res.stderr)
            self.assertNotIn("Total Actionable Findings", res.stdout)

    def test_deep_dead_endpoint_fails_closed_no_json_success(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "chunk.py").write_text('prompt = "sort these names"\n')
            res = self._cli(
                ["--deep", "--kev", "--json", "--no-progress", td],
                {"KEV_ENDPOINT": "http://127.0.0.1:1/v1/systemone"},
            )
            self.assertEqual(res.returncode, 2, res.stderr)
            self.assertNotIn("Clean", res.stdout)
            self.assertNotIn("scanned_files", res.stdout)
            self.assertIn("failed closed", res.stderr)

    def test_cli_clean_file_still_exits_zero(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "ok.py").write_text("x = 1\n")
            res = self._cli([td])
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Clean", res.stdout)

if __name__ == "__main__":
    unittest.main()
