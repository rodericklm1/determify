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
from determify.jev_evaluator import _post_json, get_api_key, resolve_decision_config, DEFAULT_TYPESAFE_URL, OPENROUTER_DECISIONS_URL
from determify.patterns import PATTERNS, MAX_GAP, _cue

class TestDetermifyScanner(unittest.TestCase):

    def test_det01_date_math_detection(self):
        content = """
        def get_date():
            prompt = "What is today's date? Please generate the full breakdown."
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
        prompt = "Does the file exist in the directory? Query the full listing."
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
            
            scanned, findings, _ = scan_targets([td])
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
        """Tests that a pathological prefix-bomb stays linear (<1s for 180KB, two bounded branches at ~2x single-branch cost)."""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("format date " * 15000)
            f.flush()
            t0 = time.perf_counter()
            scan_file(f.name)
            elapsed = time.perf_counter() - t0
        
        os.unlink(f.name)
        self.assertLess(elapsed, 1.0, f"ReDoS vulnerability detected: took {elapsed:.2f}s")

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
            unbudgeted_n, unbudgeted, _ = scan_targets([d], batch_bytes=10**9, progress=False)
            batched_n, batched, _ = scan_targets([d], batch_bytes=1, progress=False)

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
                fh.write('prompt = "what is today\'s date? Generate it"\n')
                fh.write("x = 1\n" * 50000)  # well over the 1 byte budget
            n, findings, _ = scan_targets([d], batch_bytes=1, progress=False)
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
            scanned, findings, _ = scan_targets([td], progress=False)
            self.assertEqual(scanned, 0)
            self.assertEqual(findings, [])
            self.assertLess(time.perf_counter() - t1, 0.5)

    def test_scan_targets_fifo_does_not_hang(self):
        with tempfile.TemporaryDirectory() as td:
            os.mkfifo(os.path.join(td, "pipe.py"))
            t0 = time.perf_counter()
            scanned, findings, stats = scan_targets([td], progress=False)
            self.assertEqual(scanned, 0)
            self.assertEqual(findings, [])
            self.assertEqual(stats["skipped"], 1, "FIFO must be reported as skipped")
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
                scanned, findings, _ = scan_targets([td], use_kev=True, deep_scan=True, progress=False)
                scanned_direct, findings_direct, _ = scan_targets(
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

    def _cli(self, args, extra_env=None, cwd=None):
        cmd = [sys.executable, "-m", "determify.cli", *args]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).parent.parent)
        for k in ("OPENROUTER_API_KEY", "JEV_API_KEY", "TYPESAFE_API_KEY",
                  "JEV_BASE_URL", "JEV_ENDPOINT", "TYPESAFE_BASE_URL",
                  "OPENROUTER_DECISIONS_URL", "JEV_MODEL"):
            env.pop(k, None)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=20, cwd=cwd)

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

    # --- Cue-gate regression tests (audit finding 9.1) ---

    def test_det01_to_det06_are_cue_gated(self):
        for p in PATTERNS:
            if p["id"] == "DET-07":
                continue
            self.assertIn("{0,250}", p["regex"].pattern, f"{p['id']} must gate on LLM_CONTEXT_GATE")

    def test_bare_cue_string_not_flagged(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("msg = 'check if file exists'\n")
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        self.assertEqual(findings, [])

    def test_docstring_cue_not_flagged(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write('def probe():\n    """Does the file exist?"""\n    return True\n')
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        self.assertEqual(findings, [])

    def test_cue_adjacent_to_invocation_still_flagged(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write('resp = client.messages.create(prompt="What is today\'s date? Generate it.")\n')
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        ids = [x["id"] for x in findings]
        self.assertIn("DET-01", ids)
        self.assertIn("DET-07", ids)

    def test_reverse_order_gate_before_cue_flags_det01(self):
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write('client.messages.create(model="gpt-4o", prompt="What is today\'s date?")\n')
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        ids = [x["id"] for x in findings]
        self.assertIn("DET-01", ids, "cue after the gate token must still emit DET-01")
        self.assertIn("DET-07", ids)

    # --- Deep scan reporting fixes (audit finding 9.3) ---

    def test_deep_reports_first_signal_line_and_dedupes_windows(self):
        from determify.deep_scanner import deep_scan_file

        calls = []

        def mock(payload, use_kev=False, env_file=None):
            calls.append(1)
            return {
                "answers": {
                    "contains_unnecessary_ai": {"noul": 0.9},
                    "replacement_tier": {"choice": "clean_tier_0_code", "confidence": 0.42},
                }
            }, "mock"
        lines = [f"v{i} = {i}" for i in range(1, 121)]
        lines[49] = "llm = client.messages.create(model='m', messages=[])"
        with patch("determify.deep_scanner.call_decision_endpoint", mock):
            findings = deep_scan_file("f.py", "\n".join(lines), use_kev=True)
        self.assertEqual(len(findings), 1, "overlapping windows must collapse to one finding")
        self.assertEqual(len(calls), 1, "overlapping windows must not POST the same signal line twice")
        self.assertEqual(findings[0]["line"], 50, "finding must point at the signal line")
        self.assertEqual(findings[0]["start_line"], 1)
        self.assertEqual(findings[0]["jev_eval"]["confidence"], 0.42, "confidence is the choice probability")
        self.assertEqual(findings[0]["jev_eval"]["deterministic_prob"], 0.9, "deterministic_prob is the noul")

    def test_deep_legitimate_generative_dropped_and_debug_records(self):
        import io
        from contextlib import redirect_stderr
        from determify.deep_scanner import deep_scan_file

        def mock(payload, use_kev=False, env_file=None):
            return {
                "answers": {
                    "contains_unnecessary_ai": {"noul": 0.99},
                    "replacement_tier": {"choice": "legitimate_generative", "confidence": 0.99},
                }
            }, "mock"

        content = 'llm = client.messages.create(model="m", messages=[])\n'
        err = io.StringIO()
        with patch("determify.deep_scanner.call_decision_endpoint", mock), redirect_stderr(err):
            findings = deep_scan_file("g.py", content, use_kev=True, debug=True)
        self.assertEqual(findings, [])
        self.assertIn("dropped", err.getvalue(), "debug flag must surface evaluated-but-dropped rows")

    # --- Key resolution (audit finding 9.6) ---

    def test_cwd_dotenv_not_read_implicitly(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / ".env").write_text("OPENROUTER_API_KEY=sk-FROM-CWD\n")
            old = os.environ.pop("OPENROUTER_API_KEY", None)
            prev_cwd = os.getcwd()
            try:
                os.chdir(td)
                self.assertIsNone(get_api_key())
                self.assertEqual(get_api_key(env_file=str(Path(td) / ".env")), "sk-FROM-CWD")
            finally:
                os.chdir(prev_cwd)
                if old is not None:
                    os.environ["OPENROUTER_API_KEY"] = old

    # --- Skip visibility and exit codes (audit findings 9.7, 9.8) ---

    def test_symlink_skip_is_reported(self):
        import io
        from contextlib import redirect_stderr
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "target.txt"
            target.write_text('openai.chat.completions.create(model="x", messages=[])\n')
            link = Path(td) / "link.py"
            link.symlink_to(target)
            err = io.StringIO()
            with redirect_stderr(err):
                scanned, findings, stats = scan_targets([td], progress=False)
            self.assertEqual(scanned, 0)
            self.assertEqual(findings, [])
            self.assertEqual(stats["skipped"], 1)
            self.assertIn("[skip]", err.getvalue())
            self.assertIn("symlink", err.getvalue())

    def test_unreadable_skip_is_reported(self):
        import io
        from contextlib import redirect_stderr
        if os.geteuid() == 0:
            self.skipTest("root bypasses file permission bits")
        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "locked.py"
            p.write_text('openai.chat.completions.create(model="x", messages=[])\n')
            os.chmod(p, 0)
            try:
                err = io.StringIO()
                with redirect_stderr(err):
                    scanned, findings, stats = scan_targets([td], progress=False)
            finally:
                os.chmod(p, 0o644)
            self.assertEqual(scanned, 0)
            self.assertEqual(stats["skipped"], 1)
            self.assertIn("unreadable", err.getvalue())

    def test_missing_path_exits_2_without_banner(self):
        res = self._cli(["/definitely-not-a-determify-path/xyz"])
        self.assertEqual(res.returncode, 2)
        self.assertEqual(res.stdout, "")
        self.assertIn("does not exist", res.stderr)

    def test_json_reports_skipped_field(self):
        with tempfile.TemporaryDirectory() as td:
            os.mkfifo(os.path.join(td, "pipe.py"))
            (Path(td) / "ok.py").write_text("x = 1\n")
            res = self._cli(["--json", "--no-progress", td])
            data = json.loads(res.stdout)
            self.assertEqual(data["skipped"], 1)

    # --- Banner honesty and path fallback (audit findings 9.5, 9.13) ---

    def test_kev_not_invoked_banner_is_honest(self):
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "ok.py").write_text("x = 1\n")
            res = self._cli(["--kev", "--no-progress", td], {"KEV_ENDPOINT": "http://127.0.0.1:1/v1/systemone"})
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("provider not invoked", res.stdout)
            self.assertNotIn("Decision Engine Active", res.stdout)
            self.assertIn("Clean", res.stdout)

    def test_out_of_tree_target_reports_basename_not_home_path(self):
        with tempfile.TemporaryDirectory() as outside, tempfile.TemporaryDirectory() as cwd:
            target = Path(outside) / "hit.py"
            target.write_text('openai.chat.completions.create(model="x", messages=[])\n')
            res = self._cli(["--no-progress", str(target)], cwd=cwd)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("hit.py", res.stdout)
            self.assertNotIn(str(Path.home()), res.stdout)
            self.assertNotIn(outside, res.stdout)

    def test_extensionless_executable_with_shebang_is_scanned(self):
        """Verifies that an executable script without a file extension (e.g. CLI bin) is scanned."""
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "custom-runner"
            target.write_text('#!/bin/bash\nopenai.chat.completions.create(model="gpt-4", messages=[])\n')
            target.chmod(0o755)
            scanned, findings, stats = scan_targets([td], progress=False)
            self.assertEqual(len(findings), 1)
            self.assertIn("custom-runner", findings[0]["file"])
            self.assertEqual(scanned, 1)

    def test_extensionless_non_executable_is_skipped(self):
        """Verifies that extensionless data/text files without executable bit are skipped."""
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "random-doc"
            target.write_text('Some plain text without executable bit\n')
            target.chmod(0o644)
            scanned, findings, stats = scan_targets([td], progress=False)
            self.assertEqual(len(findings), 0)
            self.assertEqual(scanned, 0)

    def test_allow_marker_exempts_next_code_line_and_does_not_hide_other_ids(self):
        """A comment marker exempts the next code line for that ID only, and is reported."""
        from determify.scanner import EXEMPTIONS
        content = (
            "#!/bin/bash\n"
            "# determify:allow DET-07 Gated generative enrichment workflow\n"
            "exec opencode run --agent librarian \"enrich\"\n"
            "prompt = \"What is today's date? Please generate the full breakdown.\"\n"
            "client.messages.create(model=\"claude\", messages=[{\"role\": \"user\", \"content\": prompt}])\n"
        )
        EXEMPTIONS.clear()
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        det07 = [x for x in findings if x["id"] == "DET-07"]
        self.assertFalse(any(x["line"] == 3 for x in det07), det07)
        self.assertTrue(det07, "a DET-07 marker must not hide a different line")
        self.assertTrue(any(e["id"] == "DET-07" and e["line"] == 3 and "Gated generative" in e["reason"] for e in EXEMPTIONS))
        # DET-01 on a later line is not covered by a DET-07 marker.
        self.assertIn("DET-01", [x["id"] for x in findings])

    def test_resolve_decision_config_typesafe_key(self):
        """Verifies TYPESAFE_API_KEY defaults base_url to TypeSafe official and model to jev-latest."""
        old_ts = os.environ.get("TYPESAFE_API_KEY")
        old_or = os.environ.get("OPENROUTER_API_KEY")
        old_jev = os.environ.get("JEV_API_KEY")
        try:
            for k in ("TYPESAFE_API_KEY", "OPENROUTER_API_KEY", "JEV_API_KEY"):
                os.environ.pop(k, None)
            os.environ["TYPESAFE_API_KEY"] = "ts-test-secret"
            cfg = resolve_decision_config()
            self.assertEqual(cfg["api_key"], "ts-test-secret")
            self.assertEqual(cfg["base_url"], DEFAULT_TYPESAFE_URL)
            self.assertEqual(cfg["model"], "jev-latest")
        finally:
            os.environ.pop("TYPESAFE_API_KEY", None)
            if old_ts: os.environ["TYPESAFE_API_KEY"] = old_ts
            if old_or: os.environ["OPENROUTER_API_KEY"] = old_or
            if old_jev: os.environ["JEV_API_KEY"] = old_jev

    def test_resolve_decision_config_openrouter_key(self):
        """Verifies OPENROUTER_API_KEY defaults base_url to OpenRouter and model to ~typesafe/jev-latest."""
        old_ts = os.environ.get("TYPESAFE_API_KEY")
        old_or = os.environ.get("OPENROUTER_API_KEY")
        old_jev = os.environ.get("JEV_API_KEY")
        try:
            for k in ("TYPESAFE_API_KEY", "OPENROUTER_API_KEY", "JEV_API_KEY"):
                os.environ.pop(k, None)
            os.environ["OPENROUTER_API_KEY"] = "sk-or-test-secret"
            cfg = resolve_decision_config()
            self.assertEqual(cfg["api_key"], "sk-or-test-secret")
            self.assertEqual(cfg["base_url"], OPENROUTER_DECISIONS_URL)
            self.assertEqual(cfg["model"], "~typesafe/jev-latest")
        finally:
            os.environ.pop("OPENROUTER_API_KEY", None)
            if old_ts: os.environ["TYPESAFE_API_KEY"] = old_ts
            if old_or: os.environ["OPENROUTER_API_KEY"] = old_or
            if old_jev: os.environ["JEV_API_KEY"] = old_jev

    def test_resolve_decision_config_cli_overrides(self):
        """Verifies that explicit CLI flags override environment variables."""
        cfg = resolve_decision_config(
            base_url="https://custom.internal.ai/v1/systemone",
            api_key="cli-secret-key",
            model="custom-jev-model"
        )
        self.assertEqual(cfg["base_url"], "https://custom.internal.ai/v1/systemone")
        self.assertEqual(cfg["api_key"], "cli-secret-key")
        self.assertEqual(cfg["model"], "custom-jev-model")

    def test_resolve_decision_config_env_file_typesafe(self):
        """Verifies reading TYPESAFE_API_KEY and JEV_BASE_URL from an explicit .env file."""
        with tempfile.TemporaryDirectory() as td:
            env_path = Path(td) / ".env.custom"
            env_path.write_text("TYPESAFE_API_KEY=ts-from-file\nJEV_BASE_URL=https://proxy.example.com/systemone\n")
            cfg = resolve_decision_config(env_file=str(env_path))
            self.assertEqual(cfg["api_key"], "ts-from-file")
            self.assertEqual(cfg["base_url"], "https://proxy.example.com/systemone")
            self.assertEqual(cfg["model"], "jev-latest")

    def test_cli_missing_key_error_is_provider_agnostic(self):
        """Verifies that running --jev without any key provides an informative, provider-agnostic error."""
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "dummy.py").write_text("x = 1\n")
            res = self._cli(["--jev", td])
            self.assertEqual(res.returncode, 2)
            self.assertIn("No Jev API key found", res.stderr)
            self.assertIn("JEV_API_KEY", res.stderr)
            self.assertIn("TYPESAFE_API_KEY", res.stderr)
            self.assertIn("OPENROUTER_API_KEY", res.stderr)

    def test_cli_custom_base_url_and_api_key_invoked(self):
        """Verifies that --base-url and --api-key properly route request and headers to custom endpoint."""
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

        received = {}

        class CustomHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0") or 0)
                body = self.rfile.read(length).decode("utf-8") if length else ""
                received["auth"] = self.headers.get("Authorization")
                received["user_agent"] = self.headers.get("User-Agent")
                received["referer"] = self.headers.get("HTTP-Referer")
                received["body"] = json.loads(body) if body else {}

                resp_payload = {
                    "model": "jev-latest",
                    "answers": {
                        "optimal_tier": {
                            "choice": "tier_0_deterministic",
                            "confidence": 0.95
                        },
                        "can_be_deterministic": {
                            "noul": 0.98
                        },
                        "actionability_score": {
                            "score": 2.8
                        }
                    }
                }
                data = json.dumps(resp_payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), CustomHandler)
        port = server.server_address[1]
        threading.Thread(target=server.serve_forever, daemon=True).start()
        try:
            with tempfile.TemporaryDirectory() as td:
                target = Path(td) / "test_file.py"
                target.write_text('openai.chat.completions.create(model="gpt-4", messages=[])\n')
                res = self._cli([
                    "--base-url", f"http://127.0.0.1:{port}/v1/systemone",
                    "--api-key", "my-secret-token",
                    "--no-progress",
                    str(target)
                ])
                self.assertEqual(res.returncode, 0, res.stderr)
                self.assertEqual(received.get("auth"), "Bearer my-secret-token")
                self.assertEqual(received.get("user_agent"), "determify")
                self.assertIsNone(received.get("referer"))
                self.assertIn("Decision Engine Active", res.stdout)
                self.assertIn(f"http://127.0.0.1:{port}/v1/systemone", res.stdout)
        finally:
            server.shutdown()
            server.server_close()

if __name__ == "__main__":
    unittest.main()
