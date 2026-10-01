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
        """Tests that a pathological prefix-bomb stays linear (<2s for 180KB, two bounded branches at ~2x single-branch cost)."""
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write("format date " * 15000)
            f.flush()
            t0 = time.perf_counter()
            scan_file(f.name)
            elapsed = time.perf_counter() - t0
        
        os.unlink(f.name)
        self.assertLess(elapsed, 2.0, f"ReDoS vulnerability detected: took {elapsed:.2f}s")

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

    def test_orm_and_database_methods_not_flagged(self):
        """ORM and database queries like Order.create(format_date()) or db.query() must not trigger false positives."""
        content = """
        class OrderService:
            def create_order(self, db, order_data):
                # ORM call using create
                order = Order.create(format_date(order_data['timestamp']))
                # Database query call
                records = db.query("check if file exists in records")
                user = User.objects.create(name="test")
                return order
        """
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        self.assertEqual(len(findings), 0, f"Expected 0 findings on ORM/DB code, got {findings}")

    def test_ast_multiline_fstring_prompt_detected(self):
        """AST scanner inspects multi-line f-strings passed into verified LLM client calls."""
        content = '''
        def get_summary(client, user_id):
            prompt = f"""
            You are a helpful assistant.
            What is today's date?
            Please provide the full schedule.
            """
            return client.chat.completions.create(
                model="gpt-4o",
                messages=[{"role": "user", "content": prompt}]
            )
        '''
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        ids = [x["id"] for x in findings]
        self.assertIn("DET-07", ids)
        self.assertIn("DET-01", ids)

    def test_prompt_file_extension_detected_without_gate(self):
        """A .prompt file is recognized by default and evaluated for cues directly."""
        content = "You are an agent. What is today's date? Count the pages in the pdf.\n"
        with tempfile.NamedTemporaryFile("w", suffix=".prompt", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        ids = [x["id"] for x in findings]
        self.assertIn("DET-01", ids)
        self.assertIn("DET-04", ids)

    def test_include_docs_cli_flag(self):
        """Markdown files are skipped by default but scanned and evaluated when --include-docs is passed."""
        with tempfile.TemporaryDirectory() as td:
            doc = Path(td) / "test_doc.md"
            doc.write_text('prompt = "What is today\'s date?"\n')
            
            # Default scan: markdown is excluded
            scanned_def, findings_def, _ = scan_targets([td], include_docs=False)
            self.assertEqual(scanned_def, 0)
            self.assertEqual(len(findings_def), 0)
            
            # With include_docs: markdown is scanned and evaluated
            scanned_inc, findings_inc, _ = scan_targets([td], include_docs=True)
            self.assertEqual(scanned_inc, 1)
            self.assertEqual(len(findings_inc), 1)
            self.assertEqual(findings_inc[0]["id"], "DET-01")

    def test_parallel_decision_triage_evaluates_findings(self):
        """When multiple findings exist, ThreadPoolExecutor evaluates them in parallel and records jev_eval."""
        content = """
        prompt1 = "What is today's date?"
        prompt2 = "Count the pages in the pdf."
        client.chat.completions.create(model="gpt-4", messages=[])
        """
        calls = []
        def mock_eval(payload, use_kev=False, env_file=None, **kwargs):
            calls.append(payload)
            return {"answers": {"optimal_tier": {"choice": "tier_0_deterministic", "confidence": 0.95}}}, "mock"

        with tempfile.TemporaryDirectory() as td:
            p = Path(td) / "test.py"
            p.write_text(content)
            with patch("determify.jev_evaluator.call_decision_endpoint", mock_eval):
                scanned, findings, stats = scan_targets([td], use_kev=True)
                self.assertEqual(scanned, 1)
                self.assertGreaterEqual(len(findings), 2)
                self.assertTrue(stats["invoked"])
                for f in findings:
                    self.assertIn("jev_eval", f)
                self.assertEqual(len(calls), len(findings))


class TestReviewerBoundaryChecklist(unittest.TestCase):
    """
    Direct verification of the 8 boundary test cases and exemption audit trail
    provided in the external reviewer's regression CSV.
    """

    def _scan(self, content: str, suffix: str = ".py"):
        from determify.scanner import EXEMPTIONS
        EXEMPTIONS.clear()
        with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        return findings, list(EXEMPTIONS)

    def test_case_1_unrelated_complete_method(self):
        """'workflow.complete()' must NOT be flagged as an LLM SDK call (expected: 0 findings)."""
        content = "workflow.complete()\ntask.complete()\n"
        findings, _ = self._scan(content)
        self.assertEqual(len(findings), 0, f"Expected 0 findings, got {findings}")

    def test_case_2_ordinary_ui_message(self):
        """'message = \"What is today's date?\"' printed to UI must NOT be flagged as an LLM call (expected: 0 findings)."""
        content = 'message = "What is today\'s date?"\nprint(message)\n'
        findings, _ = self._scan(content)
        self.assertEqual(len(findings), 0, f"Expected 0 findings, got {findings}")

    def test_case_3_non_llm_model_logger(self):
        """'model_logger.info(\"What is today's date?\")' must NOT be flagged as an LLM call (expected: 0 findings)."""
        content = 'model_logger.info("What is today\'s date?")\n'
        findings, _ = self._scan(content)
        self.assertEqual(len(findings), 0, f"Expected 0 findings, got {findings}")

    def test_case_4_sdk_construction_only(self):
        """'client = OpenAI()' is constructor setup, not a generative invocation (expected: 0 findings)."""
        content = 'client = OpenAI()\nauth_client = Anthropic()\n'
        findings, _ = self._scan(content)
        self.assertEqual(len(findings), 0, f"Expected 0 findings, got {findings}")

    def test_case_5_aliased_prompt_variable(self):
        """'question = \"What is today's date?\"; client.responses.create(input=question)' must resolve the alias to DET-01 and DET-07."""
        content = 'question = "What is today\'s date?"\nclient.responses.create(input=question)\n'
        findings, _ = self._scan(content)
        ids = {f["id"] for f in findings}
        self.assertEqual(ids, {"DET-01", "DET-07"})

    def test_case_6_annotated_prompt_assignment(self):
        """'prompt: str = \"What is today's date?\"; client.responses.create(input=prompt)' must detect DET-01 and DET-07."""
        content = 'prompt: str = "What is today\'s date?"\nclient.responses.create(input=prompt)\n'
        findings, _ = self._scan(content)
        ids = {f["id"] for f in findings}
        self.assertEqual(ids, {"DET-01", "DET-07"})

    def test_case_7_cli_string_in_valid_python(self):
        """'command = \"opencode run summarize\"' must be recognized by AST as DET-07."""
        content = 'command = "opencode run summarize"\n'
        findings, _ = self._scan(content)
        ids = [f["id"] for f in findings]
        self.assertIn("DET-07", ids)

    def test_case_8_multiline_call_site_exemption(self):
        """A suppression marker placed on the call line must exempt DET-01 even if argument is on subsequent lines."""
        content = (
            "# determify:allow DET-01 Reviewed date injection\n"
            "client.responses.create(\n"
            "    input=\"What is today's date?\"\n"
            ")\n"
        )
        findings, exemptions = self._scan(content)
        ids = [f["id"] for f in findings]
        self.assertNotIn("DET-01", ids, "DET-01 should have been exempted")
        self.assertIn("DET-07", ids, "DET-07 should remain flagged since not exempted")
        exempt_ids = [e["id"] for e in exemptions]
        self.assertIn("DET-01", exempt_ids, "Exemption must be recorded in the audit trail")

    def test_case_9_suppressed_python_sdk_call_records_exemption(self):
        """Suppressed Python call enters the audit trail and is recorded in EXEMPTIONS."""
        content = (
            "# determify:allow DET-07 Intentional generative synthesis\n"
            "client.chat.completions.create(model=\"gpt-4o\", messages=[])\n"
        )
        findings, exemptions = self._scan(content)
        self.assertEqual(len(findings), 0)
        self.assertEqual(len(exemptions), 1)
        self.assertEqual(exemptions[0]["id"], "DET-07")
        self.assertEqual(exemptions[0]["reason"], "Intentional generative synthesis")

    def test_case_10_reassigned_dynamic_value(self):
        """Dynamic reassignment invalidates prior literal, preventing false positives."""
        content = (
            'question = "What is today\'s date?"\n'
            'question = get_user_request()\n'
            'client.responses.create(input=question)\n'
        )
        findings, _ = self._scan(content)
        ids = [f["id"] for f in findings]
        self.assertEqual(ids, ["DET-07"], f"Expected only DET-07, got {ids}")

    def test_case_11_cross_function_leakage(self):
        """Local variable bindings in one function must not leak into another function."""
        content = (
            'def first():\n'
            '    question = "What is today\'s date?"\n\n'
            'def second(question):\n'
            '    return client.responses.create(input=question)\n'
        )
        findings, _ = self._scan(content)
        ids = [f["id"] for f in findings]
        self.assertEqual(ids, ["DET-07"], f"Expected only DET-07, got {ids}")

    def test_case_12_case_sensitive_identifiers(self):
        """Identifier case sensitivity is preserved: Question binds accurately."""
        content = (
            'Question = "What is today\'s date?"\n'
            'client.responses.create(input=Question)\n'
        )
        findings, _ = self._scan(content)
        ids = {f["id"] for f in findings}
        self.assertEqual(ids, {"DET-01", "DET-07"})

    def test_case_13_nested_message_reference(self):
        """Recursive container resolution detects prompt variables inside messages=[{content: var}]."""
        content = (
            'question = "What is today\'s date?"\n'
            'client.chat.completions.create(\n'
            '    messages=[{"role": "user", "content": question}]\n'
            ')\n'
        )
        findings, _ = self._scan(content)
        ids = {f["id"] for f in findings}
        self.assertEqual(ids, {"DET-01", "DET-07"})

    def test_case_14_assignment_alias_chain(self):
        """Alias chains (q = question) propagate the constant value to the call site."""
        content = (
            'question = "What is today\'s date?"\n'
            'q = question\n'
            'client.responses.create(input=q)\n'
        )
        findings, _ = self._scan(content)
        ids = {f["id"] for f in findings}
        self.assertEqual(ids, {"DET-01", "DET-07"})

    def test_case_15_attribute_name_collision(self):
        """Attribute assignments (obj.question = ...) do not overwrite or bind bare local variables."""
        content = (
            'obj.question = "What is today\'s date?"\n'
            'question = "Safe documentation note"\n'
            'client.responses.create(input=question)\n'
        )
        findings, _ = self._scan(content)
        ids = [f["id"] for f in findings]
        self.assertEqual(ids, ["DET-07"], f"Expected only DET-07, got {ids}")

    def test_deep_scan_honors_allow_fallback(self):
        """deep_scan_file passes allow_fallback flag to call_decision_endpoint."""
        from determify.deep_scanner import deep_scan_file
        passed_kwargs = {}
        def mock_call(payload, use_kev=False, env_file=None, **kwargs):
            passed_kwargs.update(kwargs)
            return {"answers": {}}, "mock"

        content = "llm = client.messages.create(model='m', messages=[])\n"
        with patch("determify.deep_scanner.call_decision_endpoint", mock_call):
            deep_scan_file("test.py", content, use_kev=False, allow_fallback=True)
        self.assertTrue(passed_kwargs.get("allow_fallback"))

    def test_security_policy_refusal_does_not_trigger_fallback(self):
        """Security policy violations (e.g. redirect refusal) fail closed and never fall back even with allow_fallback=True."""
        from determify.jev_evaluator import call_decision_endpoint
        def mock_post(url, payload, headers, timeout=8):
            raise RuntimeError("Security violation: refusing HTTP redirect (302) to http://127.0.0.1/steal")

        fallback_called = []
        def mock_kev(payload, use_kev=False, env_file=None, **kwargs):
            fallback_called.append(True)
            return {}, "kev"

        with patch("determify.jev_evaluator._post_json", mock_post):
            with self.assertRaises(RuntimeError) as ctx:
                call_decision_endpoint({"model": "test"}, api_key="sk-test", allow_fallback=True)
            self.assertIn("Security violation", str(ctx.exception))
            self.assertEqual(len(fallback_called), 0, "Fallback must NOT be called on security violations")

    def test_logger_subpath_does_not_mask_sdk_call(self):
        """audit.logger.chat.completions.create(...) must be detected as DET-07, not masked by logger check."""
        content = "audit.logger.chat.completions.create(messages=[])\n"
        findings, _ = self._scan(content)
        ids = [f["id"] for f in findings]
        self.assertIn("DET-07", ids, f"Expected DET-07 for chat.completions.create, got {ids}")

    def test_det_deep_allow_marker_exempts_finding(self):
        """# determify:allow DET-DEEP reason properly suppresses semantic deep-scan findings
        when it binds the finding's exact signal site (marker directly above it)."""
        from determify.deep_scanner import deep_scan_file
        from determify.scanner import parse_allow_markers, _record_exemption, EXEMPTIONS
        EXEMPTIONS.clear()

        def mock(payload, use_kev=False, env_file=None):
            return {
                "answers": {
                    "contains_unnecessary_ai": {"noul": 0.95},
                    "replacement_tier": {"choice": "clean_tier_0_code", "confidence": 0.90},
                }
            }, "mock"

        content = (
            "def run_ai():\n"
            "    # determify:allow DET-DEEP Authorized semantic workflow\n"
            "    llm = client.messages.create(model='m', messages=[])\n"
        )
        lines = content.splitlines()
        allowed = parse_allow_markers(lines)

        with patch("determify.deep_scanner.call_decision_endpoint", mock):
            findings = deep_scan_file(
                "app.py", content, use_kev=True, allowed=allowed, record_exemption_fn=_record_exemption
            )
        self.assertEqual(len(findings), 0, "DET-DEEP should be exempted")
        self.assertEqual(len(EXEMPTIONS), 1, "Exemption must be recorded in ledger")
        self.assertEqual(EXEMPTIONS[0]["id"], "DET-DEEP")
        self.assertEqual(EXEMPTIONS[0]["line"], 3, "exemption ownership recorded at the exact signal site")
        self.assertEqual(EXEMPTIONS[0]["reason"], "Authorized semantic workflow")

    def test_cli_allow_fallback_without_api_key(self):
        """--jev --allow-fallback without API key does not fail preflight; triggers fallback."""
        from determify.cli import _run_cli
        with tempfile.TemporaryDirectory() as td:
            target = Path(td) / "test.py"
            target.write_text("x = 1\n")
            with patch.dict(os.environ, {}, clear=True):
                with patch("sys.argv", ["determify", "--jev", "--allow-fallback", "--no-progress", str(target)]):
                    # Should run clean on a clean file without exit 2
                    try:
                        _run_cli()
                    except SystemExit as e:
                        self.assertEqual(e.code, 0, f"Expected exit 0 for clean file under fallback, got {e.code}")

    def test_lambda_scope_masks_outer_literal(self):
        """Lambda parameters mask outer variable bindings, preventing false positives."""
        content = (
            'question = "What is today\'s date?"\n'
            'f = lambda question: client.responses.create(input=question)\n'
        )
        findings, _ = self._scan(content)
        ids = [f["id"] for f in findings]
        self.assertEqual(ids, ["DET-07"], f"Expected only DET-07, got {ids}")

    def test_for_loop_target_invalidates_binding(self):
        """For-loop targets are dynamic and invalidate prior literal bindings."""
        content = (
            'question = "What is today\'s date?"\n'
            'for question in incoming:\n'
            '    client.responses.create(input=question)\n'
        )
        findings, _ = self._scan(content)
        ids = [f["id"] for f in findings]
        self.assertEqual(ids, ["DET-07"], f"Expected only DET-07, got {ids}")

    def test_conditional_if_branch_invalidates_binding(self):
        """Variables assigned conditionally inside if-branches are invalidated for subsequent code."""
        content = (
            'question = "Summarize this"\n'
            'if condition:\n'
            '    question = "What is today\'s date?"\n'
            'client.responses.create(input=question)\n'
        )
        findings, _ = self._scan(content)
        ids = [f["id"] for f in findings]
        self.assertEqual(ids, ["DET-07"], f"Expected only DET-07, got {ids}")

    def test_class_scope_does_not_leak_to_methods(self):
        """Class namespace variables do not leak into inner method bodies."""
        content = (
            'class Example:\n'
            '    question = "What is today\'s date?"\n'
            '    def run(self):\n'
            '        return client.responses.create(input=question)\n'
        )
        findings, _ = self._scan(content)
        ids = [f["id"] for f in findings]
        self.assertEqual(ids, ["DET-07"], f"Expected only DET-07, got {ids}")

    def test_walrus_and_augassign_invalidation(self):
        """Walrus dynamic assignment and augmented assignments invalidate bindings."""
        content = (
            'question = "What is today\'s date?"\n'
            'question += get_dynamic_str()\n'
            'client.responses.create(input=question)\n'
        )
        findings, _ = self._scan(content)
        ids = [f["id"] for f in findings]
        self.assertEqual(ids, ["DET-07"], f"Expected only DET-07, got {ids}")


class TestWorkOrderASTRegressions(unittest.TestCase):
    """Snippets confirmed defective in the review, plus sibling control-flow cases."""

    def _scan(self, content: str):
        from determify.scanner import EXEMPTIONS
        EXEMPTIONS.clear()
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        return [x["id"] for x in findings]

    def test_walrus_dynamic_rebind_before_arg_extraction(self):
        content = (
            'question = "What is today\'s date?"\n'
            'client.responses.create(input=(question:=fetch()))\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, f"Stale walrus binding leaked: {ids}")
        self.assertEqual(ids.count("DET-07"), 2)

    def test_walrus_literal_still_resolves(self):
        content = (
            'client.responses.create(input=(question:="What is today\'s date?"))\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertIn("DET-01", ids, "Literal walrus binding must remain resolvable")
        self.assertEqual(ids.count("DET-07"), 2)

    def test_tuple_destructuring_invalidates_all_targets(self):
        content = (
            'question = "What is today\'s date?"\n'
            'other = "also a date? what time is it"\n'
            'question, other = fetch()\n'
            'client.responses.create(input=question)\n'
            'client.responses.create(input=other)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, f"Tuple unpack left stale bindings: {ids}")

    def test_list_destructuring_invalidates_all_targets(self):
        content = (
            'question = "What is today\'s date?"\n'
            '[question] = fetch()\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, f"List unpack left stale binding: {ids}")

    def test_if_else_branch_isolation_no_leak_into_else(self):
        content = (
            'if flag:\n'
            '    question = "What is today\'s date?"\n'
            'else:\n'
            '    client.responses.create(input=question)\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, f"If-branch assignment leaked across/after branches: {ids}")
        self.assertEqual(ids.count("DET-07"), 2)

    def test_class_body_resolves_current_class_bindings(self):
        content = (
            'class Example:\n'
            '    question = "What is today\'s date?"\n'
            '    client.responses.create(input=question)\n'
            '    def run(self):\n'
            '        return client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertEqual(ids.count("DET-01"), 1, "Class-body call must resolve the class literal once")
        self.assertEqual(ids.count("DET-07"), 2)

    def test_while_body_writes_invalidated_after_block(self):
        content = (
            'while cond:\n'
            '    question = "What is today\'s date?"\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, f"Loop-body write leaked past the loop: {ids}")

    def test_try_handler_isolation(self):
        content = (
            'try:\n'
            '    question = "What is today\'s date?"\n'
            '    boom()\n'
            'except Exception:\n'
            '    client.responses.create(input=question)\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, f"Try-body write leaked into handler/post-try: {ids}")

    def test_except_as_name_invalidated(self):
        content = (
            'question = "What is today\'s date?"\n'
            'try:\n'
            '    pass\n'
            'except Exception as question:\n'
            '    client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, "except-as must mask the prior literal binding")

    def test_match_capture_and_case_isolation(self):
        content = (
            'question = "What is today\'s date?"\n'
            'match data:\n'
            '    case {"prompt_text": question}:\n'
            '        client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, "Pattern capture must invalidate the outer literal")

    def test_match_case_writes_invalidated_after(self):
        content = (
            'match command:\n'
            '    case "go":\n'
            '        question = "What is today\'s date?"\n'
            '    case other:\n'
            '        pass\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, "Case-body write leaked past the match")

    def test_with_as_target_invalidates_binding(self):
        content = (
            'question = "What is today\'s date?"\n'
            'with open(path) as question:\n'
            '    client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, "with-as rebind must mask the prior literal")

    def test_with_body_write_invalidated_after(self):
        content = (
            'with open(path) as fh:\n'
            '    question = "What is today\'s date?"\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, "with-body write must not be assumed to complete")

    def test_delete_invalidates_binding(self):
        content = (
            'question = "What is today\'s date?"\n'
            'del question\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, "del must invalidate the binding")

    def test_global_declaration_masks_module_literal(self):
        content = (
            'question = "What is today\'s date?"\n'
            'def f():\n'
            '    global question\n'
            '    question = fetch()\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, "global rebind must conservatively mask the module literal")

    def test_def_statement_name_masks_prior_literal(self):
        content = (
            'question = "What is today\'s date?"\n'
            'def question():\n'
            '    pass\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, "def rebinds the name; old literal is not proof")

    def test_import_alias_masks_prior_literal(self):
        content = (
            'question = "What is today\'s date?"\n'
            'import json as question\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        self.assertNotIn("DET-01", ids, "import binding must mask the prior literal")


def _make_decision_server(policy, label="srv"):
    """
    Start a localhost decision server. policy: dict with
    mode=json (200 + answers), status=(code), garbage, or redirect.
    Returns (server, port, requests_list) where requests_list accumulates
    {"auth": header, "body": parsed-or-raw} entries per ACTUAL received request.
    """
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    answers = {
        "answers": {
            "optimal_tier": {"choice": "tier_0_deterministic", "confidence": 0.9},
            "can_be_deterministic": {"noul": 0.9},
            "actionability_score": {"score": 2.5},
            "contains_unnecessary_ai": {"noul": 0.9},
            "replacement_tier": {"choice": "clean_tier_0_code", "confidence": 0.9},
        }
    }
    requests_list = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0") or 0)
            raw = self.rfile.read(length) if length else b""
            try:
                parsed = json.loads(raw.decode("utf-8")) if raw else {}
            except Exception:
                parsed = raw
            requests_list.append({"auth": self.headers.get("Authorization"), "body": parsed})
            mode = policy.get("mode", "json")
            if mode == "redirect":
                self.send_response(302)
                self.send_header("Location", "http://127.0.0.1:9/steal")
                self.end_headers()
                return
            if mode == "garbage":
                body = b"{not valid json at all"
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
                return
            status = policy.get("code", 200) if mode == "status" else 200
            body = json.dumps(answers).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            return

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1], requests_list


class TestEvaluatorTypedFallbackE2E(unittest.TestCase):
    """Fallback only on typed availability errors, proven against live localhost servers."""

    def _cli(self, args, extra_env=None):
        cmd = [sys.executable, "-m", "determify.cli", *args]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).parent.parent)
        for k in ("OPENROUTER_API_KEY", "JEV_API_KEY", "TYPESAFE_API_KEY",
                  "JEV_BASE_URL", "JEV_ENDPOINT", "TYPESAFE_BASE_URL",
                  "OPENROUTER_DECISIONS_URL", "JEV_MODEL", "KEV_ENDPOINT"):
            env.pop(k, None)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)

    def _finding_file(self, td):
        target = Path(td) / "app.py"
        target.write_text('openai.chat.completions.create(model="gpt-4o", messages=[])\n')
        return str(target)

    def test_post_json_typed_classification(self):
        import urllib.error
        from determify.jev_evaluator import (
            _post_json, AvailabilityError, PermanentServiceError, ResponseFormatError,
        )
        servers = []
        try:
            for mode_args in (("status", 503), ("status", 403), ("garbage", None)):
                srv, port, _ = _make_decision_server(
                    {"mode": mode_args[0], "code": mode_args[1] or 200})
                servers.append(srv)
                url = f"http://127.0.0.1:{port}/v1/systemone"
                if mode_args[0] == "status" and mode_args[1] == 503:
                    ctx = self.assertRaises(AvailabilityError)
                elif mode_args[0] == "status":
                    ctx = self.assertRaises(PermanentServiceError)
                else:
                    ctx = self.assertRaises(ResponseFormatError)
                with ctx as cm:
                    _post_json(url, {"model": "m"}, {})
                self.assertIsNotNone(cm.exception.__cause__, "cause must be preserved")
            # Dead port -> AvailabilityError (connection class)
            ctx = self.assertRaises(AvailabilityError)
            with ctx as cm:
                _post_json("http://127.0.0.1:1/v1/systemone", {"model": "m"}, {}, timeout=2)
            self.assertIsInstance(cm.exception.__cause__, (urllib.error.URLError, OSError))
        finally:
            for srv in servers:
                srv.shutdown()
                srv.server_close()

    def test_error_paths_close_httperror_without_resourcewarning(self):
        """Bounded error-body reads must close HTTPError explicitly; GC-time
        implicit cleanup surfaces ResourceWarnings under dev mode."""
        import gc
        import warnings
        from determify.jev_evaluator import _post_json, AvailabilityError, PermanentServiceError
        servers = []
        try:
            srv5, p5, _ = _make_decision_server({"mode": "status", "code": 503})
            srv4, p4, _ = _make_decision_server({"mode": "status", "code": 403})
            servers += [srv5, srv4]
            for port, exc in ((p5, AvailabilityError), (p4, PermanentServiceError)):
                with warnings.catch_warnings():
                    warnings.simplefilter("error", ResourceWarning)
                    with self.assertRaises(exc):
                        _post_json(f"http://127.0.0.1:{port}/v1/systemone", {"model": "m"}, {}, timeout=4)
                gc.collect()  # any unclosed response would warn here as an error
        finally:
            for srv in servers:
                srv.shutdown()
                srv.server_close()

    def test_429_falls_back_and_discloses_both_destinations(self):
        prim, pport, preqs = _make_decision_server({"mode": "status", "code": 429})
        kev, kport, kreqs = _make_decision_server({"mode": "json"})
        try:
            with tempfile.TemporaryDirectory() as td:
                res = self._cli(
                    ["--jev", "--base-url", f"http://127.0.0.1:{pport}/v1/systemone",
                     "--api-key", "PRIMARY-CLI-SECRET", "--allow-fallback", "--no-progress",
                     self._finding_file(td)],
                    {"KEV_ENDPOINT": f"http://127.0.0.1:{kport}/v1/systemone"},
                )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(len(preqs), 1, "primary got exactly one real request")
            self.assertEqual(len(kreqs), 1, "fallback kev got exactly one real request")
            for req in kreqs:
                self.assertNotEqual(req["auth"], "Bearer PRIMARY-CLI-SECRET",
                                    "primary CLI credential leaked into fallback headers")
            self.assertIn("falling back to authorized Kev at", res.stderr)
            self.assertIn(f"http://127.0.0.1:{pport}", res.stderr)
            self.assertIn("explicit --allow-fallback", res.stdout)
            self.assertIn(f"http://127.0.0.1:{kport}", res.stdout)
        finally:
            prim.shutdown(); prim.server_close()
            kev.shutdown(); kev.server_close()

    def test_no_fallback_flag_503_fails_closed(self):
        prim, pport, _ = _make_decision_server({"mode": "status", "code": 503})
        kev, kport, kreqs = _make_decision_server({"mode": "json"})
        try:
            with tempfile.TemporaryDirectory() as td:
                res = self._cli(
                    ["--jev", "--base-url", f"http://127.0.0.1:{pport}/v1/systemone",
                     "--api-key", "k", "--no-progress", self._finding_file(td)],
                    {"KEV_ENDPOINT": f"http://127.0.0.1:{kport}/v1/systemone"},
                )
            self.assertEqual(res.returncode, 2)
            self.assertIn("failed closed", res.stderr)
            self.assertEqual(len(kreqs), 0, "no fallback without the explicit flag")
        finally:
            prim.shutdown(); prim.server_close()
            kev.shutdown(); kev.server_close()

    def test_auth_and_format_and_security_errors_never_fall_back(self):
        cases = [
            ("auth 401", {"mode": "status", "code": 401}),
            ("forbidden 403", {"mode": "status", "code": 403}),
            ("malformed json", {"mode": "garbage"}),
            ("redirect security", {"mode": "redirect"}),
        ]
        for name, policy in cases:
            with self.subTest(name):
                prim, pport, _ = _make_decision_server(policy)
                kev, kport, kreqs = _make_decision_server({"mode": "json"})
                try:
                    with tempfile.TemporaryDirectory() as td:
                        res = self._cli(
                            ["--jev", "--base-url", f"http://127.0.0.1:{pport}/v1/systemone",
                             "--api-key", "k", "--allow-fallback", "--no-progress",
                             self._finding_file(td)],
                            {"KEV_ENDPOINT": f"http://127.0.0.1:{kport}/v1/systemone"},
                        )
                    self.assertEqual(res.returncode, 2, res.stdout)
                    self.assertEqual(len(kreqs), 0, f"{name} must not trigger fallback")
                finally:
                    prim.shutdown(); prim.server_close()
                    kev.shutdown(); kev.server_close()

    def test_missing_key_with_fallback_calls_kev_only(self):
        kev, kport, kreqs = _make_decision_server({"mode": "json"})
        try:
            with tempfile.TemporaryDirectory() as td:
                res = self._cli(
                    ["--jev", "--allow-fallback", "--no-progress", self._finding_file(td)],
                    {"KEV_ENDPOINT": f"http://127.0.0.1:{kport}/v1/systemone"},
                )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertEqual(len(kreqs), 1)
            self.assertIn("falling back to authorized Kev at", res.stderr)
        finally:
            kev.shutdown(); kev.server_close()

    def test_deep_end_to_end_fallback_and_fail_closed(self):
        from determify.deep_scanner import deep_scan_file
        # deep path: transient primary failure + flag => fallback answers
        prim, pport, preqs = _make_decision_server({"mode": "status", "code": 503})
        kev, kport, kreqs = _make_decision_server({"mode": "json"})
        try:
            with tempfile.TemporaryDirectory() as td:
                target = Path(td) / "deep_app.py"
                target.write_text('llm = client.messages.create(model="m", messages=[])\n')
                res = self._cli(
                    ["--deep", "--jev",
                     "--base-url", f"http://127.0.0.1:{pport}/v1/systemone",
                     "--api-key", "k", "--allow-fallback", "--no-progress", "--json", str(target)],
                    {"KEV_ENDPOINT": f"http://127.0.0.1:{kport}/v1/systemone"},
                )
            self.assertEqual(res.returncode, 0, res.stderr)
            data = json.loads(res.stdout)
            ids = [f["id"] for f in data["findings"]]
            self.assertIn("DET-DEEP", ids)
            self.assertTrue(any("fallback" in str(f.get("jev_eval", {}).get("provider", ""))
                                for f in data["findings"]))
            self.assertGreaterEqual(len(preqs), 1)
            self.assertGreaterEqual(len(kreqs), 1)
        finally:
            prim.shutdown(); prim.server_close()
            kev.shutdown(); kev.server_close()

    def test_deep_malformed_json_fails_closed_no_fallback(self):
        prim, pport, _ = _make_decision_server({"mode": "garbage"})
        kev, kport, kreqs = _make_decision_server({"mode": "json"})
        try:
            with tempfile.TemporaryDirectory() as td:
                target = Path(td) / "deep_app.py"
                target.write_text('llm = client.messages.create(model="m", messages=[])\n')
                res = self._cli(
                    ["--deep", "--jev",
                     "--base-url", f"http://127.0.0.1:{pport}/v1/systemone",
                     "--api-key", "k", "--allow-fallback", "--no-progress", str(target)],
                    {"KEV_ENDPOINT": f"http://127.0.0.1:{kport}/v1/systemone"},
                )
            self.assertEqual(res.returncode, 2)
            self.assertIn("failed closed", res.stderr)
            self.assertEqual(len(kreqs), 0)
        finally:
            prim.shutdown(); prim.server_close()
            kev.shutdown(); kev.server_close()


class TestDeepExemptionExactSite(unittest.TestCase):
    """One marker must never suppress an unrelated chunk site inside the same window."""

    def test_two_unrelated_sites_same_window(self):
        from determify.deep_scanner import deep_scan_file
        from determify.scanner import parse_allow_markers, _record_exemption, EXEMPTIONS
        EXEMPTIONS.clear()

        calls = []
        def mock(payload, use_kev=False, env_file=None):
            calls.append(1)
            return {
                "answers": {
                    "contains_unnecessary_ai": {"noul": 0.9},
                    "replacement_tier": {"choice": "clean_tier_0_code", "confidence": 0.9},
                }
            }, "mock"

        lines = ["x%d = %d" % (i, i) for i in range(1, 121)]
        lines[4] = "client.responses.create(model='m', input='sort names')"     # site A line 5
        lines[48] = "# determify:allow DET-DEEP Only the second site is reviewed"
        lines[49] = "llm = client.messages.create(model='m', messages=[])"       # site B line 50
        content = "\n".join(lines) + "\n"
        allowed = parse_allow_markers(content.splitlines())

        with patch("determify.deep_scanner.call_decision_endpoint", mock):
            findings = deep_scan_file(
                "two_sites.py", content, use_kev=True, allowed=allowed,
                record_exemption_fn=_record_exemption,
            )
        reported = [f["line"] for f in findings]
        self.assertEqual(reported, [5], "marker at site B must not suppress the unrelated site A")
        self.assertEqual(len(EXEMPTIONS), 1)
        self.assertEqual(EXEMPTIONS[0]["line"], 50, "exemption recorded at the owning signal site")
        self.assertEqual(len(calls), 2, "both sites evaluated; suppression is post-evaluation, exact-site")


class TestConcurrencyBoundedSubmissions(unittest.TestCase):
    """Overlap, bounds, ordering, and cancellation via events (no brittle timing)."""

    def test_overlap_proven_by_barrier_and_input_order(self):
        import threading
        from determify.concurrency import bounded_parallel_map
        barrier = threading.Barrier(3, timeout=10)

        def fn(i):
            if i < 3:
                barrier.wait()  # completes only if three tasks truly overlap
            return i * 10

        results = bounded_parallel_map(fn, range(6), max_workers=3)
        self.assertEqual(results, [0, 10, 20, 30, 40, 50], "results must follow input order")

    def test_pending_submissions_bounded_by_workers(self):
        import threading
        from determify.concurrency import bounded_parallel_map
        lock = threading.Lock()
        active = [0]
        peak = [0]

        def fn(i):
            with lock:
                active[0] += 1
                peak[0] = max(peak[0], active[0])
            ev = threading.Event()
            ev.wait(0.01)
            with lock:
                active[0] -= 1
            return i

        results = bounded_parallel_map(fn, range(20), max_workers=4)
        self.assertEqual(results, list(range(20)))
        self.assertLessEqual(peak[0], 4, "never more than workers concurrent")

    def test_failure_cancels_remaining_unscheduled_work(self):
        import threading
        from determify.concurrency import bounded_parallel_map
        lock = threading.Lock()
        started = []

        def fn(i):
            with lock:
                started.append(i)
            if i == 0:
                raise RuntimeError("boom")
            return i

        with self.assertRaises(RuntimeError):
            bounded_parallel_map(fn, range(20), max_workers=2)
        # Only the initial window was ever submitted; later work never started.
        self.assertTrue(all(s <= 1 for s in started),
                        f"items beyond the initial window started: {started}")

    def test_workers_configurable_and_bounded(self):
        from determify.concurrency import bounded_parallel_map as real
        captured = {}

        def spy(fn, items, max_workers):
            captured["workers"] = max_workers
            return real(fn, items, max_workers)

        def mock_eval(*a, **k):
            return {"answers": {}}, "mockprov"

        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "a.py").write_text(
                'openai.chat.completions.create(model="gpt-4o", messages=[])\n')
            with patch("determify.scanner.bounded_parallel_map", spy), \
                 patch("determify.jev_evaluator.call_decision_endpoint", mock_eval):
                scan_targets([td], use_kev=True, workers=2, progress=False)
        self.assertEqual(captured.get("workers"), 2)


class TestBatchPolicy(unittest.TestCase):
    """CLI None must mean the library DEFAULT_BATCH_BYTES, never a silent cap change."""

    def _run_cli_capture(self, argv, td):
        from determify import cli
        captured = {}
        def fake_scan(*args, **kwargs):
            captured.update(kwargs)
            return 0, [], {"skipped": 0, "invoked": False, "fallback_used": False}
        from unittest.mock import patch as _p
        with _p.object(cli, "scan_targets", fake_scan), \
             _p.object(sys, "argv", ["determify", *argv, td]), \
             _p.dict(os.environ, {}, clear=True):
            try:
                cli._run_cli()
            except SystemExit as e:
                self.fail(f"unexpected exit {e.code}")
        return captured

    def test_cli_forwards_none_by_default_and_mib_exact(self):
        with tempfile.TemporaryDirectory() as td:
            default_kwargs = self._run_cli_capture(["--no-progress"], td)
            self.assertIsNone(default_kwargs["batch_bytes"],
                              "CLI default must forward None so the library default applies")
            mib_kwargs = self._run_cli_capture(["--no-progress", "--batch-mb", "7"], td)
            self.assertEqual(mib_kwargs["batch_bytes"], 7 * 1_048_576,
                             "--batch-mb must forward exact MiB multiples")
            workers_kwargs = self._run_cli_capture(["--no-progress", "--workers", "3"], td)
            self.assertEqual(workers_kwargs["workers"], 3)

    def test_library_none_policy_is_default_batch_bytes(self):
        from determify import scanner
        from determify.scanner import DEFAULT_BATCH_BYTES
        captured = {}
        real_batches = scanner._batches

        def spy(files, batch_bytes):
            captured["bb"] = batch_bytes
            return real_batches(files, batch_bytes)

        from unittest.mock import patch as _p
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / "ok.py").write_text("x = 1\n")
            with _p.object(scanner, "_batches", spy):
                scanner.scan_targets([td], batch_bytes=None, progress=False)
        self.assertEqual(captured["bb"], DEFAULT_BATCH_BYTES)
        self.assertEqual(DEFAULT_BATCH_BYTES, 50_000_000)

    def test_cli_batch_mb_subprocess_forwards_and_validates(self):
        base = [sys.executable, "-m", "determify.cli"]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).parent.parent)
        with tempfile.TemporaryDirectory() as td:
            for i in range(2):
                (Path(td) / f"m{i}.py").write_text("x = 1\n" * 150000)  # ~880KB each
            res = subprocess.run(
                base + ["--batch-mb", "1", td], env=env, capture_output=True, text=True, timeout=60)
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("batches of 1 MiB", res.stderr)
            res_bad = subprocess.run(
                base + ["--batch-mb", "0", td], env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(res_bad.returncode, 2)
            self.assertIn("at least 1 MiB", res_bad.stderr)
            res_workers = subprocess.run(
                base + ["--workers", "33", td], env=env, capture_output=True, text=True, timeout=20)
            self.assertEqual(res_workers.returncode, 2)
            self.assertIn("between 1 and 32", res_workers.stderr)


class TestWorkOrderRoundTwo(unittest.TestCase):
    """M1 comprehension walrus owner frames, M2 structured fallback metadata,
    N1 batch-byte honesty, L2 container mutation aliases."""

    def _scan(self, content: str):
        from determify.scanner import EXEMPTIONS
        EXEMPTIONS.clear()
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        return [x["id"] for x in findings]

    def _cli(self, args, extra_env=None):
        cmd = [sys.executable, "-m", "determify.cli", *args]
        env = os.environ.copy()
        env["PYTHONPATH"] = str(Path(__file__).parent.parent)
        for k in ("OPENROUTER_API_KEY", "JEV_API_KEY", "TYPESAFE_API_KEY",
                  "JEV_BASE_URL", "JEV_ENDPOINT", "TYPESAFE_BASE_URL",
                  "OPENROUTER_DECISIONS_URL", "JEV_MODEL", "KEV_ENDPOINT"):
            env.pop(k, None)
        if extra_env:
            env.update(extra_env)
        return subprocess.run(cmd, env=env, capture_output=True, text=True, timeout=30)

    # ---- M1: comprehension walrus binds (invalidates) in the enclosing owner frame ----

    def test_m1_list_comp_walrus_invalidates_owner(self):
        content = (
            'question = "What is today\'s date?"\n'
            'data = [(question := fetch()) for x in xs]\n'
            'client.responses.create(input=question)\n'
        )
        self.assertEqual(self._scan(content), ["DET-07"])

    def test_m1_set_comp_walrus(self):
        content = (
            'question = "What is today\'s date?"\n'
            'data = {(question := fetch()) for x in xs}\n'
            'client.responses.create(input=question)\n'
        )
        self.assertNotIn("DET-01", self._scan(content))

    def test_m1_dict_comp_walrus(self):
        content = (
            'question = "What is today\'s date?"\n'
            'data = {k: (question := fetch()) for k in ks}\n'
            'client.responses.create(input=question)\n'
        )
        self.assertNotIn("DET-01", self._scan(content))

    def test_m1_generator_walrus_invalidated_conservatively(self):
        content = (
            'question = "What is today\'s date?"\n'
            'gen = ((question := fetch()) for x in xs)\n'
            'client.responses.create(input=question)\n'
        )
        # Generator bodies execute lazily; the write is unknown, so stale literal
        # must not be trusted (conservative invalidation, no DET-01).
        self.assertNotIn("DET-01", self._scan(content))

    def test_m1_nested_comp_walrus(self):
        content = (
            'question = "What is today\'s date?"\n'
            'data = [[(question := fetch()) for y in row] for row in matrix]\n'
            'client.responses.create(input=question)\n'
        )
        self.assertNotIn("DET-01", self._scan(content))

    def test_m1_lambda_in_comp_binds_lambda_frame_not_owner(self):
        content = (
            'question = "What is today\'s date?"\n'
            'data = [(lambda: (question := fetch()))() for x in xs]\n'
            'client.responses.create(input=question)\n'
        )
        # Python: walrus inside lambda binds the lambda's own scope, so the module
        # literal genuinely survives. Correctness preserved, not blanket-dropped.
        self.assertIn("DET-01", self._scan(content))

    def test_m1_comp_walrus_owners_inner_function_frame(self):
        content = (
            'question = "What is today\'s date?"\n'
            'def f():\n'
            '    data = [(question := fetch()) for x in xs]\n'
            '    return client.responses.create(input=question)\n'
            'client.responses.create(input=question)\n'
        )
        ids = self._scan(content)
        # f-internal call must NOT report the module literal (f-local walrus target),
        # while the module-level call keeps the still-valid module literal.
        self.assertIn("DET-01", ids)
        self.assertEqual(ids.count("DET-07"), 2)
        det01_lines = self._scan_det01_lines(content)
        self.assertTrue(all(ln in (1, 5) for ln in det01_lines), det01_lines)

    def _scan_det01_lines(self, content):
        from determify.scanner import EXEMPTIONS
        EXEMPTIONS.clear()
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as f:
            f.write(content)
            f.flush()
            findings = scan_file(f.name)
        os.unlink(f.name)
        return [x["line"] for x in findings if x["id"] == "DET-01"]

    def test_m1_walrus_in_comp_inside_call_args(self):
        content = (
            'question = "What is today\'s date?"\n'
            'client.responses.create(input=[(question := fetch()) for x in xs], prompt=question)\n'
        )
        # Arguments evaluate left to right: the comp rebinds question before the
        # call runs; prompt=question must not use the stale literal.
        self.assertNotIn("DET-01", self._scan(content))

    def test_m1_regression_all_four_original_snippets(self):
        self.assertEqual(
            self._scan('question = "What is today\'s date?"\n'
                       'client.responses.create(input=(question:=fetch()))\n'
                       'client.responses.create(input=question)\n'),
            ["DET-07", "DET-07"])
        self.assertEqual(
            self._scan('question = "What is today\'s date?"\n'
                       'question, other = fetch()\n'
                       'client.responses.create(input=question)\n'),
            ["DET-07"])
        self.assertEqual(
            self._scan('if flag:\n'
                       '    question = "What is today\'s date?"\n'
                       'else:\n'
                       '    client.responses.create(input=question)\n'),
            ["DET-07"])
        ids = self._scan('class Example:\n'
                         '    question = "What is today\'s date?"\n'
                         '    client.responses.create(input=question)\n')
        self.assertEqual(sorted(ids), ["DET-01", "DET-07"])

    # ---- L2: subscript mutation invalidates root and simple aliases ----

    def test_l2_subscript_assign_invalidates_root_and_alias(self):
        content = (
            'data = {"question": "What is today\'s date?"}\n'
            'alias = data\n'
            'data["question"] = fetch()\n'
            'client.responses.create(input=data)\n'
            'client.responses.create(input=alias)\n'
        )
        self.assertEqual(self._scan(content), ["DET-07", "DET-07"])

    def test_l2_subscript_augassign_and_delete(self):
        content = (
            'data = {"question": "what is today\'s date?"}\n'
            'data["question"] += fetch()\n'
            'client.responses.create(input=data)\n'
        )
        self.assertNotIn("DET-01", self._scan(content))
        content2 = (
            'data = {"question": "what is today\'s date?"}\n'
            'del data["question"]\n'
            'client.responses.create(input=data)\n'
        )
        self.assertNotIn("DET-01", self._scan(content2))

    def test_l2_rebind_does_not_invalidate_alias(self):
        content = (
            'data = {"question": "what is today\'s date?"}\n'
            'alias = data\n'
            'data = fetch()\n'
            'client.responses.create(input=alias)\n'
        )
        # Rebinding the name leaves aliased objects untouched in Python; the
        # alias still points at the old (tracked) container content.
        self.assertIn("DET-01", self._scan(content))

    def test_l2_fstring_literal_skeleton_still_valid(self):
        content = (
            "today = fetch()\n"
            'client.responses.create(input=f"what is today\'s date? {today}")\n'
        )
        # Dynamic holes do not void the static literal cue fragments.
        self.assertIn("DET-01", self._scan(content))

    # ---- M2: structured fallback metadata, no provider-string sniffing ----

    def test_m2_healthy_model_named_fallback_is_not_a_fallback_claim(self):
        prim, pport, preqs = _make_decision_server({"mode": "json"})
        kev, kport, kreqs = _make_decision_server({"mode": "json"})
        try:
            with tempfile.TemporaryDirectory() as td:
                target = Path(td) / "app.py"
                target.write_text('openai.chat.completions.create(model="gpt-4o", messages=[])\n')
                res = self._cli(
                    ["--jev", "--base-url", f"http://127.0.0.1:{pport}/v1/systemone",
                     "--api-key", "k", "--model", "my-fallback-model", "--no-progress", str(target)],
                    {"KEV_ENDPOINT": f"http://127.0.0.1:{kport}/v1/systemone"},
                )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("Triage queries were evaluated by", res.stdout)
            self.assertNotIn("Explicit fallback used", res.stdout)
            self.assertEqual(len(kreqs), 0, "healthy primary must never touch Kev")
            self.assertEqual(len(preqs), 1)
            self.assertIn("my-fallback-model", res.stdout)
        finally:
            prim.shutdown(); prim.server_close()
            kev.shutdown(); kev.server_close()

    def test_m2_missing_key_reports_not_contacted_never_transient(self):
        kev, kport, kreqs = _make_decision_server({"mode": "json"})
        try:
            with tempfile.TemporaryDirectory() as td:
                target = Path(td) / "app.py"
                target.write_text('openai.chat.completions.create(model="gpt-4o", messages=[])\n')
                res = self._cli(
                    ["--jev", "--allow-fallback", "--no-progress", "--json", str(target)],
                    {"KEV_ENDPOINT": f"http://127.0.0.1:{kport}/v1/systemone"},
                )
            self.assertEqual(res.returncode, 0, res.stderr)
            data = json.loads(res.stdout)
            verdicts = [f["jev_eval"] for f in data["findings"] if f.get("jev_eval")]
            self.assertTrue(verdicts)
            self.assertTrue(all(v.get("fallback_used") for v in verdicts))
            self.assertTrue(all(v["fallback"]["reason"] == "no_cloud_key" for v in verdicts))
            self.assertTrue(all(v["fallback"]["contacted_primary"] is False for v in verdicts))
            self.assertEqual(len(kreqs), len(verdicts))
        finally:
            kev.shutdown(); kev.server_close()

    def test_m2_missing_key_stdout_banner_wording(self):
        kev, kport, _ = _make_decision_server({"mode": "json"})
        try:
            with tempfile.TemporaryDirectory() as td:
                target = Path(td) / "app.py"
                target.write_text('openai.chat.completions.create(model="gpt-4o", messages=[])\n')
                res = self._cli(
                    ["--jev", "--allow-fallback", "--no-progress", str(target)],
                    {"KEV_ENDPOINT": f"http://127.0.0.1:{kport}/v1/systemone"},
                )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("was not contacted", res.stdout)
            self.assertNotIn("transient availability", res.stdout)
            self.assertIn("no cloud API key configured", res.stderr)
        finally:
            kev.shutdown(); kev.server_close()

    def test_m2_env_file_kev_destination_matches_actual_post(self):
        kev, kport, kreqs = _make_decision_server({"mode": "json"})
        try:
            with tempfile.TemporaryDirectory() as td:
                env_file = Path(td) / ".env.custom"
                kev_url = f"http://127.0.0.1:{kport}/custom-systemone-path"
                env_file.write_text(f"KEV_ENDPOINT={kev_url}\n")
                target = Path(td) / "app.py"
                target.write_text('openai.chat.completions.create(model="gpt-4o", messages=[])\n')
                res = self._cli(
                    ["--jev", "--allow-fallback", "--no-progress",
                     "--env-file", str(env_file), str(target)],
                )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn(kev_url, res.stdout,
                          "disclosed fallback destination must be the env-file-resolved URL")
            self.assertEqual(len(kreqs), 1, "request actually went to the env-file destination")
        finally:
            kev.shutdown(); kev.server_close()

    def test_m2_availability_fallback_uses_transient_wording(self):
        prim, pport, preqs = _make_decision_server({"mode": "status", "code": 503})
        kev, kport, kreqs = _make_decision_server({"mode": "json"})
        try:
            with tempfile.TemporaryDirectory() as td:
                target = Path(td) / "app.py"
                target.write_text('openai.chat.completions.create(model="gpt-4o", messages=[])\n')
                res = self._cli(
                    ["--jev", "--base-url", f"http://127.0.0.1:{pport}/v1/systemone",
                     "--api-key", "k", "--allow-fallback", "--no-progress", str(target)],
                    {"KEV_ENDPOINT": f"http://127.0.0.1:{kport}/v1/systemone"},
                )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("transient availability error", res.stdout)
            self.assertIn(f"http://127.0.0.1:{pport}", res.stdout)
            self.assertIn(f"http://127.0.0.1:{kport}", res.stdout)
            self.assertNotIn("was not contacted", res.stdout)
            self.assertEqual(len(preqs), 1)
            self.assertEqual(len(kreqs), 1)
        finally:
            prim.shutdown(); prim.server_close()
            kev.shutdown(); kev.server_close()

    # ---- N1: batch byte budget stated honestly ----

    def test_n1_batch_default_documented_as_bytes_not_mib(self):
        root = Path(__file__).parent.parent
        src = (root / "determify" / "scanner.py").read_text()
        self.assertIn("50_000_000", src)
        self.assertNotIn("# 50 MiB per batch", src)
        self.assertIn("47.7 MiB", src)
        cli_src = (root / "determify" / "cli.py").read_text()
        self.assertIn("50,000,000 bytes", cli_src)
        self.assertNotIn("omitted: 50 MiB", cli_src)
        res = subprocess.run(
            [sys.executable, "-m", "determify.cli", "--help"],
            env={**os.environ, "PYTHONPATH": str(root)},
            capture_output=True, text=True, timeout=20)
        self.assertIn("50,000,000 bytes", res.stdout)


class TestDocumentationClaims(unittest.TestCase):
    """Measured-claim sweep: no unsupported speed/precision assurances outside the
    design-maxim quotes (which stay, marked with a compute-cost caveat)."""

    FORBIDDEN = [
        "sub-ms", "sub-millisecond", "sub-100ms", "sub-90ms",
        "<5ms", "<100ms", "2ms", "95-100%",
        "Instant execution", "instant execution",
        "100% token elimination", "100% predictability",
        "air-gapped on localhost", "guaranteed air gap",
    ]

    def test_no_unsupported_metric_claims(self):
        root = Path(__file__).parent.parent
        targets = ["README.md", "SKILL.md", "determify/patterns.py", "determify/cli.py",
                   "determify/deep_scanner.py", "determify/jev_evaluator.py"]
        for rel in targets:
            text = (root / rel).read_text(encoding="utf-8")
            for phrase in self.FORBIDDEN:
                self.assertNotIn(phrase, text, f"{rel} still claims {phrase!r}")

    def test_design_maxim_kept_with_caveat(self):
        root = Path(__file__).parent.parent
        for rel in ("README.md", "SKILL.md"):
            text = (root / rel).read_text(encoding="utf-8")
            self.assertIn("Never use an LLM if a 3-line", text)
            self.assertIn("design maxim", text.lower())

    def test_skill_frontmatter_compatibility_is_string(self):
        root = Path(__file__).parent.parent
        text = (root / "SKILL.md").read_text(encoding="utf-8")
        m = re.search(r"(?m)^compatibility:\s*(.+)$", text.split("---")[1])
        self.assertIsNotNone(m, "compatibility field present")
        value = m.group(1).strip()
        self.assertTrue(value.startswith('"') and value.endswith('"'),
                        "compatibility must be a string per the metadata schema")
        self.assertNotIn("etc.", text)

    def test_exemption_binding_documented(self):
        root = Path(__file__).parent.parent
        text = (root / "determify" / "deep_scanner.py").read_text(encoding="utf-8")
        self.assertIn("exact signal line", text)


if __name__ == "__main__":
    unittest.main()
