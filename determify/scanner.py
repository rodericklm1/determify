"""
scanner.py - Core File & Directory Scanner for Determify.
Secure file reading, symlink safety, size bounds, and zero-allocation regex evaluation.
"""

import os
import sys
import stat
import errno
from pathlib import Path
from .patterns import PATTERNS
from .jev_evaluator import evaluate_with_jev
from .deep_scanner import deep_scan_file

IGNORED_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    ".pytest_cache", ".ruff_cache", "dist", "build", ".idea", ".vscode", "tests", "test"
}

SUPPORTED_EXTENSIONS = {
    ".py", ".ts", ".js", ".jsx", ".tsx", ".sh", ".bash"
}

MAX_FILE_BYTES = 1_000_000  # 1 MiB cap prevents memory exhaustion on minified bundles

def read_source_file_safe(file_path: str) -> str:
    """
    Safely opens and reads a regular file without following symlinks.
    Blocks FIFOs, character devices (/dev/zero), and oversized files.
    Uses O_NONBLOCK so opening a FIFO fails immediately rather than blocking.
    """
    fd = None
    try:
        # O_NONBLOCK prevents hanging if path is a FIFO
        fd = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except (OSError, IOError):
        return ""

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return ""
        if st.st_size > MAX_FILE_BYTES:
            return ""
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as f:
            fd = None  # fdopen transfers ownership
            return f.read(MAX_FILE_BYTES)
    except Exception:
        return ""
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass

def scan_file(file_path: str, content: str = None):
    """
    Lexical and pattern scan on a single source file.
    Deduplicates multiple matching alternations on the same line.
    """
    findings = []
    seen_keys = set()

    # Self-file skip based on real canonical path
    try:
        if os.path.samefile(file_path, __file__):
            return findings
    except (OSError, ValueError):
        pass

    if content is None:
        content = read_source_file_safe(file_path)

    if not content:
        return findings

    lines = content.splitlines()

    # DET-07: Direct SDK / CLI invocation inspection
    det07 = next((p for p in PATTERNS if p["id"] == "DET-07"), None)
    if det07:
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*")):
                continue
            if det07["regex"].search(line):
                key = (file_path, idx, det07["id"])
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append({
                        "id": det07["id"],
                        "file": file_path,
                        "line": idx,
                        "snippet": stripped[:120],
                        "name": det07["name"],
                        "description": det07["description"],
                        "fix": det07["fix"],
                        "savings": det07["savings"]
                    })

    # Line-by-line inspection for DET-01 through DET-06 (eliminates multi-line O(n²) string copies)
    for line_idx, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith(("#", "//", "/*", "*")):
            continue

        for p in PATTERNS:
            if p["id"] == "DET-07":
                continue
            if p["regex"].search(line):
                key = (file_path, line_idx, p["id"])
                if key not in seen_keys:
                    seen_keys.add(key)
                    findings.append({
                        "id": p["id"],
                        "file": file_path,
                        "line": line_idx,
                        "snippet": stripped[:120],
                        "name": p["name"],
                        "description": p["description"],
                        "fix": p["fix"],
                        "savings": p["savings"]
                    })

    return findings

def scan_targets(targets, use_jev=False, use_kev=False, deep_scan=False, env_file=None):
    """
    Scans target paths (files or directories).
    Returns (scanned_count, all_findings).
    """
    all_findings = []
    scanned_files = 0
    target_files = []
    target_dirs = []

    for t in targets:
        p = Path(t)
        if not p.exists():
            sys.stderr.write(f"Warning: Target path does not exist: {t}\n")
            continue
        if p.is_file():
            target_files.append(str(p))
        elif p.is_dir():
            target_dirs.append(str(p))

    for fpath in target_files:
        content = read_source_file_safe(fpath)
        if not content:
            continue

        scanned_files += 1
        findings = scan_file(fpath, content=content)

        if (use_jev or use_kev) and findings:
            for item in findings:
                try:
                    verdict = evaluate_with_jev(item, content, use_kev=use_kev, env_file=env_file)
                    if verdict:
                        item["jev_eval"] = verdict
                except Exception as e:
                    sys.stderr.write(f"Warning: Decision triage failed for {item.get('file')}:{item.get('line')}: {e}\n")

        if deep_scan:
            try:
                deep_findings = deep_scan_file(fpath, content, use_kev=use_kev, env_file=env_file)
                if deep_findings:
                    findings.extend(deep_findings)
            except Exception as e:
                sys.stderr.write(f"Warning: Deep scan failed for {fpath}: {e}\n")

        all_findings.extend(findings)

    for d in target_dirs:
        for root, dirs, files in os.walk(d, followlinks=False):
            dirs[:] = [sub for sub in dirs if sub not in IGNORED_DIRS]

            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext in SUPPORTED_EXTENSIONS:
                    fpath = os.path.join(root, fname)
                    content = read_source_file_safe(fpath)
                    if not content:
                        continue

                    scanned_files += 1
                    findings = scan_file(fpath, content=content)

                    if (use_jev or use_kev) and findings:
                        for item in findings:
                            try:
                                verdict = evaluate_with_jev(item, content, use_kev=use_kev, env_file=env_file)
                                if verdict:
                                    item["jev_eval"] = verdict
                            except Exception as e:
                                sys.stderr.write(f"Warning: Decision triage failed for {item.get('file')}:{item.get('line')}: {e}\n")

                    if deep_scan:
                        try:
                            deep_findings = deep_scan_file(fpath, content, use_kev=use_kev, env_file=env_file)
                            if deep_findings:
                                findings.extend(deep_findings)
                        except Exception as e:
                            sys.stderr.write(f"Warning: Deep scan failed for {fpath}: {e}\n")

                    all_findings.extend(findings)

    return scanned_files, all_findings
