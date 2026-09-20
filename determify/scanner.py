"""
scanner.py - Core File & Directory Scanner for Determify.
"""

import os
import sys
from pathlib import Path
from .patterns import PATTERNS
from .jev_evaluator import evaluate_with_jev
from .deep_scanner import deep_scan_file

IGNORED_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    ".pytest_cache", ".ruff_cache", "dist", "build", ".idea", ".vscode", "tests"
}

# Code-focused file extensions scanned by default (markdown files excluded by default to avoid documentation false positives)
SUPPORTED_EXTENSIONS = {
    ".py", ".ts", ".js", ".jsx", ".tsx", ".sh", ".bash"
}

def scan_file(file_path):
    """
    Lexical and pattern scan on a single source file.
    Deduplicates multiple matching alternations on the same line.
    """
    findings = []
    seen_keys = set()
    fname = os.path.basename(file_path)
    if fname in ("scanner.py", "patterns.py", "determify.py"):
        return findings

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except (IOError, OSError) as e:
        sys.stderr.write(f"Warning: Unable to read file {file_path}: {e}\n")
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

    # Pattern matches for DET-01 through DET-06
    for p in PATTERNS:
        if p["id"] == "DET-07":
            continue
        matches = p["regex"].finditer(content)
        for m in matches:
            line_no = content[:m.start()].count("\n") + 1
            # Skip pure comments
            if 0 <= line_no - 1 < len(lines):
                line_str = lines[line_no - 1].strip()
                if line_str.startswith(("#", "//", "/*", "*")):
                    continue

            key = (file_path, line_no, p["id"])
            if key not in seen_keys:
                seen_keys.add(key)
                findings.append({
                    "id": p["id"],
                    "file": file_path,
                    "line": line_no,
                    "snippet": m.group(0)[:120].replace("\n", " "),
                    "name": p["name"],
                    "description": p["description"],
                    "fix": p["fix"],
                    "savings": p["savings"]
                })

    return findings

def scan_targets(targets, use_jev=False, use_kev=False, deep_scan=False, env_file=None):
    """
    Scans a list of target paths (files or directories).
    Returns (scanned_count, all_findings, unreadable_count).
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
            target_files.append(str(p.resolve()))
        elif p.is_dir():
            target_dirs.append(str(p.resolve()))

    for fpath in target_files:
        try:
            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
            scanned_files += 1
            findings = scan_file(fpath)

            if (use_jev or use_kev) and findings:
                for item in findings:
                    verdict = evaluate_with_jev(item, content, use_kev=use_kev, env_file=env_file)
                    if verdict:
                        item["jev_eval"] = verdict

            if deep_scan:
                deep_findings = deep_scan_file(fpath, content, use_kev=use_kev, env_file=env_file)
                if deep_findings:
                    findings.extend(deep_findings)

            all_findings.extend(findings)
        except (IOError, OSError) as e:
            sys.stderr.write(f"Warning: Could not open file {fpath}: {e}\n")

    for d in target_dirs:
        for root, dirs, files in os.walk(d):
            # Prune ignored directories in place
            dirs[:] = [sub for sub in dirs if sub not in IGNORED_DIRS]

            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext in SUPPORTED_EXTENSIONS:
                    fpath = os.path.join(root, fname)
                    try:
                        with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                        scanned_files += 1
                        findings = scan_file(fpath)

                        if (use_jev or use_kev) and findings:
                            for item in findings:
                                verdict = evaluate_with_jev(item, content, use_kev=use_kev, env_file=env_file)
                                if verdict:
                                    item["jev_eval"] = verdict

                        if deep_scan:
                            deep_findings = deep_scan_file(fpath, content, use_kev=use_kev, env_file=env_file)
                            if deep_findings:
                                findings.extend(deep_findings)

                        all_findings.extend(findings)
                    except (IOError, OSError) as e:
                        sys.stderr.write(f"Warning: Could not open file {fpath}: {e}\n")

    return scanned_files, all_findings
