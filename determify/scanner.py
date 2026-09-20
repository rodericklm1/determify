"""
scanner.py - Core File & Directory Scanner for Determify.
"""

import os
from pathlib import Path
from .patterns import PATTERNS
from .jev_evaluator import evaluate_with_jev
from .deep_scanner import deep_scan_file

IGNORED_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__",
    ".pytest_cache", ".ruff_cache", "dist", "build", ".idea", ".vscode"
}

SUPPORTED_EXTENSIONS = {
    ".py", ".ts", ".js", ".jsx", ".tsx", ".sh", ".bash", ".md", ".json", ".yaml", ".yml"
}

def scan_file(file_path):
    """
    Lexical and pattern scan on a single source file.
    """
    findings = []
    fname = os.path.basename(file_path)
    if fname in ("scanner.py", "patterns.py", "determify.py"):
        return findings

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
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

def scan_targets(targets, use_jev=False, use_kev=False, deep_scan=False):
    """
    Scans a list of target paths (files or directories).
    """
    all_findings = []
    scanned_files = 0
    target_files = []
    target_dirs = []

    for t in targets:
        p = Path(t).resolve()
        if not p.exists():
            continue
        if p.is_file():
            target_files.append(str(p))
        elif p.is_dir():
            target_dirs.append(str(p))

    for fpath in target_files:
        scanned_files += 1
        findings = scan_file(fpath)

        if (use_jev or use_kev or deep_scan):
            try:
                with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read()

                if (use_jev or use_kev) and findings:
                    for item in findings:
                        verdict = evaluate_with_jev(item, content, use_kev=use_kev)
                        if verdict:
                            item["jev_eval"] = verdict

                if deep_scan:
                    deep_findings = deep_scan_file(fpath, content, use_kev=use_kev)
                    if deep_findings:
                        findings.extend(deep_findings)
            except Exception:
                pass

        all_findings.extend(findings)

    for d in target_dirs:
        for root, dirs, files in os.walk(d):
            # Prune ignored directories in place
            dirs[:] = [sub for sub in dirs if sub not in IGNORED_DIRS]

            for fname in files:
                ext = Path(fname).suffix.lower()
                if ext in SUPPORTED_EXTENSIONS:
                    fpath = os.path.join(root, fname)
                    scanned_files += 1
                    findings = scan_file(fpath)

                    if (use_jev or use_kev or deep_scan):
                        try:
                            with open(fpath, "r", encoding="utf-8", errors="ignore") as f:
                                content = f.read()

                            if (use_jev or use_kev) and findings:
                                for item in findings:
                                    verdict = evaluate_with_jev(item, content, use_kev=use_kev)
                                    if verdict:
                                        item["jev_eval"] = verdict

                            if deep_scan:
                                deep_findings = deep_scan_file(fpath, content, use_kev=use_kev)
                                if deep_findings:
                                    findings.extend(deep_findings)
                        except Exception:
                            pass

                    all_findings.extend(findings)

    return scanned_files, all_findings
