"""
scanner.py - Core File & Directory Scanner for Determify.
Secure file reading, symlink safety, size bounds, and zero-allocation regex evaluation.
"""

import os
import re
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

MAX_FILE_BYTES = 1_000_000  # 1,000,000 byte cap prevents memory exhaustion on minified bundles

# Batch budget: bound how much work one scan pass does before reporting progress.
# Bytes, not file count, because bytes are what bound wall-clock time.
# Default on, so a large tree is observable without the caller knowing the flag exists.
DEFAULT_BATCH_BYTES = 50_000_000  # 50 MiB per batch
MIN_BATCH_BYTES = 1_000_000        # never let a caller set a batch below one file cap

def read_source_file_safe(file_path: str, stats: dict = None) -> str:
    """
    Safely opens and reads a regular file without following symlinks.
    Blocks FIFOs, character devices (/dev/zero), and oversized files.
    Uses O_NONBLOCK so opening a FIFO fails immediately rather than blocking.
    Every skip is reported on stderr and counted in stats["skipped"] when given.
    """
    def _skip(reason):
        sys.stderr.write(f"[skip] {file_path}: {reason}\n")
        if stats is not None:
            stats["skipped"] += 1
        return ""

    fd = None
    try:
        # O_NONBLOCK prevents hanging if path is a FIFO
        fd = os.open(file_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as e:
        return _skip("symlink" if e.errno == errno.ELOOP else "unreadable")

    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            return _skip("not a regular file")
        if st.st_size > MAX_FILE_BYTES:
            return _skip(f"over {MAX_FILE_BYTES} bytes")
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as f:
            fd = None  # fdopen transfers ownership
            return f.read(MAX_FILE_BYTES)
    except Exception:
        return _skip("unreadable")
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except Exception:
                pass

# Suppression marker: `# determify:allow <ID> <reason>`, honoured by scan_file().
# A marker on a code line exempts that line. A marker on its own comment line
# exempts the next non-blank, non-comment code line. Exemption is reported, never silent.
ALLOW_MARKER_RE = re.compile(r"determify:allow\s+(DET-\d+|DET-DEEP)\b[ \t]*(.*)", re.IGNORECASE)
EXEMPTIONS = []


def parse_allow_markers(lines):
    """Return {line_number: {finding_id: reason}} for all determify:allow markers."""
    allowed = {}
    for idx, line in enumerate(lines, 1):
        match = ALLOW_MARKER_RE.search(line)
        if not match:
            continue
        finding_id = match.group(1).upper()
        reason = match.group(2).strip() or "no reason given"
        stripped = line.strip()
        target = idx
        if stripped.startswith("#") or stripped.startswith("//"):
            for next_idx in range(idx, len(lines)):
                candidate = lines[next_idx].strip()
                if candidate and not candidate.startswith("#") and not candidate.startswith("//"):
                    target = next_idx + 1
                    break
        allowed.setdefault(target, {})[finding_id] = reason
    return allowed


def _record_exemption(file_path, line_no, finding_id, reason):
    EXEMPTIONS.append({
        "file": file_path,
        "line": line_no,
        "id": finding_id,
        "reason": reason,
    })


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
    allowed = parse_allow_markers(lines) if "determify:allow" in content else {}

    # DET-07: Direct SDK / CLI invocation inspection (scripts and code files only; skip prose documentation)
    det07 = next((p for p in PATTERNS if p["id"] == "DET-07"), None)
    is_doc_file = file_path.endswith((".md", ".markdown", ".txt", ".rst"))
    if det07 and not is_doc_file:
        for idx, line in enumerate(lines, 1):
            stripped = line.strip()
            if stripped.startswith(("#", "//", "/*", "*")):
                continue
            # Skip shell logging, echo, or process-supervision lines
            if stripped.startswith(("echo ", "echo\t", "printf ", "printf\t", "pgrep ", "pkill ", "grep ", "log ", "which ")):
                continue
            if det07["regex"].search(line):
                reason = allowed.get(idx, {}).get(det07["id"])
                if reason:
                    _record_exemption(file_path, idx, det07["id"], reason)
                    continue
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
                reason = allowed.get(line_idx, {}).get(p["id"])
                if reason:
                    _record_exemption(file_path, line_idx, p["id"], reason)
                    continue
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

def _iter_target_files(targets):
    """Yields (fpath, size_bytes) for every supported file under the given targets.

    Enumerating separately from scanning is what lets us batch by byte budget and
    report progress before the work starts, instead of discovering the tree size
    only as we consume it.
    """
    for t in targets:
        p = Path(t)
        if not p.exists():
            sys.stderr.write(f"Warning: Target path does not exist: {t}\n")
            continue
        if p.is_file():
            try:
                yield str(p), p.stat().st_size
            except OSError:
                yield str(p), 0
        elif p.is_dir():
            for root, dirs, files in os.walk(str(p), followlinks=False):
                dirs[:] = [sub for sub in dirs if sub not in IGNORED_DIRS]
                for fname in files:
                    ext = Path(fname).suffix.lower()
                    is_candidate = ext in SUPPORTED_EXTENSIONS
                    fpath = os.path.join(root, fname)

                    if not is_candidate and not ext:
                        # Extensionless executable script detection (e.g. ~/.opencode/bin/obs-densify)
                        try:
                            st = os.stat(fpath)
                            if (st.st_mode & 0o111) and st.st_size > 0:
                                with open(fpath, "rb") as test_f:
                                    if test_f.read(2) == b"#!":
                                        is_candidate = True
                        except (OSError, PermissionError):
                            pass

                    if not is_candidate:
                        continue
                    try:
                        yield fpath, os.stat(fpath).st_size
                    except OSError:
                        yield fpath, 0


def _batches(files, batch_bytes):
    """Groups (fpath, size) pairs into batches bounded by total size.

    A single file larger than the budget becomes its own batch rather than being
    dropped, so a pathological input still gets scanned and reports progress.
    """
    batch, total = [], 0
    for fpath, size in files:
        if batch and total + size > batch_bytes:
            yield batch
            batch, total = [], 0
        batch.append(fpath)
        total += size
    if batch:
        yield batch


def _scan_one(fpath, use_jev, use_kev, deep_scan, env_file, stats, deep_debug=False,
              base_url=None, api_key=None, model=None):
    """Scans a single file. Returns (counted_bool, findings)."""
    content = read_source_file_safe(fpath, stats)
    if not content:
        return False, []

    findings = scan_file(fpath, content=content)

    if (use_jev or use_kev) and findings:
        for item in findings:
            try:
                verdict = evaluate_with_jev(
                    item, content, use_kev=use_kev, env_file=env_file,
                    base_url=base_url, api_key=api_key, model=model
                )
            except Exception as e:
                raise RuntimeError(
                    f"decision engine failed closed for {item.get('file')}:{item.get('line')}: {e}"
                ) from e
            if verdict:
                item["jev_eval"] = verdict
                stats["invoked"] = True

    if deep_scan:
        try:
            deep_findings = deep_scan_file(
                fpath, content, use_kev=use_kev, env_file=env_file, stats=stats, debug=deep_debug,
                base_url=base_url, api_key=api_key, model=model
            )
        except Exception as e:
            raise RuntimeError(f"deep scan failed closed for {fpath}: {e}") from e
        if deep_findings:
            findings.extend(deep_findings)

    return True, findings


def scan_targets(targets, use_jev=False, use_kev=False, deep_scan=False, env_file=None,
                 batch_bytes=DEFAULT_BATCH_BYTES, progress=True, deep_debug=False,
                 base_url=None, api_key=None, model=None):
    """Scans target paths, partitioned into byte-budgeted batches.

    A large tree is split so that progress is observable and a timeout costs one
    batch rather than the whole sweep. Findings accumulate across all batches, so
    the return value is identical whether or not batching occurs.

    Returns (scanned_count, all_findings, stats) where stats tracks skipped files
    and whether any decision-engine call actually returned.
    """
    if batch_bytes is None or batch_bytes < MIN_BATCH_BYTES:
        batch_bytes = MIN_BATCH_BYTES

    EXEMPTIONS.clear()
    all_findings = []
    scanned_files = 0
    stats = {"skipped": 0, "invoked": False}

    enumerated = list(_iter_target_files(targets))
    batches = list(_batches(enumerated, batch_bytes))

    if progress and len(batches) > 1:
        total_bytes = sum(sz for _, sz in enumerated)
        sys.stderr.write(
            f"[*] {len(enumerated)} files, {total_bytes / 1_048_576:.1f} MiB "
            f"across {len(batches)} batches of {batch_bytes / 1_048_576:.0f} MiB\n"
        )

    for idx, batch in enumerate(batches, start=1):
        batch_found = 0
        for fpath in batch:
            counted, findings = _scan_one(
                fpath, use_jev, use_kev, deep_scan, env_file, stats, deep_debug,
                base_url=base_url, api_key=api_key, model=model
            )
            if counted:
                scanned_files += 1
            if findings:
                batch_found += len(findings)
                all_findings.extend(findings)

        if progress and len(batches) > 1:
            sys.stderr.write(
                f"[*] batch {idx}/{len(batches)}: {len(batch)} files, "
                f"{batch_found} findings (running total {len(all_findings)})\n"
            )

    return scanned_files, all_findings, stats
