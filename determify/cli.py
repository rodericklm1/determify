"""
cli.py - Command Line Interface for Determify.
"""

import sys
import json
import argparse
from pathlib import Path
from .scanner import scan_targets
from .jev_evaluator import get_kev_url, OPENROUTER_DECISIONS_URL, get_api_key
from . import __version__

def main():
    try:
        _run_cli()
    except KeyboardInterrupt:
        sys.stderr.write("\nScan cancelled by user.\n")
        sys.exit(130)

def _run_cli():
    parser = argparse.ArgumentParser(
        prog="determify",
        description="determify: Find where code uses AI when a deterministic script or decision model is better."
    )
    parser.add_argument("path", nargs="*", default=["."], help="Files or directories to scan (default: current directory). Use '--' before paths starting with a dash.")
    parser.add_argument("--jev", action="store_true", help="Use TypeSafe Jev via Cloud OpenRouter Decisions API for intelligent semantic triage")
    parser.add_argument("--kev", action="store_true", help="Use on-prem Kev-0.6B (default: http://localhost:8009/v1/systemone) for sub-90ms local triage")
    parser.add_argument("--deep", action="store_true", help="Execute deep semantic chunk analysis to detect unflagged AI waste (requires --jev or --kev)")
    parser.add_argument("--deep-debug", action="store_true", help="Log chunks the deep classifier evaluated but dropped to stderr (use with --deep)")
    parser.add_argument("--env-file", default=None, help="Explicit path to .env file containing OPENROUTER_API_KEY")
    parser.add_argument("--batch-mb", type=int, default=None,
                        help="Split large trees into batches of this many MiB, reporting progress to stderr. "
                             "Default 50. Batching never changes the findings, only how much work happens per step.")
    parser.add_argument("--no-progress", action="store_true", help="Suppress per-batch progress on stderr")
    parser.add_argument("--fail-on-findings", action="store_true", help="Exit with code 1 if any actionable findings are discovered (for CI/CD)")
    parser.add_argument("--json", action="store_true", help="Output findings in JSON format")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    # Safety: --deep requires an explicit provider to prevent accidental source exfiltration
    if args.deep and not (args.jev or args.kev):
        sys.stderr.write(
            "Error: --deep requires an explicit decision engine flag (--jev for cloud, or --kev for on-prem).\n"
            "This prevents accidental transmission of source code chunks to cloud endpoints.\n"
        )
        sys.exit(2)

    # Missing targets are a usage error, not a clean scan: fail before printing anything
    missing = [t for t in args.path if not Path(t).exists()]
    if missing:
        for t in missing:
            sys.stderr.write(f"Error: Target path does not exist: {t}\n")
        sys.exit(2)

    # Pre-flight check for Cloud Jev
    if args.jev and not args.kev:
        key = get_api_key(env_file=args.env_file)
        if not key:
            sys.stderr.write(
                "Error: OPENROUTER_API_KEY not found in environment.\n"
                "To use Cloud Jev triage, export OPENROUTER_API_KEY or specify --env-file.\n"
                "To use on-prem triage without an API key, use --kev.\n"
            )
            sys.exit(2)

    try:
        scanned_files, all_findings, stats = scan_targets(
            args.path,
            use_jev=args.jev,
            use_kev=args.kev,
            deep_scan=args.deep,
            env_file=args.env_file,
            batch_bytes=(args.batch_mb * 1_048_576) if args.batch_mb else None,
            progress=not args.no_progress,
            deep_debug=args.deep_debug
        )
    except Exception as e:
        # Fail closed: stderr + exit 2, and do not print a clean or success report.
        sys.stderr.write(f"Error: decision engine failed closed: {e}\n")
        sys.exit(2)

    invoked = stats["invoked"]

    # Destination banner only after a provider call actually returned.
    if (args.jev or args.kev) and invoked and not args.json:
        dest = get_kev_url() if args.kev else OPENROUTER_DECISIONS_URL
        print(f"[*] Decision Engine Active: Triage queries were evaluated by {dest}")

    # Format findings with relative paths for both JSON and terminal
    cwd = Path.cwd().resolve()
    roots = [Path(t).resolve() for t in args.path]
    for f in all_findings:
        f_path = Path(f["file"]).resolve()
        rel = None
        try:
            rel = f_path.relative_to(cwd)
        except ValueError:
            for root in roots:
                try:
                    candidate = f_path.relative_to(root)
                except ValueError:
                    continue
                if str(candidate) != ".":
                    rel = candidate
                    break
        f["file"] = str(rel) if rel is not None else f_path.name

    if args.json:
        result = {
            "version": __version__,
            "scanned_files": scanned_files,
            "skipped": stats["skipped"],
            "total_findings": len(all_findings),
            "findings": all_findings
        }
        print(json.dumps(result, indent=2))
        if args.fail_on_findings and all_findings:
            sys.exit(1)
        return

    print("======================================================================")
    print("⚡ determify: Deterministic Execution & Token-Avoidance Scanner")
    if invoked:
        provider = "Kev-0.6B (Local)" if args.kev else "Jev (Cloud)"
        if args.deep:
            mode_desc = f"Deep Semantic Codebase Sweep (--deep via {provider})"
        elif args.kev:
            mode_desc = "Kev-0.6B On-Prem Intelligent Triage (--kev)"
        else:
            mode_desc = "Jev-Stacked Intelligent Triage (--jev)"
    elif args.kev or args.jev:
        mode_desc = "Static Lexical Analysis (provider not invoked)"
    else:
        mode_desc = "Static Lexical Analysis"

    print(f"   Mode: {mode_desc}")
    print("   Rule: Never use an LLM if a 3-line script solves it.")
    print("======================================================================")
    print(f"[*] Scanned {scanned_files} files across target paths ({stats['skipped']} skipped).\n")

    if scanned_files == 0:
        if stats["skipped"]:
            print(f"⚠️  No files were scanned: {stats['skipped']} skipped (see stderr).")
        else:
            print("⚠️  No supported files found to scan in target paths.")
        print("======================================================================")
        return

    if not all_findings:
        print("✅ Clean: Zero anti-patterns detected! All scanned code adheres to Tier 0 determinism.")
        print("======================================================================")
        return

    print(f"⚠️  Found {len(all_findings)} potential opportunities for deterministic replacement:\n")
    for f in all_findings:
        print(f"[{f['id']}] {f['file']}:{f['line']}")
        print(f"  • Issue:   {f['name']} - {f['description']}")
        print(f"  • Code:    {f['snippet']}")
        if "jev_eval" in f and f["jev_eval"]:
            je = f["jev_eval"]
            provider = je.get("provider", "Jev")
            print(f"  • 🧠 {provider} Verdict: {je['optimal_tier']} (Confidence: {je['confidence']}, Deterministic Prob: {je['deterministic_prob']})")
        print(f"  • Fix:     {f['fix']}")
        print(f"  • Savings: {f['savings']}")
        print("")

    print("======================================================================")
    print(f"Total Actionable Findings: {len(all_findings)}")
    print("======================================================================")

    if args.fail_on_findings and all_findings:
        sys.exit(1)

if __name__ == "__main__":
    main()
