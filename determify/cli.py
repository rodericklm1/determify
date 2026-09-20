"""
cli.py - Command Line Interface for Determify.
"""

import sys
import json
import argparse
from pathlib import Path
from .scanner import scan_targets
from . import __version__

def main():
    parser = argparse.ArgumentParser(
        prog="determify",
        description="determify: Find where code uses AI when a deterministic script or decision model is better."
    )
    parser.add_argument("path", nargs="*", default=["."], help="Files or directories to scan (default: current directory)")
    parser.add_argument("--jev", action="store_true", help="Use TypeSafe Jev via Cloud OpenRouter Decisions API for intelligent semantic triage")
    parser.add_argument("--kev", action="store_true", help="Use on-prem Kev-0.6B (default: http://localhost:8009/v1/systemone) for sub-90ms local triage")
    parser.add_argument("--deep", action="store_true", help="Execute deep semantic chunk analysis to detect unflagged AI waste")
    parser.add_argument("--json", action="store_true", help="Output findings in JSON format")
    parser.add_argument("-v", "--version", action="version", version=f"%(prog)s {__version__}")

    args = parser.parse_args()

    scanned_files, all_findings = scan_targets(
        args.path,
        use_jev=args.jev,
        use_kev=args.kev,
        deep_scan=args.deep
    )

    if args.json:
        result = {
            "version": __version__,
            "scanned_files": scanned_files,
            "total_findings": len(all_findings),
            "findings": all_findings
        }
        print(json.dumps(result, indent=2))
        return

    print("======================================================================")
    print("⚡ determify: Deterministic Execution & Token-Avoidance Scanner")
    mode_desc = "Static Lexical Analysis"
    if args.deep:
        provider = "Kev-0.6B (Local)" if args.kev else "Jev (Cloud)"
        mode_desc = f"Deep Semantic Codebase Sweep (--deep via {provider})"
    elif args.kev:
        mode_desc = "Kev-0.6B On-Prem Intelligent Triage (--kev)"
    elif args.jev:
        mode_desc = "Jev-Stacked Intelligent Triage (--jev)"

    print(f"   Mode: {mode_desc}")
    print("   Rule: Never use an LLM if a 3-line script solves it.")
    print("======================================================================")
    print(f"[*] Scanned {scanned_files} files across target paths.\n")

    if not all_findings:
        print("✅ Clean: Zero anti-patterns detected! All scanned code adheres to Tier 0 determinism.")
        print("======================================================================")
        return

    print(f"⚠️  Found {len(all_findings)} potential opportunities for deterministic replacement:\n")
    for f in all_findings:
        try:
            rel = Path(f["file"]).relative_to(Path.cwd())
        except ValueError:
            rel = f["file"]

        print(f"[{f['id']}] {rel}:{f['line']}")
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

if __name__ == "__main__":
    main()
