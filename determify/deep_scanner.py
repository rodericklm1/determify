"""
deep_scanner.py - Semantic Chunk Analysis for Determify.
Scans functions and script blocks using Jev or Kev to find unflagged, implicit LLM misuse.
"""

import sys
import time
from .jev_evaluator import call_decision_endpoint

SIGNAL_WORDS = ["prompt", "completion", "model", "llm", "invoke", "messages", "client"]

def deep_scan_file(file_path, file_content, use_kev=False, env_file=None, stats=None, debug=False):
    """
    Chunked semantic scan across files containing LLM signals.
    Requires an explicit decision provider (Jev or Kev).
    Overlapping windows that share a first signal line are evaluated once:
    the redundant window is skipped before the provider call, and the finding
    is reported on the signal line itself, not the window origin.
    """
    findings = []
    lines = file_content.splitlines()
    chunk_size = 60
    overlap = 15

    llm_signals = [
        "prompt", "llm", "completion", "generate", "model",
        "openai", "openrouter", "anthropic", "gemini", "claude",
        "agent", "subagent", "langchain", "llamaindex", "crewai", "autogen"
    ]
    content_lower = file_content.lower()
    if not any(sig in content_lower for sig in llm_signals):
        return []

    reported_spans = set()
    i = 0
    while i < len(lines):
        chunk_lines = lines[i:i + chunk_size]
        chunk_text = "\n".join(chunk_lines)
        start_line = i + 1
        end_line = start_line + len(chunk_lines) - 1
        i += (chunk_size - overlap)

        if not any(sig in chunk_text.lower() for sig in SIGNAL_WORDS):
            continue

        signal_line = end_line
        for offset, line_text in enumerate(chunk_lines):
            if any(sig in line_text.lower() for sig in SIGNAL_WORDS):
                signal_line = start_line + offset
                break

        if signal_line in reported_spans:
            continue
        reported_spans.add(signal_line)

        state = (
            f"File: {file_path} (Lines {start_line}-{end_line}, first signal at {signal_line})\n\n"
            f"Code Chunk:\n{chunk_text[:2000]}"
        )

        payload = {
            "model": "kev-latest" if use_kev else "~typesafe/jev-latest",
            "state": state,
            "questions": {
                "contains_unnecessary_ai": {
                    "type": "noul",
                    "instructions": "Does this code chunk contain an LLM prompt or AI call performing work that standard code (regex, math, date calculation, JSON/YAML parsing, file checking) or a sub-100ms classifier could do instead?"
                },
                "replacement_tier": {
                    "type": "choice",
                    "instructions": "What is the optimal tier for the AI logic in this chunk?",
                    "criteria": {
                        "clean_tier_0_code": "Code is already deterministic or should be rewritten in 3 lines of Python/Bash.",
                        "tier_05_decision": "Could be replaced by a small non-autoregressive decision model.",
                        "legitimate_generative": "Legitimately requires a large generative LLM (creative synthesis, deep reasoning)."
                    }
                }
            }
        }

        t0 = time.time()
        data, provider_name = call_decision_endpoint(payload, use_kev=use_kev, env_file=env_file)
        lat_ms = round((time.time() - t0) * 1000, 1)
        if stats is not None:
            stats["invoked"] = True

        ans = data.get("answers", {}) or {}
        noul_item = ans.get("contains_unnecessary_ai", {})
        raw_noul = noul_item.get("noul", 0.0) if isinstance(noul_item, dict) else 0.0
        unnecessary_prob = float(raw_noul) if isinstance(raw_noul, (int, float)) else 0.0

        tier_item = ans.get("replacement_tier", {})
        rep_tier = tier_item.get("choice", "legitimate_generative") if isinstance(tier_item, dict) else "legitimate_generative"
        raw_conf = tier_item.get("confidence", 0.0) if isinstance(tier_item, dict) else 0.0
        tier_conf = float(raw_conf) if isinstance(raw_conf, (int, float)) else 0.0

        if not (unnecessary_prob >= 0.70 and rep_tier != "legitimate_generative"):
            if debug:
                sys.stderr.write(
                    f"[deep] {file_path}:{signal_line} dropped by classifier "
                    f"(tier={rep_tier}, noul={unnecessary_prob:.2f})\n"
                )
            continue

        findings.append({
            "id": "DET-DEEP",
            "file": file_path,
            "line": signal_line,
            "start_line": start_line,
            "end_line": end_line,
            "snippet": lines[signal_line - 1].strip()[:100],
            "name": "Semantic LLM Overuse Detected (Deep Scan)",
            "description": f"Semantic analysis flagged unnecessary generative AI logic (probability {unnecessary_prob:.2f}).",
            "fix": f"Refactor to {rep_tier.replace('_', ' ').title()}.",
            "savings": "Eliminates high-latency generative roundtrips",
            "jev_eval": {
                "optimal_tier": rep_tier,
                "provider": provider_name,
                "confidence": round(tier_conf, 2),
                "deterministic_prob": round(unnecessary_prob, 2),
                "latency_ms": lat_ms
            }
        })

    return findings
