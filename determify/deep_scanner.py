"""
deep_scanner.py - Semantic Chunk Analysis for Determify.
Scans functions and script blocks using Jev or Kev to find unflagged, implicit LLM misuse.
"""

from .jev_evaluator import call_decision_endpoint

def deep_scan_file(file_path, file_content, use_kev=False):
    """
    Chunked semantic scan across files containing LLM signals.
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

    i = 0
    while i < len(lines):
        chunk_lines = lines[i:i + chunk_size]
        chunk_text = "\n".join(chunk_lines)
        start_line = i + 1
        i += (chunk_size - overlap)

        if not any(sig in chunk_text.lower() for sig in ["prompt", "completion", "model", "llm", "invoke", "messages", "client"]):
            continue

        state = (
            f"File: {file_path} (Lines {start_line}-{start_line + len(chunk_lines)})\n\n"
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

        try:
            data, provider_name = call_decision_endpoint(payload, use_kev=use_kev)
            ans = data.get("answers", {})
            unnecessary_prob = ans.get("contains_unnecessary_ai", {}).get("noul", 0.0)
            rep_tier = ans.get("replacement_tier", {}).get("choice", "legitimate_generative")

            if unnecessary_prob >= 0.70 and rep_tier != "legitimate_generative":
                findings.append({
                    "id": "DET-DEEP",
                    "file": file_path,
                    "line": start_line,
                    "snippet": chunk_lines[0].strip()[:100],
                    "name": "Semantic LLM Overuse Detected (Deep Scan)",
                    "description": f"Semantic analysis flagged unnecessary generative AI logic (probability {unnecessary_prob:.2f}).",
                    "fix": f"Refactor to {rep_tier.replace('_', ' ').title()}.",
                    "savings": "Eliminates high-latency generative roundtrips",
                    "jev_eval": {
                        "optimal_tier": rep_tier,
                        "provider": provider_name,
                        "confidence": unnecessary_prob,
                        "deterministic_prob": unnecessary_prob,
                        "latency_ms": 120.0
                    }
                })
        except Exception:
            pass

    return findings
