"""
jev_evaluator.py - Decision Evaluation Bridge for Determify.
Connects to TypeSafe Jev (Cloud OpenRouter Decisions API) or On-Prem Kev-0.6B.
"""

import os
import sys
import json
import time
import urllib.request
import urllib.error
from pathlib import Path

OPENROUTER_DECISIONS_URL = os.environ.get("OPENROUTER_DECISIONS_URL", "https://openrouter.ai/api/alpha/decisions")
DEFAULT_KEV_URL = "http://localhost:8009/v1/systemone"

def get_api_key():
    """Resolves OPENROUTER_API_KEY from environment or standard .env files."""
    key = os.environ.get("OPENROUTER_API_KEY")
    if key:
        return key

    # Check current directory and parents for .env
    cur = Path.cwd()
    candidates = [
        cur / ".env",
        cur.parent / ".env",
        Path.home() / ".env"
    ]
    for env_path in candidates:
        if env_path.exists():
            try:
                with open(env_path, "r", encoding="utf-8") as f:
                    for line in f:
                        if line.startswith("OPENROUTER_API_KEY=") and not line.strip().startswith("#"):
                            return line.strip().split("=", 1)[1].strip("\"'")
            except Exception:
                pass
    return None

def get_kev_url():
    """Resolves local Kev-0.6B endpoint URL."""
    return os.environ.get("KEV_ENDPOINT", DEFAULT_KEV_URL)

def call_decision_endpoint(payload, use_kev=False):
    """
    Executes a decision request against on-prem Kev-0.6B or Cloud Jev.
    """
    if use_kev:
        kev_url = get_kev_url()
        req = urllib.request.Request(
            kev_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8")), "kev-0.6b (local)"

    api_key = get_api_key()
    if not api_key:
        # Fallback to local Kev if no API key is set
        return call_decision_endpoint(payload, use_kev=True)

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/rodericklm1/determify",
        "X-Title": "Determify Decision Engine"
    }
    req = urllib.request.Request(
        OPENROUTER_DECISIONS_URL,
        data=json.dumps(payload).encode("utf-8"),
        headers=headers,
        method="POST"
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        return json.loads(resp.read().decode("utf-8")), "jev-latest (cloud)"

def evaluate_with_jev(finding, file_content, use_kev=False):
    """
    Evaluates an identified code finding using Jev or Kev to determine optimal tier.
    """
    lines = file_content.splitlines()
    line_idx = max(0, finding.get("line", 1) - 1)
    start_idx = max(0, line_idx - 15)
    end_idx = min(len(lines), line_idx + 15)
    context_window = "\n".join(lines[start_idx:end_idx])

    state = (
        f"File: {finding.get('file', 'unknown')}:{finding.get('line', 1)}\n"
        f"Suspected Anti-Pattern: {finding.get('name', 'Pattern')}\n"
        f"Code Line: {finding.get('snippet', '')}\n\n"
        f"Surrounding Code Context:\n{context_window[:2000]}"
    )

    payload = {
        "model": "kev-latest" if use_kev else "~typesafe/jev-latest",
        "state": state,
        "questions": {
            "optimal_tier": {
                "type": "choice",
                "instructions": "Determine the optimal architectural tier for this operation.",
                "criteria": {
                    "tier_0_deterministic": "Can be completely solved with deterministic code: regex, datetime, os/path, jq, git, or bash pipe ($0.00, 0ms).",
                    "tier_05_decision": "Is a classification, boolean check, filtering, or scoring decision that Jev/Kev can solve in <100ms.",
                    "tier_frontier_generative": "Legitimately requires open-ended creative text generation, complex code writing, or multi-turn reasoning."
                }
            },
            "can_be_deterministic": {
                "type": "noul",
                "instructions": "Can this AI operation be completely replaced by pure deterministic logic without any machine learning model?"
            },
            "actionability_score": {
                "type": "score",
                "instructions": "Rate how urgent/worthwhile it is to refactor this call site.",
                "criteria": [
                    "Legitimate generative call; leave untouched",
                    "Moderate savings; refactor when convenient",
                    "High-leverage fix; high token burn or repeated execution that should be eliminated"
                ]
            }
        }
    }

    try:
        t0 = time.time()
        data, provider_name = call_decision_endpoint(payload, use_kev=use_kev)
        lat_ms = round((time.time() - t0) * 1000, 1)

        ans = data.get("answers", {})
        tier = ans.get("optimal_tier", {}).get("choice", "tier_frontier_generative")
        confidence = ans.get("optimal_tier", {}).get("confidence", 0.0)
        det_prob = ans.get("can_be_deterministic", {}).get("noul", 0.0)
        action_score = ans.get("actionability_score", {}).get("score", 0.0)

        return {
            "optimal_tier": tier,
            "provider": provider_name,
            "confidence": round(confidence, 2),
            "deterministic_prob": round(det_prob, 2),
            "actionability_score": action_score,
            "latency_ms": lat_ms
        }
    except Exception:
        return None
