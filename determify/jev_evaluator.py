"""
jev_evaluator.py - Decision Evaluation Bridge for Determify.
Secure HTTP handling, redirect protection, scheme validation, and bounded responses.
"""

import os
import sys
import json
import stat
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path

OPENROUTER_DECISIONS_URL = os.environ.get("OPENROUTER_DECISIONS_URL", "https://openrouter.ai/api/alpha/decisions")
DEFAULT_KEV_URL = "http://localhost:8009/v1/systemone"
MAX_RESPONSE_BYTES = 256_000
ALLOWED_SCHEMES = ("http", "https")

class NoAuthRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect and strip Authorization so it cannot be copied."""

    @staticmethod
    def _strip_authorization(req):
        for store_name in ("headers", "unredirected_hdrs"):
            store = getattr(req, store_name, None)
            if not isinstance(store, dict):
                continue
            for key in list(store):
                if str(key).lower() == "authorization":
                    del store[key]

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._strip_authorization(req)
        raise RuntimeError(f"Security violation: refusing HTTP redirect ({code}) to {newurl}")

    def http_error_302(self, req, fp, code, msg, headers):
        self._strip_authorization(req)
        try:
            fp.close()
        except Exception:
            pass
        location = ""
        if headers is not None:
            location = (
                headers.get("Location")
                or headers.get("location")
                or headers.get("URI")
                or headers.get("uri")
                or ""
            )
        raise RuntimeError(f"Security violation: refusing HTTP redirect ({code}) to {location}")

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302

def _read_regular_nofollow(path: Path, limit: int = 65_536) -> str:
    """Read a regular file. Symlinks, FIFOs, and devices return empty."""
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError:
        return ""
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > limit:
            return ""
        with os.fdopen(fd, "r", encoding="utf-8", errors="replace") as handle:
            fd = None
            return handle.read(limit)
    except OSError:
        return ""
    finally:
        if fd is not None:
            try:
                os.close(fd)
            except OSError:
                pass


def get_api_key(env_file=None):
    """
    Resolves OPENROUTER_API_KEY from environment or an explicit local .env file.
    Does NOT walk parent directories or $HOME, and does not follow symlinks.
    """
    key = os.environ.get("OPENROUTER_API_KEY")
    if key:
        return key.strip().strip("\"'")

    target_env = Path(env_file) if env_file else Path.cwd() / ".env"
    text = _read_regular_nofollow(target_env)
    if not text:
        return None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if line.startswith("OPENROUTER_API_KEY="):
            val = line.split("=", 1)[1].strip()
            val = val.split(" #", 1)[0].strip()
            return val.strip("\"'")
    return None

def get_kev_url():
    """Resolves local Kev-0.6B endpoint URL."""
    return os.environ.get("KEV_ENDPOINT", DEFAULT_KEV_URL)

def _post_json(url: str, payload: dict, headers: dict, timeout: int = 8):
    """
    Executes a secure POST request:
    - Enforces http/https scheme allowlist
    - Blocks redirects
    - Caps response body to MAX_RESPONSE_BYTES
    """
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ALLOWED_SCHEMES:
        raise RuntimeError(f"Refusing non-HTTP(S) endpoint scheme '{parsed.scheme}': {url}")

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    opener = urllib.request.build_opener(NoAuthRedirectHandler)

    try:
        with opener.open(req, timeout=timeout) as resp:
            raw = resp.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise RuntimeError(f"Decision endpoint response exceeded {MAX_RESPONSE_BYTES} bytes")
            return json.loads(raw.decode("utf-8"))
    except urllib.error.HTTPError as e:
        err_msg = e.read(4096).decode("utf-8", errors="ignore")
        raise RuntimeError(f"HTTP {e.code} from {url}: {err_msg}") from e
    except urllib.error.URLError as e:
        raise RuntimeError(f"Connection failed to {url}: {e.reason}") from e
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Malformed JSON response from {url}: {e}") from e

def call_decision_endpoint(payload, use_kev=False, env_file=None):
    """
    Executes a decision request against on-prem Kev-0.6B or Cloud Jev.
    """
    if use_kev:
        kev_url = get_kev_url()
        data = _post_json(
            kev_url,
            payload,
            headers={"Content-Type": "application/json"},
            timeout=5
        )
        if not isinstance(data, dict):
            raise RuntimeError(f"Unexpected response type from Kev ({type(data).__name__})")
        return data, "kev-0.6b (local)"

    api_key = get_api_key(env_file=env_file)
    if not api_key:
        raise ValueError(
            "OPENROUTER_API_KEY not found in environment or local .env.\n"
            "To use cloud Jev triage, set OPENROUTER_API_KEY, or use --kev for on-prem triage."
        )

    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "HTTP-Referer": "https://github.com/rodericklm1/determify",
        "X-Title": "Determify Decision Engine"
    }
    data = _post_json(
        OPENROUTER_DECISIONS_URL,
        payload,
        headers=headers,
        timeout=8
    )
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected response type from OpenRouter ({type(data).__name__})")
    return data, "jev-latest (cloud)"

def evaluate_with_jev(finding, file_content, use_kev=False, env_file=None):
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

    t0 = time.time()
    data, provider_name = call_decision_endpoint(payload, use_kev=use_kev, env_file=env_file)
    lat_ms = round((time.time() - t0) * 1000, 1)

    ans = data.get("answers", {}) if isinstance(data, dict) else {}
    opt_tier = ans.get("optimal_tier", {})
    tier = opt_tier.get("choice", "tier_frontier_generative") if isinstance(opt_tier, dict) else "tier_frontier_generative"
    raw_conf = opt_tier.get("confidence", 0.0) if isinstance(opt_tier, dict) else 0.0
    confidence = float(raw_conf) if isinstance(raw_conf, (int, float)) else 0.0

    det_item = ans.get("can_be_deterministic", {})
    raw_noul = det_item.get("noul", 0.0) if isinstance(det_item, dict) else 0.0
    det_prob = float(raw_noul) if isinstance(raw_noul, (int, float)) else 0.0

    act_item = ans.get("actionability_score", {})
    action_score = act_item.get("score", 0.0) if isinstance(act_item, dict) else 0.0

    return {
        "optimal_tier": tier,
        "provider": provider_name,
        "confidence": round(confidence, 2),
        "deterministic_prob": round(det_prob, 2),
        "actionability_score": action_score,
        "latency_ms": lat_ms
    }
