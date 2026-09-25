"""
jev_evaluator.py - Decision Evaluation Bridge for Determify.
Secure HTTP handling, redirect protection, scheme validation, and bounded responses.
"""

import os
import json
import stat
import time
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path

DEFAULT_TYPESAFE_URL = "https://api.typesafe.ai/v1/systemone"
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


def _parse_env_file_safely(env_file: str) -> dict:
    """Reads key-value pairs from an explicit .env file using nofollow read."""
    if not env_file:
        return {}
    text = _read_regular_nofollow(Path(env_file))
    if not text:
        return {}
    res = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" in line:
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().split(" #", 1)[0].strip().strip("\"'")
            res[k] = v
    return res

def get_api_key(env_file=None):
    """
    Resolves API key (JEV_API_KEY, TYPESAFE_API_KEY, or OPENROUTER_API_KEY)
    from the environment, or from an explicitly requested .env file.
    Never reads the implicit cwd .env, does not walk parent
    directories or $HOME, and does not follow symlinks.
    """
    for var in ("JEV_API_KEY", "TYPESAFE_API_KEY", "OPENROUTER_API_KEY"):
        val = os.environ.get(var)
        if val and val.strip():
            return val.strip().strip("\"'")

    if not env_file:
        return None

    file_vars = _parse_env_file_safely(env_file)
    for var in ("JEV_API_KEY", "TYPESAFE_API_KEY", "OPENROUTER_API_KEY"):
        val = file_vars.get(var)
        if val and val.strip():
            return val.strip().strip("\"'")
    return None

def resolve_decision_config(base_url=None, api_key=None, model=None, env_file=None, use_kev=False):
    """
    Resolves the complete configuration for decision engine evaluation:
    - base_url (TypeSafe official, OpenRouter, local Kev, or custom proxy)
    - api_key (from CLI, environment, or explicit .env file)
    - model (e.g. 'jev-latest', '~typesafe/jev-latest', or 'kev-latest')
    """
    file_vars = _parse_env_file_safely(env_file) if env_file else {}

    # 1. API Key resolution
    resolved_key = None
    key_source = None
    if api_key and str(api_key).strip():
        resolved_key = str(api_key).strip().strip("\"'")
        key_source = "cli"
    else:
        for var in ("JEV_API_KEY", "TYPESAFE_API_KEY", "OPENROUTER_API_KEY"):
            v = os.environ.get(var) or file_vars.get(var)
            if v and v.strip():
                resolved_key = v.strip().strip("\"'")
                key_source = var
                break

    # 2. Base URL resolution
    resolved_url = None
    if use_kev:
        resolved_url = (
            base_url
            or os.environ.get("KEV_ENDPOINT")
            or file_vars.get("KEV_ENDPOINT")
            or DEFAULT_KEV_URL
        )
    elif base_url and str(base_url).strip():
        resolved_url = str(base_url).strip()
    else:
        for var in ("JEV_BASE_URL", "JEV_ENDPOINT", "TYPESAFE_BASE_URL", "OPENROUTER_DECISIONS_URL"):
            v = os.environ.get(var) or file_vars.get(var)
            if v and v.strip():
                resolved_url = v.strip()
                break
        if not resolved_url:
            if key_source == "OPENROUTER_API_KEY":
                resolved_url = OPENROUTER_DECISIONS_URL
            else:
                resolved_url = DEFAULT_TYPESAFE_URL

    # 3. Model resolution
    resolved_model = None
    if use_kev:
        resolved_model = (
            model
            or os.environ.get("KEV_MODEL")
            or file_vars.get("KEV_MODEL")
            or "kev-latest"
        )
    elif model and str(model).strip():
        resolved_model = str(model).strip()
    else:
        v = os.environ.get("JEV_MODEL") or file_vars.get("JEV_MODEL")
        if v and v.strip():
            resolved_model = v.strip()
        else:
            parsed = urllib.parse.urlparse(resolved_url)
            host = (parsed.netloc or "").split(":")[0].lower()
            if "openrouter.ai" in host:
                resolved_model = "~typesafe/jev-latest"
            else:
                resolved_model = "jev-latest"

    return {
        "base_url": resolved_url,
        "api_key": resolved_key,
        "model": resolved_model,
        "key_source": key_source,
        "use_kev": use_kev
    }

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

def call_decision_endpoint(payload, use_kev=False, env_file=None, base_url=None, api_key=None, model=None):
    """
    Executes a decision request against on-prem Kev-0.6B or Cloud Jev (TypeSafe, OpenRouter, or custom).
    """
    cfg = resolve_decision_config(
        base_url=base_url,
        api_key=api_key,
        model=model,
        env_file=env_file,
        use_kev=use_kev,
    )

    if "model" not in payload or payload.get("model") in ("~typesafe/jev-latest", "jev-latest", "kev-latest"):
        payload["model"] = cfg["model"]

    if use_kev:
        headers = {"Content-Type": "application/json"}
        if cfg["api_key"]:
            headers["Authorization"] = f"Bearer {cfg['api_key']}"
        data = _post_json(
            cfg["base_url"],
            payload,
            headers=headers,
            timeout=5
        )
        if not isinstance(data, dict):
            raise RuntimeError(f"Unexpected response type from Kev ({type(data).__name__})")
        return data, "kev-0.6b (local)"

    if not cfg["api_key"]:
        raise ValueError(
            "No Jev API key found in environment or arguments.\n"
            "To use Jev triage, provide an API key via --api-key, JEV_API_KEY, TYPESAFE_API_KEY, OPENROUTER_API_KEY, or --env-file.\n"
            "To use on-prem triage without an API key, use --kev."
        )

    headers = {
        "Authorization": f"Bearer {cfg['api_key']}",
        "Content-Type": "application/json",
    }
    parsed = urllib.parse.urlparse(cfg["base_url"])
    host = (parsed.netloc or "").split(":")[0].lower()
    if "openrouter.ai" in host:
        headers["HTTP-Referer"] = "https://github.com/rodericklm1/determify"
        headers["X-Title"] = "Determify Decision Engine"
    else:
        headers["User-Agent"] = "determify"

    data = _post_json(
        cfg["base_url"],
        payload,
        headers=headers,
        timeout=8
    )
    if not isinstance(data, dict):
        raise RuntimeError(f"Unexpected response type from decision endpoint ({type(data).__name__})")

    if "openrouter.ai" in host:
        provider_name = f"{cfg['model']} (openrouter.ai)"
    elif "typesafe.ai" in host:
        provider_name = f"{cfg['model']} (typesafe.ai)"
    else:
        provider_name = f"{cfg['model']} ({host or 'custom'})"

    return data, provider_name

def evaluate_with_jev(finding, file_content, use_kev=False, env_file=None, base_url=None, api_key=None, model=None):
    """
    Evaluates an identified code finding using Jev or Kev to determine optimal tier.
    """
    cfg = resolve_decision_config(
        base_url=base_url,
        api_key=api_key,
        model=model,
        env_file=env_file,
        use_kev=use_kev,
    )

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
        "model": cfg["model"],
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
    extra_kwargs = {}
    if base_url is not None:
        extra_kwargs["base_url"] = base_url
    if api_key is not None:
        extra_kwargs["api_key"] = api_key
    if model is not None:
        extra_kwargs["model"] = model

    data, provider_name = call_decision_endpoint(
        payload,
        use_kev=use_kev,
        env_file=env_file,
        **extra_kwargs
    )
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
