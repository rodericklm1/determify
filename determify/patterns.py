"""
patterns.py - Universal Anti-Pattern Rules for Determify.
Bounded, linear regex patterns eliminating catastrophic backtracking (ReDoS).
"""

import re

# Max gap between the cue phrase and the LLM invocation token (prevents quadratic unbounded scans)
MAX_GAP = 250

# Tightened LLM context gate: avoids bare 'create' (ORM) or bare 'query' (database) false positives
LLM_CONTEXT_GATE = r"(?:prompt|completion|llm_call|run_model|messages|generate_content|generate_reply|(?:client|completions|messages|responses|chat)\.create|(?:llm|model|agent|chain|query_engine)\.(?:invoke|query|generate|predict|run))"

CUE_RAW = {
    "DET-01": r"""what\s+is\s+today'?s\s+date|calculate\s+the\s+date|what\s+time\s+is\s+it|get\s+current\s+time|convert\s+timestamp|format\s+date""",
    "DET-02": r"""does\s+the\s+file\s+exist|check\s+if\s+file\s+exists|list\s+all\s+files\s+in\s+dir|find\s+file\s+in\s+path""",
    "DET-03": r"""extract\s+the\s+frontmatter|extract\s+the\s+yaml|parse\s+the\s+json\s+structure|extract\s+markdown\s+headers?""",
    "DET-04": r"""how\s+many\s+pages\s+is\s+this|count\s+the\s+pages\s+in\s+the\s+pdf|get\s+pdf\s+page\s+count""",
    "DET-05": r"""strip\s+all\s+html\s+tags|remove\s+the\s+base64\s+images|clean\s+up\s+all\s+whitespace|remove\s+html\s+elements""",
    "DET-06": r"""check\s+if\s+the\s+exact\s+word\s+appears|does\s+the\s+text\s+contain\s+the\s+word|is\s+the\s+keyword\s+present""",
}

# Standalone cue regexes for AST and prompt-file inspection
CUE_PATTERNS = {
    rule_id: re.compile(rf"(?i)\b(?:{raw})\b", re.IGNORECASE)
    for rule_id, raw in CUE_RAW.items()
}

def _cue(alternation: str) -> re.Pattern:
    """Compiles a safe, linear, non-DOTALL regex; order-independent cue-gate pairing, each branch gap-bounded."""
    return re.compile(
        rf"(?i)(?:(?:{alternation})\b.{{0,{MAX_GAP}}}{LLM_CONTEXT_GATE}"
        rf"|{LLM_CONTEXT_GATE}.{{0,{MAX_GAP}}}(?:{alternation})\b)",
        re.IGNORECASE
    )

PATTERNS = [
    {
        "id": "DET-01",
        "name": "Date / Time Math via LLM",
        "description": "Prompting an LLM for current date, relative dates, or timezone calculations.",
        "regex": _cue(CUE_RAW["DET-01"]),
        "fix": "Use datetime.now(), datetime.timedelta, moment/dayjs, or POSIX 'date -d' / 'date +%Y-%m-%d'",
        "savings": "Token elimination for this call ($0.00 API cost); local stdlib execution"
    },
    {
        "id": "DET-02",
        "name": "File & Path Checks via LLM",
        "description": "Using an LLM to check if a file exists, count files in a directory, or resolve file paths.",
        "regex": _cue(CUE_RAW["DET-02"]),
        "fix": "Use os.path.exists(), pathlib.Path, glob.glob(), or POSIX 'find' / 'test -f'",
        "savings": "Token elimination for this call ($0.00 API cost); local filesystem check"
    },
    {
        "id": "DET-03",
        "name": "Structured Data / Frontmatter Parsing via LLM",
        "description": "Using an LLM to extract YAML frontmatter, JSON fields, or markdown headers.",
        "regex": _cue(CUE_RAW["DET-03"]),
        "fix": r"Use json.loads(), gray-matter (JS), or regex for bounded headers. For arbitrary YAML, use PyYAML (yaml.safe_load) or ruamel.yaml",
        "savings": "Zero token cost ($0.00), deterministic parsing"
    },
    {
        "id": "DET-04",
        "name": "Document Sizing & Page Counting via LLM",
        "description": "Prompting an LLM to determine PDF page counts or classify document size.",
        "regex": _cue(CUE_RAW["DET-04"]),
        "fix": "Use 'pdfinfo <file.pdf>', pypdf, pdfjs, or os.path.getsize",
        "savings": "Deterministic local page count for $0.00 API cost"
    },
    {
        "id": "DET-05",
        "name": "Text Cleansing & Formatting via LLM",
        "description": "Prompting an LLM to strip HTML tags, remove base64 images, or normalize whitespace.",
        "regex": _cue(CUE_RAW["DET-05"]),
        "fix": "Use Python html.parser, BeautifulSoup, or cheerio for robust HTML; regex re.sub() for trivial single-line tags; sed/tr",
        "savings": "Eliminates high-cost tokens on long text buffers"
    },
    {
        "id": "DET-06",
        "name": "Simple Keyword or Topic Membership via LLM",
        "description": "Using an LLM to check for literal keyword presence or category membership when exact keywords suffice.",
        "regex": _cue(CUE_RAW["DET-06"]),
        "fix": "Use Python 'in' operator, regex word boundaries, or 'grep -E'",
        "savings": "In-process literal membership check for $0.00 API cost"
    },
    {
        "id": "DET-07",
        "name": "Ungated LLM Invocation Candidate",
        "description": "Direct generative LLM call without an upstream deterministic check or decision gate. Review if the operation is deterministic or a simple classification before invoking.",
        "regex": re.compile(
            r"""(?i)(?:openai\.(?:chat\.)?completions\.create|anthropic\.messages\.create|client\.chat\.completions|client\.messages\.create|client\.responses\.create|llm\.complete\b|model\.generate_content|ChatOpenAI\(|ChatAnthropic\(|opencode\s+run|hermes\s+run|claude\s+-p|sgpt\s+-[soec])"""
        ),
        "fix": "If call requires open-ended synthesis, retain and annotate with '# determify:allow DET-07 <reason>'. If deterministic or a decision, add upstream gate.",
        "savings": "If replaceable: removes metered token spend and the network roundtrip on this call"
    }
]
