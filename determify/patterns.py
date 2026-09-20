"""
patterns.py - Universal Anti-Pattern Rules for Determify.
Detects unnecessary LLM prompts, agent tool misconfigurations, and SDK call sites.
"""

import re

PATTERNS = [
    {
        "id": "DET-01",
        "name": "Date / Time Math via LLM",
        "description": "Prompting an LLM for current date, relative dates, or timezone calculations.",
        "regex": re.compile(
            r"""(?i)(?:what\s+is\s+today'?s\s+date|calculate\s+the\s+date|what\s+time\s+is\s+it|get\s+current\s+time|convert\s+timestamp|format\s+date)\b.*?(?:prompt|completion|llm_call|run_model|messages|create|invoke)""",
            re.DOTALL
        ),
        "fix": "Use datetime.now(), datetime.timedelta, moment/dayjs, or POSIX 'date -d' / 'date +%Y-%m-%d'",
        "savings": "100% token elimination ($0.00), <1ms latency"
    },
    {
        "id": "DET-02",
        "name": "File & Path Checks via LLM",
        "description": "Using an LLM to check if a file exists, count files in a directory, or resolve file paths.",
        "regex": re.compile(
            r"""(?i)(?:does\s+the\s+file\s+exist|check\s+if\s+file\s+exists|list\s+all\s+files\s+in\s+dir|find\s+file\s+in\s+path)""",
            re.DOTALL
        ),
        "fix": "Use os.path.exists(), pathlib.Path, glob.glob(), or POSIX 'find' / 'test -f'",
        "savings": "100% token elimination ($0.00), 0ms network latency"
    },
    {
        "id": "DET-03",
        "name": "Structured Data / Frontmatter Parsing via LLM",
        "description": "Using an LLM to extract YAML frontmatter, JSON fields, or markdown headers.",
        "regex": re.compile(
            r"""(?i)(?:extract\s+the\s+frontmatter|extract\s+the\s+yaml|parse\s+the\s+json\s+structure|extract\s+markdown\s+headers?)""",
            re.DOTALL
        ),
        "fix": r"Use yaml.safe_load(), json.loads(), gray-matter, or regex re.search(r'^title:\s*\"(.*)\"')",
        "savings": "100% token elimination, zero hallucination risk"
    },
    {
        "id": "DET-04",
        "name": "Document Sizing & Page Counting via LLM",
        "description": "Prompting an LLM to determine PDF page counts or classify document size.",
        "regex": re.compile(
            r"""(?i)(?:how\s+many\s+pages\s+is\s+this|count\s+the\s+pages\s+in\s+the\s+pdf|get\s+pdf\s+page\s+count)\b.*?(?:prompt|completion|llm_call|run_model|messages|create|invoke)""",
            re.DOTALL
        ),
        "fix": "Use 'pdfinfo <file.pdf>', pypdf, pdfjs, or os.path.getsize",
        "savings": "Instant execution, 100% precision"
    },
    {
        "id": "DET-05",
        "name": "Text Cleansing & Formatting via LLM",
        "description": "Prompting an LLM to strip HTML tags, remove base64 images, or normalize whitespace.",
        "regex": re.compile(
            r"""(?i)(?:strip\s+all\s+html\s+tags|remove\s+the\s+base64\s+images|clean\s+up\s+all\s+whitespace|remove\s+html\s+elements)\b.*?(?:prompt|completion|llm_call|run_model|messages|create|invoke)""",
            re.DOTALL
        ),
        "fix": "Use re.sub(), BeautifulSoup, cheerio, or sed/tr commands",
        "savings": "Eliminates high-cost tokens on long text buffers"
    },
    {
        "id": "DET-06",
        "name": "Simple Keyword or Topic Membership via LLM",
        "description": "Using an LLM to check for literal keyword presence or category membership when exact keywords suffice.",
        "regex": re.compile(
            r"""(?i)(?:check\s+if\s+the\s+exact\s+word\s+appears|does\s+the\s+text\s+contain\s+the\s+word|is\s+the\s+keyword\s+present)\b.*?(?:prompt|completion|llm_call|run_model|messages|create|invoke)""",
            re.DOTALL
        ),
        "fix": "Use Python 'in' operator, regex word boundaries, or 'grep -E'",
        "savings": "Instant execution, eliminates unnecessary API trips"
    },
    {
        "id": "DET-07",
        "name": "Direct SDK / Subprocess LLM Invocation in Script",
        "description": "Invoking a generative LLM SDK or subprocess without a Tier 0 or Tier 0.5 decision gate.",
        "regex": re.compile(
            r"""(?i)(?:openai\.(?:chat\.)?completions\.create|anthropic\.messages\.create|client\.chat\.completions|genai\.generate_content|ChatOpenAI\(|ChatAnthropic\(|opencode\s+run|hermes\s+run|claude\s+-p|sgpt\b)""",
            re.DOTALL
        ),
        "fix": "Determine if task is a decision (route to TypeSafe Jev/Kev) or deterministic (rewrite in pure Python/Bash)",
        "savings": "Sub-100ms latency vs 3-10s; 95-100% cost reduction"
    }
]
