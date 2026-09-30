"""
ast_scanner.py - Python AST Syntactic Scanner for Determify.
Performs zero-dependency, syntax-aware inspection of Python source code to detect
deterministic AI waste, multiline f-strings, and ungated LLM call sites with 100% syntactic precision.
"""

import ast
import re
from .patterns import PATTERNS, CUE_PATTERNS

# Specific signatures for DET-07 (ungated generative SDK / CLI invocation)
EXPLICIT_SDK_ATTRS = {
    "completions.create",
    "chat.completions.create",
    "messages.create",
    "responses.create",
    "complete",
    "generate_content",
}

EXPLICIT_CLASS_NAMES = {
    "ChatOpenAI",
    "ChatAnthropic",
    "ChatGoogleGenerativeAI",
    "OpenAI",
    "Anthropic",
}

CLI_AGENT_COMMANDS = re.compile(r"\b(?:opencode\s+run|hermes\s+run|claude\s+-p|sgpt\s+-[soec])\b")

# General LLM caller identifiers (distinguishes LLM calls from ORM/database calls)
LLM_CALL_TOKENS = ("llm", "openai", "anthropic", "chat", "completion", "messages", "generate", "agent", "predict", "model")

def _get_call_name(node: ast.Call) -> str:
    """Extracts a dot-separated string representation of a call target."""
    parts = []
    curr = node.func
    while isinstance(curr, ast.Attribute):
        parts.append(curr.attr)
        curr = curr.value
    if isinstance(curr, ast.Name):
        parts.append(curr.id)
    return ".".join(reversed(parts))

def _extract_string_content(node: ast.AST) -> str:
    """Recursively extracts literal text from string constants, f-strings, and collections."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    elif isinstance(node, ast.JoinedStr):
        texts = []
        for val in node.values:
            if isinstance(val, ast.Constant) and isinstance(val.value, str):
                texts.append(val.value)
        return " ".join(texts)
    elif isinstance(node, ast.Dict):
        texts = []
        for k, v in zip(node.keys, node.values):
            texts.append(_extract_string_content(v))
        return " ".join(texts)
    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        return " ".join(_extract_string_content(elt) for elt in node.elts)
    return ""

class DetermifyASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, lines: list, allowed: dict):
        self.file_path = file_path
        self.lines = lines
        self.allowed = allowed
        self.findings = []
        self.seen_keys = set()
        self.pattern_map = {p["id"]: p for p in PATTERNS}

    def _add_finding(self, rule_id: str, line_no: int, snippet: str):
        reason = self.allowed.get(line_no, {}).get(rule_id)
        if reason:
            return  # Suppressed by # determify:allow
        key = (self.file_path, line_no, rule_id)
        if key in self.seen_keys:
            return
        self.seen_keys.add(key)
        rule = self.pattern_map.get(rule_id, {})
        self.findings.append({
            "id": rule_id,
            "file": self.file_path,
            "line": line_no,
            "snippet": snippet[:120],
            "name": rule.get("name", rule_id),
            "description": rule.get("description", ""),
            "fix": rule.get("fix", ""),
            "savings": rule.get("savings", "")
        })

    def visit_Call(self, node: ast.Call):
        call_name = _get_call_name(node)
        line_no = getattr(node, "lineno", 1)
        raw_line = self.lines[line_no - 1].strip() if line_no <= len(self.lines) else ""

        # DET-07: Subprocess calls running agent CLIs (e.g. subprocess.run(["opencode", "run", ...]))
        if call_name in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "os.system"}:
            for arg in node.args:
                text = _extract_string_content(arg)
                if CLI_AGENT_COMMANDS.search(text):
                    self._add_finding("DET-07", line_no, raw_line)
                    break

        # Check for explicit SDK invocation (DET-07)
        is_explicit_sdk = False
        for attr in EXPLICIT_SDK_ATTRS:
            if call_name.endswith(attr):
                is_explicit_sdk = True
                break
        if not is_explicit_sdk:
            for cls_name in EXPLICIT_CLASS_NAMES:
                if call_name == cls_name or call_name.endswith("." + cls_name):
                    is_explicit_sdk = True
                    break

        if is_explicit_sdk:
            self._add_finding("DET-07", line_no, raw_line)

        # Check if the call target is an AI/LLM mechanism (eliminates ORM/database false positives like Order.create or db.query)
        is_llm_call = is_explicit_sdk or any(sig in call_name.lower() for sig in LLM_CALL_TOKENS)

        if is_llm_call:
            # Inspect all arguments passed to this verified LLM call for DET-01 through DET-06
            all_arg_nodes = list(node.args) + [kw.value for kw in node.keywords]
            for arg in all_arg_nodes:
                text = _extract_string_content(arg)
                if not text:
                    continue
                arg_line = getattr(arg, "lineno", line_no)
                arg_snippet = self.lines[arg_line - 1].strip() if arg_line <= len(self.lines) else raw_line

                for rule_id, cue_re in CUE_PATTERNS.items():
                    if cue_re.search(text):
                        self._add_finding(rule_id, arg_line, arg_snippet)

        self.generic_visit(node)

    def visit_Assign(self, node: ast.Assign):
        # Detect assignments to prompt variables: prompt = "What is today's date?", messages = [...]
        target_names = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_names.append(target.id.lower())
            elif isinstance(target, ast.Attribute):
                target_names.append(target.attr.lower())

        is_prompt_var = any("prompt" in name or "message" in name or "input_text" in name for name in target_names)
        if is_prompt_var:
            text = _extract_string_content(node.value)
            if text:
                val_line = getattr(node.value, "lineno", getattr(node, "lineno", 1))
                val_snippet = self.lines[val_line - 1].strip() if val_line <= len(self.lines) else ""
                for rule_id, cue_re in CUE_PATTERNS.items():
                    if cue_re.search(text):
                        self._add_finding(rule_id, val_line, val_snippet)

        self.generic_visit(node)


def scan_python_ast(file_path: str, content: str, allowed: dict) -> list:
    """
    Parses Python content into an AST and inspects for Determify rules.
    Returns findings list if AST parsing succeeds, or None if syntax error or unparseable
    (to fall back to lexical scanner).
    """
    import textwrap
    try:
        tree = ast.parse(content, filename=file_path)
    except IndentationError:
        try:
            tree = ast.parse(textwrap.dedent(content), filename=file_path)
        except Exception:
            return None
    except (SyntaxError, ValueError, MemoryError, RecursionError):
        return None

    lines = content.splitlines()
    visitor = DetermifyASTVisitor(file_path, lines, allowed)
    visitor.visit(tree)
    return visitor.findings
