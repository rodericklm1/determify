"""
ast_scanner.py - Syntax-Aware Python AST Scanner for Determify.
Performs zero-dependency syntactic inspection of Python source code to detect
deterministic AI waste, multiline f-strings, and ungated LLM call sites.
"""

import ast
import re
import textwrap
from .patterns import PATTERNS, CUE_PATTERNS

# Specific method suffixes for DET-07 (ungated generative SDK invocations)
EXPLICIT_SDK_ATTRS = {
    "completions.create",
    "chat.completions.create",
    "messages.create",
    "responses.create",
    "generate_content",
}

# Known chat model wrappers invoked directly or via methods
EXPLICIT_CHAT_CLASSES = {
    "ChatOpenAI",
    "ChatAnthropic",
    "ChatGoogleGenerativeAI",
}

CLI_AGENT_COMMANDS = re.compile(r"\b(?:opencode\s+run|hermes\s+run|claude\s+-p|sgpt\s+-[soec])\b")

# Logging and debugging method names to explicitly ignore as non-LLM calls
LOGGER_METHODS = {".info", ".debug", ".warning", ".error", ".log", ".critical", ".exception"}

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
    def __init__(self, file_path: str, lines: list, allowed: dict, record_exemption_fn=None):
        self.file_path = file_path
        self.lines = lines
        self.allowed = allowed
        self.record_exemption_fn = record_exemption_fn
        self.findings = []
        self.seen_keys = set()
        self.local_constants = {}  # var_name -> (text_value, lineno)
        self.pattern_map = {p["id"]: p for p in PATTERNS}

    def _add_finding(self, rule_id: str, line_no: int, snippet: str, call_start_line: int = None):
        # Check suppression on the specific line, or on the parent call statement line if multiline
        reason = self.allowed.get(line_no, {}).get(rule_id)
        if not reason and call_start_line is not None:
            reason = self.allowed.get(call_start_line, {}).get(rule_id)

        if reason:
            if self.record_exemption_fn:
                self.record_exemption_fn(self.file_path, line_no, rule_id, reason)
            return

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

    def _record_assignment(self, target_names: list, value_node: ast.AST, line_no: int):
        text = _extract_string_content(value_node)
        if not text:
            return

        # Track constant in local scope for alias resolution in subsequent calls
        for name in target_names:
            self.local_constants[name] = (text, line_no)

        val_snippet = self.lines[line_no - 1].strip() if line_no <= len(self.lines) else ""

        # DET-07: Subprocess/CLI agent invocation strings (e.g. command = "opencode run summarize")
        if CLI_AGENT_COMMANDS.search(text):
            self._add_finding("DET-07", line_no, val_snippet)

        # Explicit prompt variables (e.g. prompt = "What is today's date?", user_prompt = "...")
        # Check for 'prompt' in variable name (avoids generic words like 'message' on UI strings)
        is_prompt_var = any("prompt" in name for name in target_names)
        if is_prompt_var:
            for rule_id, cue_re in CUE_PATTERNS.items():
                if cue_re.search(text):
                    self._add_finding(rule_id, line_no, val_snippet)

    def visit_Assign(self, node: ast.Assign):
        target_names = []
        for target in node.targets:
            if isinstance(target, ast.Name):
                target_names.append(target.id.lower())
            elif isinstance(target, ast.Attribute):
                target_names.append(target.attr.lower())

        line_no = getattr(node, "lineno", 1)
        self._record_assignment(target_names, node.value, line_no)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        # Support annotated assignments: prompt: str = "What is today's date?"
        target_names = []
        if isinstance(node.target, ast.Name):
            target_names.append(node.target.id.lower())
        elif isinstance(node.target, ast.Attribute):
            target_names.append(node.target.attr.lower())

        if node.value:
            line_no = getattr(node, "lineno", 1)
            self._record_assignment(target_names, node.value, line_no)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = _get_call_name(node)
        line_no = getattr(node, "lineno", 1)
        raw_line = self.lines[line_no - 1].strip() if line_no <= len(self.lines) else ""

        # Ignore logging methods (eliminates model_logger.info("What is today's date?") false positives)
        if any(call_name.endswith(log_m) for log_m in LOGGER_METHODS) or "logger" in call_name.lower():
            self.generic_visit(node)
            return

        # DET-07: Subprocess calls running agent CLIs (e.g. subprocess.run(["opencode", "run", ...]))
        if call_name in {"subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output", "os.system"}:
            for arg in node.args:
                text = _extract_string_content(arg)
                if not text and isinstance(arg, ast.Name):
                    text, _ = self.local_constants.get(arg.id.lower(), ("", 1))
                if text and CLI_AGENT_COMMANDS.search(text):
                    self._add_finding("DET-07", line_no, raw_line)
                    break

        # Check for explicit SDK invocation (DET-07)
        is_explicit_sdk = False
        for attr in EXPLICIT_SDK_ATTRS:
            if call_name.endswith(attr):
                is_explicit_sdk = True
                break

        # LlamaIndex / Agent complete call: require qualified client context (avoids workflow.complete() false positive)
        if not is_explicit_sdk and call_name.endswith(".complete"):
            prefix = call_name.rsplit(".complete", 1)[0].lower()
            if any(tok in prefix for tok in ("llm", "client", "model", "agent", "predictor")):
                is_explicit_sdk = True

        # Chat model classes
        if not is_explicit_sdk:
            for cls_name in EXPLICIT_CHAT_CLASSES:
                if call_name == cls_name or call_name.endswith("." + cls_name):
                    is_explicit_sdk = True
                    break

        if is_explicit_sdk:
            self._add_finding("DET-07", line_no, raw_line, call_start_line=line_no)

        # Check if the call target is an AI/LLM invocation
        is_llm_call = is_explicit_sdk or any(
            sig in call_name.lower()
            for sig in ("llm.", "openai.", "anthropic.", "chat.", "agent.run", "model.predict", "llm_call")
        )

        if is_llm_call:
            # Inspect all arguments passed to this verified LLM call for DET-01 through DET-06
            all_arg_nodes = list(node.args) + [kw.value for kw in node.keywords]
            for arg in all_arg_nodes:
                text = _extract_string_content(arg)
                arg_line = getattr(arg, "lineno", line_no)

                # Constant propagation: resolve variable aliases (e.g. question = "..."; client.responses.create(input=question))
                if not text and isinstance(arg, ast.Name):
                    const_val, const_line = self.local_constants.get(arg.id.lower(), ("", arg_line))
                    if const_val:
                        text = const_val
                        arg_line = const_line

                if not text:
                    continue

                arg_snippet = self.lines[arg_line - 1].strip() if arg_line <= len(self.lines) else raw_line

                for rule_id, cue_re in CUE_PATTERNS.items():
                    if cue_re.search(text):
                        self._add_finding(rule_id, arg_line, arg_snippet, call_start_line=line_no)

        self.generic_visit(node)


def scan_python_ast(file_path: str, content: str, allowed: dict, record_exemption_fn=None) -> list:
    """
    Parses Python content into an AST and inspects for Determify rules.
    Returns findings list if AST parsing succeeds, or None if syntax error or unparseable
    (to fall back to lexical scanner).
    """
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
    visitor = DetermifyASTVisitor(file_path, lines, allowed, record_exemption_fn=record_exemption_fn)
    visitor.visit(tree)
    return visitor.findings
