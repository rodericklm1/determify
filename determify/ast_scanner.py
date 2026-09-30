"""
ast_scanner.py - Syntax-Aware Python AST Scanner for Determify.
Performs zero-dependency syntactic inspection of Python source code to detect
deterministic AI waste, multiline f-strings, and ungated LLM call sites with scope-aware binding analysis.
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

def _extract_string_content(node: ast.AST, scope_lookup=None, depth: int = 0) -> tuple:
    """
    Recursively extracts literal text and originating line number from AST nodes,
    including string constants, f-strings, collections, and scope-resolved variable references.
    Returns (string_content, origin_lineno).
    """
    if depth > 10 or node is None:
        return "", 0

    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value, getattr(node, "lineno", 0)

    elif isinstance(node, ast.JoinedStr):
        texts = []
        origin_line = getattr(node, "lineno", 0)
        for val in node.values:
            txt, line = _extract_string_content(val, scope_lookup=scope_lookup, depth=depth + 1)
            if txt:
                texts.append(txt)
                if not origin_line and line:
                    origin_line = line
        return " ".join(texts), origin_line

    elif isinstance(node, ast.Name) and scope_lookup:
        # Resolve variable reference from scope stack
        resolved = scope_lookup(node.id)
        if resolved is not None:
            text_val, origin_line = resolved
            return text_val, origin_line
        return "", getattr(node, "lineno", 0)

    elif isinstance(node, ast.Dict):
        texts = []
        origin_line = getattr(node, "lineno", 0)
        for k, v in zip(node.keys, node.values):
            if k is not None:
                kt, kl = _extract_string_content(k, scope_lookup=scope_lookup, depth=depth + 1)
                if kt:
                    texts.append(kt)
                    if not origin_line and kl:
                        origin_line = kl
            vt, vl = _extract_string_content(v, scope_lookup=scope_lookup, depth=depth + 1)
            if vt:
                texts.append(vt)
                if not origin_line and vl:
                    origin_line = vl
        return " ".join(texts), origin_line

    elif isinstance(node, (ast.List, ast.Tuple, ast.Set)):
        texts = []
        origin_line = getattr(node, "lineno", 0)
        for elt in node.elts:
            et, el = _extract_string_content(elt, scope_lookup=scope_lookup, depth=depth + 1)
            if et:
                texts.append(et)
                if not origin_line and el:
                    origin_line = el
        return " ".join(texts), origin_line

    return "", getattr(node, "lineno", 0)


class DetermifyASTVisitor(ast.NodeVisitor):
    def __init__(self, file_path: str, lines: list, allowed: dict, record_exemption_fn=None):
        self.file_path = file_path
        self.lines = lines
        self.allowed = allowed
        self.record_exemption_fn = record_exemption_fn
        self.findings = []
        self.seen_keys = set()
        # Lexical scope stack: each frame maps exact variable name -> (text_value, origin_lineno) or None (invalidated)
        self.scopes = [{}]
        self.pattern_map = {p["id"]: p for p in PATTERNS}

    def _lookup_variable(self, name: str):
        """Searches scope stack from innermost to outermost for variable binding."""
        for scope in reversed(self.scopes):
            if name in scope:
                return scope[name]
        return None

    def _bind_variable(self, name: str, val_info):
        """Binds a variable in the innermost (current) scope frame."""
        self.scopes[-1][name] = val_info

    def _invalidate_variable(self, name: str):
        """Invalidates a variable in the current scope frame (e.g. upon dynamic reassignment)."""
        self.scopes[-1][name] = None

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

    def _record_assignment(self, target_nodes: list, value_node: ast.AST, line_no: int):
        val_snippet = self.lines[line_no - 1].strip() if line_no <= len(self.lines) else ""

        for target in target_nodes:
            # Only track bare local/module names; ignore attribute targets (e.g. obj.question = ...)
            if not isinstance(target, ast.Name):
                continue

            var_name = target.id  # Preserve exact case sensitivity

            # Bounded alias chaining: q = question
            if isinstance(value_node, ast.Name):
                resolved = self._lookup_variable(value_node.id)
                if resolved is not None:
                    self._bind_variable(var_name, resolved)
                    text, orig_line = resolved
                    self._check_prompt_assignment(var_name, text, line_no, val_snippet)
                else:
                    self._invalidate_variable(var_name)
                continue

            text, _ = _extract_string_content(value_node, scope_lookup=self._lookup_variable)
            if text:
                self._bind_variable(var_name, (text, line_no))

                # DET-07: Subprocess/CLI agent invocation strings (e.g. command = "opencode run summarize")
                if CLI_AGENT_COMMANDS.search(text):
                    self._add_finding("DET-07", line_no, val_snippet)

                self._check_prompt_assignment(var_name, text, line_no, val_snippet)
            else:
                # Dynamic reassignment (e.g. question = get_user_request()): invalidate binding
                self._invalidate_variable(var_name)

    def _check_prompt_assignment(self, var_name: str, text: str, line_no: int, val_snippet: str):
        # Explicit prompt variables (e.g. prompt = "What is today's date?", user_prompt = "...")
        is_prompt_var = (
            var_name.lower() in {"prompt", "system_prompt", "user_prompt", "llm_prompt"}
            or var_name.lower().endswith("_prompt")
            or "prompt" in var_name.lower()
        )
        if is_prompt_var:
            for rule_id, cue_re in CUE_PATTERNS.items():
                if cue_re.search(text):
                    self._add_finding(rule_id, line_no, val_snippet)

    def visit_Assign(self, node: ast.Assign):
        line_no = getattr(node, "lineno", 1)
        self._record_assignment(node.targets, node.value, line_no)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        # Support annotated assignments: prompt: str = "What is today's date?"
        line_no = getattr(node, "lineno", 1)
        if node.value:
            self._record_assignment([node.target], node.value, line_no)
        else:
            if isinstance(node.target, ast.Name):
                self._invalidate_variable(node.target.id)
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        # Push new local function scope
        self.scopes.append({})
        # Function parameters mask/invalidate any outer variable bindings with the same name
        all_args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        for a in all_args:
            self._invalidate_variable(a.arg)
        if node.args.vararg:
            self._invalidate_variable(node.args.vararg.arg)
        if node.args.kwarg:
            self._invalidate_variable(node.args.kwarg.arg)

        self.generic_visit(node)
        self.scopes.pop()

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
        # Push new local async function scope
        self.scopes.append({})
        all_args = node.args.posonlyargs + node.args.args + node.args.kwonlyargs
        for a in all_args:
            self._invalidate_variable(a.arg)
        if node.args.vararg:
            self._invalidate_variable(node.args.vararg.arg)
        if node.args.kwarg:
            self._invalidate_variable(node.args.kwarg.arg)

        self.generic_visit(node)
        self.scopes.pop()

    def visit_ClassDef(self, node: ast.ClassDef):
        # Push new class scope
        self.scopes.append({})
        self.generic_visit(node)
        self.scopes.pop()

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
                text, _ = _extract_string_content(arg, scope_lookup=self._lookup_variable)
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
                text, origin_line = _extract_string_content(arg, scope_lookup=self._lookup_variable)
                if not text:
                    continue

                arg_line = origin_line if origin_line else getattr(arg, "lineno", line_no)
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
