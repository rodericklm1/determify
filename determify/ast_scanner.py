"""
ast_scanner.py - Syntax-Aware Python AST Scanner for Determify.
Performs zero-dependency syntactic inspection of Python source code to detect
deterministic AI waste, multiline f-strings, and ungated LLM call sites with robust
lexical scope stacks, conservative control-flow invalidation, and container alias resolution.

Scope model (syntactic approximation, not a data-flow engine):
- Walrus targets resolve to their true owner frame: comprehension scopes are
  skipped (they are execution closures), lambda/function frames stop the search,
  and comprehension walrus writes are applied invalidate-only, never literal-bound.
- Subscript assignment/aug-assign/delete mutates the aliased object; the root
  binding and any names sharing its exact binding object (simple `b = a` alias
  identity) are invalidated. Deeper aliasing (parameter passing, nested
  containers, returned aliases) is NOT modeled: findings are conservative
  candidates, never a soundness or precision guarantee.
- f-string resolution uses only the STATIC literal fragments of a skeleton:
  a cue inside a literal fragment is legitimate candidate evidence and is not
  masked, while arbitrary dynamic expressions, interprocedural data flow, and
  mutations through untracked aliases are outside the model. Coverage is
  reported as partial; findings are candidates, not proof.
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

# Sentinel distinguishing "name absent from frame" from "name present but invalidated"
_MISSING = object()

_COMP_NODES = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)

def _collect_arg_named_exprs(node):
    """
    Collect (NamedExpr, nested) pairs from a call-argument subtree, where
    nested=True when the NamedExpr sits below a lambda or comprehension boundary
    in that subtree (it then binds in a different runtime frame than the
    statement scope and must be treated as invalidate-only).
    """
    out = []

    def rec(n, nested):
        for child in ast.iter_child_nodes(n):
            if isinstance(child, ast.NamedExpr):
                out.append((child, nested))
                rec(child.value, nested)
            elif isinstance(child, (ast.Lambda,) + _COMP_NODES):
                rec(child, True)
            else:
                rec(child, nested)

    rec(node, False)
    return out

def _subscript_root_name(target: ast.AST):
    """d["a"]["b"] walks down to the root Name 'd'. Non-Subscript returns None."""
    if not isinstance(target, ast.Subscript):
        return None
    while isinstance(target.value, ast.Subscript):
        target = target.value
    return target.value if isinstance(target.value, ast.Name) else None

def _pattern_capture_names(pattern: ast.AST) -> set:
    """Collects the binding names a match-case pattern would capture (always dynamic)."""
    names = set()
    for sub in ast.walk(pattern):
        if isinstance(sub, (ast.MatchAs, ast.MatchStar)) and sub.name:
            names.add(sub.name)
        elif isinstance(sub, ast.MatchMapping) and sub.rest:
            names.add(sub.rest)
    return names

# Standard logging and diagnostic method names (not model inference calls)
LOGGER_METHODS = {"info", "debug", "warning", "error", "log", "critical", "exception"}

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

def _get_call_func_attr(node: ast.Call) -> str:
    """Returns the final method name of a call (e.g. 'create' from 'client.chat.completions.create')."""
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    elif isinstance(node.func, ast.Name):
        return node.func.id
    return ""

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
        # Resolve variable reference from lexical scope stack
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
        """
        Search the scope stack innermost-first, respecting class boundary isolation.
        A class frame is skipped only when it encloses another frame: in Python,
        methods and nested scopes never resolve bare names through the class
        namespace, while statements inside the class body itself can.
        """
        for depth, scope in enumerate(reversed(self.scopes)):
            if depth and scope.get("__is_class__"):
                continue
            if name in scope:
                return scope[name]
        return None

    def _bind_variable(self, name: str, val_info):
        """Binds a variable in the innermost (current) scope frame."""
        self.scopes[-1][name] = val_info

    def _invalidate_variable(self, name: str):
        """Invalidates a variable in the current scope frame (e.g. upon dynamic reassignment or parameter masking)."""
        self.scopes[-1][name] = None

    def _invalidate_container(self, name: str):
        """
        Subscript assignment/aug-assign/delete mutates the aliased object itself.
        Conservatively invalidate every frame binding of the root name and every
        name sharing its exact binding object (simple same-object alias tracking).
        Limitation: only direct `b = a` literal alias identity is modeled; rebinding,
        nested containers, and function-parameter aliasing are not tracked.
        """
        objects = []
        for scope in self.scopes:
            val = scope.get(name)
            if isinstance(val, tuple):
                objects.append(val)
                scope[name] = None
        if objects:
            for scope in self.scopes:
                for key, val in list(scope.items()):
                    if any(val is obj for obj in objects):
                        scope[key] = None

    def _apply_named_expr(self, node, invalidate_only: bool = False):
        """
        Applies a walrus (:=) binding in its true owner frame: comprehension
        frames are execution scopes, not binding scopes, so the search skips
        them and stops at the nearest regular function/lambda/module frame
        (a class-frame owner is a SyntaxError in valid Python, so no cross-class
        leak is possible). Inside a comprehension the write is dynamic by
        construction and is applied invalidate-only, so no stale literal can
        leak into later calls.
        """
        if not isinstance(node.target, ast.Name):
            return
        name = node.target.id
        idx = len(self.scopes) - 1
        skipped_comp = False
        while idx > 0 and self.scopes[idx].get("__is_comp__"):
            idx -= 1
            skipped_comp = True
        frame = self.scopes[idx]
        if invalidate_only or skipped_comp:
            frame[name] = None
            return
        text, _ = _extract_string_content(node.value, scope_lookup=self._lookup_variable)
        if text:
            frame[name] = (text, getattr(node, "lineno", 0))
        else:
            frame[name] = None

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
            # Tuple/list destructuring (a, b = ...): positional literal tracking is
            # out of scope, so conservatively invalidate every plain name in the target.
            if isinstance(target, (ast.Tuple, ast.List)):
                for sub in ast.walk(target):
                    if isinstance(sub, ast.Subscript):
                        root = _subscript_root_name(sub)
                        if root is not None:
                            self._invalidate_container(root.id)
                    elif isinstance(sub, ast.Name):
                        self._invalidate_variable(sub.id)
                continue
            # Subscript target (data["k"] = ...): mutates the aliased container object,
            # not the root binding itself, but the tracked text is now stale.
            root = _subscript_root_name(target)
            if root is not None:
                self._invalidate_container(root.id)
                continue
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

    def _invalidate_target_names(self, target_node: ast.AST):
        for sub in ast.walk(target_node):
            if isinstance(sub, ast.Name):
                self._invalidate_variable(sub.id)

    def _isolate_sections(self, sections):
        """
        Visit each statement section starting from the scope state captured
        before the compound statement, so branches never share mutated state.
        Afterwards, conservatively merge: every binding touched by any section
        is invalidated, because at runtime any subset of the sections may have
        executed. This is a syntactic approximation, not a data-flow engine.
        """
        entry = dict(self.scopes[-1])
        touched = set()
        for section in sections:
            self.scopes[-1].clear()
            self.scopes[-1].update(entry)
            for stmt in section:
                self.visit(stmt)
            for name, val in self.scopes[-1].items():
                if entry.get(name, _MISSING) != val:
                    touched.add(name)
        for name in touched:
            entry[name] = None
        self.scopes[-1].clear()
        self.scopes[-1].update(entry)

    def visit_Assign(self, node: ast.Assign):
        line_no = getattr(node, "lineno", 1)
        self._record_assignment(node.targets, node.value, line_no)
        self.generic_visit(node)

    def visit_AnnAssign(self, node: ast.AnnAssign):
        line_no = getattr(node, "lineno", 1)
        if node.value:
            self._record_assignment([node.target], node.value, line_no)
        else:
            if isinstance(node.target, ast.Name):
                self._invalidate_variable(node.target.id)
        self.generic_visit(node)

    def visit_NamedExpr(self, node):
        # Standalone or in-test walrus: bind literal or invalidate before anything
        # downstream reads the name.
        self._apply_named_expr(node)
        self.generic_visit(node)

    def visit_AugAssign(self, node: ast.AugAssign):
        # Augmented assignment (e.g. prompt += x) makes variable dynamic; invalidate.
        # A subscript target (d["k"] += x) mutates the container object instead.
        if isinstance(node.target, ast.Name):
            self._invalidate_variable(node.target.id)
        else:
            root = _subscript_root_name(node.target)
            if root is not None:
                self._invalidate_container(root.id)
        self.generic_visit(node)

    def visit_Delete(self, node: ast.Delete):
        # Explicit deletion (del question) invalidates the name; del d["k"] mutates
        # the aliased container object, so invalidate the root and its aliases.
        for target in node.targets:
            if isinstance(target, ast.Name):
                self._invalidate_variable(target.id)
            else:
                root = _subscript_root_name(target)
                if root is not None:
                    self._invalidate_container(root.id)
        self.generic_visit(node)

    def visit_Global(self, node):
        # A global declaration redirects writes to the module frame; conservatively
        # invalidate the names there so no function-body literal leaks outward.
        for name in node.names:
            self.scopes[0][name] = None
        self.generic_visit(node)

    def visit_Nonlocal(self, node):
        for name in node.names:
            for scope in self.scopes[:-1]:
                if not scope.get("__is_class__"):
                    scope[name] = None
        self.generic_visit(node)

    def visit_For(self, node: ast.For):
        # Loop iteration targets are dynamic; the body may also never execute,
        # so names written inside it are invalidated on merge.
        self.visit(node.iter)
        self._invalidate_target_names(node.target)
        self._isolate_sections([node.body, node.orelse])

    def visit_AsyncFor(self, node: ast.AsyncFor):
        self.visit(node.iter)
        self._invalidate_target_names(node.target)
        self._isolate_sections([node.body, node.orelse])

    def visit_While(self, node):
        # Zero-or-many iterations: identical treatment to For on the body.
        self.visit(node.test)
        self._isolate_sections([node.body, node.orelse])

    def visit_With(self, node: ast.With):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self._invalidate_target_names(item.optional_vars)
        # Body may exit via exception mid-way; written names are not guaranteed.
        self._isolate_sections([node.body])

    def visit_AsyncWith(self, node: ast.AsyncWith):
        for item in node.items:
            self.visit(item.context_expr)
            if item.optional_vars:
                self._invalidate_target_names(item.optional_vars)
        self._isolate_sections([node.body])

    def visit_Try(self, node):
        self._isolate_try_sections(node)

    def visit_TryStar(self, node):
        self._isolate_try_sections(node)

    def _isolate_try_sections(self, node):
        # Each handler sees only the state at the raise point (unknown), and the
        # body may abort anywhere: isolate every section from the pre-try state.
        sections = [node.body] + [[h] for h in node.handlers] + [node.orelse, node.finalbody]
        self._isolate_sections(sections)

    def visit_ExceptHandler(self, node: ast.ExceptHandler):
        if node.name:
            self._invalidate_variable(node.name)
        self.generic_visit(node)

    def visit_Match(self, node):
        # Case patterns capture dynamic subject fragments and guards/body execute
        # on at most one path: isolate each case like an if/elif chain.
        self.visit(node.subject)
        entry = dict(self.scopes[-1])
        touched = set()
        for case in node.cases:
            self.scopes[-1].clear()
            self.scopes[-1].update(entry)
            for captured in _pattern_capture_names(case.pattern):
                self._invalidate_variable(captured)
            if case.guard is not None:
                self.visit(case.guard)
            for stmt in case.body:
                self.visit(stmt)
            for name, val in self.scopes[-1].items():
                if entry.get(name, _MISSING) != val:
                    touched.add(name)
        for name in touched:
            entry[name] = None
        self.scopes[-1].clear()
        self.scopes[-1].update(entry)

    def visit_If(self, node: ast.If):
        # Statically uncertain control flow: the test (which may walrus-bind) runs
        # first, then each branch is evaluated from the pre-branch state and merged
        # conservatively so no binding leaks across branches or past the block.
        self.visit(node.test)
        self._isolate_sections([node.body, node.orelse])

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
        # Executing the def statement rebinds the function name itself (e.g.
        # `question = "literal"; def question(): ...` masks the old binding).
        self._invalidate_variable(node.name)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef):
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
        self._invalidate_variable(node.name)

    def visit_Lambda(self, node: ast.Lambda):
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
        # Class definitions create an isolated namespace that is not part of the lexical closure chain for methods
        self.scopes.append({"__is_class__": True})
        self.generic_visit(node)
        self.scopes.pop()
        self._invalidate_variable(node.name)

    def visit_ListComp(self, node):
        # Comprehensions execute in their own scope (they can read outer names but
        # walrus writes skip this frame; see _apply_named_expr).
        self.scopes.append({"__is_comp__": True})
        for gen in node.generators:
            for sub in ast.walk(gen.target):
                if isinstance(sub, ast.Name):
                    self._invalidate_variable(sub.id)
        self.generic_visit(node)
        self.scopes.pop()

    def visit_SetComp(self, node):
        # Comprehensions execute in their own scope (they can read outer names but
        # walrus writes skip this frame; see _apply_named_expr).
        self.scopes.append({"__is_comp__": True})
        for gen in node.generators:
            for sub in ast.walk(gen.target):
                if isinstance(sub, ast.Name):
                    self._invalidate_variable(sub.id)
        self.generic_visit(node)
        self.scopes.pop()

    def visit_DictComp(self, node):
        # Comprehensions execute in their own scope (they can read outer names but
        # walrus writes skip this frame; see _apply_named_expr).
        self.scopes.append({"__is_comp__": True})
        for gen in node.generators:
            for sub in ast.walk(gen.target):
                if isinstance(sub, ast.Name):
                    self._invalidate_variable(sub.id)
        self.generic_visit(node)
        self.scopes.pop()

    def visit_GeneratorExp(self, node):
        # Comprehensions execute in their own scope (they can read outer names but
        # walrus writes skip this frame; see _apply_named_expr).
        self.scopes.append({"__is_comp__": True})
        for gen in node.generators:
            for sub in ast.walk(gen.target):
                if isinstance(sub, ast.Name):
                    self._invalidate_variable(sub.id)
        self.generic_visit(node)
        self.scopes.pop()

    def visit_Import(self, node: ast.Import):
        # Binding names via import are module objects, never tracked prompt literals.
        for a in node.names:
            self._invalidate_variable((a.asname or a.name).split(".")[0])
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        for a in node.names:
            self._invalidate_variable(a.asname or a.name)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_name = _get_call_name(node)
        func_attr = _get_call_func_attr(node)
        line_no = getattr(node, "lineno", 1)
        raw_line = self.lines[line_no - 1].strip() if line_no <= len(self.lines) else ""

        # Python evaluates walrus rebinds while building the argument list, before
        # the call executes. Apply every NamedExpr target in this call's arguments
        # first so scope resolution never uses a stale literal the argument replaces.
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            for ne, nested in _collect_arg_named_exprs(arg):
                self._apply_named_expr(ne, invalidate_only=nested)

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

        # Check if the call is an AI/LLM invocation
        # Exclude standard logging calls (e.g. logger.info, model_logger.debug) unless it's a verified SDK call
        is_logger_call = func_attr in LOGGER_METHODS and ("logger" in call_name.lower() or "log" in call_name.lower())
        is_llm_call = is_explicit_sdk or (
            not is_logger_call and any(
                sig in call_name.lower()
                for sig in ("llm.", "openai.", "anthropic.", "chat.", "agent.run", "model.predict", "llm_call")
            )
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
