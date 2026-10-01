# Changelog

All notable changes to `determify` are documented here. Versions follow
semver; this file describes what changed, not performance promises.

## 0.1.9 (corrective release)

### AST scope correctness (`ast_scanner.py`)

- Walrus (`:=`) targets now resolve to their true owner frame. Comprehension
  frames are execution scopes, not binding scopes, so comprehension walrus
  writes now invalidate the enclosing function/module frame (list, set, dict,
  and generator siblings, including nested comprehensions).
- Walrus rebinds inside call arguments are applied before argument string
  extraction, so a stale literal can no longer leak into the same or a later
  call.
- Tuple/list destructuring invalidates all plain target names.
- Branch isolation: if/else, for, while, with, try/except*/except, and match
  sections are visited from the pre-statement scope state and merged
  conservatively; no state leaks across branches or past the block.
- Compile-time name masking handled for `def`/`async def`/`class` names,
  `import`/`import ... as`, `global`, `nonlocal`, `del`, and `except ... as`.
- Subscript assignment/aug-assign/delete now invalidates the mutated
  container's root binding and simple same-object aliases (`b = a` identity).
  Limitations are documented: no parameter-passing aliases, no nested
  containers, no interprocedural flow. Static f-string fragments remain
  candidate evidence (legitimate detections are not masked); findings are
  candidates, not proof.

### Decision evaluator (`jev_evaluator.py`, `cli.py`)

- Fallback is now gated on typed errors only: connection/timeout and selected
  transient HTTP statuses (408/429/5xx) may trigger the authorized Kev
  fallback. 401/403 and other permanent statuses raise
  `PermanentServiceError`, malformed or wrong-type responses raise
  `ResponseFormatError`, and both always fail closed. Security policy
  violations and programming errors never fall back. Causes are preserved.
- Fixed a latent crash: the fallback notice path used `sys.stderr` without
  importing `sys`.
- Fallback configuration is resolved exactly once per call from Kev-only
  inputs; primary CLI-supplied credentials cannot reach fallback headers.
- HTTP error responses are closed explicitly after a bounded error-body read,
  so transient (5xx/429) and permanent (401/403/404) paths no longer rely on
  GC-time implicit cleanup that surfaced ResourceWarnings.
- Structured fallback metadata (reason, exact resolved primary and Kev
  destinations, contacted-primary flag) is propagated to verdicts, deep
  findings, stats, JSON output, and the CLI banner. The missing-key case now
  reports that the primary endpoint was not contacted, instead of implying a
  primary outage. Provider-string matching removed from scanner and CLI.

### Deep scan (`deep_scanner.py`)

- A `# determify:allow DET-DEEP` marker is bound to the finding's exact
  signal site; one marker can no longer suppress unrelated sites inside the
  same 60-line window. Exemption ownership is recorded at the signal line.

### Concurrency (`concurrency.py`, new)

- Single shared stdlib bounded submission helper used by both the triage and
  deep paths: at most `--workers` pending futures, deterministic
  input-order results, queued/unsubmitted work cancelled on first failure.
  In-flight network requests finish or hit their own HTTP timeout (no
  immediate-abort claim).
- New `--workers` flag: positive, bounded 1-32, default 5.

### Batching (`scanner.py`, `cli.py`)

- CLI default (omitted `--batch-mb`) now forwards `None` so the library
  applies `DEFAULT_BATCH_BYTES` (50,000,000 bytes, about 47.7 MiB) instead of
  silently using the minimum floor.
- `--batch-mb N` uses exactly N MiB (N x 1,048,576 bytes) with validation;
  the cap is never silently altered.

### Documentation and claims

- `SKILL.md`: mktemp capture snippet documented for script/subshell
  execution (never sourced into the user's shell) with a mktemp failure
  guard; unknown/non-zero exits are never parsed or reported as clean; the
  report path is passed via argv, not interpolated into Python source; skip
  causes on stderr are retained; exit-0-with-findings clarified; consent gate
  extended to every source-bearing semantic call, not only `--deep`; the
  localhost air-gap is described as a property of the operator's deployment,
  not a guarantee; `compatibility` is a string per the Agent Skills metadata
  schema.
- Removed unsupported measured claims (`sub-ms`, `sub-100ms`, `sub-90ms`,
  `instant`, `100%`, `95-100%`, `2ms`, `<5ms`) from README, SKILL, patterns,
  and CLI help. The "3-line Bash script" line is retained and identified as a
  design maxim with a real-compute-cost caveat.
- Partial coverage is stated explicitly: default exclusion of `tests/` and
  Markdown prose, candidate-not-proof framing, and no runtime routing.

### Tests

- Full suite: 135 tests, all passing, including live localhost servers
  that count actual requests across the fallback matrix (enabled, disabled,
  missing key, security, auth, malformed), barrier-based concurrency proofs,
  exact-site exemption fixtures, and the documented scope regressions.
- Test results above are from local execution.
