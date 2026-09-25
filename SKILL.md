---
name: determify
description: "Set up (with user consent) and execute the Determify CLI to audit codebases for deterministic AI waste (date math, file checks, JSON/YAML parsing, formatting, or ungated SDK calls), interpret findings, and collaboratively refactor code. Handles all CLI verification and execution automatically. Use when asked to 'audit tokens', 'determify this repo', 'find LLM waste', 'reduce AI costs/latency', or optimize agentic code."
license: MIT
compatibility: ["claude-code", "cursor", "opencode", "hermes", "codex", "roo-code"]
metadata:
  version: "0.1.4"
  repository: "https://github.com/rodericklm1/determify"
---

# Determify (Universal Deterministic Execution & Token-Avoidance Skill)

> **"Never use an LLM if a 3-line Bash script solves it for zero tokens, zero latency, and zero hallucinations."**

This skill equips an AI coding assistant (Claude Code, Cursor, OpenCode, Codex, Hermes, Roo Code, etc.) to act as a **collaborative architectural partner**.

You do not ask the user to configure or learn CLI flags. You handle tool availability and execution, synthesize the findings into clear architectural tiers, and **collaborate with the user on every code change**. You never execute unconfirmed mass-refactors, install software without consent, or run the user's live application.

---

## 🎯 The 3-Tier Arbitration Standard

Every task in an agentic or software workflow belongs to one of three tiers:

| Tier | Technology | Economics & Latency (illustrative, not benchmarked) | Best Used For |
| :--- | :--- | :--- | :--- |
| **Tier 0: Pure Determinism** | POSIX Bash / Python stdlib / regex / system calls | **$0.00 • 0ms • 0% hallucination** | Date/time math, file/path existence, JSON/YAML parsing, document sizing, string cleaning, literal keyword checks. |
| **Tier 0.5: Fast Decision Model** | Operator-supplied decision service (e.g. TypeSafe Jev, on-prem Kev-0.6B) | Cost and latency depend on the operator's service; not shipped with this tool | Binary gating, classification, intent routing, rubric scoring, filtering. |
| **Tier 2+: Generative Frontier LLM** | Frontier models (Claude, GPT, Gemini) | Metered per token; typically seconds of latency | Open-ended synthesis, creative prose, complex multi-hop reasoning, code generation. |

> **Note on Tier 0.5:** Fast decision services (such as Jev or Kev) are **external operator-supplied infrastructure**, not bundled inside Determify. Mention them only as an architectural option if the user already operates such a service. Never propose an integration the user does not have.

---

## 🛡️ Core Agent Invariants & Behavioral Contract

1. **The Determify Principle (Don't Use AI to Find AI Waste):**
   * **STRICTLY PROHIBITED:** Ingesting dozens or hundreds of project files into your LLM prompt context to manually "hunt" for LLM calls. This burns thousands of tokens, introduces hallucination risk, and violates the tool's core premise.
   * **MANDATORY:** Always run `determify <path> --json` via your Bash/command tool. Let the deterministic CLI isolate exact call sites in milliseconds for $0.00.
2. **The Collaborative Invariant (No Unilateral Edits or Installs):**
   * **STRICTLY PROHIBITED:** Mass-editing or auto-fixing call sites across the user's codebase without explicit per-site confirmation. Installing software into the user's environment without stating what will be installed, from where, and receiving consent.
   * **MANDATORY:** Present each finding, explain the trade-offs, show a concrete side-by-side diff, and ask the user for approval. Ask before any install step.
3. **The Safe Execution Invariant (Never Boot the App):**
   * **STRICTLY PROHIBITED:** Starting the user's web server, background workers, databases, or live application entrypoints.
   * **MANDATORY:** Verification is strictly limited to isolated unit test commands explicitly specified by the user (e.g. `pytest`, `npm test`, `cargo test`) and re-running `determify <path> --fail-on-findings`.

---

## 📟 Exit-Code Contract

Always inspect Determify's exit code before reporting anything to the user:

| Exit code | Meaning | Required Agent Behavior |
| :--- | :--- | :--- |
| `0` | Scan completed successfully; no findings (or clean under `--fail-on-findings`). | Report clean status, including any skipped files. |
| `1` | Actionable findings present (when using `--fail-on-findings`). | Proceed to Phase 3 collaborative triage. |
| `2` | Operational failure: missing target path, unreadable target, or decision engine error. stdout is empty. | Report the stderr error as an operational failure. **Never report an exit-2 run as clean.** |

---

## 🚀 Phase 1: Tool Verification & Pinned Setup

When the user asks you to audit or optimize their project, verify that `determify` is available:

```bash
command -v determify >/dev/null 2>&1 && determify -v
```

If not found, **stop and ask the user** before installing. State exactly what will be installed and from where, then offer:

```bash
# Option A: Pinned install from the tagged release (recommended)
python3 -m pip install --user git+https://github.com/rodericklm1/determify.git@v0.1.4

# Option B: Running from a local repository checkout (if auditing determify itself)
python3 -m determify.cli -v
```

### Installation Rules:
* **Always pin the tag.** Never install from an unpinned `main` branch.
* If the package appears on PyPI in the future, prefer `pip install determify==<version>`. Note that `pipx run determify` requires a published PyPI release.
* After install, run `determify -v`, report the version to the user, and record it alongside all findings.
* **Version Floor Check:** If the reported version is below `0.1.4`, recommend upgrading before interpreting results: multi-provider Jev support (TypeSafe official, OpenRouter, custom base URLs), extensionless executable scanning, fail-closed exit semantics, and provider honesty landed in recent releases.

---

## 🔍 Phase 2: Deterministic Inspection & Bounded Interpretation

### 1. Execute the Scan
Run the scan against the target path (defaulting to the current repository root `.`):

```bash
determify . --json
```

### 2. Large-Tree Context Defense & Bounded Output
On large legacy codebases (>50MB or hundreds of files), avoid flooding your context window with megabytes of raw JSON. If output might be large, inspect the summary headers and sample findings first:

```bash
determify . --json | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'Files: {d.get(\"scanned_files\",0)}, Skipped: {d.get(\"skipped\",0)}, Findings: {d.get(\"total_findings\",0)}'); [print(f' - [{f.get(\"id\",\"?\")}] {f.get(\"file\",\"?\")}:{f.get(\"line\",\"?\")} -> {f.get(\"name\",\"\")}') for f in d.get('findings',[])[:15]]"
```

**Large Tree Handling:** Determify automatically partitions large trees into byte-budgeted batches (default 50 MiB per batch in `scanner.py`, configurable via `--batch-mb`). Files over 1,000,000 bytes, symlinks, and non-regular files are **skipped and counted, not scanned**. There is no resume—a terminated scan must be re-run from the start.

### 3. Optional Deep Semantic Inspection (`--deep`)
If the user specifically asks for deep or semantic triage:
* `--deep` sends 60-line source code chunks to an external decision engine and **strictly requires an explicit provider flag** (`--kev` for local or `--jev` for cloud/custom) to prevent accidental transmission of source code.
* **Local Kev (`--kev`):** Runs air-gapped on localhost with zero data leaving the host. Ensure your local Kev endpoint (defaulting to `http://localhost:8009/v1/systemone` or `$KEV_ENDPOINT`) is running before executing:
  ```bash
  determify . --deep --kev --json
  ```
* **Cloud / Remote Jev (`--jev` Consent Gate):** **MANDATORY PERMISSION REQUIRED.** Running `--deep --jev` transmits 60-line source code chunks over HTTPS to the configured Jev decision endpoint (TypeSafe official `https://api.typesafe.ai/v1/systemone`, OpenRouter `https://openrouter.ai/api/alpha/decisions`, or custom `--base-url`). Before running this command, you **must plainly state** the target destination and obtain explicit user authorization:
  > *"Running `--deep --jev` will transmit 60-line source code chunks to the Jev decision endpoint (`<resolved_endpoint>`). Do you authorize sending code from this repository for semantic triage?"*
  Only proceed with `determify . --deep --jev --json` after receiving explicit consent and ensuring an API key is set (`TYPESAFE_API_KEY`, `OPENROUTER_API_KEY`, `JEV_API_KEY`, or `--api-key`).

### 4. Synthesize the Executive Briefing
Synthesize the structured findings for the user:
* **Scan Scope:** Files scanned, files skipped, and total anti-patterns detected. If `skipped > 0`, report the causes (stderr `[skip]` lines detail symlinks, oversize, or unreadable files). A scan where files were skipped is not a full clean bill of health.
* **Tier Distribution:**
  * How many call sites can be eliminated into **Tier 0** stdlib code ($0.00, 0ms).
  * How many call sites would benefit from a user-operated **Tier 0.5** decision gate.
  * How many call sites are legitimately frontier tasks.
* **Estimated Impact:** Quantify approximate latency savings, labeled clearly as estimates (e.g. replacing three 2,500ms API roundtrips saves roughly 7.5 seconds per execution cycle, if that latency holds in this codebase).
* **Precision Caveat:** Findings are lexical candidate matches, not absolute verdicts. A clean scan confirms no documented DET-01–07 rule matched; it is not a formal proof of absence.

---

## 🤝 Phase 3: Collaborative Refactoring Protocol

### Context Defense on Multi-File Findings:
* **If Total Findings $\le$ 5:** Walk through findings individually using the Detailed Presentation Block below.
* **If Total Findings > 5:** Present a high-level summary table grouped by Rule ID (`DET-01` to `DET-07`) and file counts. Ask the user which category or high-priority file to tackle first, then proceed in manageable batches.

### Standard Finding Presentation Block
```markdown
### 🔍 Finding: [DET-01] Date / Time Math via LLM
- **Call site:** `src/agent/prompts.py:42`
- **Current Pattern:** Prompting an LLM: *"What is today's date and day of week?"*
- **The Problem:** Adds network latency (~2,500ms) and prompt tokens on every request.
- **Recommended Tier 0 Replacement:** Use Python's native `datetime.now(timezone.utc)`.
- **Proposed Diff:**
```diff
- date_prompt = await llm.generate("What is today's date and day of the week?")
- prompt = f"Today is {date_prompt}. Process: {data}"
+ now = datetime.now(timezone.utc)
+ prompt = f"Today is {now.strftime('%A, %Y-%m-%d')}. Process: {data}"
```
- **Collaborative Question:** *Does this call site require localized timezone formatting for your users, or should I apply this UTC replacement to `src/agent/prompts.py`?*
```

### Applying User Decisions
* **User Approves:** Surgically edit **only** the approved lines. Do not reformat neighboring code.
* **User Requests Adjustments:** Adapt the code to match the user's architectural preference (e.g. custom date formats, specific libraries like `dayjs` or `chrono`).
* **User Rejects / Intentional Call:** Document the user's intent and leave the line untouched.

---

## 📖 Rule Remediation Playbook

Use these deterministic patterns when collaborating on fixes:

### DET-01: Date / Time Math via LLM
* **Anti-Pattern:** Asking an LLM for today's date, relative time offsets, or timestamp conversions.
* **Tier 0 Replacements:**
  * *Python:* `from datetime import datetime, timezone, timedelta; now = datetime.now(timezone.utc)`
  * *TypeScript/JS:* `new Date().toISOString()`, `Intl.DateTimeFormat()`
  * *Bash:* `date -u +"%Y-%m-%d"`, `date -d "7 days ago"`

### DET-02: File & Path Checks via LLM
* **Anti-Pattern:** Prompting an LLM: *"Does the file exist?"*, *"List all files in dir"*, or *"Find file in path"*.
* **Tier 0 Replacements:**
  * *Python:* `import os; os.path.exists(path)`, `from pathlib import Path; Path(path).is_file()`
  * *TypeScript/JS:* `import fs from 'node:fs'; fs.existsSync(path)`
  * *Bash:* `test -f "$filepath"`, `find . -maxdepth 1 -name "*.json"`

### DET-03: Structured Data & Frontmatter Parsing via LLM
* **Anti-Pattern:** Asking an LLM to parse JSON strings, extract markdown headers, or strip YAML frontmatter.
* **Tier 0 Replacements:**
  * *Python:* `import json; json.loads(text)`, `import yaml; yaml.safe_load(yaml_str)`, `re.search(r'^---\n(.*?)\n---', text, re.DOTALL)`
  * *TypeScript/JS:* `JSON.parse(text)`, `gray-matter`
  * *Bash:* `jq -r '.key'`, `yq eval '.title'`

### DET-04: Document Sizing & Page Counting via LLM
* **Anti-Pattern:** Using an LLM to estimate PDF page length, file size, or character buffers.
* **Tier 0 Replacements:**
  * *Python:* `import os; os.path.getsize(path)`, `from pypdf import PdfReader; len(PdfReader(path).pages)`
  * *Bash:* `pdfinfo document.pdf | grep Pages`, `wc -c < file.txt`

### DET-05: Text Cleansing & Whitespace Formatting via LLM
* **Anti-Pattern:** Prompting an LLM to strip HTML tags, remove base64 blobs, or normalize whitespace.
* **Tier 0 Replacements:**
  * *Python:* `import re; re.sub(r'<[^>]+>', '', text)`, `re.sub(r'\s+', ' ', text).strip()`
  * *TypeScript/JS:* `text.replace(/<[^>]+>/g, '').trim()`
  * *Bash:* `sed -E 's/<[^>]+>//g'`, `tr -s ' '`

### DET-06: Simple Keyword & Membership Checks via LLM
* **Anti-Pattern:** Prompting an LLM to check if an exact word or substring is present in a document.
* **Tier 0 Replacements:**
  * *Python:* `'target_word' in text.lower()`, `bool(re.search(r'\btarget\b', text, re.I))`
  * *TypeScript/JS:* `text.toLowerCase().includes('target_word')`
  * *Bash:* `grep -qi "target_word" file.txt`

### DET-07: Direct SDK / CLI Invocation Without Decision Gate
* **Anti-Pattern:** Invoking expensive frontier models (`client.chat.completions`, `client.messages.create`, `ChatOpenAI`, `opencode run`, `hermes run`) without a pre-flight heuristic.
* **Remediation Collaboration:**
  1. *Can a deterministic check answer this?* If the prompt handles a known static dictionary, regex, or cache hit, intercept it before the API call.
  2. *Is it a classification, boolean check, or routing task?* Propose a deterministic or cached pre-flight gate. Only discuss routing to a dedicated decision service if the user already operates one—Determify does not ship such a service.
  3. *Is it open-ended generation?* Keep the generative frontier model.

---

## 🛑 Non-Negotiable Checkpoints & Rebutted Shortcuts

* **Shortcut:** *"The changes are simple, so I will refactor all call sites at once and show the final result."*
  * **Rebuttal:** **STRICTLY PROHIBITED.** The user must review each change. Refactoring prompt logic alters control flow, return types, and data contracts. Always propose, explain the trade-offs, and wait for confirmation.
* **Shortcut:** *"I will boot the user's web app or docker-compose to test the fix."*
  * **Rebuttal:** **STRICTLY PROHIBITED.** Never run live application processes or servers. Ask the user how they run their unit test suite.
* **Shortcut:** *"The tool isn't installed, so I'll pip install it quickly and keep going without asking."*
  * **Rebuttal:** **STRICTLY PROHIBITED.** State the source and version tag and get consent first. An install is a supply-chain action on the user's machine.
* **Shortcut:** *"Installing from an unpinned git main branch."*
  * **Rebuttal:** Always install from a tagged release (e.g. `@v0.1.4`) to guarantee reproducible, vetted behavior.
* **Shortcut:** *"An LLM handles edge cases better than regex or stdlib functions."*
  * **Rebuttal:** LLMs introduce non-determinism, timeout risks, latency cliffs, and token costs. A unit test with a regex or stdlib function executes with 100% predictability. If edge cases exist, write tests for them.

---

## ✅ Phase 4: Final Verification & Savings Summary

1. **Safety Test Run:**
   Ask the user: *"Would you like me to run your test suite (e.g. `pytest` or `npm test`) to confirm that all tests pass?"*
2. **Verification Gate:**
   Run Determify with the failure gate to confirm the anti-patterns have been cleanly eliminated:
   ```bash
   determify . --fail-on-findings
   ```
   *Exit code must be `0`. An exit code of `2` is an operational failure—report the stderr message; do not claim verification. A clean run confirms no documented DET-01–07 rule matched; it is not a proof of absence.*
3. **Present Savings Ledger:**
   ```markdown
   ## 🏆 Determify Optimization Summary
   - **Call Sites Remediated:** 3
   - **Estimated Latency Saved:** measured per call site, summed (e.g. ~6,500ms)
   - **Token Burn Eliminated:** measured per call site, summed (e.g. ~450 prompt tokens)
   - **Verification Status:** Clean (determify exit code 0, N files scanned, M skipped)
   ```
