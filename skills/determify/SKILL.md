---
name: determify
description: "Autonomously set up and execute Determify CLI to audit codebases for deterministic AI waste (date math, file checks, JSON/YAML parsing, formatting, or ungated SDK calls), interpret the findings, and collaborate with the user on surgical refactoring. Handles all CLI verification and execution automatically. Use when asked to 'audit tokens', 'determify this repo', 'find LLM waste', 'reduce AI costs/latency', or optimize agentic code."
license: MIT
---

# Determify (Universal Deterministic Execution & Token-Avoidance Skill)

> **"Never use an LLM if a 3-line Bash script solves it for zero tokens, zero latency, and zero hallucinations."**

This skill equips an AI coding assistant (Claude Code, Cursor, OpenCode, Codex, Hermes, Roo Code, etc.) to act as a **collaborative architectural partner**. 

You do not ask the user to configure or learn CLI flags. You handle tool availability and execution under the hood, synthesize the findings into clear architectural tiers, and **collaborate with the user on every code change**. You never execute unconfirmed mass-refactors or run the user's live application.

---

## 🎯 The 3-Tier Arbitration Standard

Every task in an agentic or software workflow belongs to one of three tiers:

| Tier | Technology | Economics & Latency | Best Used For |
| :--- | :--- | :--- | :--- |
| **Tier 0: Pure Determinism** | POSIX Bash / Python stdlib / regex / system calls | **$0.00 • 0ms • 0% hallucination** | Date/time math, file/path existence, JSON/YAML parsing, document sizing, string cleaning, literal keyword checks. |
| **Tier 0.5: Fast Decision Model** | TypeSafe Jev / On-Prem Kev-0.6B | **$0.000042 • <100ms** | Binary gating, classification, intent routing, rubric scoring, filtering. Emits zero output tokens. |
| **Tier 2+: Generative Frontier LLM** | Frontier models (Claude, GPT, Gemini) | **$3–$15/MTok • 2,000–8,000ms** | Open-ended synthesis, creative prose, complex multi-hop reasoning, code generation. |

---

## 🛡️ Core Agent Invariants & Behavioral Contract

1. **The Determify Principle (Don't Use AI to Find AI Waste):**
   * **STRICTLY PROHIBITED:** Ingesting dozens or hundreds of project files into your LLM prompt context to manually "hunt" for LLM calls. This burns thousands of tokens, introduces hallucination risk, and violates the tool's core premise.
   * **MANDATORY:** Always run `determify <path> --json` via your Bash/command tool. Let the deterministic CLI isolate exact call sites in milliseconds for $0.00.
2. **The Collaborative Invariant (No Unilateral Edits):**
   * **STRICTLY PROHIBITED:** Mass-editing or auto-fixing call sites across the user's codebase without explicit per-site confirmation.
   * **MANDATORY:** Present each finding, explain the trade-offs, show a concrete side-by-side diff, and ask the user for approval.
3. **The Safe Execution Invariant (Never Boot the App):**
   * **STRICTLY PROHIBITED:** Starting the user's web server, background workers, databases, or live application entrypoints.
   * **MANDATORY:** Verification is strictly limited to isolated unit test commands explicitly specified by the user (e.g. `pytest`, `npm test`, `cargo test`) and re-running `determify <path> --fail-on-findings`.

---

## 🚀 Phase 1: Tool Verification & Setup (Zero User Burden)

When the user asks you to audit or optimize their project, verify and provision `determify` in the environment quietly:

```bash
# 1. Check if determify is already available
command -v determify >/dev/null 2>&1 || python3 -m determify.cli --version >/dev/null 2>&1
```

If not found, provision it automatically using the available environment mechanism:
```bash
# Option A: Fast execution via pipx / uv (if installed)
pipx run determify --version >/dev/null 2>&1

# Option B: Install via pip from GitHub into the current environment or user site
python3 -m pip install --quiet git+https://github.com/rodericklm1/determify.git

# Option C: Running from local repository checkout (if auditing determify itself)
python3 -m determify.cli --version
```

Verify that the CLI runs and produces version output before proceeding. Do not ask the user to run setup commands unless permissions explicitly block you.

---

## 🔍 Phase 2: Deterministic Inspection & Interpretation

### 1. Execute the Scan
Run the scan against the target path (defaulting to the current repository root `.`):

```bash
determify . --json
```

*Tip: If the codebase is large (>50MB), `determify` automatically batches by byte-budget and streams progress to stderr without dropping findings.*

### 2. Interpret the Findings
Parse the structured JSON output:
```json
{
  "version": "0.1.2",
  "scanned_files": 48,
  "skipped": 0,
  "total_findings": 3,
  "findings": [...]
}
```

Synthesize the results into an **Executive Briefing**:
* **Scan Scope:** Number of files scanned and total anti-patterns detected.
* **Tier Distribution:**
  * How many call sites can be completely eliminated into **Tier 0** stdlib code ($0.00, 0ms).
  * How many call sites should be routed to a **Tier 0.5** decision gate (Jev/Kev).
  * How many call sites are legitimately frontier tasks.
* **Estimated Impact:** Quantify approximate latency savings (e.g. replacing three 2,500ms API roundtrips saves ~7.5 seconds per execution cycle).

---

## 🤝 Phase 3: Collaborative Refactoring Protocol

Walk through the findings with the user. Treat the user as the domain expert:

### Standard Finding Presentation Block
```markdown
### 🔍 Finding: [DET-01] Date / Time Math via LLM
- **Call site:** `src/agent/prompts.py:42`
- **Current Pattern:** Prompting an LLM: *"What is today's date and day of week?"*
- **The Problem:** Incurs ~2,500ms network latency and ~150 prompt tokens on every request.
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

Use these battle-tested deterministic patterns when collaborating on fixes:

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
  2. *Is it a classification, boolean check, or routing task?* Propose routing to a **Tier 0.5 decision model** (TypeSafe Jev or on-prem Kev-0.6B) for <100ms latency and $0.000042 cost.
  3. *Is it open-ended generation?* Keep the generative frontier model.

---

## 🛑 Non-Negotiable Checkpoints & Rebutted Shortcuts

* **Shortcut:** *"The changes are simple, so I will refactor all call sites at once and show the final result."*
  * **Rebuttal:** **STRICTLY PROHIBITED.** The user must review each change. Refactoring prompt logic alters control flow, return types, and data contracts. Always propose, explain the trade-offs, and wait for confirmation.
* **Shortcut:** *"I will boot the user's web app or docker-compose to test the fix."*
  * **Rebuttal:** **STRICTLY PROHIBITED.** Never run live application processes or servers. Ask the user how they run their unit test suite.
* **Shortcut:** *"An LLM handles edge cases better than regex or stdlib functions."*
  * **Rebuttal:** LLMs introduce non-determinism, timeout risks, latency cliffs (2–5s), and token costs. A unit test with a regex or stdlib function executes in 0ms with 100% predictability. If edge cases exist, write tests for them.

---

## ✅ Phase 4: Final Verification & Savings Summary

1. **Safety Test Run:**
   Ask the user: *"Would you like me to run your test suite (e.g. `pytest` or `npm test`) to confirm that all tests pass?"*
2. **Verification Gate:**
   Run Determify with the failure gate to confirm the anti-patterns have been cleanly eliminated:
   ```bash
   determify . --fail-on-findings
   ```
   *Exit code must be `0`.*
3. **Present Savings Ledger:**
   ```markdown
   ## 🏆 Determify Optimization Summary
   - **Call Sites Remediated:** 3
   - **Estimated Latency Saved:** ~6,500ms per workflow run
   - **Token Burn Eliminated:** ~450 prompt tokens per cycle ($0.00 runtime cost)
   - **Verification Status:** Clean (determify exit code 0)
   ```
