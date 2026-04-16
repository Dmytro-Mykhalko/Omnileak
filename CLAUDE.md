# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Omnileak is a Python-based orchestrator that scans Git repositories for hardcoded secrets using four industry-standard tools (Gitleaks, Trufflehog, Detect Secrets, Titus), deduplicates their results using a 3-pass algorithm, and produces clean Excel and JSON reports. It includes an AI-powered triage pipeline (via Claude Code skill) that classifies findings as true/false positives and performs deep analysis for composite vulnerabilities.

## Development Commands

### Setup
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
./install_deps.sh  # Optional: pre-download scanner tools to ./bin/
```

### Run Tests
```bash
python -m pytest tests/ -v                           # All tests
python -m pytest tests/test_deduplicator.py -v      # Single test file
python -m pytest tests/test_deduplicator.py::TestDeduplicator::test_merges_found_by -v  # Single test
```

Note: All tests use mocked data; no external scanner tools or network access required.

### Main Entry Point
```bash
python main.py --repo /path/to/repo --out ./results            # Single repo scan
python main.py --clone-urls repos.txt --clone-dir ./src --out ./results  # Multi-repo scan
python main.py --repo ~/app --tools gitleaks trufflehog --threads 2 --timeout 600  # Custom tools/parallelism
```

The CLI automatically installs missing scanner tools to `./bin/` on first run. Use `--threads N` for repo-level parallelism (1 repo = 4 tool processes, so --threads 4 ≈ 16 concurrent processes max).

### Install Claude Code Skill
```bash
cd /path/to/Omnileak
./claude-skill/install.sh  # Copies skill to ~/.claude/commands/ and sets OMNILEAK_HOME
```

Then in Claude Code (any git repo): `/scan-secrets`, `/scan-secrets --repo ~/path`, or `/scan-secrets --results ./existing-scan-dir`.

## Architecture & Key Modules

### 1. Scanner Pattern (`scanners/`)

All scanners inherit from `BaseScanner` and implement a two-step pattern:

- **`run_scan()`** — execute the tool's CLI and save raw JSON/NDJSON output
- **`parse_results()`** — parse tool-specific output format into a normalized finding dict

Finding dict structure (standardized across all tools):
```python
{
    "id": "sha256(repo|file|secret_normalized)",  # dedup key
    "repository": "repo-name",
    "file_path": "path/to/file",
    "line_number": "42",
    "secret_type": "AWS_KEY",               # from tool's RuleID/DetectorName
    "secret_value": "AKIA...",              # actual secret
    "commit_hash": "abc123def...",          # full commit hash
    "repo_url": "https://github.com/...",   # resolved from git origin
    "found_by": ["gitleaks", "titus"],      # merged across tools
}
```

Key patterns:
- **Tool availability check** — `is_available()` uses `shutil.which()` to verify CLI is in PATH before scanning
- **Timeout handling** — passed through `execute()` to all `run_command()` calls
- **ID generation** — `generate_id()` normalizes whitespace in secret values so the same credential formatted differently by different tools produces the same hash (crucial for deduplication)
- **Repo URL resolution** — done once per repo in `main.py` via `resolve_repo_url()`, then passed to all scanner instances

Special notes:
- **Gitleaks & Titus** — scan full git history with `--git` flag
- **Trufflehog** — reads NDJSON (one JSON per line); uses `run_command_to_file()` to avoid memory overload
- **Detect Secrets** — scans only current files, but enriches findings with commit hashes via `git blame` and reads actual line content from disk (not just hashes)
- **Titus** — two-stage: `scan` into SQLite datastore, then `report` as JSON; blob→path mapping via SQLite or fallback human-report parsing

### 2. Deduplication Pipeline (`core/deduplicator.py`)

Three-pass algorithm:

1. **Pass 1 — by ID** — merge findings with identical `(repo, file, secret_normalized)` keys, combine `found_by` lists
2. **Pass 2 — by secret** — group by `sha256(repo|secret_normalized)` (file-agnostic), merge findings where same secret reported at different paths
3. **Pass 3 — proximity** — group by `(repo, file, line, commit)`, merge findings whose secret values overlap (one contains the other)

Helper functions:
- `_normalize(value)` — collapse all whitespace and remove escaped newlines
- `_extract_core(value)` — strip variable assignment prefixes (`DB_PASS=`, `$x =>`) and quotes to isolate raw secret
- `_is_overlap(a, b)` — checks exact match, substring containment, or core-extracted substring (three levels, cheapest first)

The `_merge()` method picks the "best" base (most populated fields, longest secret) and fills in missing metadata from others.

### 3. Reporting (`core/reporter.py`)

Two output formats per repo:
- **JSON** — `{repo_name}_aggregated_secrets.json` with all findings and metadata
- **Excel** — `{repo_name}_secrets_report.xlsx` with General tab (all findings) + per-tool tabs

Excel features:
- Commit column converted to clickable hyperlinks via `build_commit_url()` (GitHub and GitLab patterns)
- `sanitize_for_excel()` removes illegal XML control characters and truncates oversized secret_value fields (>5000 chars)
- Auto-filters enabled on all columns for easy sorting/filtering

Multi-repo scans also produce global aggregated files.

### 4. AI Triage Pipeline (`core/ai/`)

Four-stage workflow (called by Claude Code skill):

**Step 1: Prefilter** (`prefilter.py`)
- Deterministic FP classification by file path (no AI needed)
- Categories: lock files, vendor code, minified JS, test fixtures, source maps, etc.
- Reduces volume before AI triage; auto-FPs excluded from agent dispatch

**Step 2: Agent-based Triage** (via Claude Code skill in `claude-skill/`)
- Dispatched by tier: Skip (0 FPs) → Lightweight (1–20) → Standard (21–200) → Large (200+)
- For each repo: read `triage-rules.md`, classify findings as TRUE_POSITIVE / FALSE_POSITIVE / DUPLICATE
- Output compact JSON: `{"findings": [{"id": "...", "classification": "TP", "severity": "CRITICAL", ...}]}`

**Step 3: Assembly** (`triage_writer.py`)
- Merges raw findings + AI classifications + prefilter results
- Guarantees every raw finding is accounted for; fills missing fields
- Computes risk score: `CRITICAL=10, HIGH=5, MEDIUM=2, LOW=1` points, ×1.5 for composites, ×1.3 if HIGH/CRITICAL on-disk

**Step 4: Validation & Reporting** (`triage_validator.py`, `triage_reporter.py`)
- Validator: checks schema, field types, ID coverage, count consistency
- Reporter: generates color-coded Excel (severity gradients, TP/FP/DUP fills) and markdown summary

### 5. Repository Utilities

- **`core/repo_cloner.py`** — reads URLs from text file, converts HTTPS↔SSH, clones via git with parallel workers (mirrors `--threads` flag)
- **`core/installer.py`** — auto-installs missing CLI tools from GitHub releases to `./bin/` (gitleaks, titus, trufflehog); detect-secrets via pip
- **`core/commit_tracker.py`** — saves latest commit metadata before scanning (repo name, commit hash, author, date, subject) so you can track which revision was already scanned
- **`core/excel_utils.py`** — shared utilities for both deterministic and triage reports (URL building, hyperlinks, sanitization, truncation)

### 6. Main Orchestrator (`main.py`)

High-level flow:
1. Parse CLI args; validate `--repo` / `--clone-urls` / `--out`
2. Auto-install missing tools via `ensure_tools()`
3. Discover repos (single repo or scan subdirectories for `.git` dirs)
4. Clone repos if `--clone-urls` provided
5. Spawn parallel repo scanning (ThreadPoolExecutor with `--threads` workers)
6. For each repo:
   - Save commit info
   - Run 4 tools concurrently (ThreadPoolExecutor with 4 workers per repo)
   - Deduplicate raw findings
   - Generate per-repo aggregated JSON + Excel
7. If multi-repo: generate global aggregated JSON + Excel across all repos
8. Print summary (tool counts, total findings, elapsed time)

Key invariant: `--threads` controls **repo-level** parallelism; tool-level concurrency is always 4 (one per scanner).

### 7. Claude Code Skill (`claude-skill/`)

Main skill file: `scan-secrets.md` (140+ lines of detailed instructions)

Sub-files (read on-demand by skill):
- `triage-rules.md` — TP/FP classification rules and severity matrix
- `deep-analysis.md` — checks for composite vulnerabilities, credential reuse, Docker base64 secrets
- `json-schema.md` — output JSON schema and field validation rules
- `reporting.md` — validator, Excel, and markdown report generation
- `agent-prompt.md` — self-contained prompt for spawning sub-agents on multi-repo jobs

Installer: `install.sh` — copies skill to `~/.claude/commands/scan-secrets.md` + sub-dir, sets `OMNILEAK_HOME` env var in shell profile (bash/zsh/fish).

## Testing Patterns

All tests in `tests/` use mocked data (no external dependencies):

- **`test_deduplicator.py`** — 3-pass algorithm correctness, overlap detection, merge logic
- **`test_parsers.py`** — tool-specific output parsing (Gitleaks JSON, Trufflehog NDJSON, etc.)
- **`test_prefilter.py`** — FP categorization by file path
- **`test_triage_writer.py`** — finding assembly, risk score computation
- **`test_triage_validator.py`** — schema validation, field type checking
- **`test_triage_reporter.py`** — Excel generation and color-coding
- **`test_excel_utils.py`** — URL building, truncation, sanitization
- **`test_repo_cloner.py`** — URL parsing, SSH conversion, list deduplication

Run pytest with `-v` for verbose output. Use `-k <pattern>` to filter by test name.

## Key Conventions & Gotchas

1. **Whitespace normalization is critical** — `_normalize()` strips ALL whitespace (including escaped `\n`) so secrets formatted differently by different tools have the same hash. Without this, the same credential would appear as multiple "unique" findings.

2. **Dedup pass order matters** — Pass 1 (by ID) runs before Pass 2 (by secret) because finding IDs are computed deterministically from normalized secrets; this ensures consistent grouping.

3. **`repo_url` is always passed through** — it's used to build commit hyperlinks in Excel. Resolved once per repo in `main.py` and shared across all scanner instances.

4. **Detect Secrets is file-only** — unlike gitleaks/titus which scan history, it scans current files and enriches with `git blame`. This is a design choice (detection speed vs. history coverage).

5. **Tool CLI names vs. registry keys** — all tool CLI names match their registry keys: `gitleaks`, `trufflehog`, `detect-secrets`, `titus`. Auto-installer uses these strings to dispatch to install functions.

6. **Titus blob→path mapping** — Titus doesn't include file paths in JSON output; paths are resolved via SQLite datastore queries or fallback human-report parsing. If this fails, findings are included with empty `file_path`.

7. **Excel truncation is intentional** — secret values >5000 chars are truncated (marked `[truncated]`) because Excel has a 32,767-char cell limit. Full values always available in JSON.

8. **Multi-repo vs single-repo reporting** — single-repo scans produce only per-repo outputs; multi-repo scans produce both per-repo AND global aggregated files. The main.py logic checks `len(repos) > 1` to decide.

9. **Prefilter is deterministic** — runs before any AI so obvious FPs (lock files, vendor) are eliminated without calling Claude, reducing API costs and dispatch complexity.

10. **Risk score is NOT just severity sum** — it factors in composites (×1.5) and on-disk HIGH/CRITICAL findings (×1.3), capped at 100. See `constants.py` for the formula.

## Configuration Files

- **`pyproject.toml`** — pytest config with `integration` marker for tests requiring external services
- **`requirements.txt`** — pandas, openpyxl, pytest, detect-secrets (pip-installable scanner)
- **`conftest.py`** — minimal (adds project root to sys.path so scanners/core are importable)

## Glossary

- **Omnileak ID** — sha256 hash of `repo|file|secret_normalized`; used to merge findings by location
- **Secret key** — sha256 hash of `repo|secret_normalized`; used to merge findings by secret alone (ignore file)
- **Proximity dedup** — merge findings sharing exact location `(repo, file, line, commit)` when secrets overlap
- **Found by** — list of scanner tool names that detected a finding (merged across tools)
- **Composite vulnerability** — combination of multiple leaked credentials that together expose a service (e.g., leaked AWS key + leaked RDS password)
- **On-disk** — finding exists in the current HEAD revision (vs. only in history)
- **False positive** — finding incorrectly flagged as a secret (e.g., test fixtures, vendor code, lock file hashes)
