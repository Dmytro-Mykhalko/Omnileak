# Secrets Detection Pipeline — Omnileak + AI Triage

Scan git repositories for hard-coded secrets using Omnileak (gitleaks, trufflehog, detect-secrets, titus) followed by AI-powered triage, deep analysis, and reporting.

## Arguments

$ARGUMENTS — optional named flags:

### Mode 1: Full scan (default)

- `--repo <path>` — the git repository to scan. Defaults to the current working directory.
- `--out <path>` — where to write results. Defaults to `<repo>/scanning`.

### Mode 2: Triage existing results

- `--results <path>` — path to an existing Omnileak output directory. **Skips the scan** and jumps to AI triage.
- `--repo <path>` — (optional) path to the git repository. Enables deep analysis. If omitted, deep analysis is skipped.
- `--out <path>` — where to write the triage report. Defaults to the `--results` directory.

All flags are optional and can be combined in any order.

Examples:
```
/scan-secrets                                          # full scan on cwd
/scan-secrets --repo ~/Projects/my-app                 # full scan on a specific repo
/scan-secrets --repo ~/Projects/my-app --out /tmp/out  # full scan, custom output

/scan-secrets --results ./scanning/my-app              # triage existing single-repo results
/scan-secrets --results ./scanning                     # triage existing multi-repo results
/scan-secrets --results ./scanning/my-app --repo ~/Projects/my-app   # triage + deep analysis
```

## Safety

- Do NOT push code, create PRs, or interact with remote services.
- Do NOT upload findings, secrets, or repo content to any external service.
- All output stays local on disk.
- Before starting, ask the user **once**: "This will run the full pipeline without further confirmations. Proceed?" If yes, do NOT ask for any more confirmations for the rest of the pipeline.

## Sub-files

This skill reads detailed instructions from `~/.claude/commands/scan-secrets/`:

| File | Purpose | When loaded |
|---|---|---|
| `triage-rules.md` | TP/FP classification rules, severity matrix | Step 5 |
| `deep-analysis.md` | Composite vulns, credential reuse, Docker base64 | Step 6 |
| `json-schema.md` | Output JSON schema, field rules, risk score, naming | Step 7 |
| `reporting.md` | Markdown report, Excel, validator, improvements | Steps 8-10 |
| `agent-prompt.md` | Standardized prompt for sub-agents in multi-repo mode | Multi-repo dispatch |

## Instructions

Execute this pipeline in strict order. Do NOT skip steps.

### Step 1: Determine Mode

Parse `$ARGUMENTS` for `--results`, `--repo`, and `--out`.

- If `--results` is provided → **Triage mode** (skip Steps 2-3, go to Step 4).
- Otherwise → **Full scan mode** (start at Step 2).

### Step 2: Resolve Omnileak Location (full scan only)

Find Omnileak's `main.py`. Check in this order:
1. Environment variable `$OMNILEAK_HOME` (e.g., `$OMNILEAK_HOME/main.py`)
2. `~/Tools/Omnileak/main.py`
3. `~/Omnileak/main.py`
4. `./Omnileak/main.py` (relative to cwd)

Run `ls` to verify the path exists. If none found, tell the user:
> Omnileak not found. Install it: `git clone https://github.com/Dmytro-Mykhalko/Omnileak.git` and set `export OMNILEAK_HOME=/path/to/Omnileak` or run `./Omnileak/claude-skill/install.sh`.

Stop if not found.

### Step 3: Run Omnileak (full scan only)

Resolve paths:
- **Repo path**: `--repo` value or cwd (verify `.git` directory exists)
- **Output directory**: `--out` value or `<repo>/scanning`
- **Repo name**: basename of the repo path

```bash
python3 <omnileak_path>/main.py --repo <repo_path> --out <output_directory>
```

Must run to completion. If it fails, report the error and stop.

### Step 4: Locate Results + Pre-filter

**Full scan mode:** find the aggregated JSON at:
`<output_directory>/<repo_name>/<repo_name>_aggregated_secrets.json`

**Triage mode:** search the `--results` directory:
```bash
find <results_path> -name "*_aggregated_secrets.json" -o -name "global_aggregated_secrets.json"
```

If no aggregated JSON found, tell the user and stop.

**Determine repo count.** If multiple aggregated JSONs found → multi-repo mode. If one → single-repo mode.

**For each repo's aggregated JSON, run the deterministic pre-filter:**
```bash
cd <omnileak_path> && python3 -m core.ai.prefilter <aggregated_json> --out <output_dir>/prefiltered.json
```

This auto-classifies obvious FPs (lock files, vendor code, minified JS) without using AI. Note the summary counts.

### Step 5: Dispatch — Single vs. Multi-repo

#### Single-repo: inline triage

For a single repo, proceed through Steps 5a-11 inline:

**5a.** Read `~/.claude/commands/scan-secrets/triage-rules.md` → classify the `needs_triage` findings from the pre-filter output.

**5b.** If repo path available, read `~/.claude/commands/scan-secrets/deep-analysis.md` → perform deep analysis.

**5c.** Read `~/.claude/commands/scan-secrets/json-schema.md` → write the triage JSON with ALL findings (AI-classified + auto-FPs + duplicates).

**5d.** Validate and generate Excel:
```bash
cd <omnileak_path> && python3 -m core.ai.triage_validator <json_path> --raw <aggregated_json>
cd <omnileak_path> && python3 -m core.ai.triage_reporter <json_path>
```

**5e.** Read `~/.claude/commands/scan-secrets/reporting.md` → write markdown report + pipeline improvements.

**5f.** Print summary: mode, risk score, TP/FP/DUP counts with severity breakdown, file paths.

#### Multi-repo: tiered dispatch

Classify each repo after pre-filtering:

| Tier | Condition | Strategy |
|---|---|---|
| **Skip** | 0 findings after pre-filter | Generate template output inline (risk=0, all FP) — no agent |
| **Lightweight** | 1-20 findings | Spawn agent with `agent-prompt.md` |
| **Standard** | 21-200 findings | Spawn agent with `agent-prompt.md` |
| **Large** | 200+ findings | Spawn agent with `agent-prompt.md` + batch instructions |

**For Skip tier:** Write a minimal triage JSON with all findings as auto-FP, risk_score=0. Run Excel generation. No deep analysis needed.

**For all other tiers:** Read `~/.claude/commands/scan-secrets/agent-prompt.md`. For each repo, replace the `{{placeholders}}` with actual values and spawn an agent. Run agents in parallel when possible.

**After all agents complete, run post-processing for each repo:**
```bash
cd <omnileak_path> && python3 -m core.ai.triage_validator <json_path> --raw <aggregated_json>
cd <omnileak_path> && python3 -m core.ai.triage_reporter <json_path>
```

**Print batch summary:** total repos, per-tier breakdown, aggregate risk, paths.
