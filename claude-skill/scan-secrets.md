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

### Mode 3: Resume / Retry

- `--resume <manifest.json>` — resume an interrupted multi-repo triage from the manifest. Recovers stale repos (in_progress > 10 min) back to pending, then continues from the first pending repo.
- `--retry <repo1,repo2>` — retry specific failed repos from an existing manifest. Requires `--resume` to specify the manifest path.

All flags are optional and can be combined in any order.

Examples:
```
/scan-secrets                                          # full scan on cwd
/scan-secrets --repo ~/Projects/my-app                 # full scan on a specific repo
/scan-secrets --repo ~/Projects/my-app --out /tmp/out  # full scan, custom output

/scan-secrets --results ./scanning/my-app              # triage existing single-repo results
/scan-secrets --results ./scanning                     # triage existing multi-repo results
/scan-secrets --results ./scanning/my-app --repo ~/Projects/my-app   # triage + deep analysis

/scan-secrets --resume ./scanning/manifest.json        # resume interrupted multi-repo triage
/scan-secrets --resume ./scanning/manifest.json --retry repo-a,repo-b  # retry specific repos
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
| `triage-rules.md` | TP/FP classification rules, severity matrix | Step 5a (triage) |
| `deep-analysis.md` | Composite vulns, credential reuse, Docker base64 | Step 5b (deep analysis) |
| `json-schema.md` | Output JSON schema, field rules, risk score, naming | Step 5c (JSON output) |
| `reporting.md` | Validator, Excel, markdown report, improvements | Steps 5d-5e (reports) |
| `manifest-schema.md` | Manifest format for resumable multi-repo | Multi-repo dispatch |
| `agent-prompt.md` | Self-contained prompt for sub-agents (legacy, see iterative loop) | Reference only |

## Instructions

Execute this pipeline in strict order. Do NOT skip steps.

### Step 1: Determine Mode

Parse `$ARGUMENTS` for `--results`, `--repo`, `--out`, `--resume`, and `--retry`.

- If `--resume` is provided → **Resume mode**:
  1. Load the manifest: read the JSON file at the `--resume` path.
  2. Recover stale repos (in_progress > 10 min back to pending):
     ```bash
     cd <omnileak_path> && python3 -c "
     from core.ai.manifest import recover_stale
     recovered = recover_stale('<manifest_path>')
     print(f'Recovered {len(recovered)} stale repo(s): {recovered}')
     "
     ```
  3. If `--retry` is also provided, reset each named repo to pending:
     ```bash
     cd <omnileak_path> && python3 -c "
     from core.ai.manifest import update_repo
     for name in '<repo1>,<repo2>'.split(','):
         update_repo('<manifest_path>', name.strip(), status='pending', error=None)
         print(f'Reset {name.strip()} to pending')
     "
     ```
  4. Go to Step 5.1 (iterative loop) — skip Step 5.0 since the manifest already exists.
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
cd <omnileak_path> && python3 -m core.ai.prefilter <aggregated_json> --out <repo_output_dir>/prefiltered.json
```

Where `<repo_output_dir>` is the per-repo output directory (e.g. `<output_dir>/<repo_name>/`).

This auto-classifies obvious FPs (lock files, vendor code, minified JS) without using AI. Note the summary counts.

### Step 5: Dispatch — Single vs. Multi-repo

#### Single-repo: inline triage

For a single repo, proceed through Steps 5a-5f inline:

**5a. Triage.** Read `~/.claude/commands/scan-secrets/triage-rules.md`. Deduplicate the `needs_triage` findings (group same secret across commits/tools → one primary + DUPLICATEs). Classify each as TP or FP. If more than 200 findings, work in batches of 200.

**5b. Deep analysis.** If repo path available, read `~/.claude/commands/scan-secrets/deep-analysis.md` → perform checks against actual source files.

**5c. Write JSON.** Read `~/.claude/commands/scan-secrets/json-schema.md` → write the triage JSON with ALL findings (AI-classified TPs/FPs + auto-FPs from pre-filter + DUPs). Total count must match raw Omnileak count.

**5d. Validate + Excel.** Run validation first, then generate Excel:
```bash
cd <omnileak_path> && python3 -m core.ai.triage_validator <json_path> --raw <aggregated_json>
cd <omnileak_path> && python3 -m core.ai.triage_reporter <json_path>
```
If validation fails, fix the JSON and re-validate.

**5e. Reports.** Read `~/.claude/commands/scan-secrets/reporting.md` → write markdown triage report + pipeline improvements.

**5f. Summary.** Print: mode, risk score, TP/FP/DUP counts with severity breakdown, file paths.

#### Multi-repo: iterative loop with manifest

**One agent processes repos sequentially, one at a time.** No parallel sub-agent dispatch. This keeps classification rules in fresh context and enables resumption.

##### Step 5.0: Create manifest

**Skip this step if resuming** (manifest already exists).

Step 4 already ran per-repo pre-filters. Do NOT re-run them. Build the manifest from the existing `prefiltered.json` files:

Read `~/.claude/commands/scan-secrets/manifest-schema.md` to understand the format. Create the manifest:
```bash
cd <omnileak_path> && python3 -c "
from core.ai.prefilter import prefilter_batch
from core.ai.manifest import create_manifest
results = prefilter_batch('<output_directory>')
manifest = create_manifest(results, '<output_directory>')
print(f'Created manifest: {manifest[\"path\"]} ({manifest[\"total_repos\"]} repos)')
"
```

Note: `prefilter_batch` is idempotent — if `prefiltered.json` files already exist from Step 4, this overwrites them with identical content. The main purpose here is to collect the summaries into a manifest.

##### Step 5.1: Iterative loop

**FOR each repo in the manifest (priority order), while next_pending returns a repo:**

At the **start of EVERY iteration**, re-read these files to keep rules in fresh context:
1. Read `~/.claude/commands/scan-secrets/triage-rules.md`
2. Read `~/.claude/commands/scan-secrets/json-schema.md`

Then execute these sub-steps:

**a. Update manifest → in_progress**
```bash
cd <omnileak_path> && python3 -c "
from core.ai.manifest import update_repo
from datetime import datetime, timezone
update_repo('<manifest_path>', '<repo_name>', status='in_progress',
            started_at=datetime.now(timezone.utc).isoformat())
"
```

Print status: `[<completed+1>/<total>] <repo_name> — reading pre-filtered findings (<N> to triage)...`

**b. Read pre-filtered findings**

Read this repo's `prefiltered.json`. Note `needs_triage` count.

**c. Skip-tier handling**

If `needs_triage` is 0: write a triage JSON with ALL raw findings as `FALSE_POSITIVE` (using auto-FP categories from the pre-filter). Every finding must have `fp_reason` starting with `"Auto-filtered: "`. These must appear in the Excel. Set risk_score=0. Skip to step (h).

**d. Classify findings**

Print status: `[<completed+1>/<total>] <repo_name> — classifying findings...`

Deduplicate `needs_triage` findings (group same secret across commits/tools → one primary + DUPLICATEs). Classify each as TP or FP using the rules read in step 5.1. If more than 200 findings, work in batches of 200.

**e. Deep analysis**

Print status: `[<completed+1>/<total>] <repo_name> — deep analysis...`

If repo path is available, read `~/.claude/commands/scan-secrets/deep-analysis.md` and perform checks against actual source files.

**f. Write triage JSON**

Print status: `[<completed+1>/<total>] <repo_name> — writing triage JSON...`

Write the complete triage JSON with ALL findings: AI-classified TPs/FPs + auto-FPs from pre-filter + DUPs. Total count must equal raw Omnileak count.

**g. Validate (HARD GATE)**

Print status: `[<completed+1>/<total>] <repo_name> — validating...`

```bash
cd <omnileak_path> && python3 -m core.ai.triage_validator <json_path> --raw <aggregated_json>
```

- If validation **passes** → continue to step (h).
- If validation **fails** → fix the JSON → re-validate (max 2 retries).
- If still failing after 2 retries → update manifest status to `"failed"` with the error message → move to next repo. **Never skip validation. Never continue on failure without marking it.**

**h. Excel + markdown reports**

Print status: `[<completed+1>/<total>] <repo_name> — generating Excel + reports...`

```bash
cd <omnileak_path> && python3 -m core.ai.triage_reporter <json_path>
```

Read `~/.claude/commands/scan-secrets/reporting.md` → write markdown triage report + pipeline improvements.

**i. Update manifest → done**

```bash
cd <omnileak_path> && python3 -c "
from core.ai.manifest import update_repo
from datetime import datetime, timezone
update_repo('<manifest_path>', '<repo_name>', status='done',
            risk_score=<score>, tps=<n>, fps=<n>, dups=<n>,
            validated=True, triage_json='<json_path>',
            duration_s=<elapsed>, completed_at=datetime.now(timezone.utc).isoformat())
"
```

**j. Print progress line**

After completing a repo, print:
```
[<completed>/<total>] <repo_name> | risk=<score> | TP=<n> FP=<n> DUP=<n> | validated=<bool> | <duration>s
```

##### Step 5.2: Batch summary

After the loop completes, print:
- Total repos processed, completed, failed
- Per-tier breakdown
- Aggregate risk across all repos
- Paths to manifest and output files
