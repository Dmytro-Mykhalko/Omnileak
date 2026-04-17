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

## Critical Guardrails

- **NEVER delegate classification to a batch script.** Do not write Python (or any) scripts to `/tmp/`, the repo, or the output directory that classify findings in bulk. Every finding's verdict must come from reading the actual `secret_value` and source file — not from substring patterns in a script. The ONLY scripts allowed to run are Omnileak's built-in tools: `core.ai.prefilter`, `core.ai.triage_writer`, `core.ai.triage_validator`, `core.ai.triage_reporter`, `core.ai.manifest`. Short inline `python3 -c "..."` / heredocs that *inspect* data (counts, filters for display) are fine; anything producing classifications is not.
- **Volume is not an excuse.** Hundreds of `needs_triage` findings feel tedious, but they are not a reason to write a classifier. Work through inline batches of 200. A substring-rule script misses the TP-bias and per-file context this pipeline depends on — the output will look structurally correct and be substantively wrong.
- **Final JSON is assembled by `triage_writer`, not hand-written.** The agent emits a compact `classifications.json` (verdicts only) and calls `python3 -m core.ai.triage_writer`. The writer stamps `meta.assembled_by="triage_writer/v1"`; the validator rejects anything without it.
- **NEVER classify by secret_type alone.** The scanner's `secret_type` field (e.g. "Secret Keyword", "generic-api-key") is a detection rule name, not a verdict. You MUST examine the actual `secret_value` to decide TP vs FP. A "Secret Keyword" finding with value `password: "Xy9kL2mN4pQ7rT0wBcDfGhJv"` is a TP; one with value `password_field: password` is an FP.
- **Read source files during classification, not after.** When a repo path is available, verify each finding by reading the actual file. This is part of classification, not a separate "deep analysis" afterthought.

## Sub-files

This skill reads detailed instructions from `~/.claude/commands/scan-secrets/`:

| File | Purpose | When loaded |
|---|---|---|
| `triage-rules.md` | TP/FP classification rules, severity matrix | Step 5a (triage) |
| `deep-analysis.md` | Composite vulns, credential reuse, Docker base64 | Step 5b (deep analysis) |
| `json-schema.md` | Output JSON schema, field rules, risk score, naming | Step 5c (JSON output) |
| `reporting.md` | Validator, Excel, markdown report, batch improvements | Steps 5d-5e / 5.2 |
| `manifest-schema.md` | Manifest format for resumable multi-repo | Multi-repo dispatch |
| `agent-prompt.md` | Self-contained prompt for per-repo sub-agents | Multi-repo Step 5.1c |

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

**5a. Classify with source verification.** Read `~/.claude/commands/scan-secrets/triage-rules.md`. Deduplicate the `needs_triage` findings (group same secret across commits/tools → one primary + DUPLICATEs). For each finding:
1. **Read the pre-filter enrichment** — check `tp_hint`, `high_entropy`, `sensitivity`, `decoded_docker_creds` fields. These guide your classification but don't decide it.
2. **Examine the actual secret_value** — not just the secret_type. High-entropy strings (entropy >= 4.0, length >= 20) in infrastructure/production files are almost always real.
3. **If repo path available**: read the source file to verify the value in context, check on_disk status, determine environment from the actual file structure.
4. Classify as TP or FP based on the value, not the type name.

If more than 200 findings, work in batches of 200.

**5b. Cross-file deep analysis.** If repo path available, read `~/.claude/commands/scan-secrets/deep-analysis.md` → check for composite vulnerabilities, credential reuse across environments, Docker base64 decoding (use `decoded_docker_creds` if the pre-filter already decoded it), and secrets in files tools typically miss (.sql dumps, .dist files, CI workflows).

**5c. Emit compact classifications, then assemble with triage_writer.** Do NOT hand-write the full triage-results JSON. Write a small `<repo_output_dir>/classifications.json` with your verdicts only (schema in `json-schema.md` under "Compact classifications"), then run:

```bash
cd <omnileak_path> && python3 -m core.ai.triage_writer \
  --raw <aggregated_json> \
  --classifications <repo_output_dir>/classifications.json \
  --prefilter <repo_output_dir>/prefiltered.json \
  --repo <repo_name> \
  --repo-url <repo_url> \
  --last-commit <commit_hash> \
  --out <repo_output_dir>
```

This assembles `<repo_name>_triage-results_<risk_score>.json` with auto-FPs merged in, risk score computed, and `meta.assembled_by` stamped. Capture `<risk_score>` from the filename for Step 5d/5e.

**5d. Validate + Excel.** Run validation first, then generate Excel:
```bash
cd <omnileak_path> && python3 -m core.ai.triage_validator <json_path> --raw <aggregated_json>
cd <omnileak_path> && python3 -m core.ai.triage_reporter <json_path>
```
If validation fails, fix the JSON and re-validate.

**5e. Reports.** Read `~/.claude/commands/scan-secrets/reporting.md` → write the per-repo markdown triage report and one pipeline improvements report.

**5f. Summary.** Print: mode, risk score, TP/FP/DUP counts with severity breakdown, file paths.

#### Multi-repo: sequential sub-agent dispatch

**Each repo is triaged by a fresh sub-agent with clean context.** This prevents context accumulation across repos — agent quality stays constant whether it's repo 1 or repo 39. The orchestrator (this conversation) stays lightweight: it only manages the manifest and dispatches agents.

##### Step 5.0: Create manifest

**Skip this step if resuming** (manifest already exists).

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

##### Step 5.1: Sequential dispatch loop

**FOR each repo in the manifest (priority order), while pending repos remain:**

**a. Pick next repo + update manifest**

```bash
cd <omnileak_path> && python3 -c "
from core.ai.manifest import load_manifest, next_pending, update_repo
from datetime import datetime, timezone
m = load_manifest('<manifest_path>')
repo = next_pending(m)
if repo:
    update_repo(m['path'], repo['name'], status='in_progress',
                started_at=datetime.now(timezone.utc).isoformat())
    print(f'Next: {repo[\"name\"]} (tier={repo[\"tier\"]}, needs_triage={repo[\"raw_findings\"] - repo[\"pre_filtered\"]})')
else:
    print('ALL_DONE')
"
```

If `ALL_DONE` → go to Step 5.2.

**b. Skip-tier handling**

If `needs_triage` is 0 (skip tier): handle inline — do NOT spawn an agent and do NOT hand-write the JSON. Assemble via `triage_writer` with an empty classifications file; the writer pulls every auto-FP from the pre-filter:

```bash
echo '{"findings": [], "composite_vulnerabilities": []}' > <repo_output_dir>/classifications.json
cd <omnileak_path> && python3 -m core.ai.triage_writer \
  --raw <aggregated_json> \
  --classifications <repo_output_dir>/classifications.json \
  --prefilter <repo_output_dir>/prefiltered.json \
  --repo <repo_name> \
  --repo-url <repo_url> \
  --last-commit <commit_hash> \
  --out <repo_output_dir>
```

Then run `core.ai.triage_validator` and `core.ai.triage_reporter` on the output, update the manifest to `done`, print the progress line.

**c. Spawn sub-agent**

Read `~/.claude/commands/scan-secrets/agent-prompt.md`. Replace all `{{placeholders}}` with the actual values for this repo. Spawn the agent:

```
Agent({
  description: "Triage <repo_name>",
  prompt: "<filled agent-prompt.md content>"
})
```

**Important:** Spawn ONE agent at a time. Wait for it to complete before starting the next. This ensures each agent gets a fresh, clean context — no accumulated findings from other repos.

**d. Handle agent result**

When the agent completes:
- If it produced a valid triage JSON → update manifest to `done` with risk_score, tps, fps, dups, duration
- If it failed → update manifest to `failed` with the error message

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

**e. Print progress line**

```
[<completed>/<total>] <repo_name> | risk=<score> | TP=<n> FP=<n> DUP=<n> | validated=<bool> | <duration>s
```

**f. Loop back** to step (a) for the next repo.

##### Step 5.2: Pipeline improvements (once for entire scan)

After all repos are done, read `~/.claude/commands/scan-secrets/reporting.md` and write **one** `<output_directory>/pipeline-improvements.md` covering all repos. Aggregate patterns — do not repeat per-repo observations.

##### Step 5.3: Batch summary

Print:
- Total repos processed, completed, failed
- Per-tier breakdown
- Aggregate risk across all repos
- Paths to manifest, improvements report, and output files
