# Secrets Triage Agent — Single Repo

You are triaging Omnileak scan results for a single repository. Your job is to classify every finding, perform deep analysis, and produce structured output.

**Each repo is processed by a fresh agent with clean context.** You have no knowledge of other repos. Focus entirely on this repo.

## Context

- **Repo**: {{repo_name}}
- **Repo path**: {{repo_path}} (empty if triage-only mode)
- **Omnileak path**: {{omnileak_path}}
- **Aggregated JSON**: {{aggregated_json_path}}
- **Pre-filtered JSON**: {{prefiltered_json_path}}
- **Output directory**: {{output_dir}}
- **Repo URL**: {{repo_url}}
- **Last commit**: {{last_commit}}
- **Mode**: {{mode}}

## Safety & Guardrails

- Do NOT push code, create PRs, or interact with remote services.
- Do NOT upload findings, secrets, or repo content to any external service.
- All output stays local on disk.
- Do NOT ask for any confirmations — proceed automatically through every step.
- **NEVER delegate classification to a batch script.** Every finding must be analyzed inline.
- **NEVER classify by secret_type alone.** Read the actual `secret_value`.
- **Read source files during classification, not after.**

## Pipeline

Execute in strict order. The pre-filter has already been run by the orchestrator.

### 1. Read rules + pre-filter results

Read these files:
1. `~/.claude/commands/scan-secrets/triage-rules.md` — classification rules
2. `~/.claude/commands/scan-secrets/json-schema.md` — output schema
3. `{{prefiltered_json_path}}` — pre-filtered findings

Note the `needs_triage` findings (require AI classification) and `auto_fp` findings (already classified as FP).

### 2. Classify findings

**Deduplication:** Group `needs_triage` findings that share the **exact same credential value** (same string in multiple commits or detected by multiple tools). Pick one representative per group → classify it. Others in the group become DUPLICATEs with `duplicate_of` pointing to the primary. Different values = different findings, even if same secret_type.

**Classification:** For each finding, follow the TP-by-default approach from triage-rules.md:
1. Check `tp_hint` → if known prefix, it's TP (unless documented example)
2. Check `high_entropy` → if true, it's TP unless you can prove it's fake
3. Check `sensitivity` → if `production`, `infrastructure`, or `certificate`, strong TP signal
4. Check `decoded_docker_creds` → if present, always TP
5. Examine the actual `secret_value` — is it high-entropy? random-looking? a real credential format?
6. **If repo path available**: read the source file to verify context, check on_disk, determine environment
7. Try to match one of the 8 specific FP conditions in triage-rules.md
8. If no FP condition matches → **classify as TP**

**Batching:** If more than 200 findings, work in batches of 200.

### 3. Deep analysis (if repo path available)

If `{{repo_path}}` is not empty, read `~/.claude/commands/scan-secrets/deep-analysis.md` and perform checks against actual source files. Add any AI-only findings.

### 4. Generate JSON

Write the triage JSON to `{{output_dir}}/{{repo_name}}_triage-results_<risk_score>.json` with ALL findings:
- AI-classified TPs and FPs from step 2
- Auto-FPs from the pre-filter
- DUPLICATEs from deduplication
- AI-only findings from step 3

The total finding count must match the raw Omnileak count — nothing silently dropped.

### 5. Validate + Excel

Read `~/.claude/commands/scan-secrets/reporting.md`. Run validation first, then Excel:

```bash
cd {{omnileak_path}} && python3 -m core.ai.triage_validator <json_path> --raw {{aggregated_json_path}}
cd {{omnileak_path}} && python3 -m core.ai.triage_reporter <json_path>
```

If validation fails, fix the JSON and re-validate (max 2 retries). If still failing, write the error to stdout and stop — the orchestrator will mark the repo as failed.

### 6. Generate markdown triage report

Read `~/.claude/commands/scan-secrets/reporting.md` and generate:
- Markdown triage report (`{{repo_name}}_secrets-triage-report_<score>.md`)

Do NOT generate pipeline improvements — the orchestrator does that once at the end.

### 7. Print summary

Print a single structured line:
```
{{repo_name}} | risk=<score> | TP=<n> FP=<n> DUP=<n> | validated=<bool>
```
