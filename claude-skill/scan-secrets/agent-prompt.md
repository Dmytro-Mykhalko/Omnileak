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
- **NEVER delegate classification to a batch script.** Do not write Python (or any) scripts to `/tmp/`, the repo, or the output directory that classify findings in bulk. Every finding's verdict must come from you reading the actual `secret_value` and, when a repo path is available, the source file. The ONLY scripts allowed to run are Omnileak's built-in tools: `core.ai.prefilter`, `core.ai.triage_writer`, `core.ai.triage_validator`, `core.ai.triage_reporter`, `core.ai.manifest`. Short inline `python3 -c "..."` / heredocs that *inspect* data (counting, filtering for display, checking on_disk) are fine; anything that produces classifications is not.
- **Volume is not an excuse.** If the repo has hundreds of `needs_triage` findings and you're tempted to write a classifier script: don't. Work through inline batches of 200 (see Step 2). Short sessions with fewer findings per batch beat one big script every time — the script's substring rules will miss the TP-bias and source-file reads the pipeline depends on.
- **NEVER classify by secret_type alone.** Read the actual `secret_value`.
- **Read source files during classification, not after.**
- **Assemble the final JSON with `triage_writer`, not by hand.** The validator rejects any triage JSON whose `meta.assembled_by` is not `"triage_writer/v1"` (see Step 4).

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

**Batching:** If more than 200 findings, work in batches of 200 — classify each batch inline, appending to your in-memory list of verdicts, then write them all to `classifications.json` in Step 4. Do not write a script to process batches; process them in conversation one batch at a time. Reading every `secret_value` and (when possible) source file is the point — a substring-rule script defeats the whole pipeline.

### 3. Deep analysis (if repo path available)

If `{{repo_path}}` is not empty, read `~/.claude/commands/scan-secrets/deep-analysis.md` and perform checks against actual source files. Add any AI-only findings.

### 4. Emit compact classifications, then assemble with triage_writer

**Do not hand-write the full triage-results JSON.** Emit a small `classifications.json` containing only your verdicts + composites, then let `triage_writer` assemble the full output (it copies raw fields, fills defaults, computes risk score, stamps `meta.assembled_by`).

**4a. Write `{{output_dir}}/classifications.json`** with this schema:

```json
{
  "findings": [
    {
      "omnileak_ids": ["<raw_id_1>", "<raw_id_2>"],
      "classification": "TRUE_POSITIVE",
      "severity": "CRITICAL",
      "category": "AWS Access Key",
      "on_disk": true,
      "confidence": "high",
      "environment": "production",
      "remediation": "ROTATE_IMMEDIATELY",
      "effort": "quick",
      "fp_reason": null,
      "duplicate_of": null
    }
  ],
  "composite_vulnerabilities": [ /* from Step 3, if any */ ]
}
```

Rules:
- One entry per *distinct credential*. Group raw IDs that share the same secret value into one entry's `omnileak_ids`.
- For `FALSE_POSITIVE`: set `severity`, `confidence`, `environment`, `remediation`, `effort` to `null`; fill `fp_reason`.
- For `DUPLICATE`: list only the duplicate's raw ID in `omnileak_ids`; set `duplicate_of` to the primary's *sequential id-to-be* (1-based, matching the order of your TP/FP entries).
- Do NOT include auto-FP findings from the pre-filter here — `triage_writer` pulls those from `{{prefiltered_json_path}}` directly.
- Any raw ID you don't list ends up as a DUPLICATE with no primary. The validator will fail if IDs aren't covered, so verify every `needs_triage` ID is in exactly one entry.

**4b. Run `triage_writer`:**

```bash
cd {{omnileak_path}} && python3 -m core.ai.triage_writer \
  --raw {{aggregated_json_path}} \
  --classifications {{output_dir}}/classifications.json \
  --prefilter {{prefiltered_json_path}} \
  --repo {{repo_name}} \
  --repo-url {{repo_url}} \
  --last-commit {{last_commit}} \
  --out {{output_dir}}
```

It prints the output path: `{{output_dir}}/{{repo_name}}_triage-results_<risk_score>.json`. Capture `<risk_score>` from the filename — you need it for Step 6. The writer stamps `meta.assembled_by="triage_writer/v1"`; the validator in Step 5 checks this.

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
