# Secrets Detection Pipeline — Omnileak + AI Triage

Scan the current repository for hard-coded secrets using Omnileak (deterministic tools: gitleaks, trufflehog, detect-secrets, titus) followed by AI-powered triage, deep analysis, and reporting.

## Arguments

$ARGUMENTS — optional named flags:

### Mode 1: Full scan (default)

- `--repo <path>` — the git repository to scan. Defaults to the current working directory.
- `--out <path>` — where to write results. Defaults to `<repo>/scanning`.

### Mode 2: Triage existing results

- `--results <path>` — path to an existing Omnileak output directory. **Skips the scan entirely** and jumps straight to AI triage.
- `--repo <path>` — (optional) path to the git repository. Enables deep analysis (Step 6) by reading actual repo files. If omitted, deep analysis is skipped.
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
> Omnileak not found. Install it: `git clone https://github.com/Dmytro-Mykhalko/Omnileak.git` and either set `export OMNILEAK_HOME=/path/to/Omnileak` or install the skill with `./Omnileak/claude-skill/install.sh`.

Stop if not found.

### Step 3: Run Omnileak (full scan only)

Resolve paths:
- **Repo path**: `--repo` value or cwd (verify it has a `.git` directory; if not, stop and tell the user)
- **Output directory**: `--out` value or `<repo>/scanning`
- **Repo name**: basename of the repo path

Run the deterministic scan:

```bash
python3 <omnileak_path>/main.py \
  --repo <repo_path> \
  --out <output_directory>
```

This must run to completion. Monitor the output. If it fails, report the error and stop.

### Step 4: Locate and Read Results

**Full scan mode:** find the aggregated JSON at:
`<output_directory>/<repo_name>/<repo_name>_aggregated_secrets.json`

**Triage mode:** search the `--results` directory for aggregated JSON files. Use `find` to locate them:

```bash
find <results_path> -name "*_aggregated_secrets.json" -o -name "global_aggregated_secrets.json"
```

Omnileak output follows these patterns:
- Single repo: `<dir>/<repo_name>_aggregated_secrets.json` (the `--results` path is the repo subfolder)
- Multi repo: `<dir>/global_aggregated_secrets.json` at the top level, plus per-repo files in subdirectories

If no aggregated JSON is found, tell the user the path doesn't contain Omnileak results and stop.

Resolve the **output directory** for the triage report: `--out` value, or the `--results` directory itself.

Read all found aggregated JSON files. Note the total finding count.

### Step 5: AI Triage — Classify Each Finding

#### 5a: Deduplicate — Keep One, Mark the Rest

Group findings that represent the **same logical secret** — the same credential value appearing in multiple commits, or detected by multiple tools in the same file.

- Pick **one** representative finding per group → classify it as `TRUE_POSITIVE` or `FALSE_POSITIVE` normally. Track all original `id` values in its `omnileak_ids`.
- For **every other** entry in the group, emit a separate finding with `"classification": "DUPLICATE"` and set `"duplicate_of": <id of the primary finding>`. Copy severity/environment/etc. from the primary. This ensures the total finding count in the JSON matches the raw Omnileak count — nothing is silently dropped.

#### 5b: Handle Large Result Sets

If the aggregated JSON has **more than 200 findings**, work in batches:
1. Read the first batch (up to 200 entries)
2. Triage that batch
3. Read the next batch, and so on
4. Merge results at the end

Do NOT try to read the entire file into a single prompt if it's very large.

#### 5c: Classify Each Finding

For every deduplicated finding, classify as TRUE POSITIVE or FALSE POSITIVE.

**TRUE POSITIVE** (real secret) — flag if:
- API key, token, password, private key, or credential with a real non-placeholder value
- Connection string with embedded real credentials (not `!ChangeMe!` or `db_password`)
- Hard-coded secret in source code, config, migration, env, or infrastructure files
- Secret in git history (deleted from disk but recoverable — still needs rotation)

**FALSE POSITIVE** (not a real secret) — discard if:
- In `vendor/`, `node_modules/`, or third-party library code:
  - Translation files (`password => 'Jelszó'`, `password => 'Пароль'`)
  - SDK/API schema definitions (`SecretKey`, `SecretArn`, `SecretToken` as parameter names)
  - Third-party test fixtures (`password => '123456'`)
  - Bundled frontend JS (`public/bundles/`)
- Code pattern, not a credential:
  - `password_parameter: password` (form field name)
  - `const PRIVATE_KEY = 'privateKey'` (string constant, not an actual key)
  - `$password = 'password'` in test files (mock value)
- Comment or documentation example (`# db_user:db_password@localhost`)
- YAML/JSON key name containing "secret"/"password" but with no real value attached
- GitHub Actions section headers (`secrets: |`) or vault path names (`SECRET_NAME: app-name`)
- Connection strings without real credentials (JDBC URL, no embedded password)
- Coveralls badge URLs, CI status image links
- Base64 strings that are test expected output, not credentials
- Regex patterns or type definitions containing the word "secret"
- Helm chart `existingSecret: <name>` references where the value is a simple resource name (no high-entropy string) — this is a Kubernetes secret reference, not a credential itself

**Tool-specific FP patterns** — be extra skeptical of:
- **Trufflehog**: high-entropy strings in minified JS, base64-encoded non-secrets, hex color codes
- **Detect-secrets**: keyword-only matches (`password_field`, `secret_name`) with no actual value
- **Gitleaks**: generic regex hits on words like `key`, `token` in comments or docs
- **Titus**: wide-net rules that match config scaffolding or template placeholders

#### 5d: Assign Confidence

For each TRUE POSITIVE, assign a confidence level:
- `high` — clearly a real secret (valid format, non-placeholder value, sensitive context)
- `medium` — likely real but can't fully confirm without testing (e.g. could be expired, could be an internal-only key)
- `low` — suspicious but ambiguous (e.g. long random string with no clear type)

#### 5e: Verify On-Disk Status

For each TRUE POSITIVE, check whether the secret is **currently on disk** (not just in git history):

```bash
# Check if the file still exists at the reported path
ls <repo_path>/<file_path>
# If it exists, grep for the secret value in that file
grep -F "<secret_value_snippet>" <repo_path>/<file_path>
```

- If the file exists AND contains the secret → `on_disk: true`
- If the file is gone or the secret was removed → `on_disk: false` (history-only)
- If no repo path available (triage mode without `--repo`) → `on_disk: "unknown"`

#### 5f: Severity Rubric

Assign severity based on the **environment** and **secret type**. Use this matrix:

| Environment     | API Key/Token | Private Key | Password | Infra Hostname |
|-----------------|---------------|-------------|----------|----------------|
| Production      | CRITICAL      | CRITICAL    | CRITICAL | HIGH           |
| Staging         | HIGH          | HIGH        | MEDIUM   | MEDIUM         |
| Local/Dev       | MEDIUM        | MEDIUM      | LOW      | LOW            |
| Test fixture    | LOW           | LOW         | FP       | FP             |
| Vendor code     | FP            | FP          | FP       | FP             |

Determine environment from context: file path (e.g. `docker/`, `.env.local`, `test/`), env branching in code (`if getenv('APP_ENV')`), variable names (`PROD_`, `STAGING_`), config structure. When ambiguous, assume the higher severity.

### Step 6: AI Deep Analysis — Catch What Tools Miss

> **Triage mode without `--repo`:** If no repo path is available (triage mode with no `--repo` flag), skip this step entirely — deep analysis requires access to the actual source files.

After triaging, perform additional analysis by reading repo files directly:

1. **Composite vulnerabilities**: Look for encrypted keys whose passphrases are committed in other files. Look for private key files whose App IDs / Installation IDs are in config files. Look for encryption code that derives keys from committed secrets.

2. **Non-pattern secrets**: Read config/YAML/parameters files for identifiers (App IDs, numeric IDs, internal URLs, hostnames) that are sensitive in context of other committed credentials.

3. **Severity by code context**: For secrets in migration files or code with environment branching (`if getenv('APP_ENV')`) — determine which branch is production vs staging vs local and classify severity accordingly. Production credentials = CRITICAL. Staging = HIGH. Local/dev = MEDIUM.

4. **Password / credential reuse across environments**: Compare secret values across different environment config files (e.g. `dev.yml` vs `staging.yml` vs `production.yml`). Identical credentials shared between environments is a composite vulnerability — if one environment is compromised, all others using the same credential are too. Flag each reuse pair.

5. **Files tools typically miss**: `.sql` dump files, `.dist`/`.example` files, service-specific config subdirectories (centrifugo, nginx, etc.), IDE configs in git history (`.idea/`), CI workflow files.

6. **Docker credential base64 decoding**: When a Kubernetes `dockerconfigjson` secret or `.dockercfg` is found (typically a base64 blob), decode the base64 chain to extract the inner `auth` field, which is usually `username:password` in base64. Report the decoded credentials as a separate finding — the raw base64 blob hides the actual blast radius.

### Step 7: Generate Structured JSON

All output files follow the naming convention: `<repo_name>_<base_name>_<risk_score>.<ext>`
For example, repo "my-app" with risk score 72 produces:
- `my-app_triage-results_72.json`
- `my-app_triage-results_72.xlsx`
- `my-app_secrets-triage-report_72.md`
- `my-app_pipeline-improvements_72.md`

Write `<output_directory>/<repo_name>_triage-results_<risk_score>.json` with **ALL findings** (true positives, false positives, AND duplicates) so every classification decision is tracked and the total count matches the raw Omnileak output:

```json
{
  "meta": {
    "repo": "<repo_name>",
    "scan_date": "<ISO 8601 timestamp>",
    "last_commit": "<latest_commit_in_scanned_repo: already found by omnileaks; stored in <out-dir-for-repository>/<repo>_latest_commit.txt>",
    "mode": "full_scan | triage_only",
    "risk_score": <0-100>,
    "total_raw_findings": <number>,
    "true_positives": <number>,
    "false_positives_filtered": <number>,
    "ai_only_findings": <number>,
    "deep_analysis_performed": true | false
  },
  "findings": [
    {
      "id": 1,
      "omnileak_ids": [75, 102],
      "classification": "TRUE_POSITIVE",
      "severity": "CRITICAL",
      "category": "GitHub PAT",
      "secret_value": "<value, truncate private keys to 60 chars + '...'>",
      "file_path": "path/to/file",
      "line_number": 3,
      "commit": "<hash>",
      "on_disk": true,
      "confidence": "high",
      "environment": "production",
      "remediation": "ROTATE_IMMEDIATELY",
      "effort": "quick",
      "detected_by": ["detect-secrets", "gitleaks", "titus", "trufflehog"],
      "fp_reason": null,
      "duplicate_of": null
    },
    {
      "id": 2,
      "omnileak_ids": [44],
      "classification": "FALSE_POSITIVE",
      "severity": null,
      "category": "vendor translation",
      "secret_value": "password => 'Jelszó'",
      "file_path": "vendor/translations/hu.php",
      "line_number": 88,
      "commit": "<hash>",
      "on_disk": true,
      "confidence": null,
      "environment": null,
      "remediation": null,
      "effort": null,
      "detected_by": ["detect-secrets"],
      "fp_reason": "Translation file in vendor — keyword match, not a credential",
      "duplicate_of": null
    },
    {
      "id": 3,
      "omnileak_ids": [103],
      "classification": "DUPLICATE",
      "severity": "CRITICAL",
      "category": "GitHub PAT",
      "secret_value": "<same as finding 1>",
      "file_path": "path/to/file",
      "line_number": 3,
      "commit": "<different_hash>",
      "on_disk": false,
      "confidence": null,
      "environment": null,
      "remediation": null,
      "effort": null,
      "detected_by": ["gitleaks"],
      "fp_reason": null,
      "duplicate_of": 1
    }
  ],
  "composite_vulnerabilities": [
    {
      "id": 1,
      "description": "...",
      "severity": "CRITICAL",
      "related_finding_ids": [1, 3],
      "files_involved": ["file1", "file2"]
    }
  ]
}
```

**Field rules:**
- `omnileak_ids`: the original `id` values from the aggregated JSON that map to this finding (multiple if deduplicated)
- `classification`: `TRUE_POSITIVE`, `FALSE_POSITIVE`, or `DUPLICATE`
- `severity`: one of `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` for TPs; `null` for FPs
- `environment`: one of `production`, `staging`, `local-dev`, `test`, `vendor`, `unknown` for TPs; `null` for FPs
- `remediation`: one of `ROTATE_IMMEDIATELY`, `ROTATE_SOON`, `CLEANUP` for TPs; `null` for FPs
- `effort`: one of `quick` (< 30 min, e.g. rotate a key in a dashboard), `medium` (1-2 hours, e.g. rotate + update vault + deploy), `complex` (half day+, e.g. git history purge, migration rewrite) for TPs; `null` for FPs
- `confidence`: one of `high`, `medium`, `low` for TPs; `null` for FPs
- `on_disk`: `true` if secret is currently in the working tree, `false` if history-only, `"unknown"` if no repo access
- `detected_by`: list of tools that found it, or `["AI"]` for AI-only findings
- `fp_reason`: short explanation of why a finding is a false positive; `null` for TPs and DUPs
- `duplicate_of`: the `id` of the primary finding this is a duplicate of; `null` for TPs and FPs

**Risk score** (in `meta.risk_score`): compute as:
- Each CRITICAL finding: +10 points
- Each HIGH finding: +5 points
- Each MEDIUM finding: +2 points
- Each LOW finding: +1 point
- Multiply subtotal by 1.5 if any composite vulnerabilities exist
- Multiply by 1.3 if any CRITICAL/HIGH findings are still on disk
- Cap at 100

### Step 8: Generate Excel Report

Convert the triage JSON to an Excel workbook for easy review and filtering.

```bash
cd <omnileak_path> && python3 -m core.ai.triage_reporter <output_directory>/<repo_name>_triage-results_<risk_score>.json
```

The script derives the `.xlsx` name from the input `.json` name automatically.

This produces `<output_directory>/<repo_name>_triage-results_<risk_score>.xlsx` with tabs:
- **All Findings** — every finding (TPs, DUPs, and FPs), sorted by classification then severity
- **True Positives** — only TPs, sorted by severity descending
- **Duplicates** — duplicate findings linked to their primary (audit trail)
- **False Positives** — only FPs, for audit trail
- **Composite Vulns** — composite vulnerabilities (if any)

Columns have auto-filters, severity/classification cells are color-coded, and the sheet is ready for adding custom tracking columns (Status, Assignee, etc.).

If the script fails, report the error but continue to the next step.

### Step 9: Generate Markdown Report

Write `<output_directory>/<repo_name>_secrets-triage-report_<risk_score>.md`:

#### Section 1: Executive Summary
Table with: total tool findings, true positives, false positives filtered, AI-only findings, breakdown by severity.

Include the **Risk Score** prominently: `Risk Score: XX/100` with a label:
- 0-20: LOW RISK
- 21-50: MODERATE RISK
- 51-80: HIGH RISK
- 81-100: CRITICAL RISK

#### Section 2: Composite Vulnerabilities
Cross-file / code-flow vulnerabilities found only by AI deep analysis. Omit section if none found.

#### Section 3: False Positives Filtered
Summary counts by category (e.g., "28 vendor translations, 22 SDK schemas, 16 code patterns"). Do NOT list individual FPs.

#### Section 4: Remediation Priority
Group by priority level with effort estimates:

- **Priority 1 — Rotate Immediately**: production credentials, cloud provider keys, PATs
- **Priority 2 — Rotate Soon**: staging credentials, private keys, auth tokens
- **Priority 3 — Clean Up**: .gitignore updates, git history purge, pre-commit hooks

For each item, include the effort estimate: `[quick]`, `[medium]`, or `[complex]`.

> Detailed findings are in `triage-results.json` (same directory) for programmatic use.

### Step 10: Self-Reflection — Pipeline Improvement Analysis

After completing all analysis, reflect on this run and write `<output_directory>/<repo_name>_pipeline-improvements_<risk_score>.md`:

#### Section 1: What Went Well
- Which tool caught the most true positives?
- Were the FP rules effective? Which categories filtered the most noise?
- Did the severity rubric produce sensible assignments?

#### Section 2: False Positive Patterns Discovered
- List any **new FP patterns** encountered in this repo that aren't in the current skill rules (Step 5c). Be specific — include the pattern, an example, and a proposed rule.
- These are candidates for adding to the skill prompt in future versions.

#### Section 3: Triage Gaps
- Findings where confidence was `low` — what additional information would have helped?
- Secrets where environment was hard to determine — what contextual clues were missing?
- Any findings where on-disk check was inconclusive?

#### Section 4: Tool Coverage Analysis
- Which tools had the most overlap (finding the same secrets)?
- Were there true positives found by only one tool? Which tool, and why did others miss it?
- Were there areas of the repo that no tool covered well (e.g. specific file types, config formats)?

#### Section 5: Suggested Improvements
Concrete, actionable suggestions for improving the pipeline. For each:
- **What**: the proposed change
- **Why**: what problem it solves (reference specific findings from this run)
- **Priority**: high / medium / low

Examples of what to look for:
- New FP rules to add to the skill
- Severity rubric adjustments based on edge cases encountered
- Missing file types or patterns the deep analysis should cover
- Omnileak tool configuration tweaks (e.g. custom rules, excluded paths)
- Workflow improvements (steps that were slow, redundant, or confusing)

### Step 11: Print Summary

Tell the user:
- Mode used (full scan or triage of existing results)
- **Risk Score: XX/100 (LABEL)**
- Omnileak raw findings count
- True positives after AI triage (breakdown: X critical, X high, X medium, X low)
- Additional AI-only findings (or "skipped — no repo path" if Step 6 was skipped)
- False positives filtered out
- Duplicates count
- Paths to all generated files (named `<repo>_<base>_<score>.<ext>`)
