# Triage Classification Rules

This file contains only classification rules — what is a TP, FP, severity, confidence. Process flow (dedup, batching) is in the agent prompt.

## TP-Bias Principle

**When in doubt, classify as TRUE POSITIVE.** A false negative (real secret marked FP) is far worse than a false positive (noise marked TP). Developers will re-check TPs during remediation — they won't re-check FPs. The cost of a missed credential leak is orders of magnitude higher than the cost of a developer spending 30 seconds verifying a flagged finding.

Rules:
- If you're unsure whether a value is a placeholder or real → **TP**
- If "test" appears in the filename but the file contains real-looking credentials → **TP**
- If the file is a certificate, private key, or PEM file → **TP** (always, regardless of path)
- If the value has high entropy and you can't prove it's fake → **TP**
- Only classify as FP when you have **positive evidence** that the value is not a real credential (e.g., it's a known placeholder, a translation string, a code pattern, or a variable name)

## Pre-Filter Enrichment

The pre-filter adds hints to each finding in `needs_triage`. **Use these but don't blindly trust them:**

| Field | Meaning | How to use |
|---|---|---|
| `tp_hint` | Known credential prefix matched (e.g. `known_prefix:aws_access_key`) | Strong TP signal. Only classify as FP if the value is clearly a documented example (e.g. `AKIAIOSFODNN7EXAMPLE`). |
| `high_entropy` | Shannon entropy >= 4.0 and length >= 20 chars | High-entropy strings in config/infra files are almost always real credentials. |
| `sensitivity` | File-path label: `production`, `staging`, `infrastructure`, `config`, `test` | Determines severity. Production + real credential = CRITICAL. |
| `decoded_docker_creds` | Decoded Docker registry credentials from base64 blob | Always TP — these are real registry credentials. Report the decoded value. |

## Classification Approach — Value First, Type Never

**NEVER classify by `secret_type` alone.** The scanner's secret_type (e.g. "Secret Keyword", "generic-api-key", "np.generic.5") is a detection rule name, NOT a verdict. You MUST examine the actual `secret_value`.

For each finding:
1. Extract the credential value from the raw `secret_value` string
2. Check against known credential prefixes (see below)
3. Assess the value — is it high-entropy? Is it a placeholder? Is it a code pattern?
4. Check the file context — what kind of file is this? What environment?
5. Only then decide TP or FP

## Known Credential Prefixes — Force TP

If `secret_value` starts with any of these, it is **almost certainly a TRUE POSITIVE** unless the value is a documented example (e.g. AWS's `AKIAIOSFODNN7EXAMPLE`):

| Prefix | Type |
|---|---|
| `AKIA` | AWS access key |
| `AIzaSy` | Google/Firebase API key |
| `ghp_`, `gho_`, `ghs_`, `github_pat_` | GitHub token |
| `sntrys_` | Sentry org token |
| `xoxb-`, `xoxs-`, `xoxa-`, `xoxp-` | Slack token |
| `npm_` | NPM publish token |
| `sk_live_`, `sk_test_`, `pk_live_`, `rk_live_` | Stripe key |
| `api_sk_`, `wh_sk_` | Payment processor secret/webhook key |
| `SG.` | SendGrid API key |
| `sq0csp-` | Square secret |
| `-----BEGIN RSA PRIVATE`, `-----BEGIN EC PRIVATE`, `-----BEGIN OPENSSH PRIVATE` | Private key |

## TRUE POSITIVE — flag if:

- API key, token, password, private key, or credential with a **real non-placeholder value**
- High-entropy string (entropy >= 4.0, length >= 20) in a config, infrastructure, env, or deployment file
- Connection string with embedded real credentials (check: password is NOT in the default list below, AND hostname is not localhost)
- Hard-coded secret in source code, config, migration, env, or infrastructure files
- Secret in git history (deleted from disk but recoverable — still needs rotation)
- SQL dump or migration file containing credential-like values in INSERT/UPDATE statements (especially columns named `credential_*`, `*_private_key`, `*_secret_*`)
- Kubernetes Docker registry secrets (`.dockerconfigjson` base64 blobs) — always TP, decode and report
- `erlangCookie`, RabbitMQ passwords, AMQP connection strings with non-default passwords

## FALSE POSITIVE — discard if:

- In `vendor/`, `node_modules/`, or third-party library code **AND** the value is NOT a known credential prefix:
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
- Helm chart `existingSecret: <name>` references where the value is a simple resource name (no high-entropy string)
- Regex patterns or type definitions containing the word "secret"
- Connection strings where password is a **known default**: `root`, `admin`, `guest`, `password`, `pass`, `changeme`, `!ChangeMe!`, `db_password`, `secret`, `example` AND hostname is `localhost`, `127.0.0.1`, or `0.0.0.0`

## Infrastructure File Sensitivity

Files in these paths contain **real deployment configuration**. High-entropy strings here are almost always real credentials — do NOT dismiss them as "generic pattern matches":

- `**/values_prod*/**`, `**/values_stage*/**`, `**/values_dev*/**` — Helm value overrides
- `**/helm/**/*.yaml`, `**/charts/**/*.yaml` — Helm charts
- `**/templates/secrets/**` — Kubernetes secret templates
- `**/infrastructure/**`, `**/ansible/**`, `**/terraform/**` — IaC
- `**/deploy/**` — Deployment configs
- `**/docker-compose*.yml` — Docker Compose
- `**/.env*` — Environment files (check if it's `.env.example` vs `.env.production`)

## Certificate and Key File Paths — Always TP

Any file that IS a certificate or private key is a TRUE POSITIVE regardless of where it lives:

- `**/*.pem`, `**/*.key`, `**/*.p12`, `**/*.pfx`, `**/*.jks`
- `**/certificates/**`, `**/certs/**`, `**/ssl/**`, `**/tls/**`
- `**/nginx/certificates/**`, `**/letsencrypt/**`
- `**/privkey*.pem`, `**/fullchain*.pem`
- `**/.ssh/id_*`, `**/.ssh/authorized_keys`

These are real cryptographic materials. Do NOT dismiss them because "it's just a certificate file" — that's exactly what makes it sensitive.

## Strict DUPLICATE Rules

A DUPLICATE means the **exact same credential value** appearing in a different location (different commit, different tool detected it). It does NOT mean:
- A different credential of the same type
- A similar-looking key in a different file
- The same secret_type but different secret_value

**Before marking as DUPLICATE, verify:**
1. The `secret_value` is character-for-character identical (or one contains the other)
2. If the values differ at all — even by one character — they are SEPARATE findings, not duplicates
3. If the file paths are different AND the values are different → two separate TPs, not a primary + duplicate

When grouping for dedup: group by **normalized secret value**, NOT by secret_type or file_path.

## Dangerous FP Patterns — Do NOT Make These Mistakes

These are patterns where the AI commonly misclassifies TPs as FPs. Check each one:

| Mistake | Why it's wrong | Correct classification |
|---|---|---|
| "test" in filename → FP | Files like `page-test_temp.php`, `test_config.yml` often contain real credentials used in test environments | Read the actual value. High-entropy string = TP. |
| Private key file → FP | `privkey4.pem`, `server.key` are real keys, not patterns | Always TP. The file IS the secret. |
| "Generic pattern match" → FP | Scanner's rule name doesn't determine reality | Read the value. `password: "Kx9mB2vL..."` is real regardless of rule name. |
| Same secret_type → DUP | Two AWS keys are not duplicates just because both are AWS keys | Compare actual values. Different value = separate finding. |
| History-only → FP | Secret removed from HEAD but still in git history | Still TP. Git history is recoverable. Needs rotation. |
| `.php` file → FP | PHP files are application code, not test fixtures | Read the value. Credentials in PHP config files are real. |
| Commented-out secret → FP | `// password: "realpass123"` still exposes the credential | TP if the value is real. Comments are readable. |
| `.sql` file → FP | SQL dumps contain production data | TP if credential-like values in INSERT/UPDATE statements. |

## Connection String Rules

For connection strings (JDBC, AMQP, MySQL, PostgreSQL, MongoDB, Redis):

1. Extract the password from the URL
2. Check against the default password list (see FP rules above)
3. Check the hostname:
   - `*.rds.amazonaws.com`, `ec2-*`, cloud IPs → **real infrastructure** → TP if password is non-default
   - `localhost`, `127.0.0.1`, `0.0.0.0` → likely local dev → FP if password is also default
4. Commented-out connection strings with real infrastructure hostnames are still TP (the password is exposed)

## SQL Dump Handling

SQL files (`.sql`) — especially those with `prod` or `dump` in the path — may contain:
- `INSERT INTO` statements with credential columns (`credential_private_key`, `webhook_private_key`, `api_key`)
- These are **real credentials from production databases** → always TP, severity CRITICAL

## Tool-Specific FP Patterns

Be extra skeptical of:
- **Trufflehog**: high-entropy strings in minified JS, base64-encoded non-secrets, hex color codes
- **Detect-secrets**: keyword-only matches (`password_field`, `secret_name`) with no actual value
- **Gitleaks**: generic regex hits on words like `key`, `token` in comments or docs
- **Titus**: wide-net rules that match config scaffolding or template placeholders

But **NEVER auto-FP an entire secret_type category**. Even "Secret Keyword" findings can be real: `password: "Xy9kL2mN4pQ7rT0wBcDfGhJv"` in `values_prod/rabbitmq.yaml` is CRITICAL.

## Confidence Levels

For each TRUE POSITIVE, assign:
- `high` — clearly a real secret (valid format, non-placeholder value, sensitive context)
- `medium` — likely real but can't fully confirm without testing (e.g. could be expired, could be an internal-only key)
- `low` — suspicious but ambiguous (e.g. long random string with no clear type)

## On-Disk Verification

For each TRUE POSITIVE, check if the secret is **currently on disk**:

```bash
ls <repo_path>/<file_path>
grep -F "<secret_value_snippet>" <repo_path>/<file_path>
```

- File exists AND contains the secret → `on_disk: true`
- File gone or secret removed → `on_disk: false` (history-only)
- No repo path available → `on_disk: "unknown"`

## Severity Rubric

| Environment     | API Key/Token | Private Key | Password | Infra Hostname | SQL Dump Cred |
|-----------------|---------------|-------------|----------|----------------|---------------|
| Production      | CRITICAL      | CRITICAL    | CRITICAL | HIGH           | CRITICAL      |
| Staging         | HIGH          | HIGH        | MEDIUM   | MEDIUM         | HIGH          |
| Local/Dev       | MEDIUM        | MEDIUM      | LOW      | LOW            | MEDIUM        |
| Test fixture    | LOW           | LOW         | FP       | FP             | LOW           |
| Vendor code     | FP            | FP          | FP       | FP             | FP            |

Determine environment from context: file path (`docker/`, `.env.local`, `test/`), the `sensitivity` tag from pre-filter, env branching in code (`if getenv('APP_ENV')`), variable names (`PROD_`, `STAGING_`), config structure. **When ambiguous, assume the higher severity.**
