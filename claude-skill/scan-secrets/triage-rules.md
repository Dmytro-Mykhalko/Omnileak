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

## Classification Approach — TP by Default, FP Only with Proof

**NEVER classify by `secret_type` alone.** The scanner's secret_type (e.g. "Secret Keyword", "generic-api-key", "np.generic.5") is a detection rule name, NOT a verdict. You MUST examine the actual `secret_value`.

**Start by assuming the finding is a TRUE POSITIVE.** Then try to disprove it:

1. Extract the credential value from the raw `secret_value` string
2. Check against known credential prefixes → if match, it's TP (stop here)
3. Check `high_entropy` flag → if true, it's TP unless you can prove it's fake (stop here)
4. Check `sensitivity` tag → if `production`, `infrastructure`, or `certificate`, it's TP unless the value is clearly a placeholder (stop here)
5. Check the file extension → if `.pem`, `.key`, `.p12`, `.env`, `.sql`, it's TP unless the value is clearly a placeholder
6. Try to find **positive evidence** that the value is fake:
   - Is it a known placeholder? (`password`, `changeme`, `example`, `123456`, `xxx`, `TODO`)
   - Is it a variable name or code pattern? (`password_field`, `secretName`, `const KEY = 'key'`)
   - Is it a translation string? (`Jelszó`, `Пароль`, `mot de passe`)
   - Is it a schema definition or type name? (`SecretKey: string`, `type: password`)
7. If you found positive evidence → FP. If you didn't → **TP**

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

## FALSE POSITIVE — discard ONLY with positive proof

**You may ONLY classify as FP if one of these specific conditions is met AND the value is NOT high-entropy AND the value does NOT match a known credential prefix:**

1. **Vendor translation string**: value is a human-language word for "password"/"secret" in a translation file inside `vendor/`, `node_modules/` (e.g. `password => 'Jelszó'`, `password => 'Пароль'`)
2. **SDK schema/type definition**: the match is a parameter name or type, not a value (e.g. `SecretKey: string`, `type SecretToken struct{}`)
3. **Variable/field name, not a value**: the detected string is a code identifier (e.g. `password_parameter: password`, `const PRIVATE_KEY = 'privateKey'`, `secret_name`)
4. **Known placeholder value**: the value is literally one of: `password`, `changeme`, `!ChangeMe!`, `example`, `123456`, `xxx`, `TODO`, `REPLACE_ME`, `db_password`, `secret`, `admin`, `root`, `guest`, `pass`, `test`
5. **Regex or type definition**: the match is inside a regex pattern or type annotation containing "secret"/"password"
6. **Helm secret reference**: `existingSecret: <simple-name>` where the value is a Kubernetes resource name, not a credential
7. **GitHub Actions header**: `secrets: |` or vault path like `SECRET_NAME: app-name` (no actual credential value)
8. **Connection string with default password AND localhost**: password matches the placeholder list above AND hostname is `localhost`/`127.0.0.1`/`0.0.0.0`

**If NONE of the above conditions are met → classify as TP.** Do not invent new FP reasons. When the value is high-entropy and you can't match it to a specific FP condition above, it is TP.

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

## Dangerous FP Patterns — These Are Mistakes, Not Rules

These are real mistakes observed in production triage runs. Each one led to missed credentials. Do NOT repeat them:

| Mistake | Why it's wrong | Correct classification |
|---|---|---|
| "test" in filename → FP | `page-test_temp.php`, `test_config.yml` contain real credentials for test environments | TP if value is high-entropy. "test" in path ≠ fake credential. |
| Private key / cert file → FP | `privkey4.pem`, `server.key`, `fullchain.pem` ARE the secrets | Always TP. The file is the credential. Severity CRITICAL. |
| "Generic pattern match" → FP | Scanner rule name is irrelevant | TP if value is high-entropy. Read the value, ignore the type. |
| Same secret_type → DUP | Two AWS keys are not duplicates because both are AWS keys | Different value = separate finding. Compare character-by-character. |
| Different file, same type → DUP | Key in `config/prod.yml` ≠ key in `config/stage.yml` | Different file + different value = two TPs. |
| History-only → FP | Secret deleted from HEAD but recoverable via `git log` | TP. Still needs rotation. Mark `on_disk: false`. |
| `.php` / `.py` / `.rb` → FP | Application code files contain real hardcoded credentials | TP if value is high-entropy. These are not test fixtures. |
| Commented-out secret → FP | `// password: "Kx9mB2vL..."` is visible to anyone reading the code | TP. Comments don't hide credentials from attackers. |
| `.sql` file → FP | SQL dumps from production contain real credential columns | TP if `INSERT INTO` with credential-like columns. |
| High-entropy in unfamiliar file → FP | Unknown file type doesn't mean not sensitive | TP. If you can't prove it's fake, it's real. |
| `_temp` / `_backup` / `_old` suffix → FP | Temp/backup files often contain production data | TP. These are copies of real configs. |

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

## Tool-Specific Notes

These tools have known noise patterns, but **noise from a tool does not mean all findings from that tool are FP**. Always read the value:

- **Trufflehog**: produces noise on high-entropy strings in minified JS and hex color codes — but also catches real secrets other tools miss. Read the value.
- **Detect-secrets**: keyword-only matches (`password_field`, `secret_name`) with no actual value are FP — but `password: "Kx9mB2vL..."` from detect-secrets is TP. Check if there's a real value attached.
- **Gitleaks**: generic regex hits on words like `key`, `token` in comments are noise — but gitleaks also catches real API keys in comments. Read the value.
- **Titus**: wide-net rules match scaffolding — but also catch secrets in unusual file types. Read the value.

**Bottom line**: the tool name and rule name are irrelevant. The value and file context determine TP vs FP.

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
| Test env        | LOW           | MEDIUM      | LOW      | LOW            | LOW           |
| Vendor code     | FP            | FP          | FP       | FP             | FP            |

**"Test env" means a confirmed test fixture** with placeholder values (`password: "123456"`), NOT any file with "test" in the path. Files like `test_config.yml` with real high-entropy credentials are production/staging severity, not test.

**"Vendor code" means third-party library code** in `vendor/`, `node_modules/`, `bower_components/`. Your own project code in any directory is NOT vendor code.

Determine environment from context: file path, the `sensitivity` tag from pre-filter, env branching in code (`if getenv('APP_ENV')`), variable names (`PROD_`, `STAGING_`), config structure. **When ambiguous, assume the higher severity.**
