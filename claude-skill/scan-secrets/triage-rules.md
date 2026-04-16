# Triage Classification Rules

## Deduplicate — Keep One, Mark the Rest

Group findings that represent the **same logical secret** — the same credential value appearing in multiple commits, or detected by multiple tools in the same file.

- Pick **one** representative finding per group → classify it as `TRUE_POSITIVE` or `FALSE_POSITIVE` normally. Track all original `id` values in its `omnileak_ids`.
- For **every other** entry in the group, emit a separate finding with `"classification": "DUPLICATE"` and set `"duplicate_of": <id of the primary finding>`. Copy severity/environment/etc. from the primary. This ensures the total finding count in the JSON matches the raw Omnileak count — nothing is silently dropped.

## Handle Large Result Sets

If the aggregated JSON has **more than 200 findings**, work in batches:
1. Read the first batch (up to 200 entries)
2. Triage that batch
3. Read the next batch, and so on
4. Merge results at the end

Do NOT try to read the entire file into a single prompt if it's very large.

## TRUE POSITIVE — flag if:

- API key, token, password, private key, or credential with a real non-placeholder value
- Connection string with embedded real credentials (not `!ChangeMe!` or `db_password`)
- Hard-coded secret in source code, config, migration, env, or infrastructure files
- Secret in git history (deleted from disk but recoverable — still needs rotation)

## FALSE POSITIVE — discard if:

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

## Tool-Specific FP Patterns

Be extra skeptical of:
- **Trufflehog**: high-entropy strings in minified JS, base64-encoded non-secrets, hex color codes
- **Detect-secrets**: keyword-only matches (`password_field`, `secret_name`) with no actual value
- **Gitleaks**: generic regex hits on words like `key`, `token` in comments or docs
- **Titus**: wide-net rules that match config scaffolding or template placeholders

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

| Environment     | API Key/Token | Private Key | Password | Infra Hostname |
|-----------------|---------------|-------------|----------|----------------|
| Production      | CRITICAL      | CRITICAL    | CRITICAL | HIGH           |
| Staging         | HIGH          | HIGH        | MEDIUM   | MEDIUM         |
| Local/Dev       | MEDIUM        | MEDIUM      | LOW      | LOW            |
| Test fixture    | LOW           | LOW         | FP       | FP             |
| Vendor code     | FP            | FP          | FP       | FP             |

Determine environment from context: file path (`docker/`, `.env.local`, `test/`), env branching in code (`if getenv('APP_ENV')`), variable names (`PROD_`, `STAGING_`), config structure. When ambiguous, assume the higher severity.
