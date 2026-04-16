# Deep Analysis Instructions

> **Skip entirely** if no repo path is available (triage mode without `--repo`).

After triaging, perform additional analysis by reading repo files directly:

1. **Composite vulnerabilities**: Look for encrypted keys whose passphrases are committed in other files. Look for private key files whose App IDs / Installation IDs are in config files. Look for encryption code that derives keys from committed secrets.

2. **Non-pattern secrets**: Read config/YAML/parameters files for identifiers (App IDs, numeric IDs, internal URLs, hostnames) that are sensitive in context of other committed credentials.

3. **Severity by code context**: For secrets in migration files or code with environment branching (`if getenv('APP_ENV')`) — determine which branch is production vs staging vs local and classify severity accordingly. Production credentials = CRITICAL. Staging = HIGH. Local/dev = MEDIUM.

4. **Password / credential reuse across environments**: Compare secret values across different environment config files (e.g. `dev.yml` vs `staging.yml` vs `production.yml`). Identical credentials shared between environments is a composite vulnerability — if one environment is compromised, all others using the same credential are too. Flag each reuse pair.

5. **Files tools typically miss**: `.sql` dump files, `.dist`/`.example` files, service-specific config subdirectories (centrifugo, nginx, etc.), IDE configs in git history (`.idea/`), CI workflow files.

6. **Docker credential base64 decoding**: When a Kubernetes `dockerconfigjson` secret or `.dockercfg` is found (typically a base64 blob), decode the base64 chain to extract the inner `auth` field, which is usually `username:password` in base64. Report the decoded credentials as a separate finding — the raw base64 blob hides the actual blast radius.
