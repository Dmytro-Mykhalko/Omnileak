"""Deterministic pre-filter for Omnileak aggregated findings.

Splits findings into auto-FP (no AI needed) vs needs-triage, and
enriches triage findings with classification hints.

Rule priority:
1. Known credential prefixes → forces needs_triage (overrides FP rules).
2. Path rules — match on ``file_path`` (first match wins → auto-FP).
3. Content rules — match on ``secret_value`` or ``file_path`` (auto-FP).
4. Everything else → needs_triage.

Enrichment on needs_triage findings:
- ``tp_hint`` — known credential prefix category
- ``entropy`` / ``high_entropy`` — Shannon entropy of secret value
- ``sensitivity`` — file-path sensitivity (production/infrastructure/test)
- ``decoded_docker_creds`` — decoded Docker registry credentials

Usage::

    from core.ai.prefilter import prefilter
    result = prefilter(findings)
    # result["needs_triage"]  — findings requiring AI classification
    # result["auto_fp"]       — deterministic false positives
    # result["summary"]       — counts and category breakdown

Batch mode::

    from core.ai.prefilter import prefilter_batch
    summaries = prefilter_batch("/path/to/results")

Or from the CLI::

    python3 -m core.ai.prefilter <aggregated.json> --out <filtered.json>
    python3 -m core.ai.prefilter --batch <results_dir>
"""

import base64
import glob as _glob
import json
import logging
import math
import os
import re
import sys
from collections import Counter

logger = logging.getLogger(__name__)

# ── Known credential prefixes ────────────────────────────────────────────────
# If a secret_value starts with one of these, the finding MUST stay in
# needs_triage (overrides any FP path/content rule).  The matched prefix
# is stored as ``tp_hint`` so the AI agent knows not to dismiss it.

_KNOWN_CREDENTIAL_PREFIXES = [
    ("AKIA", "aws_access_key"),
    ("AIzaSy", "google_api_key"),
    ("ghp_", "github_pat"),
    ("gho_", "github_oauth"),
    ("ghs_", "github_server"),
    ("github_pat_", "github_fine_grained"),
    ("sntrys_", "sentry_token"),
    ("xoxb-", "slack_bot_token"),
    ("xoxs-", "slack_user_token"),
    ("xoxa-", "slack_app_token"),
    ("xoxp-", "slack_legacy_token"),
    ("npm_", "npm_token"),
    ("sk_live_", "stripe_secret_live"),
    ("sk_test_", "stripe_secret_test"),
    ("pk_live_", "stripe_publishable_live"),
    ("rk_live_", "stripe_restricted_live"),
    ("api_sk_", "payment_secret_key"),
    ("wh_sk_", "webhook_secret_key"),
    ("SG.", "sendgrid_api_key"),
    ("xkeysib-", "sendinblue_key"),
    ("sq0csp-", "square_secret"),
    ("EAACEdEose0cBA", "facebook_access_token"),
    ("ya29.", "google_oauth_token"),
    ("-----BEGIN RSA PRIVATE", "rsa_private_key"),
    ("-----BEGIN EC PRIVATE", "ec_private_key"),
    ("-----BEGIN OPENSSH PRIVATE", "openssh_private_key"),
    ("-----BEGIN PGP PRIVATE", "pgp_private_key"),
    ("-----BEGIN DSA PRIVATE", "dsa_private_key"),
]

# ── Sensitivity rules ────────────────────────────────────────────────────────
# Tag findings by file-path sensitivity.  Guides the AI without deciding.

_SENSITIVITY_RULES = [
    (re.compile(r"(?:^|/)(?:values_prod|production|\.env\.prod|\.env\.production)"), "production"),
    (re.compile(r"(?:^|/)(?:values_stage|staging|\.env\.stag)"), "staging"),
    (re.compile(r"(?:^|/)(?:helm|charts)/.*\.ya?ml$"), "infrastructure"),
    (re.compile(r"(?:^|/)(?:infrastructure|ansible|deploy|terraform)/"), "infrastructure"),
    (re.compile(r"(?:^|/)docker-compose.*\.ya?ml$"), "infrastructure"),
    (re.compile(r"(?:^|/)templates/secrets/"), "infrastructure"),
    (re.compile(r"(?:^|/)(?:certificates|certs|ssl|tls|letsencrypt|nginx/certificates)/"), "certificate"),
    (re.compile(r"(?:^|/)\.ssh/"), "certificate"),
    (re.compile(r"\.(?:pem|key|p12|pfx|jks)$"), "certificate"),
    (re.compile(r"(?:^|/)privkey\d*\.pem$"), "certificate"),
    (re.compile(r"(?:^|/)\.env"), "config"),
    (re.compile(r"(?:^|/)(?:test|spec|__tests__|mock|__mocks__)/"), "test"),
]


def _check_known_prefix(secret_value):
    """Return the prefix category if *secret_value* starts with a known credential prefix."""
    for prefix, category in _KNOWN_CREDENTIAL_PREFIXES:
        if secret_value.startswith(prefix):
            return category
    return None


def _shannon_entropy(s):
    """Compute Shannon entropy (bits per character) for string *s*."""
    if not s:
        return 0.0
    freq = Counter(s)
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


def _classify_sensitivity(file_path):
    """Return a sensitivity label for *file_path*, or None."""
    for pattern, label in _SENSITIVITY_RULES:
        if pattern.search(file_path):
            return label
    return None


def _try_decode_docker_auth(secret_value):
    """Try to decode a .dockerconfigjson / .dockercfg base64 blob.

    Returns a list of ``"user:password"`` strings found inside, or None.
    """
    try:
        decoded = base64.b64decode(secret_value).decode("utf-8", errors="replace")
        data = json.loads(decoded)
        auths = data.get("auths", {})
        if not auths and "auth" in data:
            # .dockercfg format: {"registry": {"auth": "base64"}}
            auths = data
        creds = []
        for registry, info in auths.items():
            auth_b64 = info.get("auth", "") if isinstance(info, dict) else ""
            if auth_b64:
                try:
                    cred = base64.b64decode(auth_b64).decode("utf-8", errors="replace")
                    if ":" in cred:
                        creds.append(cred)
                except Exception:
                    pass
        return creds if creds else None
    except Exception:
        return None


def _enrich_finding(finding):
    """Add entropy, sensitivity, and docker-decode tags to a finding (in-place)."""
    secret_value = finding.get("secret_value", "")
    file_path = finding.get("file_path", "")

    # Entropy
    entropy = round(_shannon_entropy(secret_value), 2)
    finding["entropy"] = entropy
    finding["high_entropy"] = entropy >= 4.0 and len(secret_value) >= 20

    # Sensitivity
    finding["sensitivity"] = _classify_sensitivity(file_path)

    # Docker base64 decoding
    secret_type = finding.get("secret_type", "")
    if ("docker" in secret_type.lower()
            or "docker" in file_path.lower()
            or "dockerconfigjson" in secret_value[:50].lower()):
        decoded = _try_decode_docker_auth(secret_value)
        if decoded:
            finding["decoded_docker_creds"] = decoded


# ── FP rules ─────────────────────────────────────────────────────────────────
# Each rule: (compiled regex matching file_path, human-readable category).
# Order matters — first match wins.

_FP_RULES = [
    # Lock files — contain SRI hashes, not secrets
    (re.compile(r"(^|/)pnpm-lock\.yaml$"), "lock_file"),
    (re.compile(r"(^|/)yarn\.lock$"), "lock_file"),
    (re.compile(r"(^|/)package-lock\.json$"), "lock_file"),
    (re.compile(r"(^|/)composer\.lock$"), "lock_file"),
    (re.compile(r"(^|/)Gemfile\.lock$"), "lock_file"),
    (re.compile(r"(^|/)poetry\.lock$"), "lock_file"),
    (re.compile(r"(^|/)Pipfile\.lock$"), "lock_file"),
    (re.compile(r"(^|/)go\.sum$"), "lock_file"),
    (re.compile(r"(^|/)Cargo\.lock$"), "lock_file"),

    # Vendor / third-party code
    (re.compile(r"(^|/)node_modules/"), "vendor_code"),
    (re.compile(r"(^|/)vendor/"), "vendor_code"),
    (re.compile(r"(^|/)third[_-]?party/"), "vendor_code"),
    (re.compile(r"(^|/)bower_components/"), "vendor_code"),

    # Bundled / minified frontend assets
    (re.compile(r"(^|/)public/bundles/"), "bundled_frontend"),
    (re.compile(r"(^|/)dist/"), "bundled_frontend"),
    (re.compile(r"\.min\.js$"), "minified_code"),
    (re.compile(r"\.min\.css$"), "minified_code"),
    (re.compile(r"\.bundle\.js$"), "minified_code"),
    (re.compile(r"\.chunk\.js$"), "minified_code"),

    # Source maps
    (re.compile(r"\.map$"), "source_map"),

    # Test fixtures / snapshots
    (re.compile(r"(^|/)__snapshots__/"), "test_snapshot"),
    (re.compile(r"(^|/)fixtures/"), "test_fixture"),

    # CI badge / status images
    (re.compile(r"\.svg$"), "badge_image"),
    (re.compile(r"\.png$"), "badge_image"),
]

# ── Content-aware FP rules ──────────────────────────────────────────────────
# Each rule: (field to check, compiled regex, human-readable category).
# Checked only when no path rule matched. First match wins.

_CONTENT_FP_RULES = [
    # SRI integrity hashes (e.g. sha256-..., sha384-..., sha512-...)
    ("secret_value", re.compile(r"^sha(?:256|384|512)-"), "sri_hash"),

    # Hex color codes (#RRGGBB)
    ("secret_value", re.compile(r"^#?[0-9a-fA-F]{6}$"), "hex_color"),

    # CI badge / shields URLs in values
    ("secret_value", re.compile(r"(?:coveralls\.io|shields\.io|badge\.fury\.io|badgen\.net|img\.shields\.io)"), "ci_badge_url"),

    # Translation / i18n files
    ("file_path", re.compile(r"(^|/)(?:translations|locales|i18n|lang)/"), "translation_file"),
]


def prefilter(findings):
    """Split findings into needs_triage vs auto_fp, with enrichment.

    Priority order:
    1. Known credential prefixes → always needs_triage (overrides FP rules)
    2. Path-based FP rules → auto_fp
    3. Content-aware FP rules → auto_fp
    4. Everything else → needs_triage

    All ``needs_triage`` findings are enriched with:
    - ``tp_hint``: known prefix category (or None)
    - ``entropy``: Shannon entropy of secret_value
    - ``high_entropy``: True if entropy >= 4.0 and length >= 20
    - ``sensitivity``: file-path sensitivity label (or None)
    - ``decoded_docker_creds``: decoded credentials (only for Docker secrets)

    Parameters
    ----------
    findings : list[dict]
        Raw Omnileak aggregated findings.

    Returns
    -------
    dict
        ``needs_triage``: enriched findings requiring AI classification.
        ``auto_fp``: deterministic false positives (with ``fp_category``).
        ``summary``: counts, category breakdown, enrichment stats.
    """
    needs_triage = []
    auto_fp = []
    fp_counts = {}
    tp_hint_count = 0

    for finding in findings:
        secret_value = finding.get("secret_value", "")
        file_path = finding.get("file_path", "")

        # Priority 1: Known credential prefixes override ALL FP rules
        prefix_category = _check_known_prefix(secret_value)
        if prefix_category:
            enriched = {**finding, "tp_hint": f"known_prefix:{prefix_category}"}
            needs_triage.append(enriched)
            tp_hint_count += 1
            continue

        # Priority 2: Path-based FP rules
        matched_category = None
        for pattern, category in _FP_RULES:
            if pattern.search(file_path):
                matched_category = category
                break

        # Priority 3: Content-aware FP rules (only if path rules didn't match)
        if not matched_category:
            for field, pattern, category in _CONTENT_FP_RULES:
                value = finding.get(field, "")
                if value and pattern.search(value):
                    matched_category = category
                    break

        if matched_category:
            auto_fp.append({**finding, "fp_category": matched_category})
            fp_counts[matched_category] = fp_counts.get(matched_category, 0) + 1
        else:
            needs_triage.append({**finding, "tp_hint": None})

    # Enrich all needs_triage findings with entropy, sensitivity, docker decode
    high_entropy_count = 0
    sensitivity_counts = {}
    for finding in needs_triage:
        _enrich_finding(finding)
        if finding.get("high_entropy"):
            high_entropy_count += 1
        sens = finding.get("sensitivity")
        if sens:
            sensitivity_counts[sens] = sensitivity_counts.get(sens, 0) + 1

    summary = {
        "total": len(findings),
        "needs_triage": len(needs_triage),
        "auto_fp": len(auto_fp),
        "tp_hints": tp_hint_count,
        "high_entropy": high_entropy_count,
        "fp_categories": fp_counts,
        "sensitivity_counts": sensitivity_counts,
    }

    logger.info(
        "Pre-filter: %d total → %d need triage (%d TP hints, %d high-entropy), %d auto-FP",
        len(findings), len(needs_triage), tp_hint_count, high_entropy_count, len(auto_fp),
    )

    return {
        "needs_triage": needs_triage,
        "auto_fp": auto_fp,
        "summary": summary,
    }


def prefilter_file(input_path, output_path=None):
    """Read aggregated JSON, pre-filter, write filtered output.

    Parameters
    ----------
    input_path : str
        Path to Omnileak aggregated_secrets.json.
    output_path : str, optional
        Destination path. Defaults to ``<input_dir>/prefiltered.json``.

    Returns
    -------
    str
        Path to the written output file.
    """
    with open(input_path, "r", encoding="utf-8") as f:
        findings = json.load(f)

    result = prefilter(findings)

    if output_path is None:
        output_path = os.path.join(
            os.path.dirname(input_path), "prefiltered.json"
        )

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(result, f, indent=2)

    return output_path


def prefilter_batch(root_dir):
    """Run pre-filter on every ``*_aggregated_secrets.json`` under *root_dir*.

    Parameters
    ----------
    root_dir : str
        Top-level results directory containing per-repo subdirectories.

    Returns
    -------
    list[dict]
        One summary dict per repo: ``{"repo": name, "input": path,
        "output": path, "summary": {...}}``.
    """
    pattern = os.path.join(root_dir, "**", "*_aggregated_secrets.json")
    matches = sorted(_glob.glob(pattern, recursive=True))

    results = []
    for input_path in matches:
        repo_dir = os.path.dirname(input_path)
        output_path = os.path.join(repo_dir, "prefiltered.json")

        # Run pre-filter and grab the result in memory (avoid re-reading).
        with open(input_path, "r", encoding="utf-8") as f:
            findings = json.load(f)
        result = prefilter(findings)

        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=2)

        repo_name = os.path.basename(repo_dir)
        results.append({
            "repo": repo_name,
            "input": input_path,
            "output": output_path,
            "summary": result["summary"],
        })
        logger.info("Batch pre-filter: %s → %s", repo_name, output_path)

    return results


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(
            "Usage:\n"
            "  python3 -m core.ai.prefilter <aggregated.json> [--out <filtered.json>]\n"
            "  python3 -m core.ai.prefilter --batch <results_dir>"
        )
        sys.exit(1)

    if sys.argv[1] == "--batch":
        if len(sys.argv) < 3:
            print("Error: --batch requires a directory argument")
            sys.exit(1)
        batch_dir = sys.argv[2]
        if not os.path.isdir(batch_dir):
            print(f"Error: {batch_dir} is not a directory")
            sys.exit(1)
        summaries = prefilter_batch(batch_dir)
        if not summaries:
            print(f"No *_aggregated_secrets.json files found under {batch_dir}")
            sys.exit(1)
        for entry in summaries:
            s = entry["summary"]
            print(f"{entry['repo']}: {s['total']} total → {s['needs_triage']} triage, {s['auto_fp']} auto-FP")
        print(f"\nProcessed {len(summaries)} repo(s)")
    else:
        input_path = sys.argv[1]
        output_path = None
        if "--out" in sys.argv:
            idx = sys.argv.index("--out")
            if idx + 1 < len(sys.argv):
                output_path = sys.argv[idx + 1]

        if not os.path.isfile(input_path):
            print(f"Error: {input_path} not found")
            sys.exit(1)

        result_path = prefilter_file(input_path, output_path)
        with open(result_path, "r") as f:
            data = json.load(f)
        s = data["summary"]
        print(f"Pre-filtered: {s['total']} total → {s['needs_triage']} need triage, {s['auto_fp']} auto-FP")
        for cat, count in sorted(s["fp_categories"].items()):
            print(f"  {cat}: {count}")
        print(f"Wrote {result_path}")
