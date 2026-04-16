"""Deterministic FP pre-filter for Omnileak aggregated findings.

Classifies obvious false positives by file path and content rules
(no AI needed). This runs *before* agent dispatch to reduce the
volume of findings that require expensive AI triage.

Two rule layers:
1. Path rules — match on ``file_path`` (first match wins).
2. Content rules — match on ``secret_value`` or ``file_path`` fields
   via regex (checked only if no path rule matched).

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

import glob as _glob
import json
import logging
import os
import re
import sys

logger = logging.getLogger(__name__)

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
    """Split findings into needs_triage vs auto_fp.

    Parameters
    ----------
    findings : list[dict]
        Raw Omnileak aggregated findings.

    Returns
    -------
    dict
        ``needs_triage``: list of findings requiring AI classification.
        ``auto_fp``: list of auto-classified false positives (with ``fp_category``).
        ``summary``: counts and per-category breakdown.
    """
    needs_triage = []
    auto_fp = []
    fp_counts = {}

    for finding in findings:
        file_path = finding.get("file_path", "")
        matched_category = None

        # Pass 1: path-based rules
        for pattern, category in _FP_RULES:
            if pattern.search(file_path):
                matched_category = category
                break

        # Pass 2: content-aware rules (only if path rules didn't match)
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
            needs_triage.append(finding)

    summary = {
        "total": len(findings),
        "needs_triage": len(needs_triage),
        "auto_fp": len(auto_fp),
        "fp_categories": fp_counts,
    }

    logger.info(
        "Pre-filter: %d total → %d need triage, %d auto-FP",
        len(findings), len(needs_triage), len(auto_fp),
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
