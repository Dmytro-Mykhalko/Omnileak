"""Deterministic FP pre-filter for Omnileak aggregated findings.

Classifies obvious false positives by file path alone (no AI needed).
This runs *before* agent dispatch to reduce the volume of findings
that require expensive AI triage.

Usage::

    from core.ai.prefilter import prefilter
    result = prefilter(findings)
    # result["needs_triage"]  — findings requiring AI classification
    # result["auto_fp"]       — deterministic false positives
    # result["summary"]       — counts and category breakdown

Or from the CLI::

    python3 -m core.ai.prefilter <aggregated.json> --out <filtered.json>
"""

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

        for pattern, category in _FP_RULES:
            if pattern.search(file_path):
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


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 -m core.ai.prefilter <aggregated.json> [--out <filtered.json>]")
        sys.exit(1)

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
