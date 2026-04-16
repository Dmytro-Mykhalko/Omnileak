"""Post-processing integrity validator for triage-results.json.

Checks structural correctness, field types, ID coverage, count consistency,
and risk score accuracy. Returns a list of errors (empty = valid).

Usage::

    from core.ai.triage_validator import validate
    errors = validate("triage-results.json", raw_path="aggregated.json")
    # errors == [] means valid

Or from the CLI::

    python3 -m core.ai.triage_validator <triage-results.json> [--raw <aggregated.json>]
    # Exit 0 = valid, Exit 1 = errors
"""

import json
import logging
import os
import sys

from core.ai.constants import (
    VALID_CLASSIFICATIONS,
    VALID_SEVERITIES,
    compute_risk_score,
)

logger = logging.getLogger(__name__)

_REQUIRED_META_FIELDS = {
    "repo": str,
    "scan_date": str,
    "mode": str,
    "risk_score": (int, float),
    "total_raw_findings": (int, float),
    "true_positives": (int, float),
    "false_positives_filtered": (int, float),
}

_REQUIRED_FINDING_FIELDS = {
    "id", "omnileak_ids", "classification", "severity", "category",
    "secret_value", "file_path", "line_number", "commit",
    "on_disk", "detected_by",
}



def _check_meta(meta, errors):
    """Validate meta section."""
    if not isinstance(meta, dict):
        errors.append("meta: must be a dict")
        return

    for field, expected_type in _REQUIRED_META_FIELDS.items():
        if field not in meta:
            errors.append(f"meta: missing required field '{field}'")
        elif not isinstance(meta[field], expected_type):
            errors.append(
                f"meta.{field}: expected {expected_type.__name__ if isinstance(expected_type, type) else expected_type}, "
                f"got {type(meta[field]).__name__}"
            )


def _check_finding(finding, idx, errors):
    """Validate a single finding."""
    for field in _REQUIRED_FINDING_FIELDS:
        if field not in finding:
            errors.append(f"finding[{idx}]: missing required field '{field}'")

    cls = finding.get("classification")
    if cls not in VALID_CLASSIFICATIONS:
        errors.append(f"finding[{idx}]: invalid classification '{cls}'")
        return  # can't validate further without knowing the type

    if cls == "TRUE_POSITIVE":
        sev = finding.get("severity")
        if sev not in VALID_SEVERITIES:
            errors.append(f"finding[{idx}]: TP must have valid severity, got '{sev}'")

    if not isinstance(finding.get("omnileak_ids"), list):
        errors.append(f"finding[{idx}]: omnileak_ids must be a list")

    if not isinstance(finding.get("detected_by"), list):
        errors.append(f"finding[{idx}]: detected_by must be a list")


def _check_counts(data, errors):
    """Check that meta counts match actual findings."""
    findings = data.get("findings", [])
    meta = data.get("meta", {})

    actual_tp = sum(1 for f in findings if f.get("classification") == "TRUE_POSITIVE")
    actual_fp = sum(1 for f in findings if f.get("classification") == "FALSE_POSITIVE")

    if meta.get("true_positives") != actual_tp:
        errors.append(
            f"count mismatch: meta.true_positives={meta.get('true_positives')} "
            f"but found {actual_tp} TPs"
        )
    if meta.get("false_positives_filtered") != actual_fp:
        errors.append(
            f"count mismatch: meta.false_positives_filtered={meta.get('false_positives_filtered')} "
            f"but found {actual_fp} FPs"
        )


def _check_risk_score(data, errors):
    """Verify risk score matches the formula."""
    meta = data.get("meta", {})
    reported = meta.get("risk_score")
    if reported is None:
        return

    expected = compute_risk_score(
        data.get("findings", []),
        data.get("composite_vulnerabilities", []),
    )
    if reported != expected:
        errors.append(
            f"risk_score mismatch: reported={reported}, computed={expected}"
        )


def _check_id_coverage(data, raw_findings, errors):
    """Verify every raw finding ID appears in exactly one triage finding's omnileak_ids."""
    raw_ids = {f["id"] for f in raw_findings}
    covered_ids = set()

    for finding in data.get("findings", []):
        for oid in finding.get("omnileak_ids", []):
            if oid in covered_ids:
                errors.append(f"raw ID '{oid}' appears in multiple triage findings")
            covered_ids.add(oid)

    missing = raw_ids - covered_ids
    if missing:
        errors.append(
            f"{len(missing)} raw finding ID(s) not covered in triage: "
            f"{sorted(list(missing))[:10]}{'...' if len(missing) > 10 else ''}"
        )


def validate(triage_path, raw_path=None):
    """Validate a triage-results.json file.

    Parameters
    ----------
    triage_path : str
        Path to the triage results JSON.
    raw_path : str, optional
        Path to the original Omnileak aggregated JSON.
        If provided, validates ID coverage.

    Returns
    -------
    list[str]
        List of error messages. Empty list = valid.
    """
    errors = []

    try:
        with open(triage_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        return [f"cannot read triage JSON: {e}"]

    _check_meta(data.get("meta", {}), errors)

    findings = data.get("findings", [])
    if not isinstance(findings, list):
        errors.append("findings: must be a list")
    else:
        for i, finding in enumerate(findings):
            _check_finding(finding, i, errors)
        _check_counts(data, errors)
        _check_risk_score(data, errors)

    if raw_path:
        try:
            with open(raw_path, "r", encoding="utf-8") as f:
                raw_findings = json.load(f)
            _check_id_coverage(data, raw_findings, errors)
        except (json.JSONDecodeError, OSError) as e:
            errors.append(f"cannot read raw JSON for ID coverage check: {e}")

    return errors


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 -m core.ai.triage_validator <triage-results.json> [--raw <aggregated.json>]")
        sys.exit(1)

    triage_path = sys.argv[1]
    raw_path = None
    if "--raw" in sys.argv:
        idx = sys.argv.index("--raw")
        if idx + 1 < len(sys.argv):
            raw_path = sys.argv[idx + 1]

    if not os.path.isfile(triage_path):
        print(f"Error: {triage_path} not found")
        sys.exit(1)

    errs = validate(triage_path, raw_path)
    if errs:
        print(f"INVALID — {len(errs)} error(s):")
        for e in errs:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("VALID")
        sys.exit(0)
