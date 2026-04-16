"""Shared constants and formulas for the AI triage pipeline.

Single source of truth for classification values, severity points,
and risk score computation — used by prefilter, writer, validator,
and reporter.
"""

import math

VALID_CLASSIFICATIONS = frozenset({"TRUE_POSITIVE", "FALSE_POSITIVE", "DUPLICATE"})
VALID_SEVERITIES = frozenset({"CRITICAL", "HIGH", "MEDIUM", "LOW"})
VALID_ENVIRONMENTS = frozenset({"production", "staging", "local-dev", "test", "vendor", "unknown"})
VALID_REMEDIATIONS = frozenset({"ROTATE_IMMEDIATELY", "ROTATE_SOON", "CLEANUP"})
VALID_EFFORTS = frozenset({"quick", "medium", "complex"})
VALID_CONFIDENCES = frozenset({"high", "medium", "low"})

SEVERITY_POINTS = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


def compute_risk_score(findings, composite_vulnerabilities=None):
    """Compute risk score (0-100) from classified findings.

    Formula:
    - CRITICAL: +10, HIGH: +5, MEDIUM: +2, LOW: +1
    - x1.5 if composite vulnerabilities exist
    - x1.3 if any CRITICAL/HIGH findings are on disk
    - Cap at 100
    """
    tps = [f for f in findings if f.get("classification") == "TRUE_POSITIVE"]

    subtotal = sum(SEVERITY_POINTS.get(f.get("severity"), 0) for f in tps)

    if composite_vulnerabilities:
        subtotal = subtotal * 1.5

    if any(f.get("on_disk") is True and f.get("severity") in ("CRITICAL", "HIGH") for f in tps):
        subtotal = subtotal * 1.3

    return min(100, int(math.ceil(subtotal)))
