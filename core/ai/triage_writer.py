"""Assemble a full triage-results.json from raw findings + compact AI classifications.

The AI agent outputs a lightweight classifications file (just ID mappings +
verdicts). This module merges that with the raw Omnileak data to produce
the complete triage JSON — guaranteeing every raw finding is accounted for,
all required fields are present, and the risk score is computed correctly.

Usage::

    from core.ai.triage_writer import assemble
    path = assemble(
        raw_path="aggregated_secrets.json",
        classifications_path="classifications.json",
        prefilter_path="prefiltered.json",    # optional
        repo_name="my-app",
        repo_url="https://github.com/org/my-app",
        output_dir="./output",
    )

Or from the CLI::

    python3 -m core.ai.triage_writer \\
        --raw aggregated.json \\
        --classifications classifications.json \\
        --prefilter prefiltered.json \\
        --repo my-app \\
        --out ./output
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone

from core.ai.constants import compute_risk_score

logger = logging.getLogger(__name__)

ASSEMBLED_BY = "triage_writer/v1"


def _build_raw_index(raw_findings):
    """Index raw findings by their ID for fast lookup."""
    return {f["id"]: f for f in raw_findings}


def _make_finding(id_, raw, classification_data=None, fp_category=None):
    """Build a single triage finding from raw data + optional classification.

    For TPs: all fields populated from classification_data.
    For DUPs: severity copied from classification_data (mirrors the primary).
    For FPs and auto-FPs: severity/confidence/environment/remediation/effort are null.
    """
    cls = classification_data or {}

    if fp_category:
        classification = "FALSE_POSITIVE"
    else:
        classification = cls.get("classification", "DUPLICATE")

    # TPs and DUPs carry severity; FPs don't
    has_severity = classification in ("TRUE_POSITIVE", "DUPLICATE")

    return {
        "id": id_,
        "omnileak_ids": cls.get("omnileak_ids", [raw.get("id")]),
        "classification": classification,
        "severity": cls.get("severity") if has_severity else None,
        "category": cls.get("category", raw.get("secret_type", "")),
        "secret_value": raw.get("secret_value", ""),
        "file_path": raw.get("file_path", ""),
        "line_number": raw.get("line_number", ""),
        "commit": raw.get("commit_hash", ""),
        "on_disk": cls.get("on_disk", "unknown"),
        "confidence": cls.get("confidence") if classification == "TRUE_POSITIVE" else None,
        "environment": cls.get("environment") if classification == "TRUE_POSITIVE" else None,
        "remediation": cls.get("remediation") if classification == "TRUE_POSITIVE" else None,
        "effort": cls.get("effort") if classification == "TRUE_POSITIVE" else None,
        "detected_by": raw.get("found_by", []),
        "fp_reason": f"Auto-filtered: {fp_category}" if fp_category else cls.get("fp_reason"),
        "duplicate_of": cls.get("duplicate_of"),
    }


def assemble(
    raw_path,
    classifications_path,
    repo_name,
    output_dir,
    prefilter_path=None,
    repo_url="",
    last_commit="",
    mode="full_scan",
):
    """Assemble full triage-results.json from raw + classifications.

    Parameters
    ----------
    raw_path : str
        Path to Omnileak aggregated_secrets.json.
    classifications_path : str
        Path to compact classifications JSON from the AI agent.
    repo_name : str
        Repository name (used in meta and file naming).
    output_dir : str
        Directory to write output files.
    prefilter_path : str, optional
        Path to prefiltered.json (if pre-filtering was used).
    repo_url : str, optional
        Remote origin URL for commit hyperlinks.
    last_commit : str, optional
        Latest commit hash at scan time.
    mode : str, optional
        "full_scan" or "triage_only".

    Returns
    -------
    str
        Path to the written triage-results.json.
    """
    with open(raw_path, "r", encoding="utf-8") as f:
        raw_findings = json.load(f)

    with open(classifications_path, "r", encoding="utf-8") as f:
        classifications = json.load(f)

    prefilter_data = None
    if prefilter_path and os.path.isfile(prefilter_path):
        with open(prefilter_path, "r", encoding="utf-8") as f:
            prefilter_data = json.load(f)

    raw_index = _build_raw_index(raw_findings)
    classified_ids = set()
    all_findings = []
    finding_id = 0

    # 1. Process AI classifications
    for cls in classifications.get("findings", []):
        for oid in cls.get("omnileak_ids", []):
            classified_ids.add(oid)
        finding_id += 1
        # Use first omnileak_id's raw data as the base
        first_oid = cls["omnileak_ids"][0] if cls.get("omnileak_ids") else None
        raw = raw_index.get(first_oid, {})
        finding = _make_finding(finding_id, raw, cls)
        finding["id"] = finding_id
        all_findings.append(finding)

    # 2. Process auto-FPs from prefilter (if available)
    if prefilter_data:
        for item in prefilter_data.get("auto_fp", []):
            raw_id = item.get("id")
            if raw_id not in classified_ids:
                classified_ids.add(raw_id)
                finding_id += 1
                finding = _make_finding(finding_id, item, fp_category=item.get("fp_category", "prefilter"))
                all_findings.append(finding)

    # 3. Any raw findings not yet accounted for → unmapped (flagged as DUPLICATE
    #    of the closest match, or as unclassified)
    for raw_id, raw in raw_index.items():
        if raw_id not in classified_ids:
            finding_id += 1
            finding = _make_finding(finding_id, raw, {
                "classification": "DUPLICATE",
                "omnileak_ids": [raw_id],
                "duplicate_of": None,
                "fp_reason": None,
            })
            finding["id"] = finding_id
            all_findings.append(finding)

    composites = classifications.get("composite_vulnerabilities", [])

    risk_score = compute_risk_score(all_findings, composites)

    tp_count = sum(1 for f in all_findings if f["classification"] == "TRUE_POSITIVE")
    fp_count = sum(1 for f in all_findings if f["classification"] == "FALSE_POSITIVE")
    dup_count = sum(1 for f in all_findings if f["classification"] == "DUPLICATE")
    ai_only = sum(1 for f in all_findings
                  if f["classification"] == "TRUE_POSITIVE" and f.get("detected_by") == ["AI"])

    triage = {
        "meta": {
            "repo": repo_name,
            "repo_url": repo_url,
            "scan_date": datetime.now(timezone.utc).isoformat(),
            "last_commit": last_commit,
            "mode": mode,
            "risk_score": risk_score,
            "total_raw_findings": len(raw_findings),
            "true_positives": tp_count,
            "false_positives_filtered": fp_count,
            "duplicates": dup_count,
            "ai_only_findings": ai_only,
            "deep_analysis_performed": bool(composites),
            "assembled_by": ASSEMBLED_BY,
        },
        "findings": all_findings,
        "composite_vulnerabilities": composites,
    }

    output_name = f"{repo_name}_triage-results_{risk_score}.json"
    output_path = os.path.join(output_dir, output_name)
    os.makedirs(output_dir, exist_ok=True)

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(triage, f, indent=2)

    logger.info(
        "Assembled triage: %s (%d TPs, %d FPs, %d total, risk=%d)",
        output_path, tp_count, fp_count, len(all_findings), risk_score,
    )
    return output_path


# ── CLI ──────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if len(sys.argv) < 2 or "--help" in sys.argv:
        print(
            "Usage: python3 -m core.ai.triage_writer \\\n"
            "  --raw <aggregated.json> \\\n"
            "  --classifications <classifications.json> \\\n"
            "  --repo <name> \\\n"
            "  --out <output_dir> \\\n"
            "  [--prefilter <prefiltered.json>] \\\n"
            "  [--repo-url <url>] \\\n"
            "  [--last-commit <hash>]"
        )
        sys.exit(1)

    def _arg(flag):
        if flag in sys.argv:
            idx = sys.argv.index(flag)
            return sys.argv[idx + 1] if idx + 1 < len(sys.argv) else None
        return None

    path = assemble(
        raw_path=_arg("--raw"),
        classifications_path=_arg("--classifications"),
        repo_name=_arg("--repo") or "unknown",
        output_dir=_arg("--out") or ".",
        prefilter_path=_arg("--prefilter"),
        repo_url=_arg("--repo-url") or "",
        last_commit=_arg("--last-commit") or "",
    )
    print(f"Wrote {path}")
