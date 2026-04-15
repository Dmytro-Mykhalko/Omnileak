"""Shared Excel sanitization utilities.

Used by both ``core.reporter`` (scan results) and
``core.ai.triage_reporter`` (AI triage results) to prepare DataFrames
for openpyxl.
"""

import re

import pandas as pd

# Control characters that are illegal in XML / Excel cells.
ILLEGAL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")

# Truncate abnormally large values that would break Excel (limit: 32 767 chars).
SECRET_VALUE_LIMIT = 5000


def sanitize_for_excel(df):
    """Make a DataFrame safe for openpyxl.

    1. Strip control characters that are illegal in XML/Excel.
    2. Truncate ``secret_value`` when abnormally large (>5 000 chars).

    Full values are always available in the JSON report.
    """
    df = df.copy()
    for col in df.select_dtypes(include=["object", "string"]).columns:
        df[col] = df[col].apply(
            lambda v: ILLEGAL_CHARS_RE.sub("", v) if isinstance(v, str) else v
        )
    if "secret_value" in df.columns:
        df["secret_value"] = df["secret_value"].apply(
            lambda v: v[:SECRET_VALUE_LIMIT] + " [truncated]"
            if isinstance(v, str) and len(v) > SECRET_VALUE_LIMIT
            else v
        )
    return df
