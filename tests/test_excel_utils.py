import pandas as pd
import pytest

from core.excel_utils import sanitize_for_excel, SECRET_VALUE_LIMIT, ILLEGAL_CHARS_RE


class TestSanitizeForExcel:
    def test_strips_control_characters(self):
        df = pd.DataFrame([{"secret_value": "before\x00\x07\x0eafter", "other": "clean"}])
        result = sanitize_for_excel(df)
        assert result.iloc[0]["secret_value"] == "beforeafter"
        assert result.iloc[0]["other"] == "clean"

    def test_truncates_long_secret_value(self):
        long_val = "A" * (SECRET_VALUE_LIMIT + 500)
        df = pd.DataFrame([{"secret_value": long_val}])
        result = sanitize_for_excel(df)
        val = result.iloc[0]["secret_value"]
        assert val.endswith("[truncated]")
        assert len(val) == SECRET_VALUE_LIMIT + len(" [truncated]")

    def test_does_not_truncate_short_value(self):
        df = pd.DataFrame([{"secret_value": "short"}])
        result = sanitize_for_excel(df)
        assert result.iloc[0]["secret_value"] == "short"

    def test_does_not_modify_original(self):
        df = pd.DataFrame([{"secret_value": "before\x00after"}])
        sanitize_for_excel(df)
        assert df.iloc[0]["secret_value"] == "before\x00after"

    def test_handles_non_string_columns(self):
        df = pd.DataFrame([{"secret_value": "val", "line_number": 42}])
        result = sanitize_for_excel(df)
        assert result.iloc[0]["line_number"] == 42

    def test_handles_none_values(self):
        df = pd.DataFrame([{"secret_value": None, "other": None}])
        result = sanitize_for_excel(df)
        assert result.iloc[0]["secret_value"] is None

    def test_handles_empty_dataframe(self):
        df = pd.DataFrame(columns=["secret_value", "other"])
        result = sanitize_for_excel(df)
        assert len(result) == 0

    def test_works_without_secret_value_column(self):
        df = pd.DataFrame([{"name": "no\x00secret\x07here"}])
        result = sanitize_for_excel(df)
        assert result.iloc[0]["name"] == "nosecrethere"

    def test_truncation_at_exact_limit(self):
        exact = "B" * SECRET_VALUE_LIMIT
        df = pd.DataFrame([{"secret_value": exact}])
        result = sanitize_for_excel(df)
        assert result.iloc[0]["secret_value"] == exact  # not truncated

    def test_truncation_at_limit_plus_one(self):
        over = "C" * (SECRET_VALUE_LIMIT + 1)
        df = pd.DataFrame([{"secret_value": over}])
        result = sanitize_for_excel(df)
        assert result.iloc[0]["secret_value"].endswith("[truncated]")


class TestIllegalCharsRegex:
    def test_matches_null_byte(self):
        assert ILLEGAL_CHARS_RE.search("\x00")

    def test_matches_bell(self):
        assert ILLEGAL_CHARS_RE.search("\x07")

    def test_does_not_match_newline(self):
        assert not ILLEGAL_CHARS_RE.search("\n")

    def test_does_not_match_tab(self):
        assert not ILLEGAL_CHARS_RE.search("\t")

    def test_does_not_match_printable(self):
        assert not ILLEGAL_CHARS_RE.search("hello world 123 !@#")
