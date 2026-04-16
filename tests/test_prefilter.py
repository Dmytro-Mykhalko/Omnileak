import json
import os

import pytest

from core.ai.prefilter import (
    prefilter, prefilter_file, prefilter_batch,
    _shannon_entropy, _check_known_prefix, _classify_sensitivity,
    _try_decode_docker_auth,
)


def _finding(file_path="src/app.py", id_="f1"):
    return {
        "id": id_,
        "repository": "test-repo",
        "file_path": file_path,
        "line_number": 1,
        "secret_type": "generic",
        "secret_value": "FAKE_VALUE_000",
        "commit_hash": "aaa1111",
        "found_by": ["gitleaks"],
    }


class TestPrefilter:
    def test_normal_file_passes_through(self):
        result = prefilter([_finding("src/config.yml")])
        assert len(result["needs_triage"]) == 1
        assert len(result["auto_fp"]) == 0

    def test_node_modules_filtered(self):
        result = prefilter([_finding("node_modules/pkg/index.js")])
        assert len(result["needs_triage"]) == 0
        assert len(result["auto_fp"]) == 1
        assert result["auto_fp"][0]["fp_category"] == "vendor_code"

    def test_vendor_filtered(self):
        result = prefilter([_finding("vendor/lib/translations/hu.php")])
        assert result["auto_fp"][0]["fp_category"] == "vendor_code"

    def test_lock_files_filtered(self):
        for name in ["pnpm-lock.yaml", "yarn.lock", "package-lock.json",
                      "composer.lock", "Gemfile.lock", "go.sum", "Cargo.lock"]:
            result = prefilter([_finding(name)])
            assert len(result["auto_fp"]) == 1, f"{name} should be filtered"
            assert result["auto_fp"][0]["fp_category"] == "lock_file"

    def test_minified_js_filtered(self):
        result = prefilter([_finding("public/assets/app.min.js")])
        assert result["auto_fp"][0]["fp_category"] == "minified_code"

    def test_bundle_js_filtered(self):
        result = prefilter([_finding("assets/main.bundle.js")])
        assert result["auto_fp"][0]["fp_category"] == "minified_code"

    def test_dist_directory_filtered(self):
        result = prefilter([_finding("dist/index.js")])
        assert result["auto_fp"][0]["fp_category"] == "bundled_frontend"

    def test_source_map_filtered(self):
        result = prefilter([_finding("assets/app.js.map")])
        assert result["auto_fp"][0]["fp_category"] == "source_map"

    def test_snapshot_filtered(self):
        result = prefilter([_finding("tests/__snapshots__/App.test.js.snap")])
        assert result["auto_fp"][0]["fp_category"] == "test_snapshot"

    def test_mixed_findings(self):
        findings = [
            _finding("src/config.yml", "f1"),
            _finding("node_modules/pkg/i.js", "f2"),
            _finding("vendor/lib/x.php", "f3"),
            _finding(".env", "f4"),
        ]
        result = prefilter(findings)
        assert len(result["needs_triage"]) == 2
        assert len(result["auto_fp"]) == 2
        assert result["summary"]["total"] == 4

    def test_summary_counts(self):
        findings = [
            _finding("node_modules/a.js", "f1"),
            _finding("node_modules/b.js", "f2"),
            _finding("vendor/c.php", "f3"),
            _finding("src/d.py", "f4"),
        ]
        result = prefilter(findings)
        s = result["summary"]
        assert s["total"] == 4
        assert s["needs_triage"] == 1
        assert s["auto_fp"] == 3
        assert s["fp_categories"]["vendor_code"] == 3

    def test_empty_input(self):
        result = prefilter([])
        assert result["needs_triage"] == []
        assert result["auto_fp"] == []
        assert result["summary"]["total"] == 0

    def test_original_finding_fields_preserved(self):
        f = _finding("node_modules/pkg/i.js")
        result = prefilter([f])
        fp = result["auto_fp"][0]
        assert fp["id"] == f["id"]
        assert fp["secret_value"] == f["secret_value"]
        assert "fp_category" in fp


class TestContentRules:
    def test_sri_hash_filtered(self):
        f = _finding("src/index.html")
        f["secret_value"] = "sha256-abcdef1234567890abcdef1234567890abcdef12345678"
        result = prefilter([f])
        assert len(result["auto_fp"]) == 1
        assert result["auto_fp"][0]["fp_category"] == "sri_hash"

    def test_sha384_sri_hash_filtered(self):
        f = _finding("src/index.html")
        f["secret_value"] = "sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC"
        result = prefilter([f])
        assert result["auto_fp"][0]["fp_category"] == "sri_hash"

    def test_hex_color_filtered(self):
        f = _finding("src/styles.css")
        f["secret_value"] = "#ff6600"
        result = prefilter([f])
        assert len(result["auto_fp"]) == 1
        assert result["auto_fp"][0]["fp_category"] == "hex_color"

    def test_hex_color_without_hash_filtered(self):
        f = _finding("src/styles.css")
        f["secret_value"] = "ff6600"
        result = prefilter([f])
        assert result["auto_fp"][0]["fp_category"] == "hex_color"

    def test_non_hex_color_passes(self):
        f = _finding("src/styles.css")
        f["secret_value"] = "not_a_color_code"
        result = prefilter([f])
        assert len(result["needs_triage"]) == 1

    def test_ci_badge_url_filtered(self):
        f = _finding("README.md")
        f["secret_value"] = "https://img.shields.io/badge/coverage-95%25-green"
        result = prefilter([f])
        assert result["auto_fp"][0]["fp_category"] == "ci_badge_url"

    def test_coveralls_badge_filtered(self):
        f = _finding("README.md")
        f["secret_value"] = "https://coveralls.io/repos/github/org/repo/badge.svg"
        result = prefilter([f])
        assert result["auto_fp"][0]["fp_category"] == "ci_badge_url"

    def test_translation_file_filtered(self):
        f = _finding("translations/en/messages.json")
        result = prefilter([f])
        assert result["auto_fp"][0]["fp_category"] == "translation_file"

    def test_i18n_directory_filtered(self):
        f = _finding("src/i18n/de.json")
        result = prefilter([f])
        assert result["auto_fp"][0]["fp_category"] == "translation_file"

    def test_locales_directory_filtered(self):
        f = _finding("locales/fr.yml")
        result = prefilter([f])
        assert result["auto_fp"][0]["fp_category"] == "translation_file"

    def test_path_rule_takes_precedence_over_content(self):
        """Path rules win even if content rules would also match."""
        f = _finding("node_modules/pkg/index.js")
        f["secret_value"] = "sha256-abc123"
        result = prefilter([f])
        assert result["auto_fp"][0]["fp_category"] == "vendor_code"


class TestKnownPrefixes:
    def test_aws_key_overrides_vendor_fp(self):
        """AKIA prefix in vendor/ should NOT be auto-FP'd."""
        f = _finding("vendor/lib/config.py")
        f["secret_value"] = "AKIAIOSFODNN7EXAMPLE"
        result = prefilter([f])
        assert len(result["needs_triage"]) == 1
        assert len(result["auto_fp"]) == 0
        assert result["needs_triage"][0]["tp_hint"] == "known_prefix:aws_access_key"

    def test_github_pat_overrides_node_modules(self):
        f = _finding("node_modules/pkg/.env")
        f["secret_value"] = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"
        result = prefilter([f])
        assert len(result["needs_triage"]) == 1
        assert "github_pat" in result["needs_triage"][0]["tp_hint"]

    def test_slack_bot_token(self):
        f = _finding("config/app.yml")
        f["secret_value"] = "xoxb-FAKE000000000-FAKE000000000-FakeTestValueXx"
        result = prefilter([f])
        assert result["needs_triage"][0]["tp_hint"] == "known_prefix:slack_bot_token"

    def test_stripe_secret_live(self):
        f = _finding("config/payment.py")
        f["secret_value"] = "sk_live_FAKE00TEST"
        result = prefilter([f])
        assert "stripe_secret_live" in result["needs_triage"][0]["tp_hint"]

    def test_private_key_header(self):
        f = _finding("deploy/key.pem")
        f["secret_value"] = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQ..."
        result = prefilter([f])
        assert "rsa_private_key" in result["needs_triage"][0]["tp_hint"]

    def test_npm_token(self):
        f = _finding(".npmrc")
        f["secret_value"] = "npm_abcdefghijklmnop1234567890ABCDEF"
        result = prefilter([f])
        assert "npm_token" in result["needs_triage"][0]["tp_hint"]

    def test_sentry_token(self):
        f = _finding("config/sentry.yml")
        f["secret_value"] = "sntrys_eyJpYXQiOjE2OTg2NTY..."
        result = prefilter([f])
        assert "sentry_token" in result["needs_triage"][0]["tp_hint"]

    def test_payment_secret_key(self):
        f = _finding("db/dump.sql")
        f["secret_value"] = "api_sk_12345abcdef67890"
        result = prefilter([f])
        assert "payment_secret_key" in result["needs_triage"][0]["tp_hint"]

    def test_non_matching_prefix_no_hint(self):
        f = _finding("src/app.py")
        f["secret_value"] = "some_random_value_not_a_known_prefix"
        result = prefilter([f])
        assert result["needs_triage"][0]["tp_hint"] is None

    def test_tp_hint_count_in_summary(self):
        findings = [
            _finding("src/a.py", "f1"),
            _finding("src/b.py", "f2"),
        ]
        findings[0]["secret_value"] = "AKIAIOSFODNN7EXAMPLE"
        findings[1]["secret_value"] = "just_a_normal_value"
        result = prefilter(findings)
        assert result["summary"]["tp_hints"] == 1

    def test_google_api_key(self):
        f = _finding("src/firebase.js")
        f["secret_value"] = "AIzaSyA1B2C3D4E5F6G7H8I9J0KlMnOpQrStUv"
        result = prefilter([f])
        assert "google_api_key" in result["needs_triage"][0]["tp_hint"]


class TestEnrichment:
    def test_entropy_computed(self):
        f = _finding("src/app.py")
        f["secret_value"] = "Xy9kL2mN4pQ7rT0wBcDfGhJv"
        result = prefilter([f])
        finding = result["needs_triage"][0]
        assert "entropy" in finding
        assert finding["entropy"] > 3.0

    def test_high_entropy_flag(self):
        f = _finding("src/app.py")
        f["secret_value"] = "aB3$xZ9#kL7!mN2@pQ5&rT8*"  # high entropy, 24 chars
        result = prefilter([f])
        assert result["needs_triage"][0]["high_entropy"] is True

    def test_low_entropy_not_flagged(self):
        f = _finding("src/app.py")
        f["secret_value"] = "password_password_password"
        result = prefilter([f])
        assert result["needs_triage"][0]["high_entropy"] is False

    def test_short_string_not_high_entropy(self):
        """Even high-entropy strings under 20 chars are not flagged."""
        f = _finding("src/app.py")
        f["secret_value"] = "aB3$xZ9#kL7!"  # 13 chars
        result = prefilter([f])
        assert result["needs_triage"][0]["high_entropy"] is False

    def test_sensitivity_production(self):
        f = _finding("values_prod/rabbitmq.yaml")
        result = prefilter([f])
        assert result["needs_triage"][0]["sensitivity"] == "production"

    def test_sensitivity_infrastructure(self):
        f = _finding("helm/charts/app/values.yaml")
        result = prefilter([f])
        assert result["needs_triage"][0]["sensitivity"] == "infrastructure"

    def test_sensitivity_deploy(self):
        f = _finding("deploy/docker-compose.prod.yml")
        result = prefilter([f])
        assert result["needs_triage"][0]["sensitivity"] == "infrastructure"

    def test_sensitivity_test(self):
        f = _finding("test/config/fixtures.py")
        result = prefilter([f])
        assert result["needs_triage"][0]["sensitivity"] == "test"

    def test_sensitivity_none_for_normal_path(self):
        f = _finding("src/app.py")
        result = prefilter([f])
        assert result["needs_triage"][0]["sensitivity"] is None

    def test_sensitivity_staging(self):
        f = _finding("values_stage/db.yaml")
        result = prefilter([f])
        assert result["needs_triage"][0]["sensitivity"] == "staging"

    def test_sensitivity_env_file(self):
        f = _finding(".env")
        result = prefilter([f])
        assert result["needs_triage"][0]["sensitivity"] == "config"

    def test_sensitivity_counts_in_summary(self):
        findings = [
            _finding("values_prod/a.yaml", "f1"),
            _finding("values_prod/b.yaml", "f2"),
            _finding("test/c.py", "f3"),
            _finding("src/d.py", "f4"),
        ]
        result = prefilter(findings)
        sc = result["summary"]["sensitivity_counts"]
        assert sc.get("production") == 2
        assert sc.get("test") == 1

    def test_high_entropy_count_in_summary(self):
        findings = [
            _finding("src/a.py", "f1"),
            _finding("src/b.py", "f2"),
        ]
        findings[0]["secret_value"] = "Xy9kL2mN4pQ7rT0wBcDfGhJv"  # high entropy, 24 chars
        findings[1]["secret_value"] = "password"  # low entropy
        result = prefilter(findings)
        assert result["summary"]["high_entropy"] == 1


class TestDockerDecode:
    def test_decodes_dockerconfigjson(self):
        import base64
        inner_auth = base64.b64encode(b"myuser:mypass123").decode()
        docker_json = json.dumps({"auths": {"registry.example.com": {"auth": inner_auth}}})
        blob = base64.b64encode(docker_json.encode()).decode()

        f = _finding("templates/secrets/docker.yaml")
        f["secret_value"] = blob
        f["secret_type"] = "kubernetes-secret-yaml-dockerconfigjson"
        result = prefilter([f])
        finding = result["needs_triage"][0]
        assert "decoded_docker_creds" in finding
        assert "myuser:mypass123" in finding["decoded_docker_creds"]

    def test_no_decode_for_non_docker(self):
        f = _finding("src/app.py")
        f["secret_value"] = "just_a_regular_secret"
        result = prefilter([f])
        assert "decoded_docker_creds" not in result["needs_triage"][0]


class TestHelpers:
    def test_shannon_entropy_zero_for_empty(self):
        assert _shannon_entropy("") == 0.0

    def test_shannon_entropy_zero_for_single_char(self):
        assert _shannon_entropy("aaaa") == 0.0

    def test_shannon_entropy_high_for_random(self):
        assert _shannon_entropy("aB3$xZ9#kL7!mN2@pQ5&rT8*") > 4.0

    def test_check_known_prefix_aws(self):
        assert _check_known_prefix("AKIAIOSFODNN7EXAMPLE") == "aws_access_key"

    def test_check_known_prefix_none(self):
        assert _check_known_prefix("not_a_known_prefix") is None

    def test_classify_sensitivity_prod(self):
        assert _classify_sensitivity("values_prod/db.yaml") == "production"

    def test_classify_sensitivity_none(self):
        assert _classify_sensitivity("src/app.py") is None

    def test_try_decode_docker_auth_valid(self):
        import base64
        inner = base64.b64encode(b"user:pass").decode()
        blob = json.dumps({"auths": {"reg.io": {"auth": inner}}})
        encoded = base64.b64encode(blob.encode()).decode()
        result = _try_decode_docker_auth(encoded)
        assert result == ["user:pass"]

    def test_try_decode_docker_auth_invalid(self):
        assert _try_decode_docker_auth("not_base64_at_all") is None


class TestPrefilterFile:
    def test_writes_output(self, tmp_path):
        findings = [_finding("src/app.py"), _finding("node_modules/x.js")]
        input_path = str(tmp_path / "aggregated.json")
        with open(input_path, "w") as f:
            json.dump(findings, f)

        output_path = prefilter_file(input_path)
        assert os.path.isfile(output_path)

        with open(output_path) as f:
            data = json.load(f)
        assert len(data["needs_triage"]) == 1
        assert len(data["auto_fp"]) == 1

    def test_custom_output_path(self, tmp_path):
        input_path = str(tmp_path / "in.json")
        output_path = str(tmp_path / "custom_out.json")
        with open(input_path, "w") as f:
            json.dump([], f)

        result = prefilter_file(input_path, output_path)
        assert result == output_path
        assert os.path.isfile(output_path)


class TestPrefilterBatch:
    def test_batch_processes_multiple_repos(self, tmp_path):
        for name in ["repo-a", "repo-b"]:
            repo_dir = tmp_path / name
            repo_dir.mkdir()
            findings = [_finding("src/app.py", f"{name}-1")]
            with open(repo_dir / f"{name}_aggregated_secrets.json", "w") as f:
                json.dump(findings, f)

        summaries = prefilter_batch(str(tmp_path))
        assert len(summaries) == 2
        for s in summaries:
            assert s["summary"]["total"] == 1
            assert os.path.isfile(s["output"])

    def test_batch_empty_directory(self, tmp_path):
        summaries = prefilter_batch(str(tmp_path))
        assert summaries == []

    def test_batch_writes_prefiltered_json(self, tmp_path):
        repo_dir = tmp_path / "my-repo"
        repo_dir.mkdir()
        findings = [
            _finding("src/app.py", "f1"),
            _finding("node_modules/x.js", "f2"),
        ]
        with open(repo_dir / "my-repo_aggregated_secrets.json", "w") as f:
            json.dump(findings, f)

        summaries = prefilter_batch(str(tmp_path))
        assert len(summaries) == 1
        assert summaries[0]["summary"]["needs_triage"] == 1
        assert summaries[0]["summary"]["auto_fp"] == 1

        with open(summaries[0]["output"]) as f:
            data = json.load(f)
        assert len(data["needs_triage"]) == 1
        assert len(data["auto_fp"]) == 1
