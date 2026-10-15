from ctm.models import Asset, Finding
from ctm.scanner import normalize_scanner_records
from ctm.scoring.risk import calculate_risk


def test_string_false_is_not_true():
    data = normalize_scanner_records(
        [{
            "host": "api.example.test",
            "internet_facing": "false",
            "authentication_required": "false",
            "production": "false",
            "secret_exposed": "false",
            "severity": "high",
        }],
        "nuclei",
    )
    finding = data["findings"][0]
    asset = next(iter(data["assets"].values()))

    assert finding["exposure"]["internet_facing"] is False
    assert finding["exposure"]["authentication_required"] is False
    assert finding["evidence"]["secret_exposed"] is False
    assert asset["production"] is False


def test_non_finite_exploit_evidence_defaults_to_false():
    for value in (float("nan"), float("inf"), float("-inf")):
        data = normalize_scanner_records(
            [{"host": "api", "exploit_available": value}],
            "generic-json",
        )
        finding = data["findings"][0]
        assert finding["vulnerability"]["exploit_available"] is False


def test_finite_numeric_exploit_evidence_is_preserved():
    for value, expected in ((1, True), (0, False)):
        data = normalize_scanner_records(
            [{"host": "api", "exploit_available": value}],
            "generic-json",
        )
        finding = data["findings"][0]
        assert finding["vulnerability"]["exploit_available"] is expected


def test_numeric_criticality_is_clamped_to_one_to_five():
    low = normalize_scanner_records(
        [{"host": "low", "criticality": 0}], "trivy"
    )
    high = normalize_scanner_records(
        [{"host": "high", "criticality": 99}], "trivy"
    )

    assert next(iter(low["assets"].values()))["criticality"] == 1
    assert next(iter(high["assets"].values()))["criticality"] == 5


def test_invalid_criticality_falls_back_to_three():
    data = normalize_scanner_records(
        [{"host": "api", "criticality": "not-a-number"}], "nessus"
    )
    assert next(iter(data["assets"].values()))["criticality"] == 3


def test_non_finite_criticality_falls_back_to_three():
    for value in ("Infinity", "-Infinity", float("inf"), float("-inf")):
        data = normalize_scanner_records(
            [{"host": "api", "criticality": value}],
            "generic-json",
        )
        asset = next(iter(data["assets"].values()))
        assert asset["criticality"] == 3


def test_invalid_data_classification_becomes_unknown():
    for value in (["confidential"], {"classification": "restricted"}, 123):
        data = normalize_scanner_records(
            [{"host": "api", "data_classification": value}],
            "generic-json",
        )
        asset = next(iter(data["assets"].values()))
        assert asset["data_classification"] == "unknown"


def test_data_classification_is_normalized():
    data = normalize_scanner_records(
        [{"host": "api", "data_classification": "  CONFIDENTIAL  "}],
        "generic-json",
    )
    asset = next(iter(data["assets"].values()))
    assert asset["data_classification"] == "confidential"


def test_missing_data_classification_keeps_internal_default():
    data = normalize_scanner_records(
        [{"host": "api"}],
        "generic-json",
    )
    asset = next(iter(data["assets"].values()))
    assert asset["data_classification"] == "internal"


def test_mixed_asset_tags_keep_only_non_empty_strings():
    data = normalize_scanner_records(
        [{
            "host": "api",
            "tags": [
                " internet-facing ",
                123,
                None,
                "",
                "production",
                {"tag": "admin"},
            ],
        }],
        "generic-json",
    )

    asset = next(iter(data["assets"].values()))
    assert asset["tags"] == ["internet-facing", "production"]


def test_tuple_asset_tags_are_normalized():
    data = normalize_scanner_records(
        [{"host": "api", "tags": ("security", "", "critical")}],
        "generic-json",
    )

    asset = next(iter(data["assets"].values()))
    assert asset["tags"] == ["security", "critical"]


def test_malformed_method_uses_get_default():
    data = normalize_scanner_records(
        [{"host": "api", "method": {"unexpected": "POST"}}],
        "generic-json",
    )
    assert data["findings"][0]["method"] == "GET"


def test_malformed_path_falls_back_safely():
    data = normalize_scanner_records(
        [{"host": "api", "path": {"unexpected": "/admin"}}],
        "generic-json",
    )
    assert data["findings"][0]["path"] == "/scanner-finding/1"


def test_malformed_endpoint_type_uses_service_fallback():
    data = normalize_scanner_records(
        [{
            "host": "api",
            "endpoint_type": ["invalid"],
            "service": "API",
        }],
        "generic-json",
    )
    assert data["findings"][0]["endpoint_type"] == "api"


def test_malformed_title_falls_back_to_valid_plugin_name():
    data = normalize_scanner_records(
        [{
            "host": "api",
            "title": {"unexpected": "fake title"},
            "plugin_name": "Valid plugin title",
        }],
        "generic-json",
    )
    assert (
        data["findings"][0]["vulnerability"]["title"]
        == "Valid plugin title"
    )


def test_malformed_optional_vulnerability_text_is_ignored():
    data = normalize_scanner_records(
        [{
            "host": "api",
            "cve": ["CVE-2099-1234"],
            "description": {"unexpected": "text"},
            "attack_complexity": ["low"],
            "impact": {"level": "critical"},
        }],
        "generic-json",
    )
    vulnerability = data["findings"][0]["vulnerability"]

    assert "cve" not in vulnerability
    assert "description" not in vulnerability
    assert "attack_complexity" not in vulnerability
    assert "impact" not in vulnerability


def test_severity_is_normalized_without_promoting_status():
    data = normalize_scanner_records(
        [{"host": "api", "severity": "Moderate"}], "qualys"
    )
    finding = data["findings"][0]

    assert finding["vulnerability"]["severity"] == "medium"
    assert finding["vulnerability"]["status"] == "discovered"


def test_explicit_status_overrides_severity_mapping():
    data = normalize_scanner_records(
        [{"host": "api", "severity": "critical", "status": "discovered"}],
        "nuclei",
    )
    assert data["findings"][0]["vulnerability"]["status"] == "discovered"


def test_asset_ids_are_deterministic_and_safe():
    data = normalize_scanner_records(
        [{"host": "api.example.com:443/path?a=1&b=2"}], "Nuclei"
    )
    asset_id = next(iter(data["assets"]))

    assert asset_id == "SCANNER-NUCLEI-api.example.com:443-path-a-1-b-2"
    assert " " not in asset_id
    assert "/" not in asset_id
    assert "?" not in asset_id
    assert "&" not in asset_id


def test_distinct_targets_with_colliding_sanitized_ids_stay_separate():
    data = normalize_scanner_records(
        [{"host": "api.example.test/a"}, {"host": "api.example.test?a"}],
        "nuclei",
    )

    assert len(data["assets"]) == 2
    assert len({finding["asset_id"] for finding in data["findings"]}) == 2


def test_non_dict_controls_and_tags_are_safely_ignored():
    data = normalize_scanner_records(
        [{
            "host": "api",
            "controls": "invalid",
            "tags": "invalid",
        }],
        "generic-json",
    )
    finding = data["findings"][0]
    asset = next(iter(data["assets"].values()))

    assert finding["controls"] == {}
    assert asset["tags"] == []


def test_malformed_status_defaults_to_discovered():
    for value in ({"status": "confirmed"}, ["confirmed"], 123):
        data = normalize_scanner_records(
            [{
                "host": "api",
                "status": value,
                "severity": "high",
            }],
            "generic-json",
        )

        assert (
            data["findings"][0]["vulnerability"]["status"]
            == "discovered"
        )


def test_high_and_critical_severity_do_not_promote_validation_status():
    for severity in ("high", "critical"):
        data = normalize_scanner_records(
            [{"host": "api", "severity": severity}],
            "generic-json",
        )

        vulnerability = data["findings"][0]["vulnerability"]
        assert vulnerability["status"] == "discovered"
        assert vulnerability["severity"] == severity


def test_valid_explicit_status_is_preserved():
    data = normalize_scanner_records(
        [{
            "host": "api",
            "status": " CONFIRMED ",
            "severity": "low",
        }],
        "generic-json",
    )

    assert data["findings"][0]["vulnerability"]["status"] == "confirmed"


def test_malformed_asset_owner_is_ignored():
    for value in ({"name": "admin"}, ["admin"], 123):
        data = normalize_scanner_records(
            [{"host": "api", "owner": value}],
            "generic-json",
        )

        asset = next(iter(data["assets"].values()))
        assert asset["owner"] == ""


def test_secret_type_accepts_only_non_empty_strings():
    for value in ({"type": "api_key"}, ["api_key"], 123, "  "):
        data = normalize_scanner_records(
            [{
                "host": "api",
                "secret_type": value,
                "secret_exposed": False,
            }],
            "generic-json",
        )

        finding = data["findings"][0]
        assert finding["evidence"]["secret_type"] is None
        assert finding["evidence"]["secret_exposed"] is False


def test_valid_secret_type_is_trimmed():
    data = normalize_scanner_records(
        [{
            "host": "api",
            "secret_type": "  api_key  ",
        }],
        "generic-json",
    )

    assert data["findings"][0]["evidence"]["secret_type"] == "api_key"


def test_non_dict_records_are_skipped_without_reindexing():
    data = normalize_scanner_records(
        [
            None,
            {"host": "api", "title": "First valid finding"},
            "malformed record",
            {"host": "api", "title": "Second valid finding"},
        ],
        "generic-json",
    )

    assert len(data["findings"]) == 2
    assert [finding["id"] for finding in data["findings"]] == [
        "GENERIC-JSON-0002",
        "GENERIC-JSON-0004",
    ]


def test_valid_service_and_port_generate_normalized_path():
    data = normalize_scanner_records(
        [{"host": "api", "service": " HTTPS ", "port": "443"}],
        "generic-json",
    )

    assert data["findings"][0]["path"] == "https/443"


def test_invalid_port_uses_safe_fallback_path():
    invalid_ports = (0, -1, 65536, "70000", "abc", [], {}, True, 443.5)

    for port in invalid_ports:
        data = normalize_scanner_records(
            [{"host": "api", "service": "https", "port": port}],
            "generic-json",
        )

        assert data["findings"][0]["path"] == "/scanner-finding/1"


def test_malformed_service_uses_safe_default_for_valid_port():
    data = normalize_scanner_records(
        [{"host": "api", "service": {"name": "https"}, "port": 443}],
        "generic-json",
    )

    assert data["findings"][0]["path"] == "tcp/443"


def test_malformed_service_does_not_become_endpoint_type():
    data = normalize_scanner_records(
        [{
            "host": "api",
            "service": ["https"],
            "endpoint_type": {},
        }],
        "generic-json",
    )

    assert data["findings"][0]["endpoint_type"] == "unknown"


def test_raw_scanner_record_does_not_override_normalized_secret_evidence():
    asset = Asset(id="asset-1", name="api")

    def score_with_raw_record(raw_secret_exposed):
        finding = Finding(
            id="finding-1",
            asset_id="asset-1",
            method="GET",
            path="/",
            endpoint_type="http",
            vulnerability={"severity": "low", "status": "discovered"},
            evidence={
                "secret_exposed": False,
                "scanner_record": {
                    "secret_exposed": raw_secret_exposed,
                },
            },
        )
        calculate_risk(finding, asset)
        return finding

    raw_claim_true = score_with_raw_record(True)
    raw_claim_false = score_with_raw_record(False)

    assert raw_claim_true.score == raw_claim_false.score
    assert not any(
        "secret exposure" in reason.lower()
        for reason in raw_claim_true.rationale
    )
