from ctm.scanner import normalize_scanner_records


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


def test_severity_is_normalized_and_status_preserved():
    data = normalize_scanner_records(
        [{"host": "api", "severity": "Moderate"}], "qualys"
    )
    finding = data["findings"][0]

    assert finding["vulnerability"]["severity"] == "medium"
    assert finding["vulnerability"]["status"] == "suspected"


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
