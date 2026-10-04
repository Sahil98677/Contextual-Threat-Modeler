from ctm.engine import run


def test_engine_returns_sorted_findings():
    results = run("mock_inputs")
    assert results
    assert all(results[i].score >= results[i + 1].score for i in range(len(results) - 1))
    assert results[0].decision in {
        "TEST_IMMEDIATELY",
        "PRIORITIZE_VALIDATION",
        "INVESTIGATE",
        "MONITOR",
    }
