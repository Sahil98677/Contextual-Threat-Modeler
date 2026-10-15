import math

import pytest

from ctm.context.values import as_bool, as_optional_bool


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_boolean_uses_default(value: float) -> None:
    assert as_bool(value) is False
    assert as_bool(value, default=True) is True


@pytest.mark.parametrize("value", [math.nan, math.inf, -math.inf])
def test_non_finite_optional_boolean_remains_unknown(value: float) -> None:
    assert as_optional_bool(value) is None


@pytest.mark.parametrize(
    ("value", "expected"),
    [(True, True), (False, False), (1, True), (0, False)],
)
def test_valid_boolean_values_are_preserved(value: bool | int, expected: bool) -> None:
    assert as_bool(value) is expected
    assert as_optional_bool(value) is expected
