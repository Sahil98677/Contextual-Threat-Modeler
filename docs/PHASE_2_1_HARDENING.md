# CTM Phase 2.1 — Scanner Normalization Hardening

Phase 2.1 hardens the boundary between external scanner exports and CTM's internal data model.

## Changes

- Added explicit boolean parsing so values such as `"false"` are not treated as `True`.
- Normalized asset criticality to CTM's 1–5 range.
- Added safe fallback for malformed criticality values.
- Normalized scanner severity values to `critical`, `high`, `medium`, `low`, or `info`.
- Preserved explicit vulnerability status when supplied.
- Added deterministic, sanitized scanner asset IDs.
- Added type checks for controls and tags.
- Normalized `exploit_available` to a real boolean.
- Added regression tests for the above cases.

## Boundary behavior

Scanner exports are untrusted input. CTM should normalize and constrain external values before they influence scoring or decisions.

This layer does not execute scanners and does not change scanner exports.
