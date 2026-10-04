CONTROL_MODIFIERS = {
    "waf": 0.90,
    "file_validation": 0.75,
    "av_scanning": 0.85,
    "mfa": 0.95,
    "security_headers_strong": 0.90,
}


def control_modifier(controls: dict) -> float:
    modifier = 1.0
    if controls.get("waf"):
        modifier *= CONTROL_MODIFIERS["waf"]
    if controls.get("file_validation") is True:
        modifier *= CONTROL_MODIFIERS["file_validation"]
    if controls.get("av_scanning") is True:
        modifier *= CONTROL_MODIFIERS["av_scanning"]
    if controls.get("mfa") is True:
        modifier *= CONTROL_MODIFIERS["mfa"]
    if controls.get("security_headers") == "strong":
        modifier *= CONTROL_MODIFIERS["security_headers_strong"]
    return modifier
