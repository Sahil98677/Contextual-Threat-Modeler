from .values import as_bool

CONTROL_MODIFIERS = {
    "waf": 0.90,
    "file_validation": 0.75,
    "av_scanning": 0.85,
    "mfa": 0.95,
    "security_headers_strong": 0.90,
}

WEB_ENDPOINT_TYPES = {"admin", "api", "file_upload"}
AUTH_ENDPOINT_TYPES = {"admin", "auth", "authentication", "login"}
WAF_CWES = {
    "CWE-22",
    "CWE-77",
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-94",
    "CWE-434",
    "CWE-918",
}
FILE_UPLOAD_CWES = {"CWE-434"}
AUTHENTICATION_CWES = {"CWE-521", "CWE-522"}
SECURITY_HEADER_CWES = {"CWE-79", "CWE-352", "CWE-1021"}


def control_modifier(
    controls: dict, endpoint_type: str, vulnerability: dict
) -> float:
    modifier = 1.0
    normalized_endpoint_type = endpoint_type.strip().lower()
    cwe = str(vulnerability.get("cwe", "")).strip().upper()

    if (
        as_bool(controls.get("waf"))
        and normalized_endpoint_type in WEB_ENDPOINT_TYPES
        and cwe in WAF_CWES
    ):
        modifier *= CONTROL_MODIFIERS["waf"]
    if (
        as_bool(controls.get("file_validation"))
        and normalized_endpoint_type == "file_upload"
        and cwe in FILE_UPLOAD_CWES
    ):
        modifier *= CONTROL_MODIFIERS["file_validation"]
    if (
        as_bool(controls.get("av_scanning"))
        and normalized_endpoint_type == "file_upload"
        and cwe in FILE_UPLOAD_CWES
    ):
        modifier *= CONTROL_MODIFIERS["av_scanning"]
    if (
        as_bool(controls.get("mfa"))
        and normalized_endpoint_type in AUTH_ENDPOINT_TYPES
        and cwe in AUTHENTICATION_CWES
    ):
        modifier *= CONTROL_MODIFIERS["mfa"]
    if (
        controls.get("security_headers") == "strong"
        and normalized_endpoint_type == "admin"
        and cwe in SECURITY_HEADER_CWES
    ):
        modifier *= CONTROL_MODIFIERS["security_headers_strong"]
    return modifier
