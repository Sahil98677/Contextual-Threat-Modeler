TECHNIQUE_MAP = {
    "file_upload": ["T1190 - Exploit Public-Facing Application"],
    "admin": ["T1078 - Valid Accounts"],
    "api": ["T1190 - Exploit Public-Facing Application"],
}


def map_mitre(endpoint_type: str, internet_facing: bool, vulnerability: dict) -> list[str]:
    if not internet_facing:
        return []
    techniques = list(TECHNIQUE_MAP.get(endpoint_type, []))
    if vulnerability.get("cwe") == "CWE-434" and "T1190 - Exploit Public-Facing Application" not in techniques:
        techniques.append("T1190 - Exploit Public-Facing Application")
    return techniques
