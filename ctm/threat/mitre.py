EXPLOIT_PUBLIC_FACING = "T1190 - Exploit Public-Facing Application"
VALID_ACCOUNTS = "T1078 - Valid Accounts"
TECHNIQUE_REFERENCES = {
    EXPLOIT_PUBLIC_FACING: "https://attack.mitre.org/techniques/T1190/",
    VALID_ACCOUNTS: "https://attack.mitre.org/techniques/T1078/",
}
CREDENTIAL_WEAKNESS_CWES = {"CWE-521", "CWE-522"}


def _mapping_candidates(
    endpoint_type: str,
    internet_facing: object,
    vulnerability: dict,
) -> list[tuple[str, list[str]]]:
    normalized_endpoint_type = (
        endpoint_type.strip().lower() if isinstance(endpoint_type, str) else ""
    )
    if internet_facing is not True or not isinstance(vulnerability, dict):
        return []

    candidates: list[tuple[str, list[str]]] = []
    has_vulnerability_evidence = any(
        isinstance(vulnerability.get(field), str)
        and bool(vulnerability[field].strip())
        for field in ("cve", "cwe", "vulnerability_id", "qid", "plugin_id")
    ) or vulnerability.get("exploit_available") is True

    if normalized_endpoint_type in {"api", "file_upload"} and has_vulnerability_evidence:
        basis = ["internet_facing:true", f"endpoint_type:{normalized_endpoint_type}"]
        basis.extend(
            f"{field}:{vulnerability[field].strip()}"
            for field in ("cve", "cwe", "vulnerability_id", "qid", "plugin_id")
            if isinstance(vulnerability.get(field), str)
            and vulnerability[field].strip()
        )
        if vulnerability.get("exploit_available") is True:
            basis.append("exploit_available:true")
        candidates.append((EXPLOIT_PUBLIC_FACING, basis))

    cwe = vulnerability.get("cwe")
    if (
        normalized_endpoint_type in {"admin", "auth", "authentication", "login"}
        and isinstance(cwe, str)
        and cwe.strip().upper() in CREDENTIAL_WEAKNESS_CWES
    ):
        candidates.append(
            (
                VALID_ACCOUNTS,
                [
                    "internet_facing:true",
                    f"endpoint_type:{normalized_endpoint_type}",
                    f"cwe:{cwe.strip().upper()}",
                ],
            )
        )

    return candidates


def map_mitre(endpoint_type: str, internet_facing: bool, vulnerability: dict) -> list[str]:
    """Return candidate ATT&CK labels only when explicit supporting evidence exists."""
    return [
        technique
        for technique, _ in _mapping_candidates(
            endpoint_type,
            internet_facing,
            vulnerability,
        )
    ]


def mitre_mapping_evidence(
    endpoint_type: str,
    internet_facing: object,
    vulnerability: dict,
) -> list[dict[str, object]]:
    """Return ATT&CK candidate labels with the evidence that activated each rule."""
    return [
        {
            "technique": technique,
            "classification": "inferred_candidate",
            "basis": basis,
            "reference": TECHNIQUE_REFERENCES[technique],
            "limitation": (
                "Context supports a candidate mapping only; it does not establish "
                "adversary behavior or technique use."
            ),
        }
        for technique, basis in _mapping_candidates(
            endpoint_type,
            internet_facing,
            vulnerability,
        )
    ]
