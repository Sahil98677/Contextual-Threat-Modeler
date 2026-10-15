STRIDE_MAP = {
    "file_upload": ["Tampering", "Information Disclosure", "Elevation of Privilege", "Denial of Service"],
    "search": ["Information Disclosure", "Denial of Service"],
    "profile": ["Spoofing", "Information Disclosure", "Elevation of Privilege"],
    "admin": ["Spoofing", "Tampering", "Repudiation", "Elevation of Privilege"],
    "api": ["Spoofing", "Tampering", "Information Disclosure", "Elevation of Privilege"],
}


def map_stride(endpoint_type: str) -> list[str]:
    normalized_endpoint_type = (
        endpoint_type.strip().lower() if isinstance(endpoint_type, str) else ""
    )
    return list(STRIDE_MAP.get(normalized_endpoint_type, []))


def stride_mapping_evidence(endpoint_type: str) -> list[dict[str, str]]:
    """Describe endpoint-based STRIDE candidates without presenting them as facts."""
    normalized_endpoint_type = (
        endpoint_type.strip().lower() if isinstance(endpoint_type, str) else ""
    )
    threats = map_stride(normalized_endpoint_type)
    if not threats:
        return []

    return [
        {
            "threat": threat,
            "classification": "inferred_candidate",
            "basis": f"endpoint_type:{normalized_endpoint_type}",
            "limitation": (
                "Endpoint type suggests a threat category; this is not evidence "
                "that the threat is present or exploitable."
            ),
        }
        for threat in threats
    ]
