STRIDE_MAP = {
    "file_upload": ["Tampering", "Information Disclosure", "Elevation of Privilege", "Denial of Service"],
    "search": ["Information Disclosure", "Denial of Service"],
    "profile": ["Spoofing", "Information Disclosure", "Elevation of Privilege"],
    "admin": ["Spoofing", "Tampering", "Repudiation", "Elevation of Privilege"],
    "api": ["Spoofing", "Tampering", "Information Disclosure", "Elevation of Privilege"],
}


def map_stride(endpoint_type: str) -> list[str]:
    return list(STRIDE_MAP.get(endpoint_type, ["Information Disclosure"]))
