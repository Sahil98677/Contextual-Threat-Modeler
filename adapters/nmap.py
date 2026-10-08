"""Nmap XML scanner adapter."""
from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .base import ScannerAdapter


class NmapAdapter(ScannerAdapter):
    name = "nmap"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        root = ET.parse(Path(path)).getroot()
        findings = []

        for host in root.findall("host"):
            address = host.find("address")
            ip = address.get("addr") if address is not None else "unknown"

            for port in host.findall("./ports/port"):
                state = port.find("state")
                service = port.find("service")
                if state is None or state.get("state") != "open":
                    continue

                findings.append({
                    "source": self.name,
                    "host": ip,
                    "port": int(port.get("portid", 0)),
                    "protocol": port.get("protocol", ""),
                    "service": service.get("name") if service is not None else "unknown",
                })

        return findings
