"""Nmap XML scanner adapter."""
from __future__ import annotations

from pathlib import Path
from typing import Any
from xml.etree.ElementTree import Element

from defusedxml import ElementTree as ET

from .base import ScannerAdapter


def _child_text(element: Element | None, name: str, default: str = "") -> str:
    """Return stripped child text or a default value."""
    if element is None:
        return default
    child = element.find(name)
    if child is None or child.text is None:
        return default
    return child.text.strip()


class NmapAdapter(ScannerAdapter):
    """Parse Nmap XML and return open ports as records."""

    name = "nmap"

    def parse(self, path: str | Path) -> list[dict[str, Any]]:
        tree = ET.parse(Path(path))
        root = tree.getroot()
        if root is None:
            raise ValueError("Nmap XML export has no root element.")

        findings: list[dict[str, Any]] = []
        for host in root.findall("host"):
            address = host.find("address")
            ip = address.get("addr", "unknown") if address is not None else "unknown"

            for port in host.findall("./ports/port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue

                service = port.find("service")
                port_text = port.get("portid", "0")
                try:
                    port_number = int(port_text)
                except ValueError:
                    port_number = 0

                findings.append(
                    {
                        "source": self.name,
                        "host": ip,
                        "port": port_number,
                        "protocol": port.get("protocol", ""),
                        "service": (
                            service.get("name", "unknown")
                            if service is not None
                            else "unknown"
                        ),
                    }
                )

        return findings
