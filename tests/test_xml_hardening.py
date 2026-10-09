import pytest
from defusedxml.common import DefusedXmlException

from adapters.nessus import NessusAdapter
from adapters.qualys import QualysXMLAdapter


@pytest.mark.parametrize("adapter", [NessusAdapter(), QualysXMLAdapter()])
def test_xml_adapters_reject_entity_expansion(tmp_path, adapter):
    path = tmp_path / "hostile.xml"
    path.write_text(
        """<?xml version="1.0"?>
        <!DOCTYPE root [
          <!ENTITY xxe SYSTEM "file:///etc/passwd">
        ]>
        <root>&xxe;</root>
        """,
        encoding="utf-8",
    )
    with pytest.raises(DefusedXmlException):
        adapter.parse(path)
