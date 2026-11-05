"""get_form_structure: отказ dump-обогащения виден в ответе, а не только в логе."""

import asyncio

import httpx
from mcp.server.mcpserver import MCPServer

from mcp_baf_audit import AuditLog
from mcp_baf.client import OneCClient
from mcp_baf.config import Config
from mcp_baf.tools import form


def test_dump_rejection_reported_in_output(tmp_path):
    dump = tmp_path / "dump"
    xml = dump / "Catalogs" / "Тест" / "Forms" / "ФормаЭлемента" / "Ext" / "Form.xml"
    xml.parent.mkdir(parents=True)
    xml.write_text('<!DOCTYPE Form [<!ENTITY a "x">]><Form/>', encoding="utf-8")

    transport = httpx.MockTransport(
        lambda request: httpx.Response(200, json={"name": "ФормаЭлемента", "title": "Тест"})
    )
    audit = AuditLog(str(tmp_path / "audit"))
    client = OneCClient(Config(base_url="http://test"), transport, audit=audit)
    mcp = MCPServer("test")
    form.register(mcp, client, audit, dump_dir=str(dump))

    async def scenario():
        result = await mcp.call_tool("get_form_structure", {
            "object_type": "Catalog", "object_name": "Тест",
        })
        await client.aclose()
        return result

    text = asyncio.run(scenario()).content[0].text
    assert "ФормаЭлемента" in text
    assert "Структура из dump недоступна" in text and "DTD" in text
