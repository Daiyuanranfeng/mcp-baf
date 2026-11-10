"""Контракты инструментов: валидация URL-сегментов, filter, лимит вывода, экранирование."""

import asyncio
import json
from urllib.parse import unquote

import httpx
import pytest
from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from mcp_baf_audit import AuditLog
from mcp_baf.client import OneCClient
from mcp_baf.config import Config
from mcp_baf.dumpindex.modulenames import OBJECT_TYPE_TO_DUMP_DIR
from mcp_baf.tools import configuration_info, form, metadata, object_structure, objects
from mcp_baf.tools.common import MAX_TOOL_OUTPUT_CHARS, truncate_output

GUID = "12345678-1234-5678-9abc-123456789abc"
KIND = "Справочник.Контрагенты"
LINK = "e1cib/data/" + KIND + "?ref=9abc123456789abc5678123412345678"


def setup(tmp_path, module, result, **kwargs):
    requests = []

    def handler(request):
        requests.append(request)
        return httpx.Response(200, json=result)

    audit = AuditLog(str(tmp_path))
    client = OneCClient(Config(base_url="http://test"), httpx.MockTransport(handler), audit=audit)
    server = MCPServer("test")
    module.register(server, client, audit, **kwargs)
    return server, client, requests


def call(server, name, **arguments):
    return asyncio.run(server.call_tool(name, arguments)).content[0].text


BAD_NAMES = ["Валюты/../Admin", "Валюты?x=1", "Валюты\n", "Валюты X", "Валюты.Х", "", "1Валюты"]


@pytest.mark.parametrize("arguments", [
    *[dict(object_type="Catalog", object_name=name) for name in BAD_NAMES],
    dict(object_type="Evil", object_name="Валюты"),
    dict(object_type="Catalog;DELETE", object_name="Валюты"),
    dict(object_type="catalog", object_name="Валюты"),
])
def test_form_rejects_bad_url_segments(tmp_path, arguments):
    server, client, requests = setup(tmp_path, form, {"name": "Форма"})
    with pytest.raises(ToolError):
        call(server, "get_form_structure", **arguments)
    assert requests == []
    asyncio.run(client.aclose())


@pytest.mark.parametrize("arguments", [
    *[dict(object_type="Catalog", object_name=name) for name in BAD_NAMES],
    dict(object_type="Evil", object_name="Валюты"),
    dict(object_type="Catalog/../Admin", object_name="Валюты"),
])
def test_object_structure_rejects_bad_url_segments(tmp_path, arguments):
    server, client, requests = setup(tmp_path, object_structure, {"name": "Валюты"})
    with pytest.raises(ToolError):
        call(server, "get_object_structure", **arguments)
    assert requests == []
    asyncio.run(client.aclose())


def test_object_type_error_lists_allowed_values(tmp_path):
    server, client, _ = setup(tmp_path, object_structure, {})
    with pytest.raises(ToolError) as excinfo:
        call(server, "get_object_structure", object_type="Evil", object_name="Валюты")
    message = str(excinfo.value)
    assert "Catalog" in message and "Document" in message
    asyncio.run(client.aclose())


@pytest.mark.parametrize("module,path", [
    (form, "/form"),
    (object_structure, "/object"),
])
def test_valid_name_is_percent_encoded_in_url(tmp_path, module, path):
    server, client, requests = setup(tmp_path, module, {"name": "Валюты"})
    call(server, "get_form_structure" if module is form else "get_object_structure",
         object_type="Catalog", object_name="Валюты")
    raw = requests[0].url.raw_path.decode("ascii")
    assert unquote(raw).endswith(f"{path}/Catalog/Валюты")
    # Не-ASCII имя уходит в URL закодированным, а не сырым.
    assert "%" in raw
    asyncio.run(client.aclose())


def test_all_whitelisted_types_are_dump_types():
    for object_type in ("Catalog", "Document", "Enum", "InformationRegister",
                        "AccumulationRegister", "Report", "DataProcessor"):
        assert object_type in OBJECT_TYPE_TO_DUMP_DIR


def test_metadata_unknown_filter_is_explicit_error(tmp_path):
    server, client, requests = setup(
        tmp_path, metadata, {"Документы": ["Продажа"], "Справочники": ["Валюты"]}
    )
    with pytest.raises(ToolError) as excinfo:
        call(server, "get_metadata_tree", filter="Справочник")
    message = str(excinfo.value)
    assert "не найден" in message
    assert "Документы" in message and "Справочники" in message
    assert len(requests) == 1
    asyncio.run(client.aclose())


def test_metadata_known_filter_returns_only_that_category(tmp_path):
    server, client, _ = setup(
        tmp_path, metadata, {"Документы": ["Продажа"], "Справочники": ["Валюты"]}
    )
    text = call(server, "get_metadata_tree", filter="Документы")
    assert "Продажа" in text and "Валюты" not in text
    asyncio.run(client.aclose())


def test_metadata_tree_output_is_limited(tmp_path):
    names = [f"Объект{i:05d}" for i in range(12000)]
    server, client, _ = setup(tmp_path, metadata, {"Документы": names})
    text = call(server, "get_metadata_tree", filter="Документы")
    assert len(text) <= MAX_TOOL_OUTPUT_CHARS + 400
    assert "усечён" in text and "Объект11999" not in text
    asyncio.run(client.aclose())


def test_truncate_output_keeps_whole_lines():
    text = ("строка\n" * 20000)
    out = truncate_output(text, limit=1000)
    assert len(out) < 1200
    assert out.startswith("строка\n")
    assert "усечён" in out
    assert truncate_output("short", limit=1000) == "short"


def test_configuration_info_cells_are_escaped(tmp_path):
    server, client, _ = setup(tmp_path, configuration_info, {
        "name": "База|Тест", "version": "1.0\n2.0", "vendor": "Фирма",
        "platform_version": "8.3", "mode": "file",
    })
    text = call(server, "get_configuration_info")
    assert "| База\\|Тест |" in text
    assert "| 1.0 2.0 |" in text
    assert "1.0\n2.0" not in text
    asyncio.run(client.aclose())


def test_references_without_found_in_meta_does_not_crash():
    text = objects.format_references({"hits": [{"path": "Товары.Контрагент", "match_kind": "x"}]})
    assert "(без метаданных)" in text


def test_object_link_missing_kind_is_contract_error(tmp_path):
    server, client, _ = setup(tmp_path, objects, {
        "found": True, "presentation": "x", "link": LINK, "ref": GUID,
    })
    with pytest.raises(ToolError, match="обязательного поля kind"):
        call(server, "get_object_link", mode="make", ref=GUID, kind=KIND)
    asyncio.run(client.aclose())


def test_metadata_rights_missing_fields_do_not_crash(tmp_path):
    server, client, _ = setup(tmp_path, objects, {"rights": [{"allowed": True}], "notes": []})
    text = call(server, "get_metadata_rights", metadata_object="Документ.Продажа")
    assert "|  |  | да |" in text
    asyncio.run(client.aclose())
