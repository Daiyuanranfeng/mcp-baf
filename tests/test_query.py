"""execute_query: пагинация, проверка «только SELECT» и маскирование ПДн."""

import asyncio
import json

import httpx
import pytest
from mcp.server.mcpserver.exceptions import ToolError

from mcp_baf_audit import AuditLog
from mcp_baf.client import OneCClient
from mcp_baf.config import Config
from mcp_baf.tools import query


def setup(tmp_path, result=None, mask_pii=False):
    requests = []
    payload = result or {"columns": ["A"], "rows": [[1]], "total": 1}

    def handler(request):
        requests.append(json.loads(request.content))
        return httpx.Response(200, json=payload)

    audit = AuditLog(str(tmp_path))
    client = OneCClient(
        Config(base_url="http://test"), httpx.MockTransport(handler), audit=audit
    )
    tools = {}

    class FakeMCP:
        def tool(self, **kwargs):
            return lambda f: tools.setdefault(f.__name__, f)

    query.register(FakeMCP(), client, audit, mask_pii)
    return tools, client, requests


def call(tools, client, **kwargs):
    async def scenario():
        try:
            return await tools["execute_query"](**kwargs)
        finally:
            await client.aclose()

    return asyncio.run(scenario())


@pytest.mark.parametrize("text,expected", [
    ("ВЫБРАТЬ * ИЗ Справочник.Валюты", "ВЫБРАТЬ"),
    ("  select 1", "SELECT"),
    ("// комментарий\nВЫБРАТЬ 1", "ВЫБРАТЬ"),
    ("/* блок */\n\tSELECT 1", "SELECT"),
    ("ВЫБРАТЬСЯ ИЗ X", "ВЫБРАТЬСЯ"),
    ("SELECTED 1", "SELECTED"),
    ("SELECT1 1", "SELECT1"),
    ("УДАЛИТЬ ИЗ X", "УДАЛИТЬ"),
    ("", ""),
    ("-- 1", ""),
    ("// только комментарий", ""),
])
def test_query_keyword_normalizes_comments(text, expected):
    assert query.query_keyword(text) == expected


def test_comment_prefixed_select_reaches_extension(tmp_path):
    tools, client, requests = setup(tmp_path)
    text = call(tools, client, query="// только чтение\nВЫБРАТЬ 1")
    assert requests and requests[0]["query"].startswith("//")
    assert "Результат запроса" in text


@pytest.mark.parametrize("text", [
    "УДАЛИТЬ ИЗ Справочник.Валюты",
    "ВЫБРАТЬСЯ ИЗ X",
    "SELECTED 1",
    "/* c */ UPDATE X",
])
def test_non_select_rejected_without_http(tmp_path, text):
    tools, client, requests = setup(tmp_path)
    with pytest.raises(ToolError, match="SELECT"):
        call(tools, client, query=text)
    assert requests == []


def test_offset_passed_to_extension(tmp_path):
    tools, client, requests = setup(tmp_path)
    text = call(tools, client, query="ВЫБРАТЬ 1", limit=10, offset=40)
    assert requests[0]["offset"] == 40
    assert requests[0]["limit"] == 10
    assert "offset: 40" in text


def test_default_offset_not_sent(tmp_path):
    tools, client, requests = setup(tmp_path)
    call(tools, client, query="ВЫБРАТЬ 1")
    assert "offset" not in requests[0]


def test_truncated_result_points_to_next_page():
    out = query.format_query_result(
        {"columns": ["A"], "rows": [[1], [2]], "truncated": True}, offset=10
    )
    assert "усечён" in out
    assert "offset=12" in out


@pytest.mark.parametrize("rows", [[1, 2], ["ab"], [{"a": 1}], "not-a-list"])
def test_mask_pii_rejects_malformed_rows(rows):
    # Тихий пропуск маскирования — утечка ПДн: контракт должен падать явно.
    with pytest.raises(ValueError, match="rows"):
        query.mask_pii_result({"columns": ["A"], "rows": rows})


def test_mask_pii_tool_level_reports_contract_error(tmp_path):
    tools, client, _ = setup(tmp_path, {"columns": ["A"], "rows": [1, 2]}, mask_pii=True)
    with pytest.raises(ToolError, match="rows"):
        call(tools, client, query="ВЫБРАТЬ 1")
