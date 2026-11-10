"""Проверка list и прямых calls, обновление прав, отказ при недоступности сервиса."""

import asyncio
import json

import httpx
import pytest
from mcp.types import ToolAnnotations
from mcp.client import Client
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.mcpserver.exceptions import ToolError

from mcp_baf_audit import AuditLog, set_trace_id
from mcp_baf.access import AccessMCP
from mcp_baf.client import OneCClient
from mcp_baf.config import Config


def test_shared_cache_expiry_and_denial_audit(tmp_path):
    allowed = ['metadata.GET']
    calls = []
    executed = []
    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={'methods': allowed[:]})
    audit = AuditLog(str(tmp_path))
    client = OneCClient(Config(base_url='http://test'), httpx.MockTransport(handler), audit=audit)
    server = AccessMCP('test', access_client=client, audit=audit)
    @server.tool(annotations=ToolAnnotations(read_only_hint=True))
    async def get_metadata_tree():
        executed.append(True)
        return 'ok'
    @server.tool()
    async def bsl_syntax_help():
        return 'local'
    @server.tool()
    async def execute_query(query: str):
        raise AssertionError('hidden tool must not execute')

    async def scenario():
        assert {t.name for t in await server.list_tools()} == {'get_metadata_tree', 'bsl_syntax_help'}
        await server.list_tools()
        assert len(calls) == 1
        await server.call_tool('get_metadata_tree', {})
        # Вызов берёт права из того же кэша: лишнего запроса к базе нет.
        assert executed == [True] and len(calls) == 1
        allowed.clear()
        await server.call_tool('get_metadata_tree', {})
        assert executed == [True, True] and len(calls) == 1
        server._expires = 0
        with pytest.raises(ToolError):
            await server.call_tool('get_metadata_tree', {'private': 'PRIVATE'})
        assert executed == [True, True] and len(calls) == 2
        with pytest.raises(ToolError):
            await server.call_tool('execute_query', {'query': 'PRIVATE_QUERY'})
        assert {t.name for t in await server.list_tools()} == {'bsl_syntax_help'}
        assert await server.call_tool('bsl_syntax_help', {})
        await client.aclose()
    set_trace_id(None)
    asyncio.run(scenario())
    events = [json.loads(x) for x in (tmp_path / 'audit.log').read_text().splitlines()]
    denials = [x for x in events if x['event'] == 'tool.error']
    assert len(denials) == 2
    assert all(x['args'] == {'access_denied': True} for x in denials)
    assert 'PRIVATE' not in json.dumps(events)
    assert all(x['trace_id'] for x in denials)


@pytest.mark.parametrize('status,body', [(404, {}), (200, {'methods':'all'}), (200, {'methods':[True]}), (200, {}), (200, {'methods':None}), (200, ['metadata.GET'])])
def test_fail_closed_and_local_tools_survive(tmp_path, status, body):
    client = OneCClient(Config(base_url='http://test'), httpx.MockTransport(lambda r: httpx.Response(status, json=body)))
    server = AccessMCP('test', access_client=client, audit=AuditLog(str(tmp_path)))
    @server.tool()
    async def execute_query(query: str):
        raise AssertionError('must not execute')
    @server.tool()
    async def bsl_syntax_help():
        return 'ok'
    async def scenario():
        assert [t.name for t in await server.list_tools()] == ['bsl_syntax_help']
        with pytest.raises(ToolError, match='capabilities'):
            await server.call_tool('execute_query', {'query': 'ВЫБРАТЬ 1'})
        await client.aclose()
    asyncio.run(scenario())


@pytest.mark.parametrize('mode', ['auto', 'legacy'])
def test_real_mcp_protocol_filters_list_and_denies_hidden_call(tmp_path, mode):
    from mcp_baf.tools import objects, bsl_help
    allowed = ['refs.POST']
    requests = []
    def handler(request):
        requests.append(request.url.path)
        if request.url.path == '/capabilities':
            return httpx.Response(200, json={'methods':allowed[:]})
        return httpx.Response(200,json={'hits':[],'skipped_names':[],'truncated':False,'timeout_exceeded':False})
    audit = AuditLog(str(tmp_path))
    client = OneCClient(Config(base_url='http://test'),httpx.MockTransport(handler),audit=audit)
    server = AccessMCP('test',access_client=client,audit=audit)
    objects.register(server,client,audit)
    bsl_help.register(server,audit)
    @server.tool()
    async def request_context(ctx: Context) -> str:
        # Перехват call_tool обязан передать исходный контекст SDK 2.
        return ctx.request_id
    async def scenario():
        async with Client(server, mode=mode) as session:
            listing = await session.list_tools()
            assert {t.name for t in listing.tools} == {'find_object_references','bsl_syntax_help','request_context'}
            context_result = await session.call_tool('request_context', {})
            assert not context_result.is_error and context_result.content[0].text
            result = await session.call_tool('find_object_references',dict(ref='12345678-1234-5678-9abc-123456789abc',ref_kind='Справочник.X'))
            assert not result.is_error and 'Совпадений' in result.content[0].text
            allowed.clear()
            server._expires = 0
            result = await session.call_tool('find_object_references',dict(ref='12345678-1234-5678-9abc-123456789abc',ref_kind='Справочник.X'))
            assert result.is_error and 'прав' in result.content[0].text
            result = await session.call_tool('bsl_syntax_help',{'query':'СтрНайти'})
            assert not result.is_error
            assert {t.name for t in (await session.list_tools(cache_mode='refresh')).tools} == {'bsl_syntax_help','request_context'}
        await client.aclose()
    asyncio.run(scenario())
    assert requests.count('/refs') == 1


def test_tool_schemas_stripped_via_public_list_tools_without_touching_sdk(tmp_path):
    # Публичный путь: list_tools() — метод MCPServer (источник payload tools/list),
    # input_schema — публичное поле mcp.types.Tool. Приватный _tool_manager
    # не используется; тест падает, если SDK сменит major или эту поверхность.
    import importlib.metadata
    from typing import Annotated, Literal
    from mcp.types import Tool as MCPTool
    from pydantic import Field

    assert importlib.metadata.version('mcp').split('.')[0] == '2'
    assert 'input_schema' in MCPTool.model_fields
    assert asyncio.run(MCPServer.list_tools(MCPServer('bare'))) == []

    client = OneCClient(Config(base_url='http://test'), httpx.MockTransport(lambda r: httpx.Response(200, json={'methods': []})))
    server = AccessMCP('test', access_client=client, audit=AuditLog(str(tmp_path)))

    @server.tool()
    async def nested_tool(items: list[Literal['a', 'b']] | None = None,
                          limit: Annotated[int, Field(ge=1)] = 5) -> str:
        return 'ok'

    def titles(node):
        found = []
        if isinstance(node, dict):
            if 'title' in node:
                found.append(node['title'])
            for value in node.values():
                found.extend(titles(value))
        elif isinstance(node, list):
            for value in node:
                found.extend(titles(value))
        return found

    async def scenario():
        listed = await server.list_tools()
        assert titles(listed[0].input_schema) == []
        assert listed[0].input_schema['properties']['limit']['minimum'] == 1
        # Внутренняя схема SDK не мутирована: чистка идёт по копии.
        assert 'title' in server._tool_manager.get_tool('nested_tool').parameters
        async with Client(server) as session:
            wire = (await session.list_tools()).tools[0].model_dump(by_alias=True, exclude_none=True)
        assert titles(wire['inputSchema']) == []
        await client.aclose()

    asyncio.run(scenario())


def test_expected_errors_reach_client_but_bugs_stay_hidden(tmp_path):
    audit = AuditLog(str(tmp_path))
    client = OneCClient(Config(base_url='http://test'), httpx.MockTransport(lambda r: httpx.Response(200, json={})), audit=audit)
    server = AccessMCP('test', access_client=client, audit=audit)
    @server.tool()
    async def bad_arg() -> str:
        raise ValueError('подсказка агенту')  # вне traced_text, как в execute_query
    @server.tool()
    async def bug() -> str:
        raise KeyError('секретная внутренность')
    async def scenario():
        async with Client(server) as session:
            result = await session.call_tool('bad_arg', {})
            assert result.is_error and result.content[0].text == 'подсказка агенту'
            result = await session.call_tool('bug', {})
            assert result.is_error and 'секретная' not in result.content[0].text
        await client.aclose()
    asyncio.run(scenario())
