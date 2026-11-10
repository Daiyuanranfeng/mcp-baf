"""Сборка MCP-сервера: создание MCPServer и регистрация инструментов."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from mcp.server.mcpserver import MCPServer

from mcp_baf_audit import AuditLog
from mcp_baf import __version__, prompts
from mcp_baf.client import OneCClient
from mcp_baf.access import AccessMCP
from mcp_baf.helpindex import HelpIndex
from mcp_baf.config import Config
from mcp_baf.dumpindex import DumpIndex
from mcp_baf.tools import (
    bsl_help,
    configuration_info,
    eventlog,
    form,
    metadata,
    object_structure,
    query,
    search_code,
    validate_query,
    objects,
    platform_help,
    bsl_analysis,
)

logger = logging.getLogger(__name__)

# Версия расширения 1С, с которой совместим этот сервер.
EXPECTED_EXTENSION_VERSION = "0.5.7"

_INSTRUCTIONS = (
    "MCP-сервер для ЧТЕНИЯ базы 1С:Предприятие (BAF) через HTTP-сервис: "
    "метаданные, запросы, полнотекстовый поиск по коду, журнал регистрации, "
    "справка платформы и локальный анализ BSL. Записи в базу нет. "
    "HTTP-инструменты доступны только в пределах прав пользователя; "
    "для проверки прав требуется расширение 0.5.7 с /capabilities.\n"
    "Порядок работы с незнакомой базой: get_configuration_info (что за "
    "конфигурация) -> get_metadata_tree (какие объекты есть) -> "
    "get_object_structure (точные имена реквизитов/табличных частей) -> "
    "validate_query -> execute_query. Имена объектов и полей бери из этих "
    "инструментов, не угадывай.\n"
    "Код конфигурации ищи через search_code (требует запуска с --dump); "
    "синтаксис встроенных функций BSL — bsl_syntax_help; структура форм — "
    "get_form_structure (полная тоже требует --dump); ошибки и действия "
    "пользователей — get_event_log. Ссылки на объект ищи через "
    "find_object_references; навигация — get_object_link; права — "
    "get_metadata_rights (без анализа RLS). При --help-dir доступны "
    "search_platform_help и get_platform_element. bsl_analyze и bsl_format "
    "встроены в Python: базовые проверки фрагмента и отступы, без полного "
    "контекста конфигурации; src — текст кода, файлы не изменяются."
)


async def _check_extension_version(client: OneCClient, audit: AuditLog) -> None:
    """Сверяет версию расширения 1С с ожидаемой.

    Эндпоинт /version может отсутствовать в старых расширениях —
    в этом случае проверка молча пропускается.
    """
    try:
        info = await asyncio.wait_for(client.get("/version"), timeout=3)
    except Exception:  # noqa: BLE001 — любая ошибка означает «пропустить»
        return
    version = info.get("version", "") if isinstance(info, dict) else ""
    if version != EXPECTED_EXTENSION_VERSION:
        logger.error(
            "Extension version mismatch: got %s, expected %s. "
            'Update: mcp-baf --install "path\\to\\db"',
            version, EXPECTED_EXTENSION_VERSION,
        )
        audit.write(
            "extension_version_mismatch",
            got=version, expected=EXPECTED_EXTENSION_VERSION,
        )


def create_server(config: Config) -> MCPServer:
    audit = AuditLog(
        config.cache_dir, config.audit_max_size_mib, config.audit_archives,
        service="mcp-baf",
    )
    # Клиент получает audit → каждый вызов 1С оставляет событие one_c.http,
    # наследующее trace_id текущего инструмента (см. tools.common.traced_text).
    client = OneCClient(config, audit=audit)

    # Индекс строится в фоновом потоке — сервер стартует, не дожидаясь его.
    index = None
    help_index = HelpIndex(config.help_dir, config.cache_dir, config.reindex) if config.help_dir else None
    if config.dump_dir:
        index = DumpIndex(
            config.dump_dir,
            cache_dir=config.cache_dir,
            reindex=config.reindex,
            show_progress=config.show_progress,
        )

    @asynccontextmanager
    async def lifespan(_server: MCPServer) -> AsyncIterator[None]:
        # Пароль в аудит не попадает — только адрес и имя пользователя.
        audit.write(
            "server_start",
            version=__version__, base_url=config.base_url, user=config.user,
        )
        version_check = asyncio.create_task(
            _check_extension_version(client, audit)
        )
        try:
            yield
        finally:
            version_check.cancel()
            await client.aclose()
            if index is not None:
                index.close()
            if help_index is not None:
                await asyncio.to_thread(help_index.close)
            audit.write("server_stop")

    mcp = AccessMCP(
        name="mcp-baf",
        version=__version__,
        access_client=client,
        audit=audit,
        instructions=_INSTRUCTIONS,
        lifespan=lifespan,
    )

    # Стабильный порядок регистрации; локальные инструменты не требуют базы.
    metadata.register(mcp, client, audit)
    object_structure.register(mcp, client, audit)
    query.register(mcp, client, audit, config.mask_pii)
    if index is not None:
        search_code.register(mcp, index, audit)
    # dump-директория позволяет form-инструменту обогащать ответ из Form.xml.
    form.register(mcp, client, audit, config.dump_dir)
    validate_query.register(mcp, client, audit)
    eventlog.register(mcp, client, audit)
    configuration_info.register(mcp, client, audit)
    bsl_help.register(mcp, audit)
    objects.register(mcp, client, audit)
    if help_index is not None:
        platform_help.register(mcp, help_index, audit)
    bsl_analysis.register(mcp, audit)
    prompts.register(mcp)

    # Схемы инструментов чистятся в AccessMCP.list_tools (публичный метод SDK,
    # источник payload tools/list); приватные атрибуты _tool_manager здесь
    # не трогаются.
    return mcp
