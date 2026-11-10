"""Инструмент execute_query: выполнение запроса 1С (только чтение)."""

from __future__ import annotations

import re
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from mcp_baf_audit import AuditWriter
from mcp_baf.client import OneCClient
from mcp_baf.pii import mask_pii_result
from mcp_baf.tools.common import clamp_limit, escape_pipe, format_cell, traced_text

DEFAULT_QUERY_LIMIT = 100
MAX_QUERY_LIMIT = 1000

# Комментарии языка запросов 1С: // до конца строки и /* ... */.
_QUERY_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_FIRST_WORD_RE = re.compile(r"[^\W\d]\w*", re.UNICODE)


def query_keyword(query: str) -> str:
    """Первое ключевое слово запроса — без комментариев и ведущих пробелов.

    Проверка «только SELECT» по префиксу ломалась на комментариях перед
    запросом и на словах, начинающихся с SELECT (SELECTED, ВЫБРАТЬСЯ).
    """
    text = _QUERY_COMMENT_RE.sub(" ", query)
    match = _FIRST_WORD_RE.match(text.lstrip())
    return match.group(0).upper() if match else ""


def register(mcp: MCPServer, client: OneCClient, audit: AuditWriter,
             mask_pii: bool = False) -> None:
    @mcp.tool(
        name="execute_query",
        title="Выполнить запрос к данным",
        description=(
            "Выполнить запрос на языке 1С (ВЫБРАТЬ/SELECT) и получить данные из базы: "
            "список элементов справочника, документы за период, остатки, обороты, сведения из регистров. "
            "Используй когда нужно найти, посчитать или вывести конкретные данные. Поддерживает параметры через &Имя. "
            "Имена таблиц: Справочник.X, Документ.X, РегистрНакопления.X, РегистрСведений.X (единственное число, НЕ Справочники/Документы). "
            "Перечисления НЕ являются таблицами: используй ЗНАЧЕНИЕ(Перечисление.Имя.Значение) в WHERE/CASE. "
            "Виртуальные таблицы регистров: РегистрНакопления.X.Остатки(&Период), .Обороты(&НачалоПериода, &КонецПериода), "
            "РегистрСведений.X.СрезПоследних(&Период). "
            "Имена полей бери из get_object_structure."
        ),
        annotations=ToolAnnotations(read_only_hint=True),
    )
    async def execute_query(
        query: Annotated[str, Field(description=(
            "Текст запроса на языке запросов 1С. Только ВЫБРАТЬ/SELECT. "
            "Параметры указывай через &ИмяПараметра."
        ))],
        limit: Annotated[int, Field(description=(
            "Максимальное количество строк результата "
            f"(по умолчанию {DEFAULT_QUERY_LIMIT}, максимум {MAX_QUERY_LIMIT})"
        ))] = 0,
        offset: Annotated[int, Field(ge=0, description=(
            "Сколько строк результата пропустить (пагинация). "
            "Используй вместе с limit, чтобы читать результат порциями: "
            "следующая страница — offset + limit"
        ))] = 0,
        parameters: Annotated[dict[str, Any] | None, Field(description=(
            "Параметры запроса в виде пар ключ-значение. Ключ — имя параметра без амперсанда. "
            'Пример: {"Контрагент": "ООО Ромашка", "ДатаНачала": "2026-01-01"}'
        ))] = None,
    ) -> str:
        effective_limit = clamp_limit(limit, DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT)

        async def run() -> str:
            if not query:
                raise ValueError("query is required")

            # Клиентская проверка «только чтение» (подсказка для LLM).
            # Серверное расширение 1С само гарантирует read-only выполнение.
            if query_keyword(query) not in {"ВЫБРАТЬ", "SELECT"}:
                raise ValueError("только SELECT/ВЫБРАТЬ запросы разрешены")

            body: dict[str, Any] = {"query": query, "limit": effective_limit}
            if offset:
                body["offset"] = offset
            if parameters:
                body["parameters"] = parameters

            result = await client.post("/query", body)
            return format_query_result(
                mask_pii_result(result) if mask_pii else result, offset
            )

        return await traced_text(
            audit, "execute_query", run,
            args={
                "query": query,
                "limit": effective_limit,
                "offset": offset,
                "parameters": sorted(parameters) if parameters else [],
            },
        )


def format_query_result(r: dict[str, Any], offset: int = 0) -> str:
    """Форматирует результат запроса как markdown-таблицу."""
    columns = r.get("columns") or []
    rows = r.get("rows") or []
    # total в ответе 1С — число выгруженных строк, а не найденных: показываем
    # реально полученное количество и сдвиг страницы, чтобы не путать.
    lines = [f"## Результат запроса (записей: {len(rows)}, offset: {offset})", ""]

    if not columns or not rows:
        lines.append("Нет данных.")
        return "\n".join(lines) + "\n"

    lines.append("| " + " | ".join(escape_pipe(c) for c in columns) + " |")
    lines.append("|" + "---|" * len(columns))
    for row in rows:
        lines.append("| " + " | ".join(format_cell(cell) for cell in row) + " |")

    if r.get("truncated"):
        lines.append("")
        lines.append(
            "> Результат усечён. Показаны записи начиная с offset "
            f"{offset}. Увеличьте `limit` или сдвиньте `offset` "
            f"(следующая страница: offset={offset + len(rows)})."
        )

    return "\n".join(lines) + "\n"
