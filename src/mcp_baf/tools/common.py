"""Общие помощники для MCP-инструментов."""

from __future__ import annotations

import re
import time
from collections.abc import Awaitable, Callable, Collection
from typing import Any
from urllib.parse import quote

from mcp.server.mcpserver.exceptions import ToolError
from mcp_baf_audit import AuditWriter, get_trace_id, new_trace_id, set_trace_id

from mcp_baf.client import OneCError

# Ожидаемые отказы: их текст — подсказка агенту. SDK 2 отдаёт клиенту текст
# только ToolError, всё остальное (баги) остаётся скрытым и идёт в server.log.
# RuntimeError — состояние локальных индексов («строится», «недоступен»).
CLIENT_VISIBLE_ERRORS = (ValueError, PermissionError, RuntimeError, OneCError)


async def traced_text(
    audit: AuditWriter,
    tool: str,
    call: Callable[[], Awaitable[str]],
    *,
    args: dict[str, Any] | None = None,
) -> str:
    """Выполняет инструмент со сквозным аудитом и возвращает его текст как есть.

    Аналог mcp_baf_audit.traced, но для инструментов mcp-baf, которые
    возвращают готовый markdown, а не dict: текст НЕ оборачивается в JSON.
    Каждый вызов оставляет событие tool.call (tool, args, ok, duration_ms)
    либо tool.error с текстом исключения.

    trace_id фиксируется в начале (унаследованный из contextvar или новый,
    никогда не null) и записывается в события инструмента; вложенные события
    того же контекста (one_c.http из клиента) наследуют его через contextvar.
    Сбой аудита не ломает инструмент.
    """
    trace_id = get_trace_id() or new_trace_id()
    set_trace_id(trace_id)

    start = time.monotonic()
    try:
        result = await call()
    except Exception as exc:
        audit.write(
            "tool_error",
            level="error", trace_id=trace_id,
            tool=tool, args=args or {}, error=str(exc),
            duration_ms=int((time.monotonic() - start) * 1000),
        )
        if isinstance(exc, CLIENT_VISIBLE_ERRORS):
            raise ToolError(str(exc)) from exc
        raise

    audit.write(
        "tool_call",
        trace_id=trace_id,
        tool=tool, args=args or {}, ok=True,
        duration_ms=int((time.monotonic() - start) * 1000),
    )
    return result


def clamp_limit(value: int, default: int, maximum: int) -> int:
    """Нормализует пользовательский limit к диапазону [default, maximum]."""
    if value <= 0:
        return default
    return min(value, maximum)


# Имя объекта метаданных 1С: буква или подчёркивание, затем буквы/цифры/подчёркивания.
METADATA_NAME_RE = re.compile(r"^[^\W\d]\w*$", re.UNICODE)

# Потолок вывода инструментов: огромное дерево/структура не должно вытеснять
# из контекста агента всё остальное. Усечение всегда явно помечено в тексте.
MAX_TOOL_OUTPUT_CHARS = 60_000


def validate_metadata_name(value: str, field: str) -> str:
    """Проверяет имя объекта метаданных перед подстановкой в URL/путь."""
    if not isinstance(value, str) or not METADATA_NAME_RE.fullmatch(value):
        raise ValueError(
            f"{field}: ожидается имя объекта метаданных — буква или подчёркивание, "
            "затем буквы, цифры и подчёркивания (без пробелов, точек и слэшей)"
        )
    return value


def validate_metadata_type(value: str, allowed: Collection[str]) -> str:
    """Проверяет тип объекта по белому списку поддерживаемых типов."""
    if not isinstance(value, str) or value not in allowed:
        raise ValueError(
            "object_type: ожидается один из типов: " + ", ".join(sorted(allowed))
        )
    return value


def object_path_segments(
    object_type: str, object_name: str, allowed: Collection[str]
) -> tuple[str, str]:
    """Валидирует тип и имя объекта и возвращает percent-encoded URL-сегменты."""
    object_type = validate_metadata_type(object_type, allowed)
    object_name = validate_metadata_name(object_name, "object_name")
    return quote(object_type, safe=""), quote(object_name, safe="")


def truncate_output(text: str, limit: int = MAX_TOOL_OUTPUT_CHARS) -> str:
    """Обрезает вывод по лимиту, сохраняя целые строки и явную пометку."""
    if len(text) <= limit:
        return text
    cut = text[:limit]
    newline = cut.rfind("\n")
    if newline > limit // 2:
        cut = cut[:newline]
    return (
        cut
        + "\n\n> Результат усечён: превышен лимит вывода "
        f"({limit} символов). Показана только часть — уточните запрос "
        "(filter/limit), чтобы получить полный список.\n"
    )


def escape_pipe(s: str) -> str:
    """Экранирует вертикальную черту, чтобы не ломать markdown-таблицы."""
    return s.replace("|", "\\|")


def format_cell(v: Any) -> str:
    """Преобразует значение ячейки JSON-ответа в строку для markdown-таблицы."""
    if v is None:
        return ""
    if isinstance(v, bool):
        s = "true" if v else "false"
    elif isinstance(v, float):
        s = str(int(v)) if v == int(v) else f"{v:f}".rstrip("0").rstrip(".")
    elif isinstance(v, str):
        s = v
    else:
        s = str(v)
    return escape_pipe(s)
