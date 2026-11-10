"""Инструмент get_event_log: чтение журнала регистрации 1С."""

from __future__ import annotations

from typing import Annotated, Any, Literal

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from mcp_baf_audit import AuditWriter
from mcp_baf.client import OneCClient
from mcp_baf.tools.common import clamp_limit, traced_text

DEFAULT_EVENT_LOG_LIMIT = 50
MAX_EVENT_LOG_LIMIT = 500

EventLogLevel = Literal["Ошибка", "Предупреждение", "Информация", "Примечание"]


def register(mcp: MCPServer, client: OneCClient, audit: AuditWriter) -> None:
    @mcp.tool(
        name="get_event_log",
        title="Журнал регистрации",
        description=(
            "Прочитать журнал регистрации 1С — лог ошибок, действий пользователей "
            "и системных событий. Фильтрация по дате, уровню важности "
            "(Ошибка/Предупреждение/Информация) и пользователю."
        ),
        annotations=ToolAnnotations(read_only_hint=True),
    )
    async def get_event_log(
        start_date: Annotated[str, Field(description=(
            "Начало периода в формате ISO 8601 (например 2026-03-01T00:00:00)"
        ))] = "",
        end_date: Annotated[str, Field(
            description="Конец периода в формате ISO 8601"
        )] = "",
        level: Annotated[EventLogLevel | None, Field(description=(
            "Уровень важности: Ошибка, Предупреждение, Информация, Примечание"
        ))] = None,
        user: Annotated[str, Field(
            description="Имя пользователя 1С для фильтрации"
        )] = "",
        limit: Annotated[int, Field(description=(
            "Максимальное количество записей "
            f"(по умолчанию {DEFAULT_EVENT_LOG_LIMIT}, максимум {MAX_EVENT_LOG_LIMIT})"
        ))] = 0,
        exclude_system: Annotated[bool, Field(description=(
            "Скрыть шум платформы (транзакции, фоновые задания, сеансы); "
            "по умолчанию true"
        ))] = True,
    ) -> str:
        effective_limit = clamp_limit(
            limit, DEFAULT_EVENT_LOG_LIMIT, MAX_EVENT_LOG_LIMIT
        )

        async def run() -> str:
            body: dict[str, Any] = {"limit": effective_limit, "exclude_system": exclude_system}
            if start_date:
                body["start_date"] = start_date
            if end_date:
                body["end_date"] = end_date
            if level:
                body["level"] = level
            if user:
                body["user"] = user

            result = await client.post("/eventlog", body)
            return format_event_log(result)

        return await traced_text(
            audit, "get_event_log", run,
            args={
                "start_date": start_date,
                "end_date": end_date,
                "level": level,
                "user": user,
                "limit": effective_limit,
                "exclude_system": exclude_system,
            },
        )


def format_event_log(r: dict[str, Any]) -> str:
    lines = ["## Журнал регистрации", ""]

    events = r.get("events") or []
    if not events:
        lines.append("Записей не найдено.")
        return "\n".join(lines) + "\n"

    for i, e in enumerate(events):
        if i > 0:
            lines.extend(["", "---", ""])
        lines.append(
            f"**{e.get('date', '')}** | {e.get('level', '')} | {e.get('event', '')}"
        )
        lines.append(f"- Пользователь: {e.get('user', '')}")
        for key, label in (
            ("computer", "Компьютер"),
            ("metadata", "Метаданные"),
            ("data", "Данные"),
            ("comment", "Комментарий"),
            ("transaction", "Транзакция"),
        ):
            if e.get(key):
                lines.append(f"- {label}: {e[key]}")

    lines.append("")
    events_count = len(events)
    found = r.get("found")
    if r.get("truncated"):
        shown = f"Показано: {events_count}"
        if isinstance(found, int) and found >= events_count:
            shown += f" из {found}"
        lines.append(f"{shown}. Список может быть неполным.")
    else:
        total = found if isinstance(found, int) else r.get("total", events_count)
        lines.append(f"Всего: {total}")
    return "\n".join(lines) + "\n"
