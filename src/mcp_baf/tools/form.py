"""Инструмент get_form_structure: структура управляемой формы объекта.

HTTP-endpoint 1С в серверном контексте не отдаёт состав элементов и
обработчики формы (нет доступа к ФормаКлиентскогоПриложения) — от него
приходят только имя и заголовок. Полная структура (элементы, команды,
обработчики) берётся из Form.xml локальной dump-выгрузки, когда сервер
запущен с флагом --dump.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from mcp_baf_audit import AuditWriter
from mcp_baf.client import OneCClient, OneCError
from mcp_baf.dumpindex import formparser
from mcp_baf.dumpindex.modulenames import nfc
from mcp_baf.tools.common import escape_pipe, traced_text

logger = logging.getLogger(__name__)


def register(
    mcp: MCPServer, client: OneCClient, audit: AuditWriter, dump_dir: str = ""
) -> None:
    @mcp.tool(
        name="get_form_structure",
        title="Структура формы объекта",
        description=(
            "Получить структуру управляемой формы объекта 1С: элементы интерфейса, команды, "
            "кнопки и обработчики событий. "
            "Используй когда нужно понять как выглядит форма документа, справочника или обработки. "
            "ВАЖНО: HTTP-endpoint 1С в серверном контексте не отдаёт состав элементов и "
            "обработчики формы - для полной структуры запусти сервер с флагом --dump "
            "(выгрузка конфигурации в файлы), тогда состав элементов, команды и обработчики "
            "берутся из Form.xml. Без --dump возвращаются только имя и заголовок формы."
        ),
        annotations=ToolAnnotations(read_only_hint=True),
    )
    async def get_form_structure(
        object_type: Annotated[str, Field(
            description="Тип объекта: Document, Catalog, DataProcessor, Report и т.д."
        )],
        object_name: Annotated[str, Field(description="Имя объекта метаданных")],
        form_name: Annotated[str, Field(description=(
            "Имя формы (если не указано - возвращается первая найденная форма)"
        ))] = "",
    ) -> str:
        if not object_type or not object_name:
            raise ValueError("object_type and object_name are required")

        async def run() -> str:
            # HTTP-endpoint отдаёт имя и заголовок формы (синоним из конфигурации).
            form: dict[str, Any] = {}
            http_error: Exception | None = None
            dump_note = ""
            try:
                form = await client.get(f"/form/{object_type}/{object_name}")
            except OneCError as exc:
                http_error = exc

            if dump_dir:
                try:
                    dump_form = await asyncio.to_thread(
                        form_from_dump,
                        dump_dir, object_type, object_name, form_name,
                    )
                except Exception as dump_error:  # noqa: BLE001
                    if http_error is not None:
                        # Оба источника упали — возвращаем комбинированную ошибку,
                        # чтобы было видно, почему показать нечего.
                        raise OneCError(
                            f"fetching form structure from 1C: {http_error} "
                            f"(dump fallback: {dump_error})"
                        ) from http_error
                    # HTTP дал хотя бы имя и заголовок, но обогащение из dump
                    # не сработало — логируем, чтобы пользователь заметил.
                    logger.warning(
                        "Form dump enrichment failed: object=%s.%s form=%s error=%s",
                        object_type, object_name, form_name, dump_error,
                    )
                    # Без пометки пустой состав элементов выглядит как «у формы их нет».
                    dump_note = (
                        f"\n\n> Структура из dump недоступна: {dump_error}"
                    )
                else:
                    merge_dump_into_form(form, dump_form)
            elif http_error is not None:
                raise OneCError(
                    f"fetching form structure from 1C: {http_error}"
                ) from http_error

            return format_form_structure(form) + dump_note

        return await traced_text(
            audit, "get_form_structure", run,
            args={
                "object_type": object_type,
                "object_name": object_name,
                "form_name": form_name,
            },
        )


def form_from_dump(
    dump_dir: str, object_type: str, object_name: str, form_name: str
) -> dict[str, Any]:
    """Загружает структуру формы из Form.xml dump-выгрузки."""
    # Ключи find_form_files — NFC; NFD-имя из запроса нормализуется так же.
    form_name = nfc(form_name)
    form_files = formparser.find_form_files(dump_dir, object_type, object_name)
    if not form_files:
        raise OneCError(f"no forms found in dump for {object_type}.{object_name}")

    if form_name:
        if form_name not in form_files:
            available = ", ".join(sorted(form_files))
            raise OneCError(
                f"form {form_name!r} not found in dump (available: {available})"
            )
        selected = form_name
    else:
        # Первая форма по алфавиту — детерминированный результат.
        selected = min(form_files)

    info = formparser.parse_form_xml(form_files[selected])
    return convert_dump_form(selected, info)


def convert_dump_form(form_name: str, info: formparser.FormInfo) -> dict[str, Any]:
    """Преобразует разобранный Form.xml к формату HTTP-ответа 1С."""
    return {
        "name": form_name,
        "title": info.title,
        "elements": [
            {
                "name": e.name,
                "type": formparser.display_type(e.type),
                "title": e.title,
                "dataPath": e.data_path,
                "events": [
                    {"event": ev.event, "handler": ev.handler} for ev in e.events
                ],
            }
            for e in info.elements
        ],
        "commands": [{"name": c.name, "action": c.action} for c in info.commands],
        "handlers": [
            {"event": h.event, "handler": h.handler} for h in info.handlers
        ],
    }


def merge_dump_into_form(form: dict[str, Any], dump_form: dict[str, Any]) -> None:
    """Дополняет HTTP-ответ данными из dump.

    Имя и заголовок остаются из HTTP (там настроенный синоним), dump —
    запасной вариант. Элементы/команды/обработчики всегда берутся из dump,
    потому что HTTP их не отдаёт вовсе.
    """
    if not form.get("name"):
        form["name"] = dump_form["name"]
    if not form.get("title"):
        form["title"] = dump_form["title"]
    for key in ("elements", "commands", "handlers"):
        if dump_form[key]:
            form[key] = dump_form[key]


def format_form_structure(f: dict[str, Any]) -> str:
    lines = [f"# Форма: {f.get('name', '')}"]
    if f.get("title"):
        lines.append(f"**Заголовок:** {f['title']}")
    lines.append("")

    elements = f.get("elements") or []
    if elements:
        lines.append("## Элементы формы")
        lines.append("")
        lines.append("| Имя | Тип | Заголовок | Путь к данным |")
        lines.append("|-----|-----|-----------|---------------|")
        for e in elements:
            lines.append(
                "| {} | {} | {} | {} |".format(
                    escape_pipe(e.get("name", "")),
                    escape_pipe(e.get("type", "")),
                    escape_pipe(e.get("title", "")),
                    escape_pipe(e.get("dataPath", "")),
                )
            )
        lines.append("")

        # События уровня элементов выводятся только если они вообще есть —
        # у большинства элементов формы их нет.
        element_events = [
            (e.get("name", ""), ev)
            for e in elements
            for ev in e.get("events") or []
        ]
        if element_events:
            lines.append("### События элементов")
            lines.append("")
            for name, ev in element_events:
                lines.append(
                    f"- **{name}** (`{ev.get('event', '')}`) → {ev.get('handler', '')}()"
                )
            lines.append("")

    commands = f.get("commands") or []
    if commands:
        lines.append("## Команды формы")
        lines.append("")
        for c in commands:
            lines.append(f"- **{c.get('name', '')}** → {c.get('action', '')}")
        lines.append("")

    handlers = f.get("handlers") or []
    if handlers:
        lines.append("## Обработчики событий")
        lines.append("")
        for h in handlers:
            lines.append(f"- **{h.get('event', '')}** → {h.get('handler', '')}()")
        lines.append("")

    return "\n".join(lines) + "\n"
