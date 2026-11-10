"""Инструмент get_object_structure: реквизиты и структура объекта метаданных."""

from __future__ import annotations

from typing import Annotated, Any

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations
from pydantic import Field

from mcp_baf_audit import AuditWriter
from mcp_baf.client import OneCClient
from mcp_baf.dumpindex.modulenames import OBJECT_TYPE_TO_DUMP_DIR
from mcp_baf.tools.common import object_path_segments, traced_text, truncate_output


def register(mcp: MCPServer, client: OneCClient, audit: AuditWriter) -> None:
    @mcp.tool(
        name="get_object_structure",
        title="Реквизиты и структура объекта",
        description=(
            "Получить реквизиты, табличные части, измерения, ресурсы, значения перечисления "
            "и типы полей объекта метаданных 1С. "
            "Покажет из чего состоит справочник, документ, регистр, перечисление: "
            "какие поля, колонки, свойства, значения. "
            "Используй когда спрашивают про реквизиты, состав или структуру конкретного объекта "
            "(например «какие реквизиты у справочника Валюты» или «какие значения у перечисления СтатусыЗаказов»). "
            "Результат содержит точные имена реквизитов, табличных частей и значений перечислений "
            "для запросов и кода. "
            "Вызывай перед написанием запросов или кода, работающего с объектом."
        ),
        annotations=ToolAnnotations(read_only_hint=True),
    )
    async def get_object_structure(
        object_type: Annotated[str, Field(description=(
            "Тип объекта метаданных: Catalog, Document, Enum, InformationRegister, "
            "AccumulationRegister, AccountingRegister, CalculationRegister, ChartOfAccounts, "
            "ChartOfCharacteristicTypes, ChartOfCalculationTypes, ExchangePlan, BusinessProcess, "
            "Task, DataProcessor, Report. Для Enum дополнительно возвращается поле values "
            "со списком значений перечисления."
        ))],
        object_name: Annotated[str, Field(
            description="Имя объекта метаданных, например РеализацияТоваровУслуг"
        )],
    ) -> str:
        if not object_type or not object_name:
            raise ValueError("object_type and object_name are required")

        async def run() -> str:
            # Оба сегмента подставляются в URL: белый список типов + имя по регексу.
            url_type, url_name = object_path_segments(
                object_type, object_name, OBJECT_TYPE_TO_DUMP_DIR
            )
            obj = await client.get(f"/object/{url_type}/{url_name}")
            return truncate_output(format_object_structure(obj))

        return await traced_text(
            audit, "get_object_structure", run,
            args={"object_type": object_type, "object_name": object_name},
        )


def format_object_structure(obj: dict[str, Any]) -> str:
    lines = [f"# {obj.get('name', '')} ({obj.get('synonym', '')})", ""]

    attr_sections = [
        ("Измерения", obj.get("dimensions")),
        ("Ресурсы", obj.get("resources")),
        ("Реквизиты", obj.get("attributes")),
    ]
    for title, items in attr_sections:
        if not items:
            continue
        lines.append(f"## {title}")
        lines.extend(_attr_line(attr) for attr in items)
        lines.append("")

    tabular_parts = obj.get("tabularParts") or []
    if tabular_parts:
        lines.append("## Табличные части")
        for tp in tabular_parts:
            lines.append("")
            lines.append(f"### {tp.get('name', '')}")
            lines.extend(_attr_line(attr) for attr in tp.get("attributes") or [])

    values = obj.get("values") or []
    if values:
        lines.append("## Значения")
        for v in values:
            line = f"- **{v.get('name', '')}** ({v.get('synonym', '')})"
            if v.get("comment"):
                line += f" — {v['comment']}"
            lines.append(line)
        lines.append("")

    return "\n".join(lines) + "\n"


def _attr_line(attr: dict[str, Any]) -> str:
    return (
        f"- **{attr.get('name', '')}** ({attr.get('synonym', '')}) "
        f"— {attr.get('type', '')}"
    )
