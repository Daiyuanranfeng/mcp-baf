"""Анализ и форматирование переданного текста без изменения исходников."""

import asyncio
from typing import Annotated, Literal
import re

from mcp.types import ToolAnnotations
from pydantic import Field

from mcp_baf.bsl_native import analyze, format_source
from mcp_baf.tools.common import escape_pipe, traced_text


def register(mcp, audit):
    @mcp.tool(description="Базовый анализ текста BSL встроенным Python-анализатором: ParseError, DuplicateParameter, DuplicateVariable, UnusedLocalVariable, UnreachableCode, EmptyExcept, TrailingWhitespace, LineLength. src — код, не путь. levels: error, warning, information, hint; diagnostic_codes — фильтр кодов. Это ограниченные проверки фрагмента, не компилятор и не полный BSL Language Server; условия препроцессора не вычисляются. Файлы пользователя не изменяются.", annotations=ToolAnnotations(read_only_hint=True))
    async def bsl_analyze(src: str, levels: list[Literal["error", "warning", "information", "hint"]] | None = None, diagnostic_codes: list[str] | None = None, limit: Annotated[int, Field(ge=1, le=500)] = 50) -> str:
        async def run():
            selected = ["error", "warning"] if levels is None else levels
            if not selected:
                raise ValueError("levels: error, warning, information, hint; список не может быть пустым")
            diagnostics = await asyncio.to_thread(analyze, src)
            hits = [d for d in diagnostics if d["level"] in selected and (not diagnostic_codes or d["code"] in diagnostic_codes)]
            lines = [f"## BSL: {len(hits)} диагностик по фильтрам (всего {len(diagnostics)})", "", "> Базовые проверки фрагмента на Python; отсутствие диагностик не подтверждает компиляцию на платформе.", "", "| Строка:колонка | Уровень | Код | Сообщение |", "|---|---|---|---|"]
            for d in hits[:limit]:
                lines.append(f"| {d['line']}:{d['column']} | {d['level']} | {escape_pipe(d['code'])} | {escape_pipe(d['message']).replace(chr(10), ' ')} |")
            if len(hits) > limit:
                lines.append(f"\n> Показаны первые {limit} диагностик.")
            return "\n".join(lines)
        # Размер в символах, без кодирования src в байтовый буфер: лимит 2 MiB
        # проверяет bsl_native, а сам код в аудит не пишется.
        return await traced_text(audit, "bsl_analyze", run, args={"src_chars": len(src), "levels": levels, "diagnostic_codes": diagnostic_codes, "limit": limit})

    @mcp.tool(description="Базовое форматирование BSL встроенным Python-форматером: отступы по 4 пробела и концевые пробелы. Сохраняет токены, строки, комментарии и LF/CRLF; при ошибках поддерживаемого синтаксиса отказывает. Возвращает код; исходные файлы и база не изменяются. src — текст, не путь.", annotations=ToolAnnotations(read_only_hint=True))
    async def bsl_format(src: str) -> str:
        async def run():
            formatted = await asyncio.to_thread(format_source, src)
            fence = "`" * max(3, max((len(x) for x in re.findall(r'`+', formatted)), default=0) + 1)
            return f"{fence}bsl\n{formatted}\n{fence}"
        return await traced_text(audit, "bsl_format", run, args={"src_chars": len(src)})
