"""Поиск ссылок, навигация и права метаданных. Собственная реализация контрактов."""

from __future__ import annotations

import re
from typing import Annotated, Literal
from urllib.parse import unquote, urlsplit, parse_qs
from uuid import UUID

from mcp.types import ToolAnnotations
from pydantic import Field

from mcp_baf.tools.common import escape_pipe, traced_text

Scope = Literal["catalogs", "documents", "information_registers", "accumulation_registers", "accounting_registers", "calculation_registers", "all"]
DEFAULT_SCOPE = ["catalogs", "documents", "information_registers", "accumulation_registers"]
REFERENCE_KINDS = {
    "Справочник", "Документ", "ПланСчетов",
    "ПланВидовХарактеристик", "ПланВидовРасчета", "ПланОбмена", "БизнесПроцесс", "Задача",
}
NAME = re.compile(r"^[^\W\d]\w*$", re.UNICODE)


def validate_kind(kind: str) -> None:
    parts = kind.split(".")
    if len(parts) != 2 or parts[0] not in REFERENCE_KINDS or not NAME.fullmatch(parts[1]):
        raise ValueError("Ожидается тип из метаданных: " + ", ".join(sorted(REFERENCE_KINDS)) + ".ИмяОбъекта")


def validate_ref(ref: str) -> str:
    try:
        result = UUID(ref)
    except ValueError as exc:
        raise ValueError("Ожидается GUID, например 12345678-1234-1234-1234-123456789abc") from exc
    if result.int == 0:
        raise ValueError("Пустая ссылка не поддерживается")
    return str(result)


def parse_link(link: str) -> tuple[str, str]:
    """Внутренняя ссылка или URL публикации с фрагментом e1cib/data/."""
    parsed = urlsplit(link)
    if parsed.scheme and parsed.scheme not in {"http", "https", "e1c"}:
        raise ValueError("Ожидается e1cib/data/Тип.Имя?ref=... или URL публикации с такой ссылкой")
    candidate = unquote(parsed.fragment or link)
    if not candidate.startswith("e1cib/data/"):
        raise ValueError("Ожидается e1cib/data/Тип.Имя?ref=... или URL публикации с такой ссылкой")
    path, separator, query = candidate.partition("?")
    kind = path.removeprefix("e1cib/data/")
    validate_kind(kind)
    params = parse_qs(query, strict_parsing=True)
    values = params.get("ref", [])
    if not separator or set(params) != {"ref"} or len(values) != 1:
        raise ValueError("Ссылка должна содержать ровно один параметр ref")
    value = values[0]
    if re.fullmatch(r"[a-fA-F0-9]{32}", value):
        # Формат платформы: группы UUID 4+5+3+2+1.
        value = value[24:32] + "-" + value[20:24] + "-" + value[16:20] + "-" + value[:4] + "-" + value[4:16]
    return kind, validate_ref(value)


def _required_str(data: dict, key: str, tool: str) -> str:
    """Обязательное строковое поле ответа 1С: иначе явная ошибка контракта."""
    value = data.get(key)
    if not isinstance(value, str) or not value:
        raise ValueError(f"{tool}: ответ 1С без обязательного поля {key}")
    return value


def format_references(result: dict) -> str:
    lines = ["## Ссылки на объект", "", "В пределах прав и RLS HTTP-пользователя.", ""]
    groups: dict[str, list] = {}
    for hit in result.get("hits", []):
        # Группа — отображаемый ярлык: отсутствие поля не должно ронять инструмент.
        groups.setdefault(str(hit.get("found_in_meta") or "(без метаданных)"), []).append(hit)
    for meta, hits in groups.items():
        lines += [f"### {escape_pipe(meta)} ({len(hits)})", "", "| Объект / ключ | Поле | Вид |", "|---|---|---|"]
        for h in hits:
            lines.append("| " + " | ".join(escape_pipe(str(h.get(k, ""))).replace("\n", " ") for k in ("found_in_object", "path", "match_kind")) + " |")
    if not groups:
        lines.append("Совпадений в проверенных областях не найдено.")
    if result.get("timeout_exceeded") or result.get("truncated") or result.get("skipped_names"):
        lines += ["", "> Поиск неполный: достигнут бюджет/лимит или часть полей недоступна."]
    for s in result.get("skipped_names", []):
        lines.append(f"- {escape_pipe(str(s.get('name', '')))}: {escape_pipe(str(s.get('reason', '')))}")
    return "\n".join(lines)


def register(mcp, client, audit):
    @mcp.tool(description="Найти ссылки на объект по GUID и полному имени типа. Области: catalogs, documents, information_registers, accumulation_registers, accounting_registers, calculation_registers, all. Поиск в пределах прав/RLS. Бюджет проверяется между запросами, текущий запрос не прерывается.", annotations=ToolAnnotations(read_only_hint=True))
    async def find_object_references(
        ref: str, ref_kind: str, scope: list[Scope] | None = None,
        limit_hits: Annotated[int, Field(ge=1, le=1000)] = 200,
        limit_per_meta: Annotated[int, Field(ge=1, le=100)] = 20,
        timeout_budget_sec: Annotated[int, Field(ge=1, le=120)] = 30,
    ) -> str:
        async def run():
            validate_kind(ref_kind)
            areas = DEFAULT_SCOPE if scope is None else scope
            if not areas:
                raise ValueError("scope не может быть пустым; используйте catalogs, documents, information_registers, accumulation_registers, accounting_registers, calculation_registers, all")
            body = dict(ref=validate_ref(ref), ref_kind=ref_kind, scope=areas, limit_hits=limit_hits, limit_per_meta=limit_per_meta, timeout_budget_sec=timeout_budget_sec)
            return format_references(await client.post("/refs", body))
        return await traced_text(audit, "find_object_references", run, args=dict(ref=ref, ref_kind=ref_kind, scope=scope, limit_hits=limit_hits, limit_per_meta=limit_per_meta, timeout_budget_sec=timeout_budget_sec))

    @mcp.tool(description="Навигация: mode=make формирует внутреннюю ссылку по ref (GUID) и kind (Тип.Имя); mode=resolve принимает link e1cib/data/... или URL публикации с таким фрагментом. URL другого сервера не загружается. Внутренняя ссылка открывается в клиенте текущей базы.", annotations=ToolAnnotations(read_only_hint=True))
    async def get_object_link(mode: Literal["make", "resolve"], ref: str = "", kind: str = "", link: str = "") -> str:
        async def run():
            target_kind, target_ref = parse_link(link) if mode == "resolve" else (kind, validate_ref(ref))
            validate_kind(target_kind)
            r = await client.post("/object-link", dict(mode=mode, ref=target_ref, kind=target_kind))
            if not r.get("found"):
                return "Объект не найден или недоступен в пределах прав пользователя."
            label = str(r.get("presentation", target_ref)).replace("\\", "\\\\").replace("[", "\\[").replace("]", "\\]").replace("\n", " ")
            # Ссылка формируется платформой; запрещаем произвольные схемы в Markdown.
            output_link = r.get("link", "")
            if not output_link.startswith("e1cib/data/") or any(c in output_link for c in "\r\n<>"):
                raise ValueError("Платформа вернула неподдерживаемую навигационную ссылку")
            output_link = output_link.replace("(", "%28").replace(")", "%29")
            return f"## Объект\n\n[{label}]({output_link})\n\nТип: `{_required_str(r, 'kind', 'get_object_link')}`\nGUID: `{_required_str(r, 'ref', 'get_object_link')}`"
        return await traced_text(audit, "get_object_link", run, args={"mode": mode, "ref": ref, "kind": kind})

    @mcp.tool(description="Права объекта метаданных для текущего HTTP-пользователя; user_name и roles требуют административных прав. rights — имена прав платформы, пустой список использует типовые права объекта. Проверка RLS не выполняется. Недоступная проверка не означает отсутствие права.", annotations=ToolAnnotations(read_only_hint=True))
    async def get_metadata_rights(metadata_object: str, user_name: str = "", rights: list[str] | None = None, roles: list[str] | None = None) -> str:
        async def run():
            parts = metadata_object.split(".")
            if len(parts) != 2 or not all(NAME.fullmatch(p) for p in parts):
                raise ValueError("metadata_object: ожидается Тип.Имя из метаданных")
            r = await client.post("/metadata-rights", dict(metadata_object=metadata_object, user_name=user_name, rights=rights or [], roles=roles or []))
            lines = ["## Права метаданных", "", "RLS-ограничения не анализируются.", "", "| Право | Пользователь / роль | Доступ |", "|---|---|---|"]
            for row in r.get("rights", []):
                allowed = row.get("allowed")
                value = "да" if allowed is True else "нет" if allowed is False else "проверка недоступна"
                lines.append(f"| {escape_pipe(str(row.get('right', '')))} | {escape_pipe(str(row.get('subject', '')))} | {value} |")
            lines += [f"\n> {escape_pipe(n)}" for n in r.get("notes", [])]
            return "\n".join(lines)
        return await traced_text(audit, "get_metadata_rights", run, args={"metadata_object": metadata_object, "user_name": user_name, "rights": rights, "roles": roles})
