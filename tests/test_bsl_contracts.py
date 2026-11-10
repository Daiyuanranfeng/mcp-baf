"""Статические гарды изменений Module.bsl (без запуска 1С)."""

import re
from pathlib import Path

MODULE = (
    Path(__file__).parents[1]
    / "src/mcp_baf/extension_src/HTTPServices/MCPService/Ext/Module.bsl"
)


def body_of(source: str, name: str) -> str:
    match = re.search(r"Функция " + name + r"\(Запрос\)(.*?)КонецФункции", source, re.S)
    assert match, name
    return match.group(1)


def test_query_handler_supports_offset_pagination():
    source = MODULE.read_text(encoding="utf-8-sig")
    body = body_of(source, "ЗапросPOST")
    assert 'Параметры.Свойство("offset")' in body
    assert 'Результат.Вставить("offset", СмещениеЗапрошено)' in body
    # Пропуск строк страницы выполняется до проверки лимита: иначе offset
    # съедал бы строки самой страницы и она приходила бы короче limit.
    skip = body.index("Если Смещение > 0 Тогда")
    limit = body.index("Если Счетчик >= Лимит Тогда")
    assert skip < limit
    assert "Смещение = Смещение - 1;" in body[skip:limit]


def test_event_log_total_is_returned_count_and_found_is_separate():
    source = MODULE.read_text(encoding="utf-8-sig")
    body = body_of(source, "ЖурналРегистрацииPOST")
    assert 'Результат.Вставить("total",  МассивСобытий.Количество());' in body
    assert 'Результат.Вставить("found",  ВсегоЗаписей);' in body
    # total больше не подменяется количеством найденных записей.
    assert 'Результат.Вставить("total",  ВсегоЗаписей);' not in body
    # Неполнота списка считается и по лимиту, и по окну выгрузки.
    assert 'ВсегоЗаписей > МассивСобытий.Количество()' in body
    assert 'ВсегоЗаписей >= КапВыгрузки' in body
