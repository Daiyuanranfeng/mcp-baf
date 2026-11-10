"""Синтаксис, безопасное форматирование и приватность Python-анализатора."""

import asyncio
import json
from pathlib import Path

import pytest
from mcp.server.mcpserver import MCPServer

from mcp_baf_audit import AuditLog
from mcp_baf.bsl_native import analyze, format_source
from mcp_baf.bsl_native.lexer import lex
from mcp_baf.tools import bsl_analysis


def codes(src):
    return {item['code'] for item in analyze(src)}


@pytest.mark.parametrize('src', [
    'Процедура Тест(Знач Имя = "", Массив = Неопределено) Экспорт\nСообщить(Имя);\nКонецПроцедуры',
    'Function F(A) Export\nIf Not A = Undefined Then Return New Array(); Else Return ?(A > 0, A, 0); EndIf;\nEndFunction',
    'Для Каждого Элемент Из Коллекция Цикл\nЕсли Элемент = Null Тогда Продолжить; КонецЕсли;\nКонецЦикла;',
    'Для Номер = 1 По 10 Цикл Пока Истина Цикл Прервать; КонецЦикла; КонецЦикла;',
    'Попытка\nДанные.Поле[0] = Новый Структура("Имя", "Если КонецЕсли");\nИсключение\nВызватьИсключение;\nКонецПопытки;',
    'Асинх Процедура Тест()\nРезультат = Ждать ПолучитьАсинх();\nКонецПроцедуры',
    'Процедура Тест()\n~Метка:\nДата = \'20261004\';\nЕсли Истина Тогда Перейти ~Метка; КонецЕсли;\nКонецПроцедуры',
    '&НаСервере\n#Область Тест\nПроцедура Тест()\n// Если Попытка\nСообщить("Он сказал ""Да""");\nКонецПроцедуры\n#КонецОбласти',
    'Процедура Тест()\nТекст = "Если\n    |КонецЕсли";\nСообщить(Текст);\nКонецПроцедуры',
    'ДобавитьОбработчик Объект.Событие, Обработчики.Метод;\nУдалитьОбработчик Объект.Событие, Обработчики.Метод;',
    'А = Новый("Структура", "Ключ", 1); Метод(, А,);',
])
def test_supported_syntax(src):
    assert 'ParseError' not in codes(src)


@pytest.mark.parametrize('src', [
    'Если Истина Тогда\nСообщить(1);',
    'Процедура Тест()\nКонецФункции',
    'Сообщить((1);',
    'А = "нет закрытия;',
    'А = "начало\nбез продолжения";',
    "А = '2026';",
    'Прервать;',
    'Возврат 1;',
    'Процедура Тест() Возврат 1; КонецПроцедуры',
    'Попытка А = 1; КонецПопытки;',
    'А = 1 Б = 2;',
    '#Иначе\nА = 1;',
    '#Если Сервер Тогда\nА = 1;',
    '#Область Тест\n#КонецЕсли',
    '#If Server Then\n#Else\n#ElsIf Client Then\n#EndIf',
])
def test_errors_are_reported_and_format_refuses(src):
    assert 'ParseError' in codes(src)
    with pytest.raises(ValueError, match='Форматирование недоступно'):
        format_source(src)


def test_local_scopes_and_non_code_words():
    src = '''Процедура Первый(А)
Перем НеЧитается, Используется;
НеЧитается = 1;
Используется = 2;
Объект.НеЧитается = "НеЧитается";
// НеЧитается
Сообщить(Используется);
КонецПроцедуры
Процедура Второй()
Перем НеЧитается;
Сообщить(НеЧитается);
КонецПроцедуры'''
    results = analyze(src)
    assert [(d['line'], d['column']) for d in results if d['code'] == 'UnusedLocalVariable'] == [(2, 7)]


def test_duplicate_names_casefold_and_flow():
    src = '''Процедура Тест(А, а)
Перем Б, б, А;
Попытка Сообщить(А); Исключение КонецПопытки;
Возврат;
Сообщить(А);
КонецПроцедуры'''
    assert {'DuplicateParameter', 'DuplicateVariable', 'EmptyExcept', 'UnreachableCode'} <= codes(src)


@pytest.mark.parametrize('statement', [
    'Выполнить("Сообщить(А)");', 'Результат = Вычислить("А");',
    '#Если Сервер Тогда\nСообщить(1);\n#Иначе\nСообщить(2);\n#КонецЕсли',
])
def test_uncertain_dynamic_reads_do_not_report_unused(statement):
    assert 'UnusedLocalVariable' not in codes(f'Процедура Тест()\nПерем А;\n{statement}\nКонецПроцедуры')


def test_formatter_indent_tokens_literals_crlf_and_idempotence():
    src = '''Процедура Тест()
Если Истина Тогда
Текст = "Первая  
  |КонецЕсли  
  |";
  // Комментарий с пробелами  
Сообщить(Текст);  
ИначеЕсли Ложь Тогда
Попытка
Сообщить("""" );
Исключение
Сообщить(ОписаниеОшибки());
КонецПопытки;
Иначе
Сообщить(1);
КонецЕсли;
КонецПроцедуры'''.replace('\n', '\r\n')
    formatted = format_source(src)
    assert '\r\n        Текст' in formatted
    assert '\r\n    ИначеЕсли' in formatted
    assert '\r\n            Сообщить' in formatted
    assert '\r\n        // Комментарий с пробелами  \r\n' in formatted
    assert '\r\n  |КонецЕсли  \r\n  |";' in formatted
    assert '\r\n        Сообщить(Текст);\r\n' in formatted
    assert not formatted.endswith('\n')
    assert format_source(formatted) == formatted
    assert [(t.kind, t.text) for t in lex(src)[0]] == [(t.kind, t.text) for t in lex(formatted)[0]]


def test_one_line_block_does_not_outdent_following_statement():
    formatted = format_source('Процедура Тест()\nЕсли Истина Тогда Сообщить(1); КонецЕсли;\nСообщить(2);\nКонецПроцедуры\n')
    assert '\n    Сообщить(2);\n' in formatted


def test_information_diagnostics_and_limits():
    result = analyze('А = 1;  \n// ' + 'х' * 121)
    assert {d['code'] for d in result} == {'TrailingWhitespace', 'LineLength'}
    assert {d['level'] for d in result} == {'information'}
    for src in ('', ' ' * (2 * 1024 * 1024) + 'А=1;'):
        with pytest.raises(ValueError):
            analyze(src)
    assert 'ParseError' in codes('А = ' + '(' * 120 + '1' + ')' * 120 + ';')


def test_analyzer_accepts_own_extension():
    path = Path(__file__).parents[1] / 'src/mcp_baf/extension_src/HTTPServices/MCPService/Ext/Module.bsl'
    assert not [d for d in analyze(path.read_text()) if d['level'] == 'error']


def test_tools_filters_limits_privacy_and_no_source_file_changes(tmp_path):
    src = 'Процедура PRIVATE_CODE()\nПерем А, Б;\nВозврат;\nСообщить(1);\nКонецПроцедуры'
    original = tmp_path / 'Module.bsl'
    original.write_text(src)
    timestamp = original.stat().st_mtime_ns
    server = MCPServer('test')
    bsl_analysis.register(server, AuditLog(str(tmp_path)))
    async def scenario():
        result = (await server.call_tool('bsl_analyze', dict(src=src, levels=['warning'], diagnostic_codes=['UnusedLocalVariable'], limit=1))).content[0].text
        assert 'Показаны первые 1' in result and 'UnreachableCode' not in result
        formatted = (await server.call_tool('bsl_format', dict(src=src + '\n// ```'))).content[0].text
        assert formatted.startswith('````bsl')
    asyncio.run(scenario())
    assert 'PRIVATE_CODE' not in (tmp_path / 'audit.log').read_text()
    assert original.read_text() == src and original.stat().st_mtime_ns == timestamp


def test_audit_has_char_count_not_code_and_stays_small(tmp_path):
    # Аудит несёт только длину в символах: src не кодируется в байтовый буфер
    # ради подсчёта и сам код в журнал не попадает.
    src = 'Процедура PRIVATE_CODE()\nПерем А, Б;\nВозврат;\nКонецПроцедуры'
    server = MCPServer('test')
    bsl_analysis.register(server, AuditLog(str(tmp_path)))

    async def scenario():
        await server.call_tool('bsl_analyze', dict(src=src))
        await server.call_tool('bsl_format', dict(src=src))

    asyncio.run(scenario())
    events = [json.loads(line) for line in (tmp_path / 'audit.log').read_text('utf-8').splitlines()]
    calls = [e for e in events if e['event'] == 'tool.call']
    assert {e['tool'] for e in calls} == {'bsl_analyze', 'bsl_format'}
    for event in calls:
        assert event['args']['src_chars'] == len(src)
        assert 'src' not in event['args'] and 'src_bytes' not in event['args']
        assert 'PRIVATE_CODE' not in json.dumps(event, ensure_ascii=False)
        assert len(json.dumps(event, ensure_ascii=False)) < 1024


@pytest.mark.parametrize('src', [
    '﻿#Область Х\nПроцедура А()\nКонецПроцедуры\n#КонецОбласти\n',
    '﻿&НаСервере\nПроцедура А()\nКонецПроцедуры\n',
    'Процедура А()\nТ = "a"\n"b";\nСообщить(НСтр("ru=\'%1\'"\n"en=\'%1\'"));\nКонецПроцедуры',
    "Процедура А()\nД = '0001-01-01';\nД = '2026.10.04 10:00:00';\nКонецПроцедуры",
    'Процедура А()\nТ = "ВЫБРАТЬ\n\n// пояснение\n|1";\nКонецПроцедуры',
    'Асинх Процедура А()\nЖдать Б();\nКонецПроцедуры',
    'Процедура А()\n' + '// c\n' * 120_000 + 'КонецПроцедуры',
], ids=['bom-region', 'bom-annotation', 'adjacent-strings', 'dates', 'string-gap', 'await', 'many-comments'])
def test_real_module_syntax_is_accepted_and_formatted(src):
    # Конструкции из выгрузок типовых конфигураций, дававшие ложный ParseError.
    assert 'ParseError' not in codes(src)
    assert format_source(format_source(src)) == format_source(src)


def test_preprocessor_branch_does_not_make_code_unreachable():
    src = 'Процедура А()\n#Если Сервер Тогда\nВозврат;\n#КонецЕсли\nБ = 1;\nКонецПроцедуры'
    assert 'UnreachableCode' not in codes(src)
    assert 'UnreachableCode' in codes('Процедура А()\nВозврат;\nБ = 1;\nКонецПроцедуры')


def test_format_keeps_working_on_duplicates_and_odd_line_breaks():
    # Дубли имён — не синтаксис; \f и \x85 не являются переводом строки BSL.
    assert format_source('Процедура А(Б, Б)\nВ = 1;\nКонецПроцедуры') == 'Процедура А(Б, Б)\n    В = 1;\nКонецПроцедуры'
    src = 'Процедура А()\n// a\x0cb\x85c\nЕсли Б Тогда\nВ = 1;\nКонецЕсли;\nКонецПроцедуры\n'
    assert format_source(src) == 'Процедура А()\n    // a\x0cb\x85c\n    Если Б Тогда\n        В = 1;\n    КонецЕсли;\nКонецПроцедуры\n'


def test_format_indents_statement_continuations():
    src = 'Процедура А()\nЕсли Б И\nВ Тогда\nВызов(Г,\nД);\nКонецЕсли;\nКонецПроцедуры'
    assert format_source(src) == (
        'Процедура А()\n    Если Б И\n        В Тогда\n        Вызов(Г,\n            Д);\n    КонецЕсли;\nКонецПроцедуры'
    )
