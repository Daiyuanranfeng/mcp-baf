"""Узгодженість XML-джерел, прав, маршрутів і серверних обробників."""

from pathlib import Path
import re
import xml.etree.ElementTree as ET

from mcp_baf import __version__
from mcp_baf.access import EXTENSION_METHODS, TOOL_METHODS
from mcp_baf.bsl_native.lexer import lex
from mcp_baf.bsl_native.parser import Parser
from mcp_baf.server import EXPECTED_EXTENSION_VERSION

ROOT = Path(__file__).parents[1]
EXTENSION = ROOT/'src/mcp_baf/extension_src'
MD = {'m':'http://v8.1c.ru/8.3/MDClasses'}
RIGHTS = {'r':'http://v8.1c.ru/8.2/roles'}
DUMP = {'d':'http://v8.1c.ru/8.3/xcf/dumpinfo'}


def test_access_right_calls_have_required_platform_arguments():
    # ПравоДоступа(Право, ОбъектМетаданных, ПользовательИлиРоль):
    # первые два параметра обязательны. Парсер фрагментов BSL не знает API платформы.
    source = (EXTENSION/'HTTPServices/MCPService/Ext/Module.bsl').read_text(encoding='utf-8-sig')
    tokens = [token for token in lex(source)[0] if token.kind != 'comment']
    calls = 0
    for index, token in enumerate(tokens):
        if token.text.casefold() != 'праводоступа':
            continue
        assert tokens[index + 1].text == '('
        depth, commas = 0, 0
        for argument in tokens[index + 1:]:
            if argument.text == '(':
                depth += 1
            elif argument.text == ')':
                depth -= 1
                if depth == 0:
                    break
            elif argument.text == ',' and depth == 1:
                commas += 1
        assert depth == 0
        assert 2 <= commas + 1 <= 3, f'ПравоДоступа: строка {token.line}, параметров {commas + 1}'
        calls += 1
    assert calls > 0


def test_extension_does_not_assign_read_only_chars_global():
    # Символы/Chars — системный объект, а не свободное имя локальной переменной.
    source = (EXTENSION/'HTTPServices/MCPService/Ext/Module.bsl').read_text(encoding='utf-8-sig')
    nodes = Parser(lex(source)[0]).parse()
    while nodes:
        node = nodes.pop()
        if node.kind == 'assignment':
            assert node.token.text.casefold() not in {'символы', 'chars'}, f'Запись системного объекта: строка {node.token.line}'
        nodes.extend(node.children)


def test_register_key_metadata_uses_platform_property_names():
    # Контракт платформы: у регистра сведений нет свойства Периодичность.
    # Ошибка этого имени превращала каждый поиск в регистре в пропуск.
    source = (EXTENSION/'HTTPServices/MCPService/Ext/Module.bsl').read_text(encoding='utf-8-sig')
    body = re.search(r'Функция КлючиРегистра\(Мета, Область\)(.*?)КонецФункции', source, re.S).group(1)
    tokens = [token for token in lex(body)[0] if token.kind != 'comment']
    properties = {
        tokens[index + 2].text.casefold()
        for index, token in enumerate(tokens[:-2])
        if token.text.casefold() == 'мета' and tokens[index + 1].text == '.'
    }
    assert 'периодичностьрегистрасведений' in properties
    # Подчинение регистратору читается из РежимЗаписи; у регистра расчёта нет Период.
    assert properties <= {'периодичностьрегистрасведений', 'режимзаписи', 'измерения'}
    assert '"calculation_registers", "ПериодРегистрации", "Период"' in body


def test_all_routes_ids_rights_handlers_and_guards():
    root = ET.parse(EXTENSION/'HTTPServices/MCPService.xml').getroot()
    service = root.find('m:HTTPService',MD)
    templates = service.findall('m:ChildObjects/m:URLTemplate',MD)
    names = [t.find('m:Properties/m:Name',MD).text for t in templates]
    assert len(set(names)) == len(names) == 13
    module = (EXTENSION/'HTTPServices/MCPService/Ext/Module.bsl').read_text(encoding='utf-8-sig')
    rights = ET.parse(EXTENSION/'Roles/MCP_ОсновнаяРоль/Ext/Rights.xml').getroot()
    grants = {o.find('r:name',RIGHTS).text for o in rights.findall('r:object',RIGHTS) if o.find('r:right/r:value',RIGHTS).text == 'true'}
    assert len(grants) == len(rights.findall('r:object',RIGHTS))
    dump = ET.parse(EXTENSION/'ConfigDumpInfo.xml').getroot()
    entries = {item.get('name'):item.get('id') for item in dump.findall('.//d:Metadata',DUMP)}
    ids = [element.get('uuid') for element in root.iter() if element.get('uuid')]
    assert len(ids) == len(set(ids))
    found = set()
    expected_grants = set()
    for template in templates:
        name = template.find('m:Properties/m:Name',MD).text
        route = template.find('m:Properties/m:Template',MD).text
        fullname = 'HTTPService.MCPService.URLTemplate.' + name
        assert entries[fullname] == template.get('uuid')
        for method in template.findall('m:ChildObjects/m:Method',MD):
            methodname = method.find('m:Properties/m:Name',MD).text
            verb = method.find('m:Properties/m:HTTPMethod',MD).text
            handler = method.find('m:Properties/m:Handler',MD).text
            assert entries[fullname+'.Method.'+methodname] == method.get('uuid')
            assert fullname+'.Method.'+methodname in grants
            expected_grants.add(fullname+'.Method.'+methodname)
            body = re.search(r'Функция '+handler+r'\(Запрос\)(.*?)КонецФункции',module,re.S)
            assert body, handler
            # /version тоже подчиняется праву использования метода, как и все маршруты.
            assert f'МетодДоступен("{name}", "{methodname}"' in body.group(1), handler
            found.add(route.split('/')[1]+'.'+verb)
    assert set(TOOL_METHODS.values()) <= found
    # /capabilities обязан объявлять ровно те методы, которых ждёт Python:
    # методы инструментов и маршруты без инструмента (выгрузка .cfe).
    capabilities = re.search(r'Функция ВозможностиGET\(Запрос\)(.*?)КонецФункции', module, re.S).group(1)
    declared = dict(re.findall(r'Карта\.Вставить\("(\w+)", "([\w.-]+)"\)', capabilities))
    assert set(declared.values()) == set(TOOL_METHODS.values()) | EXTENSION_METHODS
    assert set(declared) <= set(names)
    # Право Use принадлежит точке вызова HTTPService.URLTemplate.Method.
    # Роль не выдаёт прав контейнерам метаданных или бизнес-объектам.
    assert grants == expected_grants
    # Новые обработчики не переключают привилегированный режим и не пишут данные.
    new_logic = module[module.index('Функция МетодДоступен'):]
    assert 'УстановитьПривилегированныйРежим' not in new_logic
    assert '.Записать(' not in new_logic
    assert 'УстановитьПараметр("Цель", Цель)' in new_logic
    # Клиенту не уходят пути модулей и номера строк; сам объект не считается ссылкой на себя.
    assert 'ОписаниеОшибки()' not in new_logic
    assert 'Поле.Имя <> "Ссылка"' in new_logic


def test_package_and_extension_versions():
    configuration = ET.parse(EXTENSION/'Configuration.xml').getroot()
    assert configuration.find('m:Configuration/m:Properties/m:Version',MD).text == EXPECTED_EXTENSION_VERSION
    source = (EXTENSION/'HTTPServices/MCPService/Ext/Module.bsl').read_text(encoding='utf-8-sig')
    assert f'Результат.Вставить("version", "{EXPECTED_EXTENSION_VERSION}")' in source
    assert f'Версия расширения: {EXPECTED_EXTENSION_VERSION}' in source
    assert f'version = "{__version__}"' in (ROOT/'pyproject.toml').read_text()


def test_reference_queries_enforce_platform_permissions_and_bind_target():
    source = (EXTENSION/'HTTPServices/MCPService/Ext/Module.bsl').read_text(encoding='utf-8-sig')
    for handler in ('НавигацияPOST', 'СсылкиPOST'):
        body = re.search(r'Функция '+handler+r'\(Запрос\)(.*?)КонецФункции', source, re.S).group(1)
        queries = re.findall(r'Новый Запрос\("([^"]*)"', body)
        assert queries, handler
        # Получение строк и ключей выполняется платформой с правами и RLS.
        assert all(query.startswith('ВЫБРАТЬ РАЗРЕШЕННЫЕ ') for query in queries), handler
        assert '.УстановитьПараметр("Цель", ' in body
        assert '= &Цель' in body
        assert 'УстановитьПривилегированныйРежим' not in body
