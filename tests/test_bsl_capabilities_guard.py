"""Статичний гард Module.bsl і карт доступів для маршруту /extensions.

BSL у pytest не виконується, тому контракт «маршрут оголошений і обмежений»
перевіряється читанням вихідників розширення: /capabilities, обробник, право,
ліміт розміру й відсутність повного дампу всіх .cfe одним відповіддю.
"""

from pathlib import Path
import re
import xml.etree.ElementTree as ET

from mcp_baf.access import EXTENSION_METHODS, TOOL_METHODS

ROOT = Path(__file__).parents[1]
EXTENSION = ROOT/'src/mcp_baf/extension_src'
MODULE = EXTENSION/'HTTPServices/MCPService/Ext/Module.bsl'
ACCESS = ROOT/'src/mcp_baf/access.py'
MD = {'m': 'http://v8.1c.ru/8.3/MDClasses'}
RIGHTS = {'r': 'http://v8.1c.ru/8.2/roles'}


def module_text() -> str:
    return MODULE.read_text(encoding='utf-8-sig')


def body(name: str) -> str:
    """Тіло функції <name>(Запрос) без КонецФункции."""
    match = re.search(r'Функция ' + name + r'\(Запрос\)(.*?)КонецФункции', module_text(), re.S)
    assert match, f'нет обработчика {name}'
    return str(match.group(1))


def test_route_declared_in_capabilities_and_access_maps():
    # Без объявления в /capabilities право Расширения.GET не видно Python-стороне,
    # и канал выгрузки кода расширений выпадает из модели доступа.
    declared = dict(re.findall(r'Карта\.Вставить\("(\w+)", "([\w.-]+)"\)', body('ВозможностиGET')))
    assert declared.get('Расширения') == 'extensions.GET'
    assert EXTENSION_METHODS == {'extensions.GET'}
    assert set(declared.values()) == set(TOOL_METHODS.values()) | EXTENSION_METHODS
    # Маршрут без MCP-инструмента не подменяет имя инструмента в TOOL_METHODS.
    assert not set(TOOL_METHODS) & EXTENSION_METHODS
    assert not set(TOOL_METHODS.values()) & EXTENSION_METHODS


def test_extensions_route_exists_with_right_check_and_xml_contract():
    root = ET.parse(EXTENSION/'HTTPServices/MCPService.xml').getroot()
    templates = {t.find('m:Properties/m:Name', MD).text: t
                 for t in root.findall('.//m:URLTemplate', MD)}
    assert 'Расширения' in templates
    assert templates['Расширения'].find('m:Properties/m:Template', MD).text == '/extensions'
    handlers = [m.find('m:Properties/m:Handler', MD).text
                for m in templates['Расширения'].findall('m:ChildObjects/m:Method', MD)]
    assert handlers == ['РасширенияGET']
    grants = {o.find('r:name', RIGHTS).text
              for o in ET.parse(EXTENSION/'Roles/MCP_ОсновнаяРоль/Ext/Rights.xml').getroot()
              .findall('r:object', RIGHTS)
              if o.find('r:right/r:value', RIGHTS).text == 'true'}
    assert 'HTTPService.MCPService.URLTemplate.Расширения.Method.GET' in grants
    assert 'МетодДоступен("Расширения", "GET")' in body('РасширенияGET')


def test_extensions_handler_paginates_by_name_and_never_dumps_everything():
    text = body('РасширенияGET')
    # Пагинация по имени: перечень без данных, затем один .cfe по ?name=.
    assert 'Запрос.ПараметрыЗапроса.Получить("name")' in text
    # Повторённый параметр приходит массивом — берём только строку.
    assert 'ТипЗнч(ЗначениеИмени) = Тип("Строка")' in text
    assert 'Если ПустаяСтрока(ИмяЗапроса) Тогда' in text
    listing = text[:text.index('Найденное = Неопределено')]
    assert '"extensions"' in listing and '"name"' in listing
    assert 'Base64Строка' not in listing and '"data"' not in listing
    # Данные читаются ровно для одного расширения: полного дампа больше нет.
    assert re.findall(r'(\S+)\.ПолучитьДанные\(\)', text) == ['Найденное']
    assert text.count('Base64Строка') == 1
    assert 'ОтветОшибка(404, "Extension not found")' in text
    assert 'Результат.Вставить("name", Найденное.Имя)' in text
    assert 'Результат.Вставить("size", Размер)' in text


def test_extensions_response_is_size_limited():
    text = body('РасширенияGET')
    assert 'Размер = Данные.Размер()' in text
    assert 'Если Размер > ПределРазмераРасширения() Тогда' in text
    assert 'ОтветОшибка(413,' in text and '"extension_too_large"' in text
    # Лимит проверяется до кодирования в base64, иначе память уже потрачена.
    assert text.index('ПределРазмераРасширения()') < text.index('Base64Строка(Данные)')
    limit = re.search(r'Функция ПределРазмераРасширения\(\)(.*?)КонецФункции', module_text(), re.S)
    assert limit, 'нет функции ПределРазмераРасширения'
    factors = re.search(r'Возврат\s+(\d+)\s*\*\s*(\d+)\s*\*\s*(\d+)\s*;', limit.group(1))
    assert factors, 'лимит должен быть целым числом байт'
    assert int(factors.group(1)) * int(factors.group(2)) * int(factors.group(3)) == 16 * 1024 * 1024


def test_method_available_keeps_out_param_and_reason_order():
    match = re.search(r'Функция МетодДоступен\(([^)]*)\)(.*?)КонецФункции', module_text(), re.S)
    assert match
    assert 'ПричинаОтказа = ""' in match.group(1)  # значение по умолчанию — это не запись
    text = match.group(2)
    # Out-параметр нельзя обнулять на входе: причина отказа иначе теряется.
    assert not [line for line in text.splitlines() if line.strip() == 'ПричинаОтказа = "";']
    # Порядок этапов критичен: причина указывает, где именно отказ.
    codes = ['service_not_found', 'template_not_found', 'method_not_found', 'method_use_denied']
    positions = [text.index(f'ПричинаОтказа = "{code}"') for code in codes]
    assert positions == sorted(positions)
    assert text.index('Возврат Истина') > positions[-1]


def test_version_route_obeys_method_right_like_other_routes():
    assert 'МетодДоступен("Версия", "GET")' in body('ВерсияGET')
    assert 'ОтветОшибка(403, "Нет права использования метода")' in body('ВерсияGET')


def test_capabilities_denial_is_audited_without_secrets():
    source = ACCESS.read_text(encoding='utf-8')
    assert 'access.capabilities_unavailable' in source
    assert 'reason=type(exc).__name__' in source
    assert 'error=str(exc)[:300]' in source
    # Отказ логируется в ветке except, а не только меняет текст ошибки.
    denied = source[source.index('except Exception as exc:'):]
    assert denied.index('access.capabilities_unavailable') < denied.index('self._expires')
    assert 'password' not in denied[:denied.index('self._expires')]
