"""Преобразование путей dump-выгрузки в человекочитаемые имена модулей.

Порт dump/index.go (bslPathToModuleName) и dump/metadata_types.go из Go-версии.
"""

from __future__ import annotations

import unicodedata
from typing import NamedTuple


def nfc(s: str) -> str:
    """Приводит строку к Unicode NFC (порт dump.NFC из Go-версии).

    macOS распаковывает dump-выгрузку с русскими именами в NFD: Й и Ё
    (в обоих регистрах) хранятся на диске как база + комбинируемый знак,
    а запросы и имена из HTTP-ответов 1С приходят в NFC. Ключи, выведенные
    из путей на диске, поэтому нормализуются в единственной точке. Уже
    нормализованный вход (Windows/Linux/HTTP) возвращается как есть.
    """
    if unicodedata.is_normalized("NFC", s):
        return s
    return unicodedata.normalize("NFC", s)

# Таблица типов метаданных 1С: (англ. ед.ч., англ. мн.ч. — директория dump,
# рус. отображаемый префикс). Единый источник истины, как в Go-версии.
METADATA_TYPES = [
    ("Catalog", "Catalogs", "Справочник"),
    ("Document", "Documents", "Документ"),
    ("DataProcessor", "DataProcessors", "Обработка"),
    ("Report", "Reports", "Отчет"),
    ("InformationRegister", "InformationRegisters", "РегистрСведений"),
    ("AccumulationRegister", "AccumulationRegisters", "РегистрНакопления"),
    ("AccountingRegister", "AccountingRegisters", "РегистрБухгалтерии"),
    ("CalculationRegister", "CalculationRegisters", "РегистрРасчета"),
    ("ChartOfAccounts", "ChartsOfAccounts", "ПланСчетов"),
    ("ChartOfCharacteristicTypes", "ChartsOfCharacteristicTypes", "ПланВидовХарактеристик"),
    ("ChartOfCalculationTypes", "ChartsOfCalculationTypes", "ПланВидовРасчета"),
    ("ExchangePlan", "ExchangePlans", "ПланОбмена"),
    ("BusinessProcess", "BusinessProcesses", "БизнесПроцесс"),
    ("Task", "Tasks", "Задача"),
    ("Enum", "Enums", "Перечисление"),
    ("Constant", "Constants", "Константа"),
]

# Тип объекта из input инструментов (англ. ед.ч.) -> директория dump (мн.ч.).
OBJECT_TYPE_TO_DUMP_DIR = {singular: plural for singular, plural, _ in METADATA_TYPES}

# Директория dump (англ. мн.ч.) -> русский префикс имени модуля.
DUMP_DIR_NAMES = {plural: russian for _, plural, russian in METADATA_TYPES}
# Common-типы и журналы документов не имеют единственного числа в input
# инструментов, поэтому добавляются напрямую (как в Go-версии).
DUMP_DIR_NAMES["CommonModules"] = "ОбщийМодуль"
DUMP_DIR_NAMES["CommonForms"] = "ОбщаяФорма"
DUMP_DIR_NAMES["CommonCommands"] = "ОбщаяКоманда"
DUMP_DIR_NAMES["DocumentJournals"] = "ЖурналДокументов"

# Имя BSL-файла -> суффикс типа модуля. Ключ — голое имя файла, поэтому
# запись покрывает и XML-формат (.../Ext/<File>.bsl), и EDT (.../<File>.bsl).
MODULE_NAME_SUFFIXES = {
    "ObjectModule.bsl": "МодульОбъекта",
    "ManagerModule.bsl": "МодульМенеджера",
    "Module.bsl": "МодульФормы",
    "RecordSetModule.bsl": "МодульНабораЗаписей",
    "CommandModule.bsl": "МодульКоманды",
    "ValueManagerModule.bsl": "МодульМенеджераЗначения",
}

# Поддиректория dump -> русский сегмент имени дочернего объекта
# (Forms/ФормаДок -> ".Форма.ФормаДок.").
SUBDIR_SEGMENT_NAMES = {
    "Forms": "Форма",
    "Commands": "Команда",
}

# Корневая директория расширений конфигурации.
EXTENSION_DIR_NAME = "Расширения"

# Имена директорий выгрузки (англ. единственное и множественное число),
# которые не могут быть каталогом расширения: манифест в Catalogs/ или
# Documents/ — подделка или ошибка, а не расширение.
CATEGORY_LIKE_DIR_NAMES = frozenset(
    [singular for singular, _, _ in METADATA_TYPES]
    + list(DUMP_DIR_NAMES)
)


def resolve_module_name(rel_path: str, ext_roots: dict[str, str] | None = None) -> str:
    """Имя модуля с учётом вложенных кореньев расширений из ext_roots.

    rel_path под каталогом ``Расширения/`` обрабатывается path-конвенцией
    (bsl_path_to_module_name). Для остальных путей ищется самый длинный
    префикс из ext_roots (rel_dir -> имя из Configuration.xml, см.
    dumpindex.extroots): модули под таким корнем получают
    ``ext.<имя>.``-пространство, остальная часть пути разбирается как у
    основной конфигурации. Если префикс не найден или после него осталось
    меньше двух сегментов — обычное поведение bsl_path_to_module_name.
    """
    parts = nfc(rel_path).replace("\\", "/").split("/")
    if parts[0] != EXTENSION_DIR_NAME and ext_roots:
        for depth in range(len(parts) - 1, 0, -1):
            ext_name = ext_roots.get("/".join(parts[:depth]))
            if ext_name is not None:
                rest = parts[depth:]
                if len(rest) >= 2:
                    return f"ext.{ext_name}." + _base_config_module_name(rest)
                break
    return bsl_path_to_module_name(rel_path)


def bsl_path_to_module_name(rel_path: str) -> str:
    """Преобразует относительный путь .bsl файла в имя модуля.

    Пример: "Documents/РеализацияТоваров/Ext/ObjectModule.bsl"
    -> "Документ.РеализацияТоваров.МодульОбъекта".

    Модули расширений (Расширения/<ext>/...) получают префикс "ext.<ext>.",
    остальная часть пути разбирается как у основной конфигурации.

    Имя нормализуется в NFC: на macOS путь с диска приходит в NFD, а имя
    модуля сравнивается с NFC-строками из запросов и ответов 1С. Сырой
    путь для файлового ввода-вывода остаётся у вызывающего кода.
    """
    rel_path = nfc(rel_path)
    parts = rel_path.replace("\\", "/").split("/")
    if len(parts) < 2:
        return rel_path

    if parts[0] == EXTENSION_DIR_NAME and len(parts) >= 4:
        return f"ext.{parts[1]}." + _base_config_module_name(parts[2:])

    return _base_config_module_name(parts)


def _base_config_module_name(parts: list[str]) -> str:
    category = parts[0]
    prefix = DUMP_DIR_NAMES.get(category, category)
    object_name = parts[1]

    file_name = parts[-1]
    suffix = MODULE_NAME_SUFFIXES.get(file_name)
    if suffix is None:
        suffix = file_name.removesuffix(".bsl")

    # У общих модулей Module.bsl — это "Модуль", а не "МодульФормы".
    if category == "CommonModules" and file_name == "Module.bsl":
        if "Forms" not in parts:
            suffix = "Модуль"

    # Путь через Forms/Commands добавляет сегмент с именем формы/команды.
    for i, p in enumerate(parts):
        kind = SUBDIR_SEGMENT_NAMES.get(p)
        if kind is not None and i + 1 < len(parts):
            return f"{prefix}.{object_name}.{kind}.{parts[i + 1]}.{suffix}"

    return f"{prefix}.{object_name}.{suffix}"


class ModuleNameParts(NamedTuple):
    category: str  # например "Справочник"
    name: str      # например "Номенклатура"
    module: str    # например "МодульОбъекта"


def parse_module_name(full_name: str) -> ModuleNameParts:
    """Разбирает "Справочник.Номенклатура.МодульОбъекта" на части.

    Для путей форм ("Документ.Док.Форма.ФормаДок.МодульФормы") типом модуля
    считается последний сегмент.
    """
    parts = full_name.split(".")
    if len(parts) >= 3:
        return ModuleNameParts(parts[0], parts[1], parts[-1])
    if len(parts) == 2:
        return ModuleNameParts(parts[0], parts[1], "")
    return ModuleNameParts("", full_name, "")
