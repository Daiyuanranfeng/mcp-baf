"""Поиск вложенных кореньев расширений в dump-выгрузке.

Порт поведения feenlace/mcp-1c (ветка fix/issue-46-nested-extension-depth):
выгрузка основной конфигурации лежит в корне --dump, а проекты расширений —
в подкаталогах вида <обёртка>/<extension>/ (например ``Mach3/extension/``)
со своим ``Configuration.xml``. Без распознавания манифеста такие модули
получают ключ, выведенный из «мусорных» сегментов пути, и фильтры
``category``/``module`` их не находят.

Правила (совпадают с upstream по смыслу):
- расширение — каталог, содержащий ``Configuration.xml`` с ``<Name>``;
- имя читается из ``Properties/Name``, при его отсутствии — из прямого
  дочернего ``Name`` (разные выкладки кладут его по-разному);
- каталоги «вида» (Catalogs, Documents, ... — английские имена директорий
  выгрузки) манифестом стать не могут: подделка ``Обёртка/Catalogs`` не
  должна уводить обычные объекты в чужое пространство имён;
- спуск на второй уровень идёт только там, где первый уровень не нашёл
  манифеста, и ограничен бюджетом каталогов/чтений (на переполнении —
  предупреждение в лог, молчание запрещено);
- имя, записанное спуском, обязано быть уникальным среди имён каталогов
  ``Расширения/<имя>/`` и среди других имён спуска; при коллизии
  снимается КАЖДАЯ спорная запись спуска (конвенция Расширения/ не
  страдает никогда);
- подкаталоги ``Расширения/`` не исследуются — они уже покрыты
  path-конвенцией ``ext.<имя каталога>.`` в bsl_path_to_module_name.
"""

from __future__ import annotations

import logging
import os

from mcp_baf.dumpindex.modulenames import (
    CATEGORY_LIKE_DIR_NAMES,
    EXTENSION_DIR_NAME,
    nfc,
)
from mcp_baf.dumpindex.xmlguard import UnsafeXML, parse_file

logger = logging.getLogger(__name__)

# Бюджет спуска на второй уровень: каталогов в одной обёртке и суммарных
# чтений манифестов. Значения — консервативная гипотеза (как upstream):
# каталог, оборачивающий выгрузку, мал по построению. Переполнение не
# теряет файлы (они остаются с path-ключом), но виднеет в логе.
MAX_NESTED_SCAN_ENTRIES = 32
MAX_MANIFEST_READS = 256

CONFIG_FILE_NAME = "Configuration.xml"

# Стандартные каталоги корня XML-выгрузки, не перечисленные в METADATA_TYPES
# (перечислены по реальной выгрузке BASSmallBusiness). Как и каталоги «вида»,
# они не могут быть обёрткой расширения, поэтому не опрашиваются и не
# поднимают бюджетных предупреждений.
STANDARD_DUMP_ROOT_DIRS = frozenset({
    "CommandGroups", "CommonAttributes", "CommonPictures", "CommonTemplates",
    "DefinedTypes", "DocumentNumerators", "EventSubscriptions", "Ext",
    "FilterCriteria", "FunctionalOptions", "FunctionalOptionsParameters",
    "HTTPServices", "Languages", "Roles", "ScheduledJobs", "SessionParameters",
    "SettingsStorages", "StyleItems", "Styles", "Subsystems", "WebServices",
    "XDTOPackages",
})


def _manifest_name(cfg_path: str, reads_budget: list[int]) -> str:
    """Читает имя расширения из Configuration.xml (или '' при отказе)."""
    if reads_budget[0] <= 0:
        logger.warning(
            "extroots: бюджет чтений манифестов (%d) исчерпан — часть "
            "вложенных расширений может остаться без пространства имён",
            MAX_MANIFEST_READS,
        )
        return ""
    reads_budget[0] -= 1
    try:
        root = parse_file(cfg_path)
    except (OSError, UnsafeXML) as exc:
        logger.warning("extroots: манифест %s отвергнут: %s", cfg_path, exc)
        return ""
    except Exception as exc:  # noqa: BLE001 — битый XML не должен ронять индекс
        logger.warning("extroots: манифест %s не разобран: %s", cfg_path, exc)
        return ""

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1] if "}" in tag else tag

    # Корень — MetaDataObject с дочерним Configuration (или сам Configuration).
    cfg_elem = root if local(root.tag) == "Configuration" else None
    if cfg_elem is None:
        for elem in root:
            if local(elem.tag) == "Configuration":
                cfg_elem = elem
                break
    if cfg_elem is None:
        return ""

    name = ""
    for child in cfg_elem:
        if local(child.tag) == "Properties":
            for sub in child:
                if local(sub.tag) == "Name" and (sub.text or "").strip():
                    return (sub.text or "").strip()
        elif local(child.tag) == "Name" and (child.text or "").strip():
            name = (child.text or "").strip()
    return name


def _list_dirs(path: str) -> list[str]:
    try:
        return sorted(
            e for e in os.listdir(path) if os.path.isdir(os.path.join(path, e))
        )
    except OSError:
        return []


def _rejected_dir_name(name: str) -> bool:
    """Имя каталога не может принадлежать расширению (каталог «вида»,
    стандартный каталог корня выгрузки, скрытый или служебный Расширения)."""
    return (
        name in CATEGORY_LIKE_DIR_NAMES
        or name in STANDARD_DUMP_ROOT_DIRS
        or name == EXTENSION_DIR_NAME
        or name.startswith(".")
    )


def discover_extension_roots(dump_dir: str) -> dict[str, str]:
    """Находит вложенные корни расширений: rel_dir -> имя из манифеста.

    Ключи — относительные пути каталога-расширения с '/' в NFC (как rel_path
    в индексе). Пустой словарь, если вложенных расширений нет. Корневой
    Configuration.xml (основная конфигурация) в результат не попадает.
    """
    by_name: dict[str, list[str]] = {}  # имя расширения -> его rel-корни
    reads_budget = [MAX_MANIFEST_READS]

    claimed = set()  # имена из path-конвенции Расширения/<каталог>/
    ext_root = os.path.join(dump_dir, EXTENSION_DIR_NAME)
    if os.path.isdir(ext_root):
        claimed.update(_list_dirs(ext_root))

    for child in _list_dirs(dump_dir):
        if _rejected_dir_name(child):
            continue
        child_abs = os.path.join(dump_dir, child)
        child_cfg = os.path.join(child_abs, CONFIG_FILE_NAME)
        if os.path.isfile(child_cfg):
            name = _manifest_name(child_cfg, reads_budget)
            if name:
                by_name.setdefault(name, []).append(nfc(child))
            continue
        # Первый уровень манифеста не нашёл — спускаемся на второй.
        grandchildren = _list_dirs(child_abs)
        if len(grandchildren) > MAX_NESTED_SCAN_ENTRIES:
            logger.warning(
                "extroots: каталог %s содержит %d подкаталогов (> %d) — "
                "спуск пропущен, вложенные расширения в нём не распознаются",
                child, len(grandchildren), MAX_NESTED_SCAN_ENTRIES,
            )
            continue
        for grand in grandchildren:
            if _rejected_dir_name(grand):
                continue
            grand_cfg = os.path.join(child_abs, grand, CONFIG_FILE_NAME)
            if os.path.isfile(grand_cfg):
                name = _manifest_name(grand_cfg, reads_budget)
                if name:
                    by_name.setdefault(name, []).append(nfc(f"{child}/{grand}"))

    # Коллизия имени: снимается КАЖДАЯ запись спуска с этим именем —
    # порядок обхода (осортированный) не должен решать, кто «настоящий».
    result: dict[str, str] = {}
    for name, rel_dirs in by_name.items():
        if name in claimed or len(rel_dirs) > 1:
            logger.warning(
                "extroots: имя расширения %r спорное (каталоги: %s) — "
                "записи сняты, модули получат path-ключи",
                name, ", ".join(rel_dirs),
            )
            continue
        result[rel_dirs[0]] = name
    return result
