"""Тесты индекса поиска по dump-выгрузке (SQLite FTS5)."""

import codecs

import pytest

from mcp_baf.dumpindex import DumpIndex, SearchParams

BUILD_TIMEOUT = 30


def mk_bsl(root, rel_path, content, bom=False):
    path = root / rel_path.replace("/", "\\")
    path.parent.mkdir(parents=True, exist_ok=True)
    data = content.encode("utf-8")
    if bom:
        data = codecs.BOM_UTF8 + data
    path.write_bytes(data)


@pytest.fixture
def index(tmp_path):
    mk_bsl(
        tmp_path,
        "Catalogs/Номенклатура/Ext/ObjectModule.bsl",
        "Процедура ПередЗаписью()\n"
        "    Позиция = СтрНайти(Наименование, \"тест\");\n"
        "КонецПроцедуры\n",
        bom=True,
    )
    mk_bsl(
        tmp_path,
        "Documents/Реализация/Ext/ObjectModule.bsl",
        "Процедура ОбработкаПроведения()\n"
        "    // проведение документа реализации\n"
        "    ДвиженияСформированы = Истина;\n"
        "КонецПроцедуры\n",
    )
    mk_bsl(
        tmp_path,
        "Catalogs/Номенклатура/Ext/ManagerModule.bsl",
        "Функция ПолучитьСписок() Экспорт\n"
        "    Возврат Новый Массив;\n"
        "КонецФункции\n",
    )
    idx = DumpIndex(str(tmp_path), use_cache=False)
    assert idx.wait_ready(BUILD_TIMEOUT), "index build timed out"
    yield idx
    idx.close()


def test_module_count(index):
    assert index.module_count() == 3


def test_smart_search(index):
    matches, total = index.search(SearchParams(query="проведение документа"))
    assert total >= 1
    assert matches[0].module == "Документ.Реализация.МодульОбъекта"
    assert matches[0].score > 0
    assert "проведение документа" in matches[0].context


def test_smart_synonym_english_finds_russian(index):
    # Поиск по английскому имени находит русские вхождения: StrFind -> СтрНайти.
    matches, total = index.search(SearchParams(query="StrFind"))
    assert total >= 1
    assert matches[0].module == "Справочник.Номенклатура.МодульОбъекта"
    assert "СтрНайти" in matches[0].context


def test_exact_search_case_insensitive(index):
    matches, total = index.search(SearchParams(query="стрнайти", mode="exact"))
    assert total == 1
    assert matches[0].line == 2


def test_regex_search(index):
    matches, total = index.search(
        SearchParams(query=r"Функция \w+\(\) Экспорт", mode="regex")
    )
    assert total == 1
    assert matches[0].module == "Справочник.Номенклатура.МодульМенеджера"


def test_regex_invalid(index):
    with pytest.raises(ValueError, match="invalid regex"):
        index.search(SearchParams(query="[unclosed", mode="regex"))


def test_regex_too_long_rejected(index):
    with pytest.raises(ValueError, match="too long"):
        index.search(SearchParams(query="a" * 1000, mode="regex"))


@pytest.mark.parametrize("pattern", [r"(a+)+$", r"(\w*)*", r"(\d+)*\s", r"(x+x+)+y"])
def test_regex_nested_quantifier_rejected(index, pattern):
    with pytest.raises(ValueError, match="nested quantifier"):
        index.search(SearchParams(query=pattern, mode="regex"))


def test_regex_time_budget_enforced(index, monkeypatch):
    from mcp_baf.dumpindex import index as index_module

    monkeypatch.setattr(index_module, "REGEX_TIME_BUDGET", -1.0)
    with pytest.raises(ValueError, match="time budget"):
        index.search(SearchParams(query="Процедура|Функция", mode="regex"))


def test_line_search_streams_rows(index):
    """Режимы regex/exact не тянут весь код модулей через fetchall()."""

    class NoFetchallCursor:
        def __init__(self, cursor):
            self._cursor = cursor

        def __iter__(self):
            return iter(self._cursor)

        def fetchone(self):
            return self._cursor.fetchone()

        def fetchall(self):
            raise AssertionError("fetchall() must not be used for line-by-line search")

    class NoFetchallConn:
        def __init__(self, conn):
            self._conn = conn

        def execute(self, *args, **kwargs):
            return NoFetchallCursor(self._conn.execute(*args, **kwargs))

        def close(self):
            self._conn.close()

    original = index._db
    index._db = NoFetchallConn(original)
    try:
        matches, total = index.search(SearchParams(query="Процедура", mode="exact"))
    finally:
        index._db = original
    assert total == 2
    assert len(matches) == 2


def test_category_filter(index):
    _, total = index.search(
        SearchParams(query="Процедура", mode="exact", category="Документ")
    )
    assert total == 1


def test_module_filter(index):
    matches, _ = index.search(
        SearchParams(query="Экспорт", mode="exact", module="МодульМенеджера")
    )
    assert len(matches) == 1
    assert "МодульМенеджера" in matches[0].module


def test_limit_and_total(index):
    # По одному заголовку Процедура/Функция в каждом из трёх модулей.
    matches, total = index.search(
        SearchParams(query="Процедура|Функция", mode="regex", limit=2)
    )
    assert len(matches) == 2
    assert total == 3


def test_empty_dir(tmp_path):
    idx = DumpIndex(str(tmp_path), use_cache=False)
    assert idx.wait_ready(BUILD_TIMEOUT)
    assert idx.module_count() == 0
    matches, total = idx.search(SearchParams(query="что-нибудь"))
    assert matches == [] and total == 0
    idx.close()


def test_bom_stripped(index):
    matches, _ = index.search(SearchParams(query="ПередЗаписью", mode="exact"))
    assert matches[0].line == 1
    assert matches[0].context.startswith("Процедура")


def test_nfd_dump_names_resolve_to_nfc(tmp_path):
    # macOS распаковывает выгрузку с NFD-именами (Й = И + комбинируемый знак).
    # Имена модулей и фильтры должны сходиться в NFC, иначе фильтр по
    # NFC-значению никогда не найдёт NFD-ключ из пути на диске.
    nfd_object = "И\u0306огурт"  # "Йогурт" в NFD
    mk_bsl(
        tmp_path,
        f"InformationRegisters/{nfd_object}/Ext/RecordSetModule.bsl",
        "Процедура ПередЗаписью(Отказ, Замещение)\nКонецПроцедуры\n",
    )
    idx = DumpIndex(str(tmp_path), use_cache=False)
    assert idx.wait_ready(BUILD_TIMEOUT)
    try:
        # Фильтры переданы в NFD (например, скопированы из macOS-выгрузки) —
        # search() нормализует аргументы так же, как ключи индекса.
        matches, total = idx.search(
            SearchParams(
                query="ПередЗаписью",
                mode="exact",
                category="РегистрСведении\u0306",   # "РегистрСведений" в NFD
                module="МодульНабораЗаписеи\u0306",  # "МодульНабораЗаписей" в NFD
            )
        )
        assert total == 1
        # Имя модуля в результате — NFC ("Йогурт" одним символом Й).
        assert matches[0].module == "РегистрСведений.Йогурт.МодульНабораЗаписей"
    finally:
        idx.close()


def test_symlink_bsl_outside_dump_skipped(tmp_path):
    dump = tmp_path / "dump"
    secret = tmp_path / "secret.txt"
    secret.write_text("СекретнаяСтрока\n", encoding="utf-8")
    mk_bsl(dump, "CommonModules/Общий/Ext/Module.bsl", "Процедура А()\nКонецПроцедуры\n")
    (dump / "Leak.bsl").symlink_to(secret)
    idx = DumpIndex(str(dump), use_cache=False)
    assert idx.wait_ready(BUILD_TIMEOUT)
    try:
        assert idx.module_count() == 1
        _, total = idx.search(SearchParams(query="СекретнаяСтрока", mode="exact"))
        assert total == 0
    finally:
        idx.close()


# ── Вложенные корни расширений (<обёртка>/<ext>/Configuration.xml) ──

MANIFEST = (
    '<?xml version="1.0" encoding="UTF-8"?>\n'
    '<MetaDataObject xmlns="http://v8.1c.ru/8.3/MDClasses">\n'
    "  <Configuration><Properties><Name>{name}</Name>"
    "<ConfigurationExtensionPurpose>AddOn</ConfigurationExtensionPurpose></Properties>"
    "</Configuration>\n</MetaDataObject>\n"
)


def mk_manifest(root, rel_dir, name):
    path = root / rel_dir / "Configuration.xml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(MANIFEST.format(name=name), encoding="utf-8")


def test_nested_extension_root_gets_ext_namespace(tmp_path):
    # Сценарий feenlace/mcp-1c issue 46: обёртка Mach3/extension глубже
    # первого уровня. Без распознавания манифеста модуль расширения получал
    # ключ «Mach3.extension.МодульОбъекта»; основной конфигурации теперь
    # ничего не теряют и расширение получает своё пространство имён.
    mk_bsl(tmp_path, "Documents/ПеремещениеЗапасов/Ext/ObjectModule.bsl",
           "ДвиженияСформированы = Истина;")
    mk_manifest(tmp_path, "Mach3/extension", "ИнтеграцияMach3")
    mk_bsl(tmp_path, "Mach3/extension/Documents/ПеремещениеЗапасов/Ext/ObjectModule.bsl",
           "ДвиженияСформированы = Ложь;")
    idx = DumpIndex(str(tmp_path), use_cache=False)
    assert idx.wait_ready(BUILD_TIMEOUT), idx.build_error()
    try:
        matches, total = idx.search(
            SearchParams(query="ДвиженияСформированы", mode="exact", limit=10))
        names = {m.module for m in matches}
        assert total == 2
        assert "Документ.ПеремещениеЗапасов.МодульОбъекта" in names
        assert "ext.ИнтеграцияMach3.Документ.ПеремещениеЗапасов.МодульОбъекта" in names
    finally:
        idx.close()


def test_warm_cache_added_file_under_nested_ext_root(tmp_path):
    dump, cache = tmp_path / "dump", tmp_path / "cache"
    dump.mkdir()
    mk_bsl(dump, "Catalogs/Тест/Ext/ObjectModule.bsl", "А = 1;")
    idx = DumpIndex(str(dump), cache_dir=str(cache))
    assert idx.wait_ready(BUILD_TIMEOUT), idx.build_error()
    idx.close()

    mk_manifest(dump, "Обёртка/расш", "МоеРасширение")
    mk_bsl(dump, "Обёртка/расш/CommonModules/МодульРасш/Module.bsl", "Б = 2;")
    idx = DumpIndex(str(dump), cache_dir=str(cache))
    assert idx.wait_ready(BUILD_TIMEOUT), idx.build_error()
    try:
        matches, total = idx.search(SearchParams(query="Б = 2;", mode="exact"))
        assert total == 1
        assert matches[0].module == "ext.МоеРасширение.ОбщийМодуль.МодульРасш.Модуль"
    finally:
        idx.close()


def test_warm_cache_rebuilds_when_ext_roots_change(tmp_path):
    # Манифест добавлен к уже проиндексированным файлам: их ключи в кэше
    # устарели, кэш должен перестроиться, а не отдавать path-ключи.
    dump, cache = tmp_path / "dump", tmp_path / "cache"
    mk_bsl(dump, "Обёртка/расш/CommonModules/М/Module.bsl", "Б = 2;")
    idx = DumpIndex(str(dump), cache_dir=str(cache))
    assert idx.wait_ready(BUILD_TIMEOUT), idx.build_error()
    idx.close()

    mk_manifest(dump, "Обёртка/расш", "Расш")
    idx = DumpIndex(str(dump), cache_dir=str(cache))
    assert idx.wait_ready(BUILD_TIMEOUT), idx.build_error()
    try:
        matches, _ = idx.search(SearchParams(query="Б = 2;", mode="exact"))
        assert matches[0].module == "ext.Расш.ОбщийМодуль.М.Модуль"
    finally:
        idx.close()
