"""Тесты обнаружения вложенных корней расширений (порт feenlace issue 46)."""

import pytest

from mcp_baf.dumpindex import extroots
from mcp_baf.dumpindex.extroots import discover_extension_roots
from mcp_baf.dumpindex.modulenames import bsl_path_to_module_name, resolve_module_name
from mcp_baf.dumpindex.xmlguard import UnsafeXML

MANIFEST_TMPL = """<?xml version="1.0" encoding="UTF-8"?>
<MetaDataObject xmlns="http://v8.1c.ru/8.3/MDClasses">
  <Configuration uuid="3c3d7fc2-4bc0-4a3e-b90a-0d528f3f512f">
    <InternalInfo/>
    <Properties>
      <Name>{name}</Name>
      <Version>1.0.0</Version>
    </Properties>
  </Configuration>
</MetaDataObject>
"""

# Name вне Properties — другая форма выгрузки (см. тред issue 46).
MANIFEST_FLAT = """<?xml version="1.0" encoding="UTF-8"?>
<MetaDataObject xmlns="http://v8.1c.ru/8.3/MDClasses">
  <Configuration uuid="3c3d7fc2-4bc0-4a3e-b90a-0d528f3f512f">
    <Name>{name}</Name>
  </Configuration>
</MetaDataObject>
"""


def mk(root, rel_path, content="Перем = 1;"):
    path = root / rel_path
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def mk_manifest(root, rel_dir, name, tmpl=MANIFEST_TMPL):
    return mk(root, f"{rel_dir}/Configuration.xml", tmpl.format(name=name))


def make_main_config(root):
    mk(root, "Configuration.xml", MANIFEST_TMPL.format(name="БАСМалыйБизнес"))
    mk(root, "Documents/ПеремещениеЗапасов/Ext/ObjectModule.bsl",
       "Процедура ОбработкаПроведения() КонецПроцедуры")


# ── discover_extension_roots ──

def test_nested_extension_root_at_depth_two(tmp_path):
    make_main_config(tmp_path)
    mk_manifest(tmp_path, "Mach3/extension", "ИнтеграцияMach3")
    mk(tmp_path, "Mach3/extension/Documents/ПеремещениеЗапасов/Ext/ObjectModule.bsl",
       "Процедура ОбработкаПроведения() // расширение КонецПроцедуры")
    assert discover_extension_roots(str(tmp_path)) == {
        "Mach3/extension": "ИнтеграцияMach3",
    }


def test_extension_root_at_depth_one(tmp_path):
    make_main_config(tmp_path)
    mk_manifest(tmp_path, "МоеРасширение", "МоеРасширение")
    assert discover_extension_roots(str(tmp_path)) == {
        "МоеРасширение": "МоеРасширение",
    }


def test_name_outside_properties_supported(tmp_path):
    make_main_config(tmp_path)
    mk_manifest(tmp_path, "Mach3/extension", "ИнтеграцияMach3", tmpl=MANIFEST_FLAT)
    assert discover_extension_roots(str(tmp_path)) == {
        "Mach3/extension": "ИнтеграцияMach3",
    }


def test_main_config_manifest_not_returned(tmp_path):
    make_main_config(tmp_path)
    assert discover_extension_roots(str(tmp_path)) == {}


def test_category_like_dir_rejected_as_extension(tmp_path):
    # Манифест в Обёртка/Catalogs не должен уводить обычные справочники.
    make_main_config(tmp_path)
    mk_manifest(tmp_path, "Обёртка/Catalogs", "Подмена")
    assert discover_extension_roots(str(tmp_path)) == {}


def test_category_like_child_rejected(tmp_path):
    make_main_config(tmp_path)
    mk_manifest(tmp_path, "Documents/МоеРасш", "Подмена")
    assert discover_extension_roots(str(tmp_path)) == {}


def test_child_manifest_blocks_descent(tmp_path):
    # Ребёнок с собственным манифестом уже ответил — внук не опрашивается.
    make_main_config(tmp_path)
    mk_manifest(tmp_path, "Внук", "Первое")
    mk_manifest(tmp_path, "Внук/Внутри", "Второе")
    assert discover_extension_roots(str(tmp_path)) == {"Внук": "Первое"}


def test_name_collision_drops_both_nested(tmp_path):
    make_main_config(tmp_path)
    mk_manifest(tmp_path, "ОбёрткаА/поддельное", "Честное")
    mk_manifest(tmp_path, "ОбёрткаБ/поддельное", "Честное")
    assert discover_extension_roots(str(tmp_path)) == {}


def test_collision_with_rasshireniya_convention_drops_nested(tmp_path):
    # Имя, занятое каталогом Расширения/<имя>/ (там namespace = имя
    # каталога), неприкосновенно: вложенная запись с тем же Name снимается.
    make_main_config(tmp_path)
    mk_manifest(tmp_path, "Расширения/Честное", "ЛюбоеИмяИзМанифеста")
    mk_manifest(tmp_path, "Обёртка/поддельное", "Честное")
    roots = discover_extension_roots(str(tmp_path))
    assert roots == {}  # спорная запись снята
    # path-конвенция продолжает работать без ext_roots:
    name = resolve_module_name(
        "Расширения/Честное/Documents/Х/Ext/ObjectModule.bsl", roots)
    assert name == "ext.Честное.Документ.Х.МодульОбъекта"


def test_rasshireniya_subtree_not_probed(tmp_path):
    make_main_config(tmp_path)
    mk_manifest(tmp_path, "Расширения/МоеРасш", "ДругоеИмя")
    assert discover_extension_roots(str(tmp_path)) == {}


def test_unparseable_manifest_skipped(tmp_path):
    make_main_config(tmp_path)
    mk(tmp_path, "Обёртка/битое/Configuration.xml", "<<<не xml>>>")
    assert discover_extension_roots(str(tmp_path)) == {}


def test_manifest_without_name_skipped(tmp_path):
    make_main_config(tmp_path)
    mk(tmp_path, "Обёртка/безымяное/Configuration.xml",
       '<?xml version="1.0"?><MetaDataObject><Configuration/>'
       "</MetaDataObject>")
    assert discover_extension_roots(str(tmp_path)) == {}


def test_dtd_manifest_refused(tmp_path):
    make_main_config(tmp_path)
    mk(tmp_path, "Обёртка/хитрое/Configuration.xml",
       '<?xml version="1.0"?><!DOCTYPE Configuration '
       '[<!ENTITY a "x">]><Configuration><Name>&a;</Name></Configuration>')
    assert discover_extension_roots(str(tmp_path)) == {}


def test_nested_scan_budget_warns_and_skips(tmp_path, monkeypatch, caplog):
    make_main_config(tmp_path)
    for i in range(33):
        mk_manifest(tmp_path, f"МногоПодкаталогов/расш{i}", f"Расш{i}")
    monkeypatch.setattr(extroots, "MAX_NESTED_SCAN_ENTRIES", 4)
    assert discover_extension_roots(str(tmp_path)) == {}
    assert "спуск пропущен" in caplog.text


def test_hidden_dirs_ignored(tmp_path):
    make_main_config(tmp_path)
    mk_manifest(tmp_path, ".git/extension", "Скрытое")
    assert discover_extension_roots(str(tmp_path)) == {}


# ── resolve_module_name ──

ROOTS = {"Mach3/extension": "ИнтеграцияMach3"}


def test_resolve_nested_extension_key():
    name = resolve_module_name(
        "Mach3/extension/Documents/ПеремещениеЗапасов/Ext/ObjectModule.bsl",
        ROOTS,
    )
    assert name == "ext.ИнтеграцияMach3.Документ.ПеремещениеЗапасов.МодульОбъекта"


def test_resolve_without_roots_is_path_key():
    rel = "Mach3/extension/Documents/ПеремещениеЗапасов/Ext/ObjectModule.bsl"
    assert resolve_module_name(rel, None) == bsl_path_to_module_name(rel)
    assert resolve_module_name(rel, {}) == bsl_path_to_module_name(rel)


def test_resolve_main_config_unaffected_by_roots():
    rel = "Documents/ПеремещениеЗапасов/Ext/ObjectModule.bsl"
    assert resolve_module_name(rel, ROOTS) == "Документ.ПеремещениеЗапасов.МодульОбъекта"


def test_resolve_rasshireniya_convention_wins_over_roots():
    # Даже если кто-то передал корень под Расширения/ — конвенция пути.
    rel = "Расширения/Явное/Docs/X/Ext/ObjectModule.bsl"
    name = resolve_module_name(rel, {"Расширения/Явное": "ИзМанифеста"})
    assert name == "ext.Явное.Docs.X.МодульОбъекта"


def test_resolve_too_short_tail_falls_back():
    # Под корнем меньше двух сегментов — разбор невозможен, откат.
    rel = "Mach3/extension/Configuration.bsl"
    assert resolve_module_name(rel, ROOTS) == bsl_path_to_module_name(rel)


def test_resolve_backslashes_and_nfd():
    name = resolve_module_name(
        "Mach3\\extension\\Documents\\Отчеты\\Ext\\ObjectModule.bsl", ROOTS)
    assert name == "ext.ИнтеграцияMach3.Документ.Отчеты.МодульОбъекта"


def test_xmlguard_rejects_entity_directly():
    from mcp_baf.dumpindex.xmlguard import guard
    with pytest.raises(UnsafeXML):
        guard(b'<a><!ENTITY x "y"/></a>')


def test_standard_dump_dirs_never_probed(tmp_path, caplog):
    # Реальная выгрузка: Roles/XDTOPackages/CommonPictures содержат сотни
    # подкаталогов-данных — стандартные каталоги корня не опрашиваются и
    # не поднимают бюджетных предупреждений.
    make_main_config(tmp_path)
    for std in ("Roles", "XDTOPackages", "CommonPictures"):
        for i in range(40):
            mk(tmp_path, f"{std}/Объект{i}/Ext/Module.bsl", "А = 1;")
    assert discover_extension_roots(str(tmp_path)) == {}
    assert "спуск пропущен" not in caplog.text


def test_symlinked_manifest_outside_dump_refused(tmp_path):
    # Тот же контур, что у обхода индекса (PR #20): манифест-симлинк
    # наружу dump-корня не читается.
    dump = tmp_path / "dump"
    mk(dump, "Configuration.xml", MANIFEST_TMPL.format(name="БАСМалыйБизнес"))
    mk(dump, "Documents/ПеремещениеЗапасов/Ext/ObjectModule.bsl", "А = 1;")
    outside = tmp_path / "outside" / "Configuration.xml"
    outside.parent.mkdir(parents=True)
    outside.write_text(MANIFEST_TMPL.format(name="Чужая"), encoding="utf-8")
    ext_dir = dump / "Обёртка" / "расш"
    ext_dir.mkdir(parents=True)
    (ext_dir / "Configuration.xml").symlink_to(outside)
    assert discover_extension_roots(str(dump)) == {}
