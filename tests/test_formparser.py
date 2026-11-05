"""Тесты разбора Form.xml.

Фикстуры в testdata/ — реальные файлы dump-выгрузки 1С (схема xcf/logform),
скопированные из dump/testdata Go-версии; ожидания — из dump/formparser_test.go.
"""

from pathlib import Path

import pytest

from mcp_baf.dumpindex import formparser

TESTDATA = Path(__file__).parent / "testdata"


def parse_fixture(name):
    return formparser.parse_form_xml(str(TESTDATA / name))


def test_empty_form():
    form = parse_fixture("empty_form.xml")
    assert form.title == ""
    assert form.elements == []
    assert form.commands == []
    assert len(form.handlers) == 1
    assert form.handlers[0].event == "OnOpen"
    assert form.handlers[0].handler == "ПриОткрытии"


def test_common_form_password():
    form = parse_fixture("common_form_password.xml")
    assert form.title == ""

    fields = {
        (e.name, e.type): e for e in form.elements
    }
    field = fields.get(("НовыйПароль", "InputField"))
    assert field is not None, form.elements
    assert field.data_path == "НовыйПароль"

    assert len(form.handlers) == 1
    assert form.handlers[0].event == "OnCreateAtServer"
    assert form.handlers[0].handler == "ПриСозданииНаСервере"

    assert len(form.commands) == 1
    assert form.commands[0].name == "СоздатьДругой"
    assert form.commands[0].action == "СоздатьДругой"


def test_register_record_form():
    form = parse_fixture("register_record_form.xml")
    want_fields = {
        "Идентификатор": "Запись.Идентификатор",
        "Дата": "Запись.Дата",
        "Запрос": "Запрос",
    }
    by_name = {e.name: e for e in form.elements if e.type == "InputField"}
    for name, data_path in want_fields.items():
        assert name in by_name, form.elements
        assert by_name[name].data_path == data_path

    assert form.commands == []
    assert len(form.handlers) == 1


def test_catalog_list_form():
    form = parse_fixture("catalog_list_form.xml")

    tables = [e for e in form.elements if e.name == "Список" and e.type == "Table"]
    assert len(tables) == 1, form.elements
    table = tables[0]
    assert table.data_path == "Список"
    assert len(table.events) == 1
    assert table.events[0].event == "OnChange"
    assert table.events[0].handler == "СписокПриИзменении"

    # Два событийных обработчика уровня формы; OnChange элемента не «протёк».
    events = {h.event: h.handler for h in form.handlers}
    assert events == {
        "OnOpen": "ПриОткрытии",
        "OnCreateAtServer": "ПриСозданииНаСервере",
    }

    # Вложенные элементы не наследуют события таблицы.
    for e in form.elements:
        if e.name != "Список":
            assert e.events == [], (e.name, e.events)

    assert form.commands == []


def test_element_level_events():
    xml = """<?xml version="1.0" encoding="UTF-8"?>
<Form xmlns="http://v8.1c.ru/8.3/xcf/logform" xmlns:v8="http://v8.1c.ru/8.1/data/core" version="2.21">
  <Events>
    <Event name="OnOpen">ПриОткрытии</Event>
  </Events>
  <ChildItems>
    <InputField name="Поле1" id="1">
      <DataPath>Объект.Поле1</DataPath>
      <Events>
        <Event name="OnChange">Поле1ПриИзменении</Event>
      </Events>
    </InputField>
    <UsualGroup name="Группа" id="2">
      <Events>
        <Event name="OnChange">ГруппаПриИзменении</Event>
      </Events>
      <ChildItems>
        <InputField name="Поле2" id="3">
          <DataPath>Объект.Поле2</DataPath>
          <Events>
            <Event name="OnChange">Поле2ПриИзменении</Event>
          </Events>
        </InputField>
        <InputField name="ПолеБезСобытий" id="4">
          <DataPath>Объект.ПолеБезСобытий</DataPath>
        </InputField>
      </ChildItems>
    </UsualGroup>
  </ChildItems>
</Form>"""
    form = formparser.parse_form_xml_data(xml)

    assert len(form.handlers) == 1
    assert (form.handlers[0].event, form.handlers[0].handler) == (
        "OnOpen", "ПриОткрытии",
    )

    by_name = {e.name: e.events for e in form.elements}
    want = {
        "Поле1": ("OnChange", "Поле1ПриИзменении"),
        "Группа": ("OnChange", "ГруппаПриИзменении"),
        "Поле2": ("OnChange", "Поле2ПриИзменении"),
    }
    for name, (event, handler) in want.items():
        events = by_name[name]
        assert len(events) == 1, (name, events)
        assert (events[0].event, events[0].handler) == (event, handler)
    assert by_name["ПолеБезСобытий"] == []

    # Вложенность развёрнута в плоский список в порядке обхода.
    assert [e.name for e in form.elements] == [
        "Поле1", "Группа", "Поле2", "ПолеБезСобытий",
    ]


def test_display_type():
    assert formparser.display_type("InputField") == "ПолеВвода"
    assert formparser.display_type("Table") == "ТаблицаФормы"
    assert formparser.display_type("НеизвестныйТип") == "НеизвестныйТип"


def test_find_form_files(tmp_path):
    form_xml = tmp_path / "Catalogs" / "Тест" / "Forms" / "ФормаСписка" / "Ext" / "Form.xml"
    form_xml.parent.mkdir(parents=True)
    form_xml.write_text("<Form/>", encoding="utf-8")

    files = formparser.find_form_files(str(tmp_path), "Catalog", "Тест")
    assert list(files) == ["ФормаСписка"]
    assert files["ФормаСписка"] == str(form_xml)

    # Нет директории Forms — пустой результат, не ошибка.
    assert formparser.find_form_files(str(tmp_path), "Document", "Нет") == {}


def test_find_form_files_rejects_traversal(tmp_path):
    with pytest.raises(ValueError, match="path traversal"):
        formparser.find_form_files(str(tmp_path), "Catalog", "..\\evil")
    with pytest.raises(ValueError, match="unknown object type"):
        formparser.find_form_files(str(tmp_path), "Nonsense", "Тест")


def test_find_form_files_normalizes_nfd_entries(tmp_path):
    # macOS отдаёт listdir в NFD — ключ словаря должен быть NFC, чтобы
    # form_name из запроса (NFC) находил форму; путь хранит сырое имя.
    nfd_form = "ФормаНастрои\u0306ки"  # "ФормаНастройки" в NFD
    form_xml = tmp_path / "Catalogs" / "Тест" / "Forms" / nfd_form / "Ext" / "Form.xml"
    form_xml.parent.mkdir(parents=True)
    form_xml.write_text("<Form/>", encoding="utf-8")

    files = formparser.find_form_files(str(tmp_path), "Catalog", "Тест")
    assert list(files) == ["ФормаНастройки"]  # NFC
    assert files["ФормаНастройки"] == str(form_xml)


def test_find_form_files_skips_symlink_outside_dump(tmp_path):
    outside = tmp_path / "outside.xml"
    outside.write_text("<Form/>", encoding="utf-8")
    dump = tmp_path / "dump"
    ext = dump / "Catalogs" / "Тест" / "Forms" / "Чужая" / "Ext"
    ext.mkdir(parents=True)
    (ext / "Form.xml").symlink_to(outside)
    assert formparser.find_form_files(str(dump), "Catalog", "Тест") == {}


def test_find_form_files_rejects_ambiguous_nfc_collision(tmp_path):
    # Два разных файла с диска (NFC «Й» и NFD «И»+combining) сошлись в
    # одно NFC-имя: молча выбрать один — показать чужую форму.
    forms = tmp_path / "Catalogs" / "Тест" / "Forms"
    for raw in ("ФормаЙ", "ФормаИ\u0306"):
        p = forms / raw / "Ext" / "Form.xml"
        p.parent.mkdir(parents=True)
        p.write_text("<Form/>", encoding="utf-8")
    with pytest.raises(ValueError, match="ambiguous form names"):
        formparser.find_form_files(str(tmp_path), "Catalog", "Тест")


def test_parse_form_xml_data_rejects_dtd():
    # Выгрузка 1С не содержит DTD; документ с DTD/сущностями отвергается
    # целиком (аналог «refuse unsupported» из feenlace/mcp-1c).
    with pytest.raises(ValueError, match="DTD"):
        formparser.parse_form_xml_data(
            '<!DOCTYPE Form [<!ENTITY a "x">]><Form><Title>&a;</Title></Form>'
        )


def test_parse_form_xml_rejects_dtd_file(tmp_path):
    p = tmp_path / "Form.xml"
    p.write_text(
        '<?xml version="1.0"?>\n<!DOCTYPE Form [<!ENTITY a "x">]>\n'
        "<Form><Title>&a;</Title></Form>",
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="DTD"):
        formparser.parse_form_xml(str(p))


def test_parse_form_xml_accepts_plain_declaration(tmp_path):
    # Штатная выгрузка начинается с XML-декларации — guard её не трогает.
    p = tmp_path / "Form.xml"
    p.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<Form xmlns="http://v8.1c.ru/8.3/xcf/logform">'
        "<ChildItems>"
        '<InputField name="Поле1"><DataPath>Объект.Поле1</DataPath></InputField>'
        "</ChildItems></Form>",
        encoding="utf-8",
    )
    info = formparser.parse_form_xml(str(p))
    assert [e.name for e in info.elements] == ["Поле1"]
