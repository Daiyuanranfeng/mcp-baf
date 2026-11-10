"""Тесты маскирования ПДн в execute_query."""

from mcp_baf.config import load_config, parse_args
from mcp_baf.tools.query import mask_pii_result


def _r(columns, rows):
    return {"columns": columns, "rows": rows, "total": len(rows)}


def test_column_masking_stable_tokens():
    out = mask_pii_result(_r(
        ["Контрагент.ИНН", "Сумма", "Телефон"],
        [["1234567890", 5, ""], ["1234567890", 7, "x"], ["999", 1, None]],
    ))["rows"]
    assert out[0][0].startswith("PII:") and out[0][0] == out[1][0] != out[2][0]
    assert out[0][1] == 5 and out[0][2] == "" and out[2][2] is None
    assert out[1][2].startswith("PII:")


def test_regex_phone_email():
    cell = "тел +380 50 123-45-67, 0671234567, a.b@ex.com; код 12345"
    out = mask_pii_result(_r(["Комментарий"], [[cell]]))["rows"][0][0]
    assert out.count("PII:") == 3 and "12345" in out and "@" not in out and "380" not in out


def test_config_default_env_cli(monkeypatch):
    monkeypatch.delenv("mcp_baf_MASK_PII", raising=False)
    assert load_config(parse_args([])).mask_pii is False
    monkeypatch.setenv("mcp_baf_MASK_PII", "1")
    assert load_config(parse_args([])).mask_pii is True
    monkeypatch.delenv("mcp_baf_MASK_PII")
    assert load_config(parse_args(["--mask-pii"])).mask_pii is True


# --- Маскирование вне execute_query: журнал, формы, код ---

def test_mask_pii_text_replaces_contacts_only():
    from mcp_baf.pii import mask_pii_text

    out = mask_pii_text("тел 0671234567, a.b@ex.com; код 12345")
    assert out.count("PII:") == 2 and "12345" in out
    assert mask_pii_text(None) == ""
    assert mask_pii_text(7) == "7"


def test_form_structure_masks_title_and_handlers():
    from mcp_baf.tools.form import format_form_structure

    form = {
        "name": "ФормаЭлемента",
        "title": "Карточка, тел +380 67 123-45-67",
        "elements": [{
            "name": "Телефон", "type": "Поле", "title": "client@example.com",
            "dataPath": "Объект.Телефон", "events": [],
        }],
        "commands": [],
        "handlers": [],
    }
    plain = format_form_structure(form)
    masked = format_form_structure(form, mask_pii=True)
    assert "+380 67 123-45-67" in plain and "client@example.com" in plain
    assert "123-45-67" not in masked and "client@example.com" not in masked
    assert masked.count("PII:") == 2
    assert "Объект.Телефон" in masked


def test_search_code_masks_context():
    from mcp_baf.dumpindex import Match
    from mcp_baf.tools.search_code import format_search_result

    matches = [Match(module="ОбщийМодуль.Почта", line=3,
                     context='Сообщить("client@example.com");', score=1.0)]
    plain = format_search_result(matches, 1, "почта", "smart")
    masked = format_search_result(matches, 1, "почта", "smart", mask_pii=True)
    assert "client@example.com" in plain
    assert "client@example.com" not in masked and "PII:" in masked
    assert "ОбщийМодуль.Почта" in masked
