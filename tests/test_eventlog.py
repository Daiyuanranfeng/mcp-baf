"""Тесты маскирования ПДн в журнале регистрации (get_event_log)."""

from mcp_baf.tools.eventlog import format_event_log

EVENTS = {
    "events": [
        {
            "date": "2026-03-01T10:00:00",
            "level": "Информация",
            "event": "Изменение объекта",
            "user": "Иванов",
            "computer": "PC-01",
            "metadata": "Справочник.Контрагенты",
            "data": "Телефон клиента +380 50 123-45-67",
            "comment": "письмо на client@example.com",
            "transaction": "00000001",
        },
    ],
    "total": 1,
}


def test_event_log_without_masking_keeps_contacts():
    out = format_event_log(EVENTS)
    assert "123-45-67" in out and "client@example.com" in out


def test_event_log_masks_phone_and_email():
    out = format_event_log(EVENTS, mask_pii=True)
    assert "123-45-67" not in out
    assert "client@example.com" not in out
    assert out.count("PII:") == 2
    # имена полей и служебные значения не искажены
    assert "Пользователь: Иванов" in out
    assert "Справочник.Контрагенты" in out
    assert "00000001" in out


def test_event_log_masking_empty_result():
    out = format_event_log({"events": [], "total": 0}, mask_pii=True)
    assert "Записей не найдено." in out
