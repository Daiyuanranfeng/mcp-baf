"""Гарды на контракт зависимостей (issue #37).

`mcp-baf-audit` пишет `audit.log` по схеме v2; формат — часть контракта между
mcp-baf и пакетом аудита. Без верхней границы в pyproject minor bump 0.3 мог бы
тихо сменить формат, а тест на SCHEMA_VERSION поймал бы это только в момент
установки. Оба гарда держат контракт явным.
"""

import pathlib
import tomllib

import mcp_baf_audit

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXPECTED_SPEC = "mcp-baf-audit~=0.2.1"
EXPECTED_SCHEMA_VERSION = "2"


def _audit_spec() -> str:
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    specs = [dep for dep in data["project"]["dependencies"] if dep.startswith("mcp-baf-audit")]
    assert len(specs) == 1, f"ожидался один spec mcp-baf-audit, получено: {specs}"
    return specs[0]


def test_audit_dependency_has_upper_bound():
    assert _audit_spec() == EXPECTED_SPEC


def test_audit_schema_version_is_v2():
    assert mcp_baf_audit.SCHEMA_VERSION == EXPECTED_SCHEMA_VERSION, (
        "SCHEMA_VERSION пакета mcp-baf-audit изменился — формат audit.log "
        "больше не совпадает с контрактом mcp-baf"
    )
