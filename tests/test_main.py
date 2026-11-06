"""Режим установки и справка CLI не должны импортировать MCP-сервер."""

import subprocess
import sys

import pytest


@pytest.mark.parametrize('mode', ['--help', '--version', '--install'])
def test_cli_works_when_mcp_sdk_import_is_unavailable(tmp_path, mode):
    # Отдельный процесс исключает уже импортированный другими тестами SDK.
    script = '''
import importlib.abc
import sys

class UnavailableSDK(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname == "mcp" or fullname.startswith("mcp.") or fullname == "mcp_baf.server":
            raise ModuleNotFoundError("MCP SDK unavailable", name=fullname)

sys.meta_path.insert(0, UnavailableSDK())
from mcp_baf import installer
def install(**kwargs):
    assert kwargs["db_path"] == "TEST_DATABASE"
    print("MOCK_INSTALL_CALLED")
installer.install = install
from mcp_baf.__main__ import main
sys.argv = ["mcp-baf"] + sys.argv[1:]
main()
'''
    args = [mode]
    if mode == '--install':
        args += ['TEST_DATABASE', '--cache-dir', str(tmp_path)]
    result = subprocess.run([sys.executable, '-c', script, *args], capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    if mode == '--install':
        assert 'MOCK_INSTALL_CALLED' in result.stdout
        assert 'Extension installed successfully.' in result.stdout


# ── _run_dump: диспетчер --install --dump ──

from types import SimpleNamespace  # noqa: E402

from mcp_baf.__main__ import _run_dump  # noqa: E402


def _dump_args(**over):
    base = dict(install="srv\\b", dump="/out", dump_extensions=None, server=True,
                platform="1cv8.exe", db_user="u", db_password="p",
                platform_version="")
    base.update(over)
    return SimpleNamespace(**base)


def test_run_dump_parses_list(monkeypatch):
    seen = {}

    def fake_dump(**kw):
        seen.update(kw)
        return {"base_error": None, "extensions": {"A": None, "B": None}}

    from mcp_baf import installer
    monkeypatch.setattr(installer, "dump", fake_dump)
    _run_dump(_dump_args(dump_extensions="A, B"))
    assert seen["extensions"] == ["A", "B"]
    assert seen["server_mode"] is True


def test_run_dump_all_keyword_passthrough(monkeypatch):
    seen = {}
    from mcp_baf import installer
    monkeypatch.setattr(installer, "dump",
                        lambda **kw: seen.update(kw) or {"base_error": None, "extensions": {}})
    _run_dump(_dump_args(dump_extensions="all"))
    assert seen["extensions"] == "all"


def test_run_dump_failed_extension_exits_1(monkeypatch):
    from mcp_baf import installer
    monkeypatch.setattr(installer, "dump",
                        lambda **kw: {"base_error": None, "extensions": {"A": "boom"}})
    with pytest.raises(SystemExit) as exc:
        _run_dump(_dump_args(dump_extensions="A"))
    assert exc.value.code == 1


def test_run_dump_install_error_exits_1(monkeypatch):
    from mcp_baf import installer

    def boom(**kw):
        raise installer.InstallError("nope")

    monkeypatch.setattr(installer, "dump", boom)
    with pytest.raises(SystemExit) as exc:
        _run_dump(_dump_args())
    assert exc.value.code == 1
