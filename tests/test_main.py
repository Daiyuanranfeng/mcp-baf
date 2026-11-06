"""Режим установки и справка CLI не должны импортировать MCP-сервер."""

import subprocess
import sys
from types import SimpleNamespace

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


# ── --install --dump: разбор --dump-extensions и связка с main() ──


def _run_main(monkeypatch, tmp_path, *argv):
    """main() с подменёнными install/dump; возвращает (calls, exit_code)."""
    from mcp_baf import installer
    from mcp_baf.__main__ import main

    calls = []
    monkeypatch.setattr(installer, "install", lambda **kw: calls.append(("install", kw)))
    monkeypatch.setattr(installer, "dump", lambda **kw: calls.append(("dump", kw))
                        or {"base_error": None, "extensions": {}})
    monkeypatch.setattr(sys, "argv", ["mcp-baf", "--cache-dir", str(tmp_path), *argv])
    try:
        main()
    except SystemExit as exc:
        return calls, exc.code
    return calls, 0


def test_install_dump_list_parsed_and_passed(monkeypatch, tmp_path):
    calls, code = _run_main(monkeypatch, tmp_path, "--install", "db", "--dump", "/out",
                            "--dump-extensions", "A, B,a")
    assert code == 0
    assert [c[0] for c in calls] == ["install", "dump"]
    assert calls[1][1]["extensions"] == ["A", "B", "a"]  # дубли снимает installer.dump


@pytest.mark.parametrize("value", [[], ["ALL"], ["all"]])
def test_install_dump_all_forms(monkeypatch, tmp_path, value):
    calls, code = _run_main(monkeypatch, tmp_path, "--install", "db", "--dump", "/out",
                            "--dump-extensions", *value)
    assert code == 0
    assert calls[1][1]["extensions"] == "all"


def test_install_without_dump_flag_does_not_export(monkeypatch, tmp_path):
    calls, code = _run_main(monkeypatch, tmp_path, "--install", "db")
    assert code == 0
    assert [c[0] for c in calls] == ["install"]


@pytest.mark.parametrize("argv", [
    ["--install", "db", "--dump-extensions"],   # без --dump
    ["--dump", "/out", "--dump-extensions"],    # без --install
])
def test_dump_extensions_requires_install_and_dump(monkeypatch, tmp_path, argv):
    calls, code = _run_main(monkeypatch, tmp_path, *argv)
    assert code == 1
    assert calls == []


@pytest.mark.parametrize("value", [",", " , ", "../x", "Catalogs", "A:B", "."])
def test_bad_extension_names_rejected_before_install(monkeypatch, tmp_path, value):
    calls, code = _run_main(monkeypatch, tmp_path, "--install", "db", "--dump", "/out",
                            f"--dump-extensions={value}")
    assert code == 1
    assert calls == []


def test_failed_extension_exits_1(monkeypatch, tmp_path):
    from mcp_baf import installer
    from mcp_baf.__main__ import _run_dump

    monkeypatch.setattr(installer, "dump",
                        lambda **kw: {"base_error": None, "extensions": {"A": "boom"}})
    args = SimpleNamespace(install="db", dump="/out", server=False, platform="",
                           db_user="", db_password="", platform_version="")
    with pytest.raises(SystemExit) as exc:
        _run_dump(args, ["A"])
    assert exc.value.code == 1


def test_base_dump_error_exits_1(monkeypatch, tmp_path):
    from mcp_baf import installer

    def boom(**kw):
        raise installer.InstallError("nope")

    monkeypatch.setattr(installer, "install", lambda **kw: None)
    monkeypatch.setattr(installer, "dump", boom)
    monkeypatch.setattr(sys, "argv", ["mcp-baf", "--cache-dir", str(tmp_path),
                                      "--install", "db", "--dump", "/out"])
    from mcp_baf.__main__ import main
    with pytest.raises(SystemExit) as exc:
        main()
    assert exc.value.code == 1
