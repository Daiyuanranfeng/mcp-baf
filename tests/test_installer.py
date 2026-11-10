"""Тесты вспомогательной логики installer (без запуска DESIGNER)."""

import os

import pytest

from mcp_baf import installer


@pytest.mark.parametrize(
    ("source", "want"),
    [
        (r"C:\Program Files\BAF\8.3.18.1627\bin\1cv8.exe", (3, 18)),
        (r"C:\Program Files\1cv8\8.3.27.1859\bin\1cv8.exe", (3, 27)),
        ("/opt/1cv8/x86_64/8.3.22.1709/1cv8", (3, 22)),
        ("/Applications/1cv8.localized/8.3.25.1000/1cv8.app/Contents/MacOS/1cv8", (3, 25)),
        ("8.5.1.100", (5, 1)),
        ("no version here", (0, 0)),
    ],
)
def test_extract_platform_minor(source, want):
    assert installer.extract_platform_minor(source) == want


def test_platform_patterns_baf_first(monkeypatch):
    monkeypatch.setattr(installer.sys, "platform", "win32")
    patterns = installer._platform_patterns()
    assert patterns[0] == r"C:\Program Files\BAF\8.*\bin\1cv8.exe"
    assert patterns[1] == r"C:\Program Files (x86)\BAF\8.*\bin\1cv8.exe"


def test_parse_platform_version_override_priority():
    assert installer.parse_platform_version(
        r"C:\1cv8\8.3.27\bin\1cv8.exe", "8.3.13"
    ) == (3, 13)


@pytest.mark.parametrize(
    ("path", "want"),
    [
        (r"C:\Program Files\BAF\8.3.18.1627\bin\1cv8.exe", "2.11"),
        (r"C:\Program Files\1cv8\8.3.27.1859\bin\1cv8.exe", "2.20"),
        (r"C:\Program Files\1cv8\8.3.25.1394\bin\1cv8.exe", "2.18"),
        (r"C:\Program Files\1cv8\8.3.14.100\bin\1cv8.exe", "2.8"),
        (r"C:\Program Files\1cv8\8.3.13.100\bin\1cv8.exe", "2.7"),
        ("8.5.1.100", "2.21"),
        ("unknown", "2.7"),
    ],
)
def test_format_version_for_platform(path, want):
    assert installer.format_version_for_platform(path) == want


def test_patch_format_version(tmp_path):
    xml = tmp_path / "Configuration.xml"
    xml.write_text(
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<MetaDataObject xmlns="http://v8.1c.ru/8.3/MDClasses" version="2.18">\n'
        "</MetaDataObject>\n",
        encoding="utf-8",
    )
    installer.patch_format_version(str(tmp_path), "2.8")
    content = xml.read_text(encoding="utf-8")
    assert 'version="2.8"' in content
    # XML-декларация не тронута.
    assert '<?xml version="1.0"' in content


def test_patch_extension_xml_replace_and_insert(tmp_path):
    cfg = tmp_path / "Configuration.xml"
    cfg.write_text(
        "<Configuration>\n"
        "\t\t<Properties>\n"
        "\t\t\t<ConfigurationExtensionCompatibilityMode>Version8_3_24"
        "</ConfigurationExtensionCompatibilityMode>\n"
        "\t\t</Properties>\n"
        "</Configuration>\n",
        encoding="utf-8",
    )
    installer.patch_extension_xml(str(cfg), "Version8_3_10", "")
    content = cfg.read_text(encoding="utf-8")
    assert (
        "<ConfigurationExtensionCompatibilityMode>Version8_3_10"
        "</ConfigurationExtensionCompatibilityMode>"
    ) in content

    # Отсутствующий тег вставляется перед </Properties>.
    installer.patch_extension_xml(str(cfg), "", "Version8_2")
    content = cfg.read_text(encoding="utf-8")
    assert "<InterfaceCompatibilityMode>Version8_2</InterfaceCompatibilityMode>" in content
    assert content.index("InterfaceCompatibilityMode") < content.index("</Properties>")


def test_strip_inherited_properties(tmp_path):
    cfg = tmp_path / "Configuration.xml"
    cfg.write_text(
        "<Properties>\n"
        "<DefaultRunMode>ManagedApplication</DefaultRunMode>\n"
        "<Vendor>Тест</Vendor>\n"
        "<Synonym>Остаётся</Synonym>\n"
        "<DefaultRoles>\n<xr:Item>Роль</xr:Item>\n</DefaultRoles>\n"
        "</Properties>\n",
        encoding="utf-8",
    )
    installer.strip_inherited_properties(str(cfg))
    content = cfg.read_text(encoding="utf-8")
    assert "DefaultRunMode" not in content
    assert "Vendor" not in content
    assert "DefaultRoles" not in content
    assert "<Synonym>Остаётся</Synonym>" in content


def test_strip_unsupported_elements(tmp_path):
    cfg = tmp_path / "Configuration.xml"
    cfg.write_text(
        "<Configuration>\n"
        "<KeepMappingToExtendedConfigurationObjectsByIDs>true"
        "</KeepMappingToExtendedConfigurationObjectsByIDs>\n"
        "<InternalInfo>\n"
        "<xr:ContainedObject>\n"
        "<xr:ClassId>fb282519-d103-4dd3-bc12-cb271d631dfc</xr:ClassId>\n"
        "<xr:ObjectId>some-id</xr:ObjectId>\n"
        "</xr:ContainedObject>\n"
        "<xr:ContainedObject>\n"
        "<xr:ClassId>другой-класс</xr:ClassId>\n"
        "<xr:ObjectId>id2</xr:ObjectId>\n"
        "</xr:ContainedObject>\n"
        "</InternalInfo>\n"
        "</Configuration>\n",
        encoding="utf-8",
    )
    other = tmp_path / "Roles" / "Роль.xml"
    other.parent.mkdir()
    other.write_text(
        "<Role>\n<InternalInfo>\n<данные/>\n</InternalInfo>\n<Имя>Роль</Имя>\n</Role>\n",
        encoding="utf-8",
    )

    installer.strip_unsupported_elements(str(tmp_path))

    cfg_content = cfg.read_text(encoding="utf-8")
    # Configuration.xml: KeepMapping и Role-ContainedObject удалены,
    # сам InternalInfo с остальным содержимым остаётся (там UUID расширения).
    assert "KeepMappingToExtendedConfigurationObjectsByIDs" not in cfg_content
    assert "fb282519" not in cfg_content
    assert "<InternalInfo>" in cfg_content
    assert "другой-класс" in cfg_content

    # В остальных файлах InternalInfo вырезается целиком.
    other_content = other.read_text(encoding="utf-8")
    assert "InternalInfo" not in other_content
    assert "<Имя>Роль</Имя>" in other_content


def test_classify_designer_error_compat_mode():
    err = installer.classify_designer_error(
        "1C DESIGNER failed (exit code 1):\n"
        "Расширение конфигурации с указанным именем не найдено!"
    )
    assert "режим совместимости конфигурации запрещает расширения" in str(err)
    assert "Оригинальная ошибка DESIGNER" in str(err)


def test_classify_designer_error_compat_mode_ukrainian():
    # Украинская локализация платформы пишет ошибки на украинском.
    err = installer.classify_designer_error(
        "1C DESIGNER failed (exit code 1):\n"
        "Розширення конфігурації з вказаним ім'ям не знайдено!"
    )
    assert "режим совместимости конфигурации запрещает расширения" in str(err)


def test_classify_designer_error_passthrough():
    err = installer.classify_designer_error("какая-то другая ошибка")
    assert str(err) == "какая-то другая ошибка"


def _copy_extension_sources(tmp_path):
    import shutil

    dst = tmp_path / "ext"
    shutil.copytree(installer.EXTENSION_SRC, dst)
    return dst


def test_localize_extension_ua(tmp_path):
    ext_dir = _copy_extension_sources(tmp_path)
    installer.localize_extension(str(ext_dir), "ua")

    service = (ext_dir / "HTTPServices" / "MCPService.xml").read_text(
        encoding="utf-8-sig"
    )
    # Код языка синонимов сменён на украинский.
    assert "<v8:lang>ru</v8:lang>" not in service
    assert "<v8:lang>uk</v8:lang>" in service
    # Тексты синонимов переведены.
    assert "<v8:content>Метадані</v8:content>" in service
    assert "<v8:content>Перевірка запиту</v8:content>" in service
    assert "<v8:content>Метаданные</v8:content>" not in service
    # Имена объектов и обработчики не тронуты — они привязаны к Module.bsl.
    assert "<Name>Метаданные</Name>" in service

    cfg = (ext_dir / "Configuration.xml").read_text(encoding="utf-8-sig")
    assert "<v8:lang>uk</v8:lang>" in cfg
    assert "<v8:content>MCP HTTPService</v8:content>" in cfg


def test_localize_extension_ru_is_noop(tmp_path):
    ext_dir = _copy_extension_sources(tmp_path)
    before = (ext_dir / "HTTPServices" / "MCPService.xml").read_bytes()
    installer.localize_extension(str(ext_dir), "ru")
    after = (ext_dir / "HTTPServices" / "MCPService.xml").read_bytes()
    assert before == after


def test_localize_extension_keeps_bom(tmp_path):
    # Локализация не должна терять UTF-8 BOM там, где он был в исходнике.
    ext_dir = _copy_extension_sources(tmp_path)
    bom_before = {}
    for root, _dirs, files in os.walk(ext_dir):
        for name in files:
            if name.lower().endswith(".xml"):
                path = os.path.join(root, name)
                with open(path, "rb") as f:
                    bom_before[path] = f.read(3) == b"\xef\xbb\xbf"

    installer.localize_extension(str(ext_dir), "ua")

    for path, had_bom in bom_before.items():
        with open(path, "rb") as f:
            assert (f.read(3) == b"\xef\xbb\xbf") == had_bom, path


def test_translations_cover_all_cyrillic_synonyms():
    # Каждый русский (кириллический) текст синонима в исходниках должен
    # иметь перевод, иначе после --lang ua останется русский текст с
    # украинским кодом языка.
    import re

    for root, _dirs, files in os.walk(installer.EXTENSION_SRC):
        for name in files:
            if not name.lower().endswith(".xml"):
                continue
            content = open(
                os.path.join(root, name), encoding="utf-8-sig"
            ).read()
            for text in re.findall(r"<v8:content>([^<]+)</v8:content>", content):
                if re.search(r"[а-яёА-ЯЁ]", text):
                    assert text in installer._SYNONYM_TRANSLATIONS_UA, (
                        f"{name}: no Ukrainian translation for {text!r}"
                    )


def test_install_rejects_unknown_lang():
    with pytest.raises(installer.InstallError, match="unsupported --lang"):
        installer.install("C:\\db", lang="en")


def test_lang_default_and_choices():
    from mcp_baf import config

    assert config.parse_args([]).lang == "ua"
    assert config.parse_args(["--lang", "ru"]).lang == "ru"
    with pytest.raises(SystemExit):
        config.parse_args(["--lang", "en"])


def test_extension_sources_present():
    # XML-исходники расширения должны попадать в пакет.
    expected = [
        "Configuration.xml",
        "ConfigDumpInfo.xml",
        os.path.join("HTTPServices", "MCPService.xml"),
        os.path.join("HTTPServices", "MCPService", "Ext", "Module.bsl"),
        os.path.join("Roles", "MCP_ОсновнаяРоль.xml"),
        os.path.join("Roles", "MCP_ОсновнаяРоль", "Ext", "Rights.xml"),
    ]
    for rel in expected:
        assert os.path.isfile(os.path.join(installer.EXTENSION_SRC, rel)), rel


def test_no_default_language():
    # DefaultLanguage (ОсновнойЯзык) — контролируемое свойство: оно должно
    # совпадать с основным языком базы, который заранее неизвестен (BAF —
    # украинский, другие базы — русский). Поэтому свойство и заимствованный
    # объект языка из расширения исключены — значение наследуется от базы.
    cfg = open(
        os.path.join(installer.EXTENSION_SRC, "Configuration.xml"),
        encoding="utf-8-sig",
    ).read()
    assert "<DefaultLanguage>" not in cfg
    assert "<Language>" not in cfg
    dump_info = open(
        os.path.join(installer.EXTENSION_SRC, "ConfigDumpInfo.xml"),
        encoding="utf-8-sig",
    ).read()
    assert "Language.Русский" not in dump_info


@pytest.mark.parametrize("message", [
    "Неизвестный объект метаданных - Document.АктВыполненныхРабот",
    "Невідомий об’єкт метаданих - Document.АктВыполненныхРабот",
    "Ошибка при загрузке конфигурации",
    "Помилка під час завантаження конфігурації",
])
def test_designer_fatal_log_is_detected_even_with_zero_exit(message):
    assert installer._designer_log_is_fatal(message)
    assert not installer._designer_log_is_fatal("Расширение конфигурации загружено")


def test_run_designer_fails_closed_on_zero_exit_fatal_log(monkeypatch):
    from types import SimpleNamespace

    def fake_run(argv, capture_output, timeout=None):
        with open(argv[argv.index("/Out") + 1], "w", encoding="utf-8") as log:
            log.write("Невідомий об’єкт метаданих - Catalog.Номенклатура")
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(installer.subprocess, "run", fake_run)
    error = installer._run_designer("1cv8.exe", "C:\\db", False, "", "", "/LoadConfigFromFiles", "dump")
    assert error is not None and "fatal load error" in error


def test_normalize_names_nfc(tmp_path):
    import unicodedata

    nfd = unicodedata.normalize("NFD", "Основной")
    (tmp_path / nfd).mkdir()
    (tmp_path / nfd / (nfd + ".xml")).write_text("x", encoding="utf-8")
    installer.normalize_names_nfc(str(tmp_path))
    names = [n for _root, dirs, files in os.walk(tmp_path) for n in dirs + files]
    assert names and all(n == unicodedata.normalize("NFC", n) for n in names)


# ── dump(): експорт конфігурації та розширень ──

def _recorder():
    calls = []

    def fake(platform_exe, db_path, server_mode, db_user, db_password, *extra):
        calls.append((platform_exe, db_path, server_mode, db_user, db_password, *extra))
        return None

    return calls, fake


def test_dump_base_only_single_call(monkeypatch, tmp_path):
    calls, fake = _recorder()
    monkeypatch.setattr(installer, "_run_designer", fake)
    result = installer.dump("C:\\db", str(tmp_path / "out"), platform_exe="1cv8.exe")
    out = str(os.path.abspath(str(tmp_path / "out")))
    assert result == {"base_error": None, "extensions": {}}
    assert calls == [("1cv8.exe", "C:\\db", False, "", "", "/DumpConfigToFiles", out)]


def test_dump_all_extensions_base_then_moved_subdirs(monkeypatch, tmp_path):
    out = tmp_path / "out"
    (out / "A").mkdir(parents=True)
    (out / "A" / "stale.bsl").write_text("old")
    calls = []

    def fake(platform_exe, db_path, server_mode, db_user, db_password, *extra):
        calls.append(extra)
        if "-AllExtensions" in extra:  # платформа кладёт расширения в подпапки
            for name in ("A", "Catalogs"):
                os.makedirs(os.path.join(extra[1], name))
                open(os.path.join(extra[1], name, "Configuration.xml"), "w").close()
        return None

    monkeypatch.setattr(installer, "_run_designer", fake)
    result = installer.dump("srv\\b", str(out), extensions="all", platform_exe="1cv8.exe")
    assert calls[0] == ("/DumpConfigToFiles", str(out))  # основа — отдельно и первой
    assert calls[1][0] == "/DumpConfigToFiles" and calls[1][2] == "-AllExtensions"
    assert calls[1][1] != str(out)  # расширения — во временный каталог
    assert not os.path.exists(calls[1][1])  # временный каталог убран
    assert (out / "A" / "Configuration.xml").exists()
    assert not (out / "A" / "stale.bsl").exists()
    assert not (out / "Catalogs").exists()  # не затирает каталог основы
    assert result["extensions"]["A"] is None and result["extensions"]["Catalogs"]


def test_dump_specific_extensions_into_subdirs(monkeypatch, tmp_path):
    calls, fake = _recorder()
    monkeypatch.setattr(installer, "_run_designer", fake)
    out = str(tmp_path / "out")
    installer.dump("C:\\db", out, extensions=["MCP_HTTPService", "ЧестныйЗнак"],
                   platform_exe="1cv8.exe")
    assert len(calls) == 3
    base, e1, e2 = calls
    assert base[-2:] == ("/DumpConfigToFiles", os.path.abspath(out))
    assert e1[-4:] == ("/DumpConfigToFiles", os.path.join(os.path.abspath(out), "MCP_HTTPService"),
                       "-Extension", "MCP_HTTPService")
    assert e2[-4:] == ("/DumpConfigToFiles", os.path.join(os.path.abspath(out), "ЧестныйЗнак"),
                       "-Extension", "ЧестныйЗнак")


def test_dump_rejects_path_in_extension_name(monkeypatch, tmp_path):
    calls, fake = _recorder()
    monkeypatch.setattr(installer, "_run_designer", fake)
    for bad in ("../evil", "a/b", "a\\b", "", ".", "..", "x.", "a:b", "a?b",
                "Catalogs", "Ext", "CommonModules", ".hidden"):
        with pytest.raises(installer.InstallError):
            installer.dump("C:\\db", str(tmp_path / "o"), extensions=[bad],
                           platform_exe="1cv8.exe")
    assert calls == []  # перевірка імен — до будь-якого виклику DESIGNER


def test_dump_dedupes_extension_names_case_insensitive(monkeypatch, tmp_path):
    calls, fake = _recorder()
    monkeypatch.setattr(installer, "_run_designer", fake)
    result = installer.dump("C:\\db", str(tmp_path / "o"), extensions=["A", "B", "a"],
                            platform_exe="1cv8.exe")
    assert len(calls) == 3  # основа + A + B
    assert len(result["extensions"]) == 2


def test_dump_base_failure_raises(monkeypatch, tmp_path):
    monkeypatch.setattr(installer, "_run_designer",
                        lambda *a, **k: "DESIGNER failed (exit code 1)")
    with pytest.raises(installer.InstallError, match="DumpConfigToFiles"):
        installer.dump("C:\\db", str(tmp_path / "o"), platform_exe="1cv8.exe")


def test_dump_extension_failure_collected_others_continue(monkeypatch, tmp_path):
    def fake(platform_exe, db_path, server_mode, db_user, db_password, *extra):
        return "boom" if extra[-1] == "Біле" else None

    monkeypatch.setattr(installer, "_run_designer", fake)
    result = installer.dump("C:\\db", str(tmp_path / "o"),
                            extensions=["Здорове", "Біле"], platform_exe="1cv8.exe")
    assert result["extensions"] == {"Здорове": None, "Біле": "boom"}


def test_dump_rejects_unknown_string_extensions(monkeypatch, tmp_path):
    monkeypatch.setattr(installer, "_run_designer", lambda *a, **k: None)
    with pytest.raises(installer.InstallError, match="all"):
        installer.dump("C:\\db", str(tmp_path / "o"), extensions="some",
                       platform_exe="1cv8.exe")


def test_dump_all_skips_root_files_and_blocked_target(monkeypatch, tmp_path):
    out = tmp_path / "out"

    def fake(platform_exe, db_path, server_mode, db_user, db_password, *extra):
        if "-AllExtensions" in extra:
            root = extra[1]
            for name in ("A", "B"):
                os.makedirs(os.path.join(root, name))
                open(os.path.join(root, name, "Configuration.xml"), "w").close()
            open(os.path.join(root, "ConfigDumpInfo.xml"), "w").close()
        return None

    monkeypatch.setattr(installer, "_run_designer", fake)
    (out / "B").mkdir(parents=True)
    (out / "B" / "stale.bsl").write_text("locked-by-av")

    real_rmtree = installer.shutil.rmtree

    def blocked(path, *a, **kw):
        # «B» не видаляється: імітація заблокованого антивірусом каталогу
        if os.path.basename(str(path)) == "B":
            return
        real_rmtree(path, *a, **kw)

    monkeypatch.setattr(installer.shutil, "rmtree", blocked)
    result = installer.dump("srv\\b", str(out), extensions="all", platform_exe="1cv8.exe")
    assert result["extensions"]["A"] is None
    assert (out / "A" / "Configuration.xml").exists()
    # заблокована ціль — зібрана помилка, без тихого вкладення B/B
    assert result["extensions"]["B"] and "could not be removed" in result["extensions"]["B"]
    assert not (out / "B" / "B").exists()
    # службовий файл з кореня вивантажки не «розширення»
    assert "ConfigDumpInfo.xml" not in result["extensions"]
    assert not (out / "ConfigDumpInfo.xml").exists()


# --- Выбор платформы: версия, а не лексикографический порядок строк ---

def test_newest_platform_sorts_by_version_not_string():
    paths = [
        "/opt/1cv8/x86_64/8.3.9.100/1cv8",
        "/opt/1cv8/x86_64/8.3.14.100/1cv8",
        "/opt/1cv8/x86_64/8.3.10.100/1cv8",
    ]
    # строкой «8.3.9» > «8.3.14», версией — наоборот
    assert installer.newest_platform(paths) == paths[1]


def test_newest_platform_prefers_higher_build():
    paths = [
        "/opt/1cv8/x86_64/8.3.14.100/1cv8",
        "/opt/1cv8/x86_64/8.3.14.1627/1cv8",
    ]
    assert installer.newest_platform(paths) == paths[1]


def test_newest_platform_without_version_never_wins():
    paths = ["/opt/1cv8/x86_64/broken/1cv8", "/opt/1cv8/x86_64/8.3.5/1cv8"]
    assert installer.newest_platform(paths) == paths[1]


def test_find_platform_uses_version_order(monkeypatch):
    found = [
        "/opt/1cv8/x86_64/8.3.9.100/1cv8",
        "/opt/1cv8/x86_64/8.3.14.100/1cv8",
    ]
    monkeypatch.setattr(installer, "_platform_patterns",
                        lambda: ["/opt/1cv8/x86_64/8.*/1cv8"])
    monkeypatch.setattr(installer.glob, "glob", lambda pattern: found)
    assert installer.find_platform() == found[1]


def test_find_platform_keeps_pattern_priority(monkeypatch):
    monkeypatch.setattr(installer, "_platform_patterns", lambda: ["a/*", "b/*"])

    def fake_glob(pattern):
        return ["a/8.3.5/1cv8"] if pattern == "a/*" else ["b/8.3.27/1cv8"]

    monkeypatch.setattr(installer.glob, "glob", fake_glob)
    # BAF раньше 1cv8: старый BAF приоритетнее новой 1cv8 из другого шаблона
    assert installer.find_platform() == "a/8.3.5/1cv8"


# --- Таймаут DESIGNER ---

def _timeout_run(monkeypatch, calls):
    def fake_run(argv, capture_output, timeout=None):
        calls.append(timeout)
        raise installer.subprocess.TimeoutExpired(argv[0], timeout)

    monkeypatch.setattr(installer.subprocess, "run", fake_run)


def test_run_designer_timeout_reports_clear_error(monkeypatch):
    calls = []
    _timeout_run(monkeypatch, calls)
    error = installer._run_designer(
        "1cv8.exe", "C:\\db", False, "", "", "/DumpConfigToFiles", "out"
    )
    assert error is not None
    assert "таймаут" in error
    assert "mcp_baf_DESIGNER_TIMEOUT" in error
    assert calls == [installer.DEFAULT_DESIGNER_TIMEOUT]


def test_run_designer_timeout_env_override(monkeypatch):
    monkeypatch.setenv("mcp_baf_DESIGNER_TIMEOUT", "42")
    calls = []
    _timeout_run(monkeypatch, calls)
    error = installer._run_designer(
        "1cv8.exe", "C:\\db", False, "", "", "/DumpConfigToFiles", "out"
    )
    assert error is not None and "42" in error
    assert calls == [42]


def test_designer_timeout_ignores_bad_env(monkeypatch):
    for raw in ("", "abc", "0", "-5"):
        monkeypatch.setenv("mcp_baf_DESIGNER_TIMEOUT", raw)
        assert installer.designer_timeout() == installer.DEFAULT_DESIGNER_TIMEOUT


# --- Пароль базы: файл/оточение вместо argv ---

def test_db_password_from_file_strips_trailing_newline(monkeypatch, tmp_path):
    secret = tmp_path / "db-pass"
    secret.write_text("s3cret\n\n", encoding="utf-8")
    monkeypatch.delenv("mcp_baf_DB_PASSWORD", raising=False)
    monkeypatch.setenv("mcp_baf_DB_PASSWORD_FILE", str(secret))
    assert installer.resolve_db_password() == "s3cret"


def test_db_password_plain_env(monkeypatch):
    monkeypatch.delenv("mcp_baf_DB_PASSWORD_FILE", raising=False)
    monkeypatch.setenv("mcp_baf_DB_PASSWORD", "env-pass")
    assert installer.resolve_db_password() == "env-pass"


def test_db_password_env_and_file_conflict(monkeypatch, tmp_path):
    secret = tmp_path / "p"
    secret.write_text("x", encoding="utf-8")
    monkeypatch.setenv("mcp_baf_DB_PASSWORD", "a")
    monkeypatch.setenv("mcp_baf_DB_PASSWORD_FILE", str(secret))
    with pytest.raises(installer.InstallError, match="mcp_baf_DB_PASSWORD_FILE"):
        installer.resolve_db_password()


def test_db_password_missing_file_error_names_path(monkeypatch, tmp_path):
    monkeypatch.delenv("mcp_baf_DB_PASSWORD", raising=False)
    monkeypatch.setenv("mcp_baf_DB_PASSWORD_FILE", str(tmp_path / "nope"))
    with pytest.raises(installer.InstallError) as exc:
        installer.resolve_db_password()
    assert "mcp_baf_DB_PASSWORD_FILE" in str(exc.value)
    assert "nope" in str(exc.value)


def test_db_password_cli_wins_and_warns(monkeypatch, capsys):
    monkeypatch.setenv("mcp_baf_DB_PASSWORD", "env-pass")
    assert installer.resolve_db_password("cli-pass") == "cli-pass"
    err = capsys.readouterr().err
    assert "ps" in err and "mcp_baf_DB_PASSWORD_FILE" in err


def test_build_designer_args_keeps_password_flag():
    args = installer._build_designer_args("db", False, "u", "p", "log")
    assert args[args.index("/P") + 1] == "p"


def test_install_uses_password_file(monkeypatch, tmp_path):
    captured = {}

    def fake_install_from(ext_dir, platform_exe, db_path, server_mode,
                          db_user, db_password, platform_version, lang):
        captured["db_password"] = db_password

    monkeypatch.setattr(installer, "_install_from", fake_install_from)
    secret = tmp_path / "db-pass"
    secret.write_text("file-pass\n", encoding="utf-8")
    monkeypatch.delenv("mcp_baf_DB_PASSWORD", raising=False)
    monkeypatch.setenv("mcp_baf_DB_PASSWORD_FILE", str(secret))
    installer.install("C:\\db", platform_exe="1cv8.exe")
    assert captured["db_password"] == "file-pass"
