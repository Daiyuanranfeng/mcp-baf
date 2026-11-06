"""Установка расширения MCP в базу 1С через DESIGNER (порт installer/installer.go).

XML-исходники расширения распаковываются во временный каталог, патчатся под
версию целевой платформы (версия формата выгрузки, режим совместимости,
неподдерживаемые элементы) и загружаются командой /LoadConfigFromFiles с
цепочкой повторов под известные ошибки старых платформ.
"""

from __future__ import annotations

import glob
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unicodedata

EXTENSION_NAME = "MCP_HTTPService"

# Каталог с XML-исходниками расширения (копия extension/src из Go-версии).
EXTENSION_SRC = os.path.join(os.path.dirname(__file__), "extension_src")

# Версия формата XML-выгрузки по умолчанию, когда версию платформы определить
# не удалось. 2.7 — формат платформ старше 8.3.14 (нижней записи таблицы).
DEFAULT_FORMAT_VERSION = "2.7"

# Версия формата XML-выгрузки для платформ 1С 8.5.x.
PLATFORM_85_FORMAT_VERSION = "2.21"

# Минорная версия платформы 8.3.X -> версия формата XML-выгрузки, которую она
# ввела. Платформа читает форматы не новее собственного.
# Источник: официальные release notes 1С. Отсортировано по убыванию.
PLATFORM_FORMAT_VERSIONS = [
    (27, "2.20"),
    (26, "2.19"),
    (25, "2.18"),
    (24, "2.17"),
    (23, "2.16"),
    (22, "2.15"),
    (21, "2.14"),
    (20, "2.13"),
    (19, "2.12"),
    (18, "2.11"),
    (17, "2.10"),
    (16, "2.9.1"),
    (15, "2.9"),
    (14, "2.8"),
]

# Язык синонимов расширения по умолчанию. XML-исходники хранятся с русскими
# синонимами (v8:lang ru); при "ua" временная копия локализуется перед
# загрузкой: код языка меняется на uk (код украинского языка в BAF),
# тексты синонимов переводятся. Имена объектов и обработчики не трогаются —
# они привязаны к коду Module.bsl.
DEFAULT_LANG = "ua"

SUPPORTED_LANGS = ("ua", "ru")

# Украинский код языка в XML-выгрузке 1С (значение v8:lang).
_UA_LANG_CODE = "uk"

# Переводы текстов синонимов (русский -> украинский). Только строки,
# реально встречающиеся в <v8:content> XML-исходников; латинские
# синонимы (MCP HTTPService, GET, POST) одинаковы в обоих языках.
_SYNONYM_TRANSLATIONS_UA = {
    "Возможности": "Можливості",
    "Ссылки": "Посилання",
    "Навигация": "Навігація",
    "ПраваМетаданных": "Права метаданих",
    "Метаданные": "Метадані",
    "Объект": "Об'єкт",
    "Запрос": "Запит",
    "Версия": "Версія",
    "Форма": "Форма",
    "Проверка запроса": "Перевірка запиту",
    "Журнал регистрации": "Журнал реєстрації",
    "Конфигурация": "Конфігурація",
    "Расширения": "Розширення",
}

_LANG_TAG_RU = "<v8:lang>ru</v8:lang>"
_LANG_TAG_UA = f"<v8:lang>{_UA_LANG_CODE}</v8:lang>"

ROLE_NOTE = (
    "Примечание: роль MCP_ОсновнаяРоль установлена с правами доступа к HTTP-сервису.\n"
    'Пользователям с ролью "Полные права" дополнительных действий не требуется.\n'
    "Для остальных пользователей назначьте роль MCP_ОсновнаяРоль вручную в Конфигураторе."
)

# version="2.X[.Y]" в XML-файлах выгрузки. Префикс "2." исключает
# XML-декларацию (<?xml version="1.0"?>) без отдельной проверки.
_VERSION_ATTR_RE = re.compile(r'(version=")2\.\d+(?:\.\d+)?(")')

# 8.Major.Minor из пути к платформе или строки версии.
_PLATFORM_VERSION_RE = re.compile(r"8\.(\d+)\.(\d+)")

# Элементы, появившиеся в 8.3.15, которые отвергают старые платформы.
_KEEP_MAPPING_RE = re.compile(
    r"\s*<KeepMappingToExtendedConfigurationObjectsByIDs>[^<]*"
    r"</KeepMappingToExtendedConfigurationObjectsByIDs>"
)
_INTERNAL_INFO_RE = re.compile(
    r"\s*<InternalInfo\s*/>|\s*<InternalInfo>.*?</InternalInfo>", re.DOTALL
)
# xr:ContainedObject с ClassId роли (fb282519-...): платформы 8.3.13 и старше
# не знают этот ClassId и падают с «Неверный идентификатор класса».
_ROLE_CONTAINED_OBJECT_RE = re.compile(
    r"\s*<xr:ContainedObject>\s*"
    r"<xr:ClassId>fb282519-d103-4dd3-bc12-cb271d631dfc</xr:ClassId>\s*"
    r"<xr:ObjectId>[^<]*</xr:ObjectId>\s*"
    r"</xr:ContainedObject>",
    re.DOTALL,
)
_DEFAULT_RUN_MODE_RE = re.compile(r"\s*<DefaultRunMode>[^<]*</DefaultRunMode>")

# Свойства, конфликтующие с заимствованными свойствами базовой конфигурации
# в старых режимах совместимости (8.3.13 и ниже).
_INHERITED_TAGS = (
    "DefaultRunMode|UsePurposes|ScriptVariant|DefaultRoles|"
    "Vendor|Version|DefaultLanguage|BriefInformation|DetailedInformation|"
    "Copyright|VendorInformationAddress|ConfigurationInformationAddress"
)
_INHERITED_PROPERTY_RE = re.compile(
    rf"\s*<(?:{_INHERITED_TAGS})>.*?</(?:{_INHERITED_TAGS})>", re.DOTALL
)

# Ошибка DESIGNER, означающая что режим совместимости базы вообще не
# поддерживает расширения (8.3.8 и старше) — в batch-режиме платформа выдаёт
# только невнятное «не найдено». Локализованные платформы (uk) пишут
# сообщения на своём языке — учитываем оба варианта.
_COMPAT_MODE_NOT_FOUND_RE = re.compile(
    r"расширение\s+конфигурации\s+с\s+указанным\s+именем\s+не\s+найдено"
    r"|розширення\s+конфігурації\s+(?:з|із)\s+вказаним\s+(?:ім'ям|іменем)\s+не\s+знайдено",
    re.IGNORECASE,
)


# DESIGNER on some 8.3 releases returns exit code 0 even when
# /LoadConfigFromFiles rejected part of the dump.  These messages are fatal,
# not informational output, and must not be followed by "installed successfully".
_DESIGNER_FATAL_LOG_RE = re.compile(
    r"неизвестн\w*\s+объект\s+метаданн\w*"
    r"|невідом\w*\s+об[’'ʼ]?єкт\s+метадан\w*"
    r"|ошибк\w*\s+(?:при\s+)?загрузк\w*\s+конфигурац\w*"
    r"|помилк\w*\s+(?:під\s+час\s+)?завантажен\w*\s+конфігурац\w*"
    r"|ошибк\w*\s+инициализац\w*\s+модул\w*"
    r"|помилк\w*\s+ініціалізаці\w*\s+модул\w*"
    r"|право\s+[^\n\r]*?(?<!не\s)огранич\w*\s+профил\w*\s+безопасност\w*"
    r"|право\s+[^\n\r]*?(?<!не\s)обмежен\w*\s+профіл\w*\s+безпек\w*",
    re.IGNORECASE,
)


def _error_contains(error: str, *needles: str) -> bool:
    """Регистронезависимый поиск любого из вариантов текста ошибки
    (русская и украинская локализации DESIGNER)."""
    lowered = error.lower()
    return any(needle.lower() in lowered for needle in needles)


class InstallError(Exception):
    """Ошибка установки расширения с понятным пользователю текстом."""


def _designer_log_is_fatal(log: str) -> bool:
    """True when a nominally successful DESIGNER run contains a load error."""
    return bool(_DESIGNER_FATAL_LOG_RE.search(log))


def install(
    db_path: str,
    server_mode: bool = False,
    platform_exe: str = "",
    db_user: str = "",
    db_password: str = "",
    platform_version: str = "",
    lang: str = DEFAULT_LANG,
) -> None:
    """Устанавливает расширение MCP в базу 1С.

    Если platform_exe пуст, платформа ищется в стандартных путях.
    platform_version — необязательное переопределение (например "8.3.13"),
    когда версию нельзя определить из пути. При server_mode=True база
    считается клиент-серверной и DESIGNER вызывается с /S вместо /F.
    lang — язык синонимов расширения: "ua" (по умолчанию) или "ru".
    """
    if lang not in SUPPORTED_LANGS:
        raise InstallError(
            f"unsupported --lang value: {lang!r} "
            f"(supported: {', '.join(SUPPORTED_LANGS)})"
        )
    if not platform_exe:
        platform_exe = find_platform()
    print(f"Platform: {platform_exe}")

    ext_dir = tempfile.mkdtemp(prefix="mcp-baf-ext-")
    try:
        _install_from(ext_dir, platform_exe, db_path, server_mode,
                      db_user, db_password, platform_version, lang)
    finally:
        shutil.rmtree(ext_dir, ignore_errors=True)


def _safe_extension_name(name: str) -> str:
    """Имя расширения из CLI: без путей — оно становится подкаталогом выгрузки.

    Отклоняются и имена, которые индексатор не примет за корень расширения
    (стандартные каталоги выгрузки вроде Catalogs/Ext, скрытые, «.»/«..»):
    выгрузка в такой подкаталог смешалась бы с файлами основной конфигурации.
    """
    from mcp_baf.dumpindex.extroots import _rejected_dir_name

    name = (name or "").strip()
    if (not name or re.search(r'[\\/<>:"|?*\x00-\x1f]', name)
            or name.endswith(".") or _rejected_dir_name(name)):
        raise InstallError(f"некоректне ім'я розширення: {name!r}")
    return name


def dump(
    db_path: str,
    out_dir: str,
    extensions: "list[str] | str | None" = None,
    server_mode: bool = False,
    platform_exe: str = "",
    db_user: str = "",
    db_password: str = "",
    platform_version: str = "",
) -> dict:
    """Выгружает конфигурацию из базы DESIGNER /DumpConfigToFiles в out_dir.

    extensions=None — только основная конфигурация;
    extensions="all" — основная, затем все расширения командой
        -AllExtensions (основу она не выгружает) во временный каталог,
        откуда каждое переносится в подпапку <out_dir>/<имя>/;
    extensions=[...] — основная плюс каждое указанное расширение
        отдельной командой -Extension в свою подпапку <out_dir>/<имя>/
        (без флага -Extension подпапка обязательна: платформа пишет
        выгрузку расширения её собственным Configuration.xml в корень
        целевого каталога).

    Подпапки расширений индексатор (dumpindex.extroots) распознаёт по
    ConfigurationExtensionPurpose — код сразу виден в search_code как
    ext.<имя>.*. Имена расширений валидируются заранее: они становятся
    именами подкаталогов.

    Возвращает {"base_error": str|None, "extensions": {имя: str|None}};
    при ошибке выгрузки основной конфигурации бросает InstallError —
    без неё искать нечего.
    """
    # Имена расширений в 1С регистронезависимы — дубль означал бы повторную выгрузку.
    names = list({_safe_extension_name(n).casefold(): _safe_extension_name(n)
                  for n in (extensions or [])}.values()) \
        if not isinstance(extensions, str) else []
    if isinstance(extensions, str) and extensions != "all":
        raise InstallError(f"--dump-extensions: ожидалось 'all' або список, отримано {extensions!r}")

    if not platform_exe:
        platform_exe = find_platform()
    print(f"Platform: {platform_exe}")
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)

    def run(*extra: str) -> str | None:
        return _run_designer(
            platform_exe, db_path, server_mode, db_user, db_password, *extra
        )

    result: dict = {"base_error": None, "extensions": {}}

    print(f"Exporting configuration (may take several minutes): {out_dir}")
    result["base_error"] = run("/DumpConfigToFiles", out_dir)
    if result["base_error"]:
        raise InstallError(f"DumpConfigToFiles: {result['base_error']}")

    if extensions == "all":
        # -AllExtensions выгружает только расширения (основу — нет, проверено
        # на 8.3.18). Во временный каталог: не зависим от того, чистит ли
        # DESIGNER цель, и не даём расширению затереть каталог основы.
        tmp = tempfile.mkdtemp(prefix="mcp-baf-ext-")
        try:
            print("Exporting all extensions...")
            err = run("/DumpConfigToFiles", tmp, "-AllExtensions")
            if err:
                raise InstallError(f"DumpConfigToFiles -AllExtensions: {err}")
            for name in sorted(os.listdir(tmp)):
                src = os.path.join(tmp, name)
                if not os.path.isdir(src):
                    continue  # ConfigDumpInfo.xml та службове з кореня вивантажки
                try:
                    _safe_extension_name(name)
                except InstallError as exc:
                    result["extensions"][name] = str(exc)
                    continue
                dst = os.path.join(out_dir, name)
                shutil.rmtree(dst, ignore_errors=True)
                if os.path.exists(dst):
                    # Заблокований антивірусом каталог-жертва: shutil.move
                    # інакше мовчки запхав би джерело всередину нього.
                    result["extensions"][name] = (
                        f"target directory {dst} exists and could not be removed"
                        " (locked by another process?)")
                    continue
                shutil.move(src, dst)
                result["extensions"][name] = None
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
        return result

    for name in names:
        ext_dir = os.path.join(out_dir, name)
        print(f"Exporting extension: {name} -> {ext_dir}")
        result["extensions"][name] = run(
            "/DumpConfigToFiles", ext_dir, "-Extension", name)
    return result


def _install_from(
    ext_dir: str,
    platform_exe: str,
    db_path: str,
    server_mode: bool,
    db_user: str,
    db_password: str,
    platform_version: str,
    lang: str = DEFAULT_LANG,
) -> None:
    shutil.copytree(EXTENSION_SRC, ext_dir, dirs_exist_ok=True)
    normalize_names_nfc(ext_dir)
    # Показываем источник из импортированного пакета: каталог cwd может
    # содержать другую версию, чем окружение, из которого запущен CLI.
    module_path = os.path.join(EXTENSION_SRC, "HTTPServices", "MCPService", "Ext", "Module.bsl")
    with open(module_path, encoding="utf-8-sig") as module:
        source = module.read()
    version = re.search(r'^// Версия расширения:\s*(\S+)', source, re.MULTILINE)
    print(f"Extension sources: {os.path.abspath(EXTENSION_SRC)}")
    print(f"Extension version: {version[1] if version else 'unknown'}")

    # Синонимы локализуются до остальных патчей: дальше регулярные
    # выражения работают уже с целевым языком.
    localize_extension(ext_dir, lang)

    # Версия формата XML подгоняется под целевую платформу.
    patch_format_version(ext_dir, format_version_for_platform(platform_exe))

    cfg_path = os.path.join(ext_dir, "Configuration.xml")
    major, minor = parse_platform_version(platform_exe, platform_version)

    role_note_needed = False
    if major > 0:  # версия определена
        if _older_than(major, minor, 3, 10):
            raise InstallError(
                f"платформа 8.{major}.{minor} не поддерживается, "
                "минимальная версия 8.3.10"
            )
        if _older_than(major, minor, 3, 14):
            # Предварительный патч: режим совместимости 8.3.10, удаление
            # неподдерживаемых элементов и заимствованных свойств — без
            # лишних попыток DESIGNER, которые всё равно бы упали.
            patch_extension_xml(cfg_path, "Version8_3_10", "")
            strip_unsupported_elements(ext_dir)
            strip_inherited_properties(cfg_path)
            role_note_needed = True

    def load() -> str | None:
        return _run_designer(
            platform_exe, db_path, server_mode, db_user, db_password,
            "/LoadConfigFromFiles", ext_dir, "-Extension", EXTENSION_NAME,
        )

    # Оптимистичная загрузка без предварительного удаления: команда
    # /ManageCfgExtensions -delete на некоторых платформах открывает GUI
    # и зависает, поэтому удаляем старое расширение только по ошибке
    # «Уже существует».
    print("Loading extension into database...")
    error = load()

    if error is not None and _error_contains(error, "Уже существует", "Вже існує"):
        delete_error = _run_designer(
            platform_exe, db_path, server_mode, db_user, db_password,
            "/ManageCfgExtensions", "-delete", "-Extension", EXTENSION_NAME,
        )
        if delete_error is not None:
            raise InstallError(
                f"deleting old extension before retry: {delete_error}"
            )
        print("Removed old extension:", EXTENSION_NAME)
        error = load()

    if error is not None:
        # Платформы старше 8.3.15 не знают KeepMapping/InternalInfo/ClassId
        # роли — вырезаем и повторяем. На новых платформах не применяем:
        # слово InternalInfo встречается и в легитимных ошибках формата,
        # а вырезание ContainedObject роли там только ломает Configuration.xml.
        strip_allowed = major == 0 or _older_than(major, minor, 3, 15)
        if (strip_allowed
                and ("KeepMappingToExtendedConfigurationObjectsByIDs" in error
                     or "InternalInfo" in error
                     or _error_contains(error, "идентификатор класса",
                                        "ідентифікатор класу"))):
            print("Retrying without unsupported XML elements (old platform)...")
            strip_unsupported_elements(ext_dir)
            error = load()

        # База без DefaultRunMode=ManagedApplication отвергает расширение
        # с ошибкой про «ОсновнойРежимЗапуска» — убираем свойство.
        if error is not None and _error_contains(
                error, "ОсновнойРежимЗапуска", "ОсновнийРежимЗапуску"):
            print("Retrying without DefaultRunMode property "
                  "(controlled property mismatch)...")
            _patch_file(cfg_path, lambda c: _DEFAULT_RUN_MODE_RE.sub("", c))
            error = load()

        # Режим совместимости расширения выше, чем у базы: сначала
        # Version8_3_10 (ещё поддерживает роли), затем DontUse.
        if error is not None and _error_contains(
                error, "режим совместимости", "режим сумісності"):
            print("Retrying with compatibility mode 8.3.10...")
            patch_extension_xml(cfg_path, "Version8_3_10", "")
            error = load()

            if error is not None and _error_contains(
                    error, "режим совместимости", "режим сумісності"):
                print("Retrying without compatibility mode...")
                patch_extension_xml(cfg_path, "DontUse", "")
                error = load()

        # Старые конфигурации (совместимость 8.3.13 и ниже) отвергают
        # переопределение заимствованных свойств.
        if (error is not None
                and _error_contains(
                    error,
                    "переопределение свойств заимствованных объектов",
                    "перевизначення властивостей запозичених об'єктів")):
            print("Retrying without inherited properties (old compat mode)...")
            strip_inherited_properties(cfg_path)
            error = load()
            if error is None:
                role_note_needed = True

        if error is not None:
            raise classify_designer_error(
                f"loading extension config: {error}"
            )

    # Применение расширения к базе — отдельный обязательный вызов.
    print("Updating database...")
    error = _run_designer(
        platform_exe, db_path, server_mode, db_user, db_password,
        "/UpdateDBCfg", "-Extension", EXTENSION_NAME,
    )
    if error is not None:
        if _error_contains(
                error,
                "переопределение свойств заимствованных объектов",
                "перевизначення властивостей запозичених об'єктів"):
            print("Retrying without inherited properties (old compat mode)...")
            strip_inherited_properties(cfg_path)
            reload_error = load()
            if reload_error is not None:
                raise classify_designer_error(
                    f"reloading extension config after strip: {reload_error}"
                )
            retry_error = _run_designer(
                platform_exe, db_path, server_mode, db_user, db_password,
                "/UpdateDBCfg", "-Extension", EXTENSION_NAME,
            )
            if retry_error is not None:
                raise classify_designer_error(
                    f"updating database config: {retry_error}"
                )
            print(ROLE_NOTE)
            return
        raise classify_designer_error(f"updating database config: {error}")

    if role_note_needed:
        print(ROLE_NOTE)


def classify_designer_error(message: str) -> InstallError:
    """Заменяет известные сбивающие с толку ошибки DESIGNER понятным текстом.

    Оригинальный текст сохраняется в конце, чтобы опытные пользователи
    видели детали.
    """
    if _COMPAT_MODE_NOT_FOUND_RE.search(message):
        return InstallError(
            "Установка расширения не удалась.\n\n"
            "Самая частая причина: режим совместимости конфигурации запрещает расширения.\n"
            "Проверьте: Конфигуратор -> Свойства корня -> Режим совместимости.\n"
            "Для поддержки расширений нужно «Не использовать» или «Версия 8.3.11» и новее.\n\n"
            "Другие возможные причины:\n"
            "  • Неверные --db-user / --db-password (имя из Конфигуратор -> "
            "Администрирование -> Пользователи)\n"
            "  • База открыта в Конфигураторе и заблокирована\n"
            "  • База в режиме только-чтение\n\n"
            "Оригинальная ошибка DESIGNER:\n" + message
        )
    return InstallError(message)


def _run_designer(
    platform_exe: str,
    db_path: str,
    server_mode: bool,
    db_user: str,
    db_password: str,
    *extra_args: str,
) -> str | None:
    """Запускает 1C DESIGNER, перехватывая вывод через /Out.

    Возвращает None при успехе, текст ошибки при неудаче (как error в Go).
    """
    fd, log_path = tempfile.mkstemp(prefix="mcp-baf-log-", suffix=".txt")
    os.close(fd)
    try:
        args = _build_designer_args(
            db_path, server_mode, db_user, db_password, log_path, *extra_args
        )
        try:
            result = subprocess.run([platform_exe, *args], capture_output=True)
        except OSError:
            return f"1C DESIGNER failed to start: {platform_exe}"

        try:
            with open(log_path, "rb") as f:
                log_data = f.read().lstrip(b"\xef\xbb\xbf")
        except OSError:
            log_data = b""

        # Старые платформы под Windows пишут лог в Windows-1251.
        try:
            log_str = log_data.decode("utf-8")
        except UnicodeDecodeError:
            log_str = log_data.decode("cp1251", errors="replace")
        log_str = log_str.strip()
    finally:
        try:
            os.remove(log_path)
        except OSError:
            pass

    if result.returncode != 0:
        if log_str:
            return (
                f"1C DESIGNER failed (exit code {result.returncode}):\n{log_str}"
            )
        return f"1C DESIGNER failed with exit code {result.returncode} (no log output)"

    if log_str and _designer_log_is_fatal(log_str):
        return "1C DESIGNER reported a fatal load error:\n" + log_str

    if log_str:
        print(log_str)
    return None


def _build_designer_args(
    db_path: str,
    server_mode: bool,
    db_user: str,
    db_password: str,
    log_path: str,
    *extra_args: str,
) -> list[str]:
    conn_flag = "/S" if server_mode else "/F"
    args = ["DESIGNER", conn_flag, db_path]
    if db_user:
        args += ["/N", db_user]
    if db_password:
        args += ["/P", db_password]
    args += ["/WA-", "/DisableStartupDialogs", "/DisableStartupMessages"]
    args += list(extra_args)
    args += ["/Out", log_path]
    return args


def find_platform() -> str:
    """Ищет исполняемый файл платформы BAF/1С в стандартных путях текущей ОС.

    Возвращает последний (лексикографически — самый новый) из найденных.
    """
    for pattern in _platform_patterns():
        matches = sorted(glob.glob(pattern))
        if matches:
            return matches[-1]
    raise InstallError("1C platform not found in standard paths")


def _platform_patterns() -> list[str]:
    if sys.platform == "win32":
        return [
            r"C:\Program Files\BAF\8.*\bin\1cv8.exe",
            r"C:\Program Files (x86)\BAF\8.*\bin\1cv8.exe",
            r"C:\Program Files\1cv8\8.*\bin\1cv8.exe",
            r"C:\Program Files (x86)\1cv8\8.*\bin\1cv8.exe",
            r"C:\Program Files\1cv8t\8.*\bin\1cv8t.exe",
            r"C:\Program Files (x86)\1cv8t\8.*\bin\1cv8t.exe",
            r"C:\Program Files\1cv82\8.*\bin\1cv8.exe",
            r"C:\Program Files (x86)\1cv82\8.*\bin\1cv8.exe",
        ]
    if sys.platform == "darwin":
        return [
            "/Applications/1cv8.localized/*/1cv8.app/Contents/MacOS/1cv8",
            "/Applications/1cv8t.localized/*/1cv8t.app/Contents/MacOS/1cv8t",
        ]
    return [
        "/opt/1cv8/x86_64/8.3.*/1cv8",
        "/opt/1cv8/x86_64/8.5.*/1cv8",
        "/opt/1C/v8.3/x86_64/1cv8",
    ]


def _older_than(major: int, minor: int, target_major: int, target_minor: int) -> bool:
    """Сравнение (major, minor) кортежем: 8.5.1 НЕ старше 8.3.14."""
    if major != target_major:
        return major < target_major
    return minor < target_minor


def extract_platform_minor(source: str) -> tuple[int, int]:
    """Извлекает (major, minor) из пути платформы или строки версии.

    Для "8.3.27.1859" возвращает (3, 27); (0, 0) — версия не распознана.
    """
    m = _PLATFORM_VERSION_RE.search(source)
    if m is None:
        return 0, 0
    return int(m.group(1)), int(m.group(2))


def parse_platform_version(platform_exe: str, override_version: str) -> tuple[int, int]:
    """Определяет (major, minor) платформы; переопределение в приоритете."""
    return extract_platform_minor(override_version or platform_exe)


def format_version_for_platform(platform_exe: str) -> str:
    """Лучшая версия формата XML-выгрузки для данной платформы."""
    major, minor = extract_platform_minor(platform_exe)
    if major == 0:
        return DEFAULT_FORMAT_VERSION
    if major >= 5:
        return PLATFORM_85_FORMAT_VERSION
    if major == 3:
        for min_minor, version in PLATFORM_FORMAT_VERSIONS:
            if minor >= min_minor:
                return version
    return DEFAULT_FORMAT_VERSION


def normalize_names_nfc(ext_dir: str) -> None:
    """Приводит имена файлов и каталогов временной копии к NFC.

    Исходники, побывавшие на macOS (zip с APFS, SMB-копия, wheel, собранный
    на Mac), могут нести NFD-имена: «й» хранится как «и» + диакритика.
    NTFS и 1C DESIGNER сравнивают имена побайтово, поэтому такой файл для
    DESIGNER «не существует». APFS, наоборот, нечувствительна к нормализации
    и не даёт переименовать NFD в NFC напрямую — поэтому переименование
    идёт через промежуточное имя.
    """
    for root, dirs, files in os.walk(ext_dir, topdown=False):
        for name in dirs + files:
            nfc = unicodedata.normalize("NFC", name)
            if nfc == name:
                continue
            tmp = os.path.join(root, nfc + ".nfc-tmp")
            os.rename(os.path.join(root, name), tmp)
            os.rename(tmp, os.path.join(root, nfc))


def _patch_file(path: str, transform) -> None:
    with open(path, encoding="utf-8") as f:
        content = f.read()
    patched = transform(content)
    if patched != content:
        with open(path, "w", encoding="utf-8") as f:
            f.write(patched)


def patch_format_version(ext_dir: str, target_version: str) -> None:
    """Переписывает version="2.X" во всех XML-файлах расширения."""
    for root, _dirs, files in os.walk(ext_dir):
        for name in files:
            if name.lower().endswith(".xml"):
                _patch_file(
                    os.path.join(root, name),
                    lambda c: _VERSION_ATTR_RE.sub(
                        rf"\g<1>{target_version}\g<2>", c
                    ),
                )


def localize_extension(ext_dir: str, lang: str) -> None:
    """Локализует синонимы расширения под выбранный язык.

    XML-исходники хранятся по-русски, поэтому "ru" — no-op. Для "ua"
    код языка синонимов меняется на uk, тексты переводятся по словарю.
    Перевод привязан к обёртке <v8:content>, чтобы не задеть совпадающие
    Name/Handler (например, обработчик МетаданныеGET в Module.bsl).
    """
    if lang == "ru":
        return

    def transform(content: str) -> str:
        content = content.replace(_LANG_TAG_RU, _LANG_TAG_UA)
        for ru_text, ua_text in _SYNONYM_TRANSLATIONS_UA.items():
            content = content.replace(
                f"<v8:content>{ru_text}</v8:content>",
                f"<v8:content>{ua_text}</v8:content>",
            )
        return content

    for root, _dirs, files in os.walk(ext_dir):
        for name in files:
            if name.lower().endswith(".xml"):
                _patch_file(os.path.join(root, name), transform)


def _replace_or_insert_xml_tag(content: str, tag: str, value: str) -> str:
    """Заменяет значение тега или вставляет новый тег перед </Properties>."""
    pattern = re.compile(rf"<{tag}>[^<]+</{tag}>")
    replacement = f"<{tag}>{value}</{tag}>"
    if pattern.search(content):
        return pattern.sub(replacement, content)
    return content.replace(
        "</Properties>", f"\t\t\t{replacement}\n\t\t</Properties>", 1
    )


def patch_extension_xml(path: str, compat_mode: str, interface_mode: str) -> None:
    """Обновляет режимы совместимости в Configuration.xml расширения."""
    def transform(content: str) -> str:
        if compat_mode:
            content = _replace_or_insert_xml_tag(
                content, "ConfigurationExtensionCompatibilityMode", compat_mode
            )
        if interface_mode:
            content = _replace_or_insert_xml_tag(
                content, "InterfaceCompatibilityMode", interface_mode
            )
        return content

    _patch_file(path, transform)


def strip_inherited_properties(cfg_path: str) -> None:
    """Удаляет из Configuration.xml свойства, переопределяющие заимствованные
    свойства базовой конфигурации (нужно для совместимости 8.3.13 и ниже)."""
    _patch_file(cfg_path, lambda c: _INHERITED_PROPERTY_RE.sub("", c))


def strip_unsupported_elements(ext_dir: str) -> None:
    """Удаляет элементы XML, которые не понимают платформы 8.3.10–8.3.14.

    Configuration.xml сохраняет свой InternalInfo (там маппинг UUID
    расширения), но теряет KeepMapping... и ContainedObject роли. Из
    остальных XML-файлов InternalInfo вырезается целиком.
    """
    cfg_path = os.path.join(ext_dir, "Configuration.xml")
    _patch_file(
        cfg_path,
        lambda c: _ROLE_CONTAINED_OBJECT_RE.sub("", _KEEP_MAPPING_RE.sub("", c)),
    )

    for root, _dirs, files in os.walk(ext_dir):
        for name in files:
            if not name.lower().endswith(".xml"):
                continue
            if name.lower() == "configuration.xml":
                continue
            _patch_file(
                os.path.join(root, name),
                lambda c: _INTERNAL_INFO_RE.sub("", c),
            )
