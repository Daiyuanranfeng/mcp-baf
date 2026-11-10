"""Конфигурация MCP-сервера.

Приоритет источников (от низшего к высшему): значения по умолчанию,
переменные окружения, флаги командной строки.
"""

from __future__ import annotations

import argparse
import os
import sys
from dataclasses import dataclass
from urllib.parse import urlsplit

from mcp_baf_audit import (
    DEFAULT_AUDIT_ARCHIVES,
    DEFAULT_AUDIT_MAX_SIZE_MIB,
)

DEFAULT_BASE_URL = "http://localhost:8080/hs/mcp-baf"

TRANSPORTS = ("stdio", "https", "http")
DEFAULT_HTTP_HOST = "127.0.0.1"
DEFAULT_HTTP_PORT = 8001

# Лимит размера ответа 1С по умолчанию, в мебибайтах (MiB).
# 128 MiB покрывает крупные базы с расширениями, оставаясь потолком против OOM.
DEFAULT_MAX_RESPONSE_SIZE_MIB = 128

# Таймаут HTTP-запроса к 1С по умолчанию, в секундах. Запас нужен
# для передачи крупных ответов /extensions (сотни мегабайт).
DEFAULT_REQUEST_TIMEOUT = 300

# Таймауты httpx по фазам. connect короткий: недоступный хост/порт должен
# падать за секунды, а не висеть 300 с. read совпадает с request_timeout.
DEFAULT_CONNECT_TIMEOUT = 10
DEFAULT_WRITE_TIMEOUT = 60
DEFAULT_POOL_TIMEOUT = 10

# Повторы идемпотентных запросов на транзиентные ошибки (транспорт/5xx).
# retry_attempts — число повторов ПОСЛЕ первой попытки; 0 отключает повторы.
DEFAULT_RETRY_ATTEMPTS = 2
# База экспоненциального backoff, секунды: 0.5, 1.0, 2.0 ...
DEFAULT_RETRY_BACKOFF = 0.5


@dataclass
class Config:
    base_url: str = DEFAULT_BASE_URL
    user: str = ""
    password: str = ""
    max_response_size_mib: int = DEFAULT_MAX_RESPONSE_SIZE_MIB
    # Таймаут чтения ответа 1С (фаза read у httpx), секунды.
    request_timeout: int = DEFAULT_REQUEST_TIMEOUT
    # Остальные фазы httpx: установка соединения, отправка тела, ожидание
    # свободного слота в пуле. connect намеренно короткий.
    connect_timeout: int = DEFAULT_CONNECT_TIMEOUT
    write_timeout: int = DEFAULT_WRITE_TIMEOUT
    pool_timeout: int = DEFAULT_POOL_TIMEOUT
    # Повторы идемпотентных запросов: число повторов после первой попытки
    # (0 — выключено) и база экспоненциального backoff в секундах.
    retry_attempts: int = DEFAULT_RETRY_ATTEMPTS
    retry_backoff: float = DEFAULT_RETRY_BACKOFF
    # Разрешить повторы и для неидемпотентных запросов (записи).
    retry_non_idempotent: bool = False
    # Путь к выгрузке конфигурации (DumpConfigToFiles); включает search_code.
    dump_dir: str = ""
    help_dir: str = ""
    # Каталог кэша индекса и логов (по умолчанию платформенный кэш).
    cache_dir: str = ""
    # Принудительная пересборка кэша индекса.
    reindex: bool = False
    # Подробное логирование в файл server.log в кэш-каталоге.
    debug: bool = False
    # Управление прогрессом на stderr: True => выводить (терминальный запуск).
    show_progress: bool = False
    # Ротация audit.log: лимит размера (MiB) и число хранимых архивов.
    audit_max_size_mib: int = DEFAULT_AUDIT_MAX_SIZE_MIB
    audit_archives: int = DEFAULT_AUDIT_ARCHIVES
    # Транспорт MCP: stdio (по умолчанию), https (streamable-http за TLS) или
    # http — без TLS, только вместе с allow_insecure_http (двойной opt-in).
    transport: str = "stdio"
    allow_insecure_http: bool = False
    http_host: str = DEFAULT_HTTP_HOST
    http_port: int = DEFAULT_HTTP_PORT
    # Разрешённые Host через запятую; пусто — набор по умолчанию
    # (localhost, 127.0.0.1, [::1], bind-хост, hostname). Защита от
    # DNS-rebinding включена всегда, пока её явно не выключат.
    http_allowed_hosts: str = ""
    # Выключатель защиты от DNS-rebinding (только для отладки/сервер-сервер).
    dns_rebinding_protection: bool = True
    # Bearer-токен, обязателен для https/http: без него чтение базы открыто сети.
    http_token: str = ""
    # Свои cert/key для https; пусто — самоподписанный CA в <cache_dir>/tls/.
    tls_cert: str = ""
    tls_key: str = ""
    # Маскирование ПДн (ФИО, ИНН, телефоны, email...) в ответах инструментов:
    # execute_query, журнал регистрации, структура формы, найденный код.
    mask_pii: bool = False


class ConfigError(Exception):
    """Некорректная конфигурация запуска (сообщение показывается пользователю)."""


def _env_int(name: str, default: int) -> int:
    """Читает целое из переменной окружения.

    Некорректные или неположительные значения игнорируются —
    остаётся значение по умолчанию.
    """
    value = os.environ.get(name, "")
    try:
        n = int(value)
    except ValueError:
        return default
    return n if n > 0 else default


def _env_int_nonneg(name: str, default: int) -> int:
    """Как _env_int, но 0 — допустимое значение (выключатель повторов)."""
    value = os.environ.get(name, "").strip()
    try:
        n = int(value)
    except ValueError:
        return default
    return n if n >= 0 else default


def _env_float(name: str, default: float) -> float:
    """Читает неотрицательное число из переменной окружения."""
    value = os.environ.get(name, "").strip()
    try:
        n = float(value)
    except ValueError:
        return default
    return n if n >= 0 else default


_TRUE = ("1", "true", "yes", "on")


def _env_bool(name: str, default: bool = False) -> bool:
    """Читает булев флаг из переменной окружения (1/true/yes/on)."""
    value = os.environ.get(name)
    if value is None or not value.strip():
        return default
    return value.strip().lower() in _TRUE


def _env_secret(name: str) -> str:
    """Читает секрет из NAME или из файла NAME_FILE (Docker secrets).

    Из файла срезаются только хвостовые \\r\\n. Одновременное задание обоих
    вариантов и нечитаемый файл — ошибка запуска; текст ошибки называет
    переменную и путь, но не содержимое.
    """
    value = os.environ.get(name, "")
    path = os.environ.get(f"{name}_FILE", "")
    if not path:
        return value
    if value:
        raise ConfigError(f"задайте лише одне з {name} / {name}_FILE")
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().rstrip("\r\n")
    except (OSError, UnicodeDecodeError) as exc:
        # str(exc) у UnicodeDecodeError містить байти файлу — беремо лише тип.
        raise ConfigError(
            f"{name}_FILE: не вдалося прочитати файл {path} ({type(exc).__name__})"
        ) from None


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="mcp-baf",
        description="MCP server for 1C:Enterprise HTTP service",
    )
    parser.add_argument("--base", default="", help="Base URL of 1C HTTP service")
    parser.add_argument("--user", default="", help="1C HTTP service user")
    parser.add_argument("--help-dir", default="", help="Directory with platform .hbk help files")
    parser.add_argument(
        "--pass", "--password", dest="password", default="",
        help="1C HTTP service password (env mcp_baf_PASSWORD / "
             "mcp_baf_PASSWORD_FILE is preferred: CLI flags are visible in ps).",
    )
    parser.add_argument(
        "--dump", default="",
        help="Path to DumpConfigToFiles output (enables search_code). "
             "With --install: also export the database (and extensions via "
             "--dump-extensions) to this directory after installing.",
    )
    parser.add_argument(
        "--dump-extensions", default=None, metavar="all|NAME[,...]", nargs="?",
        const="all",
        help="With --install --dump: also export extensions into <dump>/<name>/ "
             "subdirectories - flag alone or 'all' for every extension, or a "
             "comma-separated list of names; omitted - main configuration only",
    )
    parser.add_argument(
        "--cache-dir", default="",
        help="Directory for index cache and logs (default: platform cache dir)",
    )
    parser.add_argument(
        "--reindex", action="store_true",
        help="Force rebuild of search index cache",
    )
    parser.add_argument(
        "--debug", action="store_true",
        help="Enable verbose logging to file (server.log in cache dir). "
             "Also suppresses the stderr progress indicator.",
    )
    parser.add_argument(
        "--quiet", action="store_true",
        help="Suppress all stderr progress output even in a terminal. "
             "Takes precedence over --verbose. Also activated by mcp_baf_NO_TTY=1.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Force progress output to stderr even when stdin is a pipe "
             "(useful for MCP client debugging). Overridden by --quiet.",
    )
    # Режим установки расширения.
    parser.add_argument(
        "--install", default="", metavar="DB_PATH",
        help="Install extension into 1C database at given path",
    )
    parser.add_argument(
        "--lang", default="ua", choices=("ua", "ru"),
        help="Language of extension synonyms for --install: "
             "ua (Ukrainian, default) or ru (Russian)",
    )
    parser.add_argument(
        "--server", action="store_true",
        help=r"Treat --install value as server connection string (server\database)",
    )
    parser.add_argument(
        "--platform", default="",
        help="Path to 1C platform executable (auto-detected if omitted)",
    )
    parser.add_argument(
        "--platform-version", default="",
        help="1C platform version override (e.g. 8.3.13), "
             "auto-detected from path if omitted",
    )
    parser.add_argument(
        "--db-user", default="",
        help="1C database user for DESIGNER (install mode)",
    )
    parser.add_argument(
        "--db-password", default="",
        help="1C database password for DESIGNER (install mode). Prefer env "
             "mcp_baf_DB_PASSWORD or mcp_baf_DB_PASSWORD_FILE: a CLI password "
             "is visible in ps and shell history.",
    )
    parser.add_argument(
        "--max-response-size", type=int, default=0, metavar="MIB",
        help="Maximum size of a 1C HTTP response, in mebibytes (MiB). "
             f"Default: {DEFAULT_MAX_RESPONSE_SIZE_MIB}.",
    )
    parser.add_argument(
        "--request-timeout", type=int, default=0, metavar="SECONDS",
        help="Read timeout for an HTTP response from 1C, in seconds. "
             f"Default: {DEFAULT_REQUEST_TIMEOUT}.",
    )
    parser.add_argument(
        "--connect-timeout", type=int, default=0, metavar="SECONDS",
        help="Connect timeout to 1C (env mcp_baf_CONNECT_TIMEOUT). "
             f"Default: {DEFAULT_CONNECT_TIMEOUT}.",
    )
    parser.add_argument(
        "--write-timeout", type=int, default=0, metavar="SECONDS",
        help="Write timeout when sending a request to 1C (env mcp_baf_WRITE_TIMEOUT). "
             f"Default: {DEFAULT_WRITE_TIMEOUT}.",
    )
    parser.add_argument(
        "--pool-timeout", type=int, default=0, metavar="SECONDS",
        help="Pool timeout waiting for a free connection (env mcp_baf_POOL_TIMEOUT). "
             f"Default: {DEFAULT_POOL_TIMEOUT}.",
    )
    parser.add_argument(
        "--retry-attempts", type=int, default=None, metavar="N",
        help="Retries after the first attempt for idempotent requests on "
             "transport errors/5xx (env mcp_baf_RETRY_ATTEMPTS; 0 disables). "
             f"Default: {DEFAULT_RETRY_ATTEMPTS}.",
    )
    parser.add_argument(
        "--retry-backoff", type=float, default=None, metavar="SECONDS",
        help="Base of the exponential retry backoff (env mcp_baf_RETRY_BACKOFF). "
             f"Default: {DEFAULT_RETRY_BACKOFF}.",
    )
    parser.add_argument(
        "--retry-non-idempotent", action="store_true",
        help="Also retry non-idempotent (write) requests "
             "(env mcp_baf_RETRY_NON_IDEMPOTENT=1).",
    )
    parser.add_argument(
        "--audit-max-size", type=int, default=0, metavar="MIB",
        help="Rotate audit.log when it exceeds this size, in MiB. "
             f"Default: {DEFAULT_AUDIT_MAX_SIZE_MIB}.",
    )
    parser.add_argument(
        "--audit-archives", type=int, default=0, metavar="N",
        help="Number of rotated audit-*.log archives to keep. "
             f"Default: {DEFAULT_AUDIT_ARCHIVES}.",
    )
    parser.add_argument(
        "--transport", default="", choices=TRANSPORTS,
        help="MCP transport: stdio (default), https (streamable-http over TLS) "
             "or http (no TLS; also requires --allow-insecure-http)",
    )
    parser.add_argument(
        "--mask-pii", action="store_true",
        help="Mask personal data in tool output: execute_query results, event log, "
             "form structure and found code (env mcp_baf_MASK_PII=1).",
    )
    parser.add_argument(
        "--allow-insecure-http", action="store_true",
        help="Permit --transport http without TLS (env mcp_baf_ALLOW_INSECURE_HTTP=1).",
    )
    parser.add_argument(
        "--http-host", default="", metavar="HOST",
        help=f"Bind host for --transport http(s). Default: {DEFAULT_HTTP_HOST}.",
    )
    parser.add_argument(
        "--http-port", type=int, default=0, metavar="PORT",
        help=f"Bind port for --transport http(s). Default: {DEFAULT_HTTP_PORT}.",
    )
    parser.add_argument(
        "--http-allowed-hosts", default="", metavar="HOSTS",
        help="Comma-separated allowed Host headers for --transport http(s). "
             "Empty uses the built-in set (localhost, 127.0.0.1, [::1], bind host, "
             "hostname) and keeps DNS-rebinding protection on.",
    )
    parser.add_argument(
        "--disable-dns-rebinding", action="store_true",
        help="Turn off Host/Origin validation for --transport http(s) "
             "(env mcp_baf_HTTP_DISABLE_DNS_REBINDING=1). Not recommended.",
    )
    parser.add_argument(
        "--http-token", default="", metavar="TOKEN",
        help="Bearer token required on every request for --transport http(s) "
             "(env mcp_baf_HTTP_TOKEN is preferred: CLI flags are visible in ps).",
    )
    parser.add_argument(
        "--tls-cert", default="", metavar="PATH",
        help="PEM certificate (chain) for --transport https. Empty with "
             "--tls-key also empty: generate a local CA in <cache-dir>/tls/.",
    )
    parser.add_argument(
        "--tls-key", default="", metavar="PATH",
        help="PEM private key for --transport https.",
    )
    parser.add_argument(
        "--version", action="version", version=f"mcp-baf {_version()}",
    )
    return parser.parse_args(argv)


def _version() -> str:
    from mcp_baf import __version__

    return __version__


def load_config(args: argparse.Namespace) -> Config:
    """Собирает конфигурацию: defaults -> env -> CLI-флаги."""
    cfg = Config(
        base_url=os.environ.get("mcp_baf_BASE_URL", DEFAULT_BASE_URL),
        user=os.environ.get("mcp_baf_USER", ""),
        password=_env_secret("mcp_baf_PASSWORD"),
        max_response_size_mib=_env_int(
            "mcp_baf_MAX_RESPONSE_SIZE", DEFAULT_MAX_RESPONSE_SIZE_MIB
        ),
        request_timeout=_env_int("mcp_baf_REQUEST_TIMEOUT", DEFAULT_REQUEST_TIMEOUT),
        connect_timeout=_env_int("mcp_baf_CONNECT_TIMEOUT", DEFAULT_CONNECT_TIMEOUT),
        write_timeout=_env_int("mcp_baf_WRITE_TIMEOUT", DEFAULT_WRITE_TIMEOUT),
        pool_timeout=_env_int("mcp_baf_POOL_TIMEOUT", DEFAULT_POOL_TIMEOUT),
        retry_attempts=_env_int_nonneg("mcp_baf_RETRY_ATTEMPTS", DEFAULT_RETRY_ATTEMPTS),
        retry_backoff=_env_float("mcp_baf_RETRY_BACKOFF", DEFAULT_RETRY_BACKOFF),
        retry_non_idempotent=_env_bool("mcp_baf_RETRY_NON_IDEMPOTENT"),
        dump_dir=os.environ.get("mcp_baf_DUMP_DIR", ""),
        help_dir=os.environ.get("mcp_baf_HELP_DIR", ""),
        audit_max_size_mib=_env_int(
            "mcp_baf_AUDIT_MAX_SIZE", DEFAULT_AUDIT_MAX_SIZE_MIB
        ),
        audit_archives=_env_int("mcp_baf_AUDIT_ARCHIVES", DEFAULT_AUDIT_ARCHIVES),
        transport=os.environ.get("mcp_baf_TRANSPORT", "") or "stdio",
        allow_insecure_http=_env_bool("mcp_baf_ALLOW_INSECURE_HTTP"),
        mask_pii=_env_bool("mcp_baf_MASK_PII"),
        http_host=os.environ.get("mcp_baf_HTTP_HOST", "") or DEFAULT_HTTP_HOST,
        http_port=_env_int("mcp_baf_HTTP_PORT", DEFAULT_HTTP_PORT),
        http_allowed_hosts=os.environ.get("mcp_baf_HTTP_ALLOWED_HOSTS", ""),
        dns_rebinding_protection=not _env_bool("mcp_baf_HTTP_DISABLE_DNS_REBINDING"),
        http_token=_env_secret("mcp_baf_HTTP_TOKEN"),
        tls_cert=os.environ.get("mcp_baf_TLS_CERT", ""),
        tls_key=os.environ.get("mcp_baf_TLS_KEY", ""),
    )

    if args.base:
        cfg.base_url = args.base
    # Креды в URL утекли бы в аудит server_start и в debug-логи httpx.
    if urlsplit(cfg.base_url).username is not None:
        raise ConfigError("не вказуйте логін/пароль у --base: використовуйте --user / --password")
    if args.user:
        cfg.user = args.user
    if args.password:
        cfg.password = args.password
    if args.dump:
        cfg.dump_dir = args.dump
    cfg.help_dir = args.help_dir or cfg.help_dir
    if args.max_response_size > 0:
        cfg.max_response_size_mib = args.max_response_size
    if args.request_timeout > 0:
        cfg.request_timeout = args.request_timeout
    if args.connect_timeout > 0:
        cfg.connect_timeout = args.connect_timeout
    if args.write_timeout > 0:
        cfg.write_timeout = args.write_timeout
    if args.pool_timeout > 0:
        cfg.pool_timeout = args.pool_timeout
    if args.retry_attempts is not None:
        cfg.retry_attempts = max(0, args.retry_attempts)
    if args.retry_backoff is not None:
        cfg.retry_backoff = max(0.0, args.retry_backoff)
    cfg.retry_non_idempotent = args.retry_non_idempotent or cfg.retry_non_idempotent
    if args.audit_max_size > 0:
        cfg.audit_max_size_mib = args.audit_max_size
    if args.audit_archives > 0:
        cfg.audit_archives = args.audit_archives

    cfg.transport = args.transport or cfg.transport
    cfg.allow_insecure_http = args.allow_insecure_http or cfg.allow_insecure_http
    cfg.mask_pii = args.mask_pii or cfg.mask_pii
    cfg.http_host = args.http_host or cfg.http_host
    if args.http_port > 0:
        cfg.http_port = args.http_port
    cfg.http_allowed_hosts = args.http_allowed_hosts or cfg.http_allowed_hosts
    if args.disable_dns_rebinding:
        cfg.dns_rebinding_protection = False
    cfg.http_token = args.http_token or cfg.http_token
    cfg.tls_cert = args.tls_cert or cfg.tls_cert
    cfg.tls_key = args.tls_key or cfg.tls_key
    _check_transport(cfg)

    cfg.cache_dir = args.cache_dir or os.environ.get("mcp_baf_CACHE_DIR", "")
    cfg.reindex = args.reindex
    cfg.debug = args.debug

    # Эффективный TTY-режим: показывать прогресс при терминальном запуске.
    # --verbose форсирует вывод, --quiet и mcp_baf_NO_TTY=1 подавляют,
    # --debug уводит всё в файл вместо stderr.
    show = sys.stdin.isatty()
    if args.verbose:
        show = True
    if args.quiet or os.environ.get("mcp_baf_NO_TTY") == "1":
        show = False
    cfg.show_progress = show and not args.debug

    return cfg


def _check_transport(cfg: Config) -> None:
    """Сетевой транспорт: только с токеном, plain http — только с явным opt-in."""
    if cfg.transport not in TRANSPORTS:
        raise ConfigError(f"mcp_baf_TRANSPORT: unknown transport '{cfg.transport}'")
    if cfg.transport == "stdio":
        return
    if cfg.transport == "http" and not cfg.allow_insecure_http:
        raise ConfigError(
            "plain http transport is disabled: use --transport https, or opt in "
            "explicitly with --allow-insecure-http / mcp_baf_ALLOW_INSECURE_HTTP=1"
        )
    if not cfg.http_token:
        raise ConfigError(
            f"--transport {cfg.transport} requires a bearer token: set mcp_baf_HTTP_TOKEN "
            "(or --http-token); without it the 1C base is readable by anyone on the network"
        )
    if not cfg.http_token.isascii():
        raise ConfigError("HTTP-токен должен содержать только ASCII-символы")
    if bool(cfg.tls_cert) != bool(cfg.tls_key):
        raise ConfigError("set both mcp_baf_TLS_CERT and mcp_baf_TLS_KEY, or neither")
