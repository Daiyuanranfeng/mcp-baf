"""Точка входа: mcp-baf --base <url> --user <user> --pass <password>."""

from __future__ import annotations

import hmac
import logging
import logging.handlers
import os
import sys

from mcp_baf_audit import default_cache_dir
from mcp_baf.config import Config, ConfigError, load_config, parse_args

SERVER_LOG_NAME = "server.log"
SERVER_LOG_MAX_BYTES = 5 * (1 << 20)
SERVER_LOG_BACKUPS = 3


def _setup_logging(debug: bool, cache_dir: str) -> None:
    """Настраивает логирование.

    MCP-клиенты показывают каждую строку stderr как [error], поэтому туда
    попадает только ERROR и выше. Операционный журнал всегда пишется в
    server.log в кэш-каталоге (ротация по размеру, журнал переживает
    рестарты) на уровне INFO; --debug поднимает уровень до DEBUG и
    включает подробности httpx. Бизнес-аудит ведётся отдельно в audit.log
    через mcp-baf-audit.
    """
    root = logging.getLogger()
    root.setLevel(logging.DEBUG if debug else logging.INFO)

    stderr_handler = logging.StreamHandler(sys.stderr)
    stderr_handler.setLevel(logging.ERROR)
    stderr_handler.setFormatter(
        logging.Formatter("%(levelname)s %(name)s %(message)s")
    )
    root.addHandler(stderr_handler)

    if not debug:
        # httpx дублирует наши строки клиента — оставляем только WARNING.
        for noisy in ("httpx", "httpcore", "httpx2", "httpcore2"):
            logging.getLogger(noisy).setLevel(logging.WARNING)

    log_dir = cache_dir or default_cache_dir("mcp-baf")
    try:
        os.makedirs(log_dir, exist_ok=True)
        file_handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, SERVER_LOG_NAME),
            maxBytes=SERVER_LOG_MAX_BYTES,
            backupCount=SERVER_LOG_BACKUPS,
            encoding="utf-8",
        )
    except OSError:
        return  # не удалось создать лог-файл — остаёмся на ERROR-only stderr
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s")
    )
    root.addHandler(file_handler)


def _parse_dump_extensions(raw: str | None) -> "list[str] | str | None":
    """--dump-extensions: не задан — None (только основная конфигурация);
    без значения или «all» — "all"; иначе — проверенный список имён.

    Вызывается до установки, чтобы опечатка в именах не стоила полной установки.
    """
    if raw is None:
        return None
    if raw.strip().lower() == "all":
        return "all"
    from mcp_baf import installer

    names = [installer._safe_extension_name(s) for s in raw.split(",") if s.strip()]
    if not names:
        raise installer.InstallError("--dump-extensions: порожній список розширень")
    return names


def _run_dump(args, extensions: "list[str] | str | None") -> None:
    """Экспорт конфигурации после установки (mcp-baf --install ... --dump DIR)."""
    from mcp_baf import installer

    try:
        summary = installer.dump(
            db_path=args.install,
            out_dir=args.dump,
            extensions=extensions,
            server_mode=args.server,
            platform_exe=args.platform,
            db_user=args.db_user,
            db_password=args.db_password,
            platform_version=args.platform_version,
        )
    except installer.InstallError as exc:
        print(f"Dump error: {exc}", file=sys.stderr)
        sys.exit(1)
    failed = sorted(n for n, err in summary["extensions"].items() if err)
    if failed:
        print(f"Export completed with failed extensions: {', '.join(failed)}",
              file=sys.stderr)
        sys.exit(1)
    print(f"Configuration exported to {args.dump}")


def main() -> None:
    args = parse_args()
    try:
        config = load_config(args)
    except ConfigError as exc:
        print(f"Configuration error: {exc}", file=sys.stderr)
        sys.exit(1)
    _setup_logging(config.debug, config.cache_dir)

    if args.dump_extensions is not None and not (args.install and args.dump):
        print("--dump-extensions requires --install and --dump", file=sys.stderr)
        sys.exit(1)

    # Режим установки расширения.
    if args.install:
        from mcp_baf import installer

        # При перенаправлении вывода Windows даёт stdout в cp1252: кириллица
        # (имена расширений, пути, лог DESIGNER) иначе роняет уже после установки.
        sys.stdout.reconfigure(errors="backslashreplace")
        sys.stderr.reconfigure(errors="backslashreplace")
        try:
            dump_extensions = _parse_dump_extensions(args.dump_extensions)
        except installer.InstallError as exc:
            print(f"Dump error: {exc}", file=sys.stderr)
            sys.exit(1)
        print("Installing MCP extension into 1C database...")
        try:
            installer.install(
                db_path=args.install,
                server_mode=args.server,
                platform_exe=args.platform,
                db_user=args.db_user,
                db_password=args.db_password,
                platform_version=args.platform_version,
                lang=args.lang,
            )
        except installer.InstallError as exc:
            print(f"Installation error: {exc}", file=sys.stderr)
            sys.exit(1)
        print("Extension installed successfully.")
        if args.dump:
            _run_dump(args, dump_extensions)
        return

    # Установка расширения, --help и --version не зависят от API MCP SDK.
    from mcp_baf.server import create_server

    server = create_server(config)
    if config.transport == "stdio":
        server.run(transport="stdio")
    else:
        tls = _resolve_tls(config) if config.transport == "https" else None
        _run_http(server, config, tls)


class _BearerAuthASGI:
    """ASGI-слой перед streamable-http: статический bearer-токен на каждый запрос."""

    def __init__(self, app, token: str) -> None:
        self._app = app
        self._expected = f"Bearer {token}".encode()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self._app(scope, receive, send)
            return
        values = [v for n, v in scope.get("headers") or [] if n == b"authorization"]
        # Несколько Authorization не принимаем: неясно, какому доверять.
        if len(values) != 1 or not hmac.compare_digest(values[0], self._expected):
            await send({
                "type": "http.response.start",
                "status": 401,
                "headers": [(b"content-type", b"text/plain; charset=utf-8"),
                            (b"www-authenticate", b"Bearer")],
            })
            await send({"type": "http.response.body", "body": b"unauthorized"})
            return
        # SDK сверяет владельца MCP-сессии через scope["user"]
        # (GHSA-jpw9-pfvf-9f58); без него проверка не срабатывает.
        from mcp.server.auth.middleware.bearer_auth import AuthenticatedUser
        from mcp.server.auth.provider import AccessToken

        scope["user"] = AuthenticatedUser(
            AccessToken(token=values[0].decode("latin-1"), client_id="mcp-baf", scopes=[])
        )
        await self._app(scope, receive, send)


def _resolve_tls(config: Config) -> tuple[str, str]:
    """(cert, key) для https: явные файлы или самоподписанный CA в <cache_dir>/tls/."""
    if config.tls_cert:
        return config.tls_cert, config.tls_key
    from mcp_baf.tls import ensure_self_signed, self_signed_hosts

    directory = os.path.join(config.cache_dir or default_cache_dir("mcp-baf"), "tls")
    hosts = self_signed_hosts(
        config.http_host,
        *(h.rsplit(":", 1)[0] for h in config.http_allowed_hosts.split(",")),
    )
    ca, cert, key = ensure_self_signed(directory, hosts)
    logging.getLogger(__name__).warning(
        "https: собственный сертификат не задан — самоподписанный CA %s", ca
    )
    return cert, key


def _host_pattern(host: str) -> str:
    """Шаблон Host для DNS-rebinding: без порту додає :*, явний порт зберігає.

    SDK порівнює Host точно або за шаблоном ``host:*``, тому запис без порту
    ніколи не збігається з реальним ``host:port``. IPv6 беремо в дужки.
    """
    if host.startswith("["):
        return host if "]:" in host else f"{host}:*"
    if host.count(":") >= 2:
        return f"[{host}]:*"
    return host if ":" in host else f"{host}:*"


def _http_security(allowed_hosts: str, scheme: str):
    """Захист від DNS-rebinding: пусто — виключений (server-to-server за іменем сервісу)."""
    from mcp.server.transport_security import TransportSecuritySettings

    hosts = [_host_pattern(h.strip()) for h in allowed_hosts.split(",") if h.strip()]
    if not hosts:
        return TransportSecuritySettings(enable_dns_rebinding_protection=False)
    return TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=[f"{scheme}://{h}" for h in hosts],
    )


def _run_http(server, config: Config, tls: tuple[str, str] | None) -> None:
    """streamable-http (uvicorn) за bearer-слоем; TLS, если передан tls."""
    import anyio
    import uvicorn

    app = _BearerAuthASGI(
        server.streamable_http_app(
            host=config.http_host,
            transport_security=_http_security(
                config.http_allowed_hosts, "https" if tls else "http"
            ),
        ),
        config.http_token,
    )

    async def serve() -> None:
        await uvicorn.Server(uvicorn.Config(
            app,
            host=config.http_host,
            port=config.http_port,
            log_level="info",
            ssl_certfile=tls[0] if tls else None,
            ssl_keyfile=tls[1] if tls else None,
        )).serve()

    anyio.run(serve)


if __name__ == "__main__":
    main()
