"""Тесты конфигурации: приоритет defaults -> env -> CLI."""

import os

from mcp_baf_audit import DEFAULT_AUDIT_ARCHIVES, DEFAULT_AUDIT_MAX_SIZE_MIB

import pytest

from mcp_baf.config import ConfigError, load_config, parse_args


def test_audit_defaults():
    cfg = load_config(parse_args([]))
    assert cfg.audit_max_size_mib == DEFAULT_AUDIT_MAX_SIZE_MIB
    assert cfg.audit_archives == DEFAULT_AUDIT_ARCHIVES


def test_audit_env_overrides_defaults(monkeypatch):
    monkeypatch.setenv("mcp_baf_AUDIT_MAX_SIZE", "5")
    monkeypatch.setenv("mcp_baf_AUDIT_ARCHIVES", "7")
    cfg = load_config(parse_args([]))
    assert cfg.audit_max_size_mib == 5
    assert cfg.audit_archives == 7


def test_audit_cli_overrides_env(monkeypatch):
    monkeypatch.setenv("mcp_baf_AUDIT_MAX_SIZE", "5")
    cfg = load_config(parse_args(["--audit-max-size", "11", "--audit-archives", "3"]))
    assert cfg.audit_max_size_mib == 11
    assert cfg.audit_archives == 3


def test_http_token_must_be_ascii():
    argv = ["--transport", "https", "--http-token", "токен"]
    with pytest.raises(ConfigError, match="ASCII"):
        load_config(parse_args(argv))


def test_audit_invalid_env_falls_back_to_default(monkeypatch):
    monkeypatch.setenv("mcp_baf_AUDIT_MAX_SIZE", "not-a-number")
    cfg = load_config(parse_args([]))
    assert cfg.audit_max_size_mib == DEFAULT_AUDIT_MAX_SIZE_MIB


def test_dump_dir_default_empty(monkeypatch):
    monkeypatch.delenv("mcp_baf_DUMP_DIR", raising=False)
    cfg = load_config(parse_args([]))
    assert cfg.dump_dir == ""


def test_dump_dir_from_env(monkeypatch):
    monkeypatch.setenv("mcp_baf_DUMP_DIR", "/dumps/from-env")
    cfg = load_config(parse_args([]))
    assert cfg.dump_dir == "/dumps/from-env"


def test_dump_dir_cli_overrides_env(monkeypatch):
    monkeypatch.setenv("mcp_baf_DUMP_DIR", "/dumps/from-env")
    cfg = load_config(parse_args(["--dump", "/dumps/from-cli"]))
    assert cfg.dump_dir == "/dumps/from-cli"


def test_local_features_cli_overrides_env(monkeypatch):
    monkeypatch.setenv("mcp_baf_HELP_DIR", "/help/env")
    env = load_config(parse_args([]))
    assert env.help_dir == "/help/env"
    cli = load_config(parse_args(["--help-dir", "/help/cli"]))
    assert cli.help_dir == "/help/cli"


def test_password_file_strips_trailing_newline_only(monkeypatch, tmp_path):
    secret = tmp_path / "pw"
    secret.write_bytes(" p@ss \r\n".encode())
    monkeypatch.delenv("mcp_baf_PASSWORD", raising=False)
    monkeypatch.setenv("mcp_baf_PASSWORD_FILE", str(secret))
    assert load_config(parse_args([])).password == " p@ss "


def test_password_plain_env_and_empty_file_var(monkeypatch):
    monkeypatch.setenv("mcp_baf_PASSWORD", "plain")
    monkeypatch.setenv("mcp_baf_PASSWORD_FILE", "")
    assert load_config(parse_args([])).password == "plain"


def test_password_and_file_together_is_error(monkeypatch, tmp_path):
    secret = tmp_path / "pw"
    secret.write_text("x")
    monkeypatch.setenv("mcp_baf_PASSWORD", "plain")
    monkeypatch.setenv("mcp_baf_PASSWORD_FILE", str(secret))
    with pytest.raises(ConfigError, match="лише одне з mcp_baf_PASSWORD / mcp_baf_PASSWORD_FILE"):
        load_config(parse_args([]))


def test_password_missing_file_error_names_variable_and_path(monkeypatch, tmp_path):
    monkeypatch.delenv("mcp_baf_PASSWORD", raising=False)
    monkeypatch.setenv("mcp_baf_PASSWORD_FILE", str(tmp_path / "nope"))
    with pytest.raises(ConfigError, match="mcp_baf_PASSWORD_FILE.*nope"):
        load_config(parse_args([]))


def test_base_url_with_credentials_rejected():
    with pytest.raises(ConfigError, match="--user"):
        load_config(parse_args(["--base", "http://u:secret@host/hs/mcp-baf"]))


def test_dump_extensions_flag_forms():
    a = parse_args(["--install", "db", "--dump", "/x"])
    assert a.dump == "/x"
    assert a.dump_extensions is None
    a = parse_args(["--install", "db", "--dump", "/x", "--dump-extensions"])
    assert a.dump_extensions == "all"
    a = parse_args(["--install", "db", "--dump", "/x", "--dump-extensions", "A,B"])
    assert a.dump_extensions == "A,B"


def test_password_flags_help_warns_about_ps(capsys):
    with pytest.raises(SystemExit):
        parse_args(["--help"])
    out = capsys.readouterr().out
    # пароль сервиса и пароль базы: оба флага видны в ps — предупреждаем
    assert "--pass" in out and "visible in ps" in out
    assert "--db-password" in out and "mcp_baf_DB_PASSWORD_FILE" in out


# ── Таймаути httpx по фазах і політика повторів ──


@pytest.fixture
def clean_env(monkeypatch):
    """Изолирует тест от mcp_baf_* переменных окружения хоста."""
    for name in list(os.environ):
        if name.startswith("mcp_baf_"):
            monkeypatch.delenv(name, raising=False)
    return monkeypatch


def test_timeout_defaults_are_split_by_phase(clean_env):
    cfg = load_config(parse_args([]))
    assert cfg.request_timeout == 300  # read
    assert cfg.connect_timeout == 10   # connect короткий
    assert cfg.write_timeout == 60
    assert cfg.pool_timeout == 10


def test_phase_timeouts_from_env(clean_env):
    clean_env.setenv("mcp_baf_CONNECT_TIMEOUT", "3")
    clean_env.setenv("mcp_baf_WRITE_TIMEOUT", "45")
    clean_env.setenv("mcp_baf_POOL_TIMEOUT", "4")
    cfg = load_config(parse_args([]))
    assert (cfg.connect_timeout, cfg.write_timeout, cfg.pool_timeout) == (3, 45, 4)


def test_phase_timeouts_cli_overrides_env(clean_env):
    clean_env.setenv("mcp_baf_CONNECT_TIMEOUT", "3")
    cfg = load_config(parse_args(["--connect-timeout", "12", "--write-timeout", "30",
                                  "--pool-timeout", "8"]))
    assert (cfg.connect_timeout, cfg.write_timeout, cfg.pool_timeout) == (12, 30, 8)


def test_retry_defaults(clean_env):
    cfg = load_config(parse_args([]))
    assert cfg.retry_attempts == 2
    assert cfg.retry_backoff == 0.5
    assert cfg.retry_non_idempotent is False


def test_retry_env_and_cli(clean_env):
    clean_env.setenv("mcp_baf_RETRY_ATTEMPTS", "5")
    clean_env.setenv("mcp_baf_RETRY_BACKOFF", "0.25")
    clean_env.setenv("mcp_baf_RETRY_NON_IDEMPOTENT", "1")
    cfg = load_config(parse_args([]))
    assert (cfg.retry_attempts, cfg.retry_backoff, cfg.retry_non_idempotent) == (5, 0.25, True)

    clean_env.delenv("mcp_baf_RETRY_ATTEMPTS")
    cfg = load_config(parse_args(["--retry-attempts", "0", "--retry-backoff", "1.5"]))
    assert cfg.retry_attempts == 0  # явный 0 выключает повторы
    assert cfg.retry_backoff == 1.5
    assert load_config(parse_args(["--retry-non-idempotent"])).retry_non_idempotent is True


def test_invalid_retry_env_falls_back_to_default(clean_env):
    clean_env.setenv("mcp_baf_RETRY_ATTEMPTS", "many")
    clean_env.setenv("mcp_baf_RETRY_BACKOFF", "-1")
    cfg = load_config(parse_args([]))
    assert cfg.retry_attempts == 2
    assert cfg.retry_backoff == 0.5

