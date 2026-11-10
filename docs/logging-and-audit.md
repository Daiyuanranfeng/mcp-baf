# Логування та аудит

[← Назад до змісту](README.md)

mcp-baf веде два незалежні журнали в кеш-каталозі (типово
`~/Library/Caches/mcp-baf/` на macOS, `%LOCALAPPDATA%\mcp-baf\` на Windows,
`~/.cache/mcp-baf/` на Linux; перевизначається `--cache-dir` /
`mcp_baf_CACHE_DIR`): **бізнес-аудит** (`audit.log`) і **операційний журнал**
(`server.log`). Це різні речі з різним призначенням і різною ротацією — не
плутайте їх, коли шукаєте причину проблеми.

## `audit.log` — журнал бізнес-подій (JSONL)

Єдиний контракт аудиту для сервісів BAF реалізує окремий пакет
[`mcp-baf-audit`](https://github.com/andriy4k07/mcp-baf-audit) (та сама схема
v2, що й у `baf-write-mcp`). `server.create_server` створює
`AuditLog(config.cache_dir, config.audit_max_size_mib, config.audit_archives,
service="mcp-baf")` — один інстанс на процес.

### Спільний конверт (схема v2)

Кожен рядок — JSON-об'єкт з такими полями конверта:

| Поле | Зміст |
|---|---|
| `schema_version` | `"2"` |
| `ts` | ISO8601 UTC з мілісекундами |
| `service` | `"mcp-baf"` |
| `session` | ID запуску процесу (спільний для всіх подій одного старту сервера) |
| `seq` | наскрізний номер події в межах сеансу |
| `trace_id` | зв'язує події однієї логічної операції (див. нижче); `null`, якщо контекст ще не встановлено |
| `event` | канонічне ім'я події (`domain.action`) |
| `level` | `"info"` або `"error"` |

Пакет `mcp-baf-audit` нормалізує старі "плоскі" імена (`tool_call`,
`server_start`, `extension_version_mismatch`, …) у канонічні (`tool.call`,
`server.start`, `server.version_mismatch`) на запису — саме канонічне ім'я
й опиняється в `event.log`, незалежно від того, яке ім'я передав виклик у
коді.

**Важлива деталь схеми:** у mcp-baf одночасно використовуються два API
пакета — і форма запису відрізняється:

- `server.py` і `tools/common.py` викликають **`audit.write(event, **details)`**
  — старий "плоский" API: усі `details` (наприклад `tool`, `args`, `ok`,
  `duration_ms`) лягають у корінь запису, без зайвих `null`-полів.
- `client.py` викликає **`audit.event(...)`** — канонічний API: запис завжди
  містить повний набір необов'язкових полів конверта (`tool`, `request_id`,
  `object`, `actor`, `source_channel`, `ok`, `duration_ms`, `status`,
  `payload`, `error`), навіть якщо вони `null`, а деталі події лежать у
  вкладеному `payload`.

Тобто `tool.call` і `one_c.http` в одному й тому ж файлі виглядають
по-різному за формою — це навмисно, не пошкодження логу.

### Які події пише mcp-baf

| Подія (`event`) | Джерело | Коли |
|---|---|---|
| `server.start` | `server.py` (лічилка `server_start`) | старт сервера: `version`, `base_url`, `user` (без пароля) |
| `server.stop` | `server.py` (`server_stop`) | зупинка сервера (при виході з lifespan) |
| `server.version_mismatch` | `server.py` (`extension_version_mismatch`) | версія розширення 1С (`/version`) не збігається з `EXPECTED_EXTENSION_VERSION`: `got`, `expected` |
| `tool.call` | `tools/common.py:traced_text` (`tool_call`) | **кожен** успішний виклик будь-якого інструмента: `tool`, `args`, `ok=true`, `duration_ms` |
| `tool.error` | `tools/common.py:traced_text` (`tool_error`) | виняток у тілі інструмента: `tool`, `args`, `error`, `duration_ms`, `level="error"` |
| `one_c.http` | `client.py:OneCClient._audit_http` | **рівно одна подія на кожен HTTP-виклик 1С** (успіх чи ні): `status`, `duration_ms`, `payload.response_bytes` — тіло запиту й відповіді ніколи не пишеться |
| `access.capabilities_unavailable` | `access.py:AccessMCP._capabilities` | `/capabilities` не відповів або повернув непридатне тіло, тому HTTP-інструменти закрито: `reason` (клас винятку), `error` (текст клієнта, ≤300 символів), `level="error"`. Тіло `/capabilities` потрапляє лише як текст помилки 1С; дані бази не пишуться, секрети редагує пакет аудиту |

### `trace_id`: як `tool.call` пов'язується з `one_c.http`

`traced_text` на старті виклику інструмента бере `trace_id` з contextvar
(`get_trace_id()`) або генерує новий (`new_trace_id()`, hex16) і фіксує його
назад у contextvar (`set_trace_id`). Усі виклики 1С, зроблені всередині
цього ж async-контексту через `client.py`, автоматично успадковують той
самий `trace_id` — `OneCClient` не отримує його явно, він читає contextvar
за замовчуванням. Результат: одну "операцію" (виклик інструмента + усі його
звернення до 1С) можна витягнути одним `grep`:

```sh
grep '"trace_id": "9f86d081884c7d65"' audit.log
```

### Секрети

Редакція виконується централізовано в самому пакеті `mcp-baf-audit`
(`redact.default_redactor`) для всіх ключів, що містять `password`, `token`,
`authorization` або `secret` (регістронезалежно, на будь-якій глибині
структури) — значення замінюється на `***`. Домену (коду mcp-baf) не треба
самому думати про фільтрацію — досить передати дані як є.

### Приклад JSONL (реальні поля з коду)

```jsonl
{"schema_version": "2", "ts": "2026-07-14T09:12:03.501+00:00", "service": "mcp-baf", "session": "a1b2c3d4e5f6", "seq": 1, "trace_id": null, "event": "server.start", "level": "info", "version": "0.3.0", "base_url": "http://localhost:8080/hs/mcp-baf", "user": "Адміністратор"}
{"schema_version": "2", "ts": "2026-07-14T09:12:11.884+00:00", "service": "mcp-baf", "session": "a1b2c3d4e5f6", "seq": 4, "trace_id": "9f86d081884c7d65", "event": "tool.call", "level": "info", "tool": "get_metadata_tree", "args": {"filter": "Справочники"}, "ok": true, "duration_ms": 42}
{"schema_version": "2", "ts": "2026-07-14T09:12:11.901+00:00", "service": "mcp-baf", "session": "a1b2c3d4e5f6", "seq": 5, "trace_id": "9f86d081884c7d65", "event": "one_c.http", "level": "info", "tool": null, "request_id": null, "object": null, "actor": null, "source_channel": null, "ok": true, "duration_ms": 17, "status": 200, "payload": {"method": "GET", "endpoint": "/metadata", "response_bytes": 8341}, "error": null}
{"schema_version": "2", "ts": "2026-07-14T09:13:47.220+00:00", "service": "mcp-baf", "session": "a1b2c3d4e5f6", "seq": 9, "trace_id": "1c2d3e4f5a6b7c8d", "event": "tool.error", "level": "error", "tool": "execute_query", "args": {"limit": 10}, "error": "executing request to 1C: connection refused", "duration_ms": 3012}
{"schema_version": "2", "ts": "2026-07-14T18:00:02.117+00:00", "service": "mcp-baf", "session": "a1b2c3d4e5f6", "seq": 41, "trace_id": null, "event": "server.stop", "level": "info"}
```

Зверніть увагу: `request_id` у полі `payload`/конверта `one_c.http` для
mcp-baf завжди `null` — це поле схеми спільне з `baf-write-mcp`, де воно
несе доменний `request_id` потоку `propose → create`; читаюча сторона 1С-тіла
з таким ідентифікатором просто не надсилає.

### Ротація

За розміром: коли `audit.log` перевищує ліміт, файл перейменовується в
`audit-<YYYYMMDD-HHMMSS>.log`, архіви понад ліміт видаляються (найстаріші
першими).

| Прапор | Env | За замовчуванням |
|---|---|---|
| `--audit-max-size` | `mcp_baf_AUDIT_MAX_SIZE` | 50 MiB |
| `--audit-archives` | `mcp_baf_AUDIT_ARCHIVES` | 20 |

## `server.log` — операційний журнал

Налаштовується в `__main__.py:_setup_logging` і пишеться **завжди** (окремо
від `audit.log`, стандартним `logging`, а не `mcp-baf-audit`):

- Рівень **INFO** за замовчуванням; **`--debug`** піднімає корінь логера до
  DEBUG і знімає приглушення `httpx`/`httpcore` (без `--debug` ці логери
  обмежені `WARNING`, бо httpx дублює власні рядки клієнта).
- Ротація за розміром: **5 MiB × 3 бекапи** (`RotatingFileHandler`),
  журнал переживає рестарти сервера.
- Файл — `server.log` у тому ж кеш-каталозі, що й `audit.log`.
- Якщо каталог/файл журналу створити не вдалося (`OSError`) — сервер не
  падає, просто залишається без файлового логування (тільки ERROR у
  stderr).

### stderr — тільки ERROR

MCP-клієнти (Claude Desktop, Claude Code тощо) рендерять **будь-який**
рядок у stderr як помилку (`[error]`). Тому в stderr-хендлер потрапляють
виключно записи рівня `ERROR` і вище — усе інше (включно з детальним
трасуванням запитів до 1С за `--debug`) йде тільки у файл `server.log`.

## Швидкий перегляд журналу

```sh
# уся історія однієї операції (виклик інструмента + всі звернення до 1С)
grep '"trace_id": "<trace_id>"' audit.log

# усі помилки інструментів
grep '"event": "tool.error"' audit.log

# розбіжність версії розширення 1С
grep '"event": "server.version_mismatch"' audit.log
```

## Аудит нових інструментів

`find_object_references` логуює тип, GUID, області й ліміти; знайдені записи не логуються. `get_object_link` не логуює передане посилання чи представлення. BSL-інструменти записують кількість байтів коду й фільтри, без коду й діагностик. Відмови `AccessMCP.call_tool` мають `args.access_denied=true` без переданих бізнес-аргументів. Перевірка `/capabilities` і виконання HTTP-інструмента залишають окремі `one_c.http`-події в одному trace.
