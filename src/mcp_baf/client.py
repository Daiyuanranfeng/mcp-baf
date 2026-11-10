"""Асинхронный HTTP-клиент для общения с 1С:Предприятие."""

from __future__ import annotations

import json
import re
import time
from typing import TYPE_CHECKING, Any

import httpx

from mcp_baf.config import Config

if TYPE_CHECKING:  # тип только для подсказок — без обязательной зависимости в рантайме
    from mcp_baf_audit import AuditWriter

_MIB = 1 << 20

# Клиенту показываем лишь короткий фрагмент тела ошибки 1С: полный ответ
# может содержать данные базы (ПДн, тексты документов) и не нужен агенту.
MAX_ERROR_DETAIL_CHARS = 300

# Телефоны/почта в тексте ошибки 1С маскируются: тело ответа может включать ПДн.
_ERROR_PII_RE = re.compile(
    r"(?<!\d)(?:\+?38[\s-]*)?\(?0[\s-]*\d[\s-]*\d\)?(?:[\s-]*\d){7}(?!\d)"
    r"|[\w.+-]+@[\w-]+(?:\.[\w-]+)+"
)
# Управляющие символы (в т.ч. переводы строк) превращаем в пробел: аудит и
# текст ошибки должны оставаться однострочными.
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]+")


def scrub_error_detail(detail: str, limit: int = MAX_ERROR_DETAIL_CHARS) -> str:
    """Маскирует ПДн и обрезает тело ошибки 1С до безопасной длины."""
    text = " ".join(_CONTROL_RE.sub(" ", detail).split())
    text = _ERROR_PII_RE.sub("***", text)
    if len(text) > limit:
        text = text[:limit].rstrip() + "…"
    return text


class OneCError(Exception):
    """Ошибка взаимодействия с 1С с понятным пользователю текстом."""


class OneCClient:
    """HTTP-клиент к HTTP-сервису 1С.

    Если задан пользователь, ко всем запросам добавляется basic auth.
    Ответ крупнее лимита отбрасывается с понятной ошибкой вместо OOM.
    Каждый вызов 1С оставляет ровно одно событие аудита one_c.http
    (метод, эндпоинт, статус, длительность, размер ответа); тело не логируется.
    """

    def __init__(
        self,
        config: Config,
        transport: httpx.AsyncBaseTransport | None = None,
        *,
        audit: AuditWriter | None = None,
    ) -> None:
        self._base_url = config.base_url.rstrip("/")
        self._max_response_size = config.max_response_size_mib * _MIB
        self._audit = audit

        auth = None
        if config.user:
            auth = httpx.BasicAuth(config.user, config.password)

        self._http = httpx.AsyncClient(
            auth=auth,
            timeout=httpx.Timeout(config.request_timeout),
            # Закрываем соединение после каждого запроса,
            # чтобы не упираться в лимит сеансов 1С.
            headers={"Connection": "close"},
            transport=transport,
        )

    async def get(self, endpoint: str) -> Any:
        """GET-запрос к эндпоинту 1С с разбором JSON-ответа."""
        return await self._do("GET", endpoint)

    async def post(self, endpoint: str, body: Any) -> Any:
        """POST-запрос к эндпоинту 1С с JSON-телом и разбором JSON-ответа."""
        return await self._do("POST", endpoint, body)

    async def _do(self, method: str, endpoint: str, body: Any = None) -> Any:
        kwargs: dict[str, Any] = {}
        if body is not None:
            kwargs["json"] = body
        # request_id для аудита берём из тела (если есть), а не из лога тела.
        request_id = body.get("request_id") if isinstance(body, dict) else None

        start = time.monotonic()

        def elapsed_ms() -> int:
            return int((time.monotonic() - start) * 1000)

        # Состояние для ровно одного события one_c.http (пишется в finally).
        status_code: int | None = None
        response_bytes = 0
        # В аудит уходит только тип ошибки (и статус), но не её текст.
        error_kind: str | None = None
        try:
            try:
                async with self._http.stream(
                    method, self._base_url + endpoint, **kwargs
                ) as resp:
                    status_code = resp.status_code
                    if resp.status_code != 200:
                        detail = scrub_error_detail(
                            (await resp.aread())[:4096].decode("utf-8", "replace")
                        )
                        error_kind = f"http_{resp.status_code}"
                        raise OneCError(
                            f"1C returned status {resp.status_code}: {detail}"
                        )

                    # Читаем не более limit+1 байт: если поток обрезан потолком,
                    # выдаём понятную ошибку вместо невнятной ошибки декодера.
                    raw = bytearray()
                    async for chunk in resp.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > self._max_response_size:
                            response_bytes = len(raw)
                            error_kind = "response_too_large"
                            raise OneCError(self._response_too_large_message())
                    response_bytes = len(raw)
            except httpx.HTTPError as exc:
                error_kind = "transport_error"
                raise OneCError(
                    f"executing request to 1C: {scrub_error_detail(str(exc))}"
                ) from exc

            try:
                return json.loads(raw.decode("utf-8"))
            except (ValueError, UnicodeDecodeError) as exc:
                error_kind = "decode_error"
                raise OneCError(f"decoding 1C response: {exc}") from exc
        finally:
            self._audit_http(
                method, endpoint, status_code, elapsed_ms(),
                response_bytes, request_id, error_kind,
            )

    def _audit_http(
        self,
        method: str,
        endpoint: str,
        status: int | None,
        duration_ms: int,
        response_bytes: int,
        request_id: str | None,
        error_kind: str | None,
    ) -> None:
        """Пишет ровно одно событие one_c.http. Тело запроса/ответа не логируется."""
        if self._audit is None:
            return
        self._audit.event(
            "one_c.http",
            level="error" if error_kind else "info",
            ok=error_kind is None,
            request_id=request_id or None,
            status=status,
            duration_ms=duration_ms,
            error=error_kind,
            payload={
                "method": method,
                "endpoint": endpoint,
                "response_bytes": response_bytes,
                "error_kind": error_kind,
            },
        )

    def _response_too_large_message(self) -> str:
        limit_mib = self._max_response_size // _MIB
        return (
            f"ответ 1С превысил лимит размера ({limit_mib} MiB). "
            "Увеличьте лимит флагом --max-response-size <МиБ> "
            "или переменной окружения mcp_baf_MAX_RESPONSE_SIZE"
        )

    async def aclose(self) -> None:
        await self._http.aclose()
