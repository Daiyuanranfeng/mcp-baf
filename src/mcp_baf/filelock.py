"""Межпроцессная файловая блокировка для общих файлов кэша.

Нужна там, где два процесса (сервер + дашборд, два инстанса MCP) пишут в
один и тот же каталог кэша: генерация TLS-комплекта и сборка index.db.
POSIX — `fcntl.flock` (блокировка живёт на open file description, поэтому
два разных `os.open` конфликтуют даже внутри одного процесса — это важно
для потоков), Windows — `msvcrt.locking` на одном байте файла.
"""

from __future__ import annotations

import contextlib
import os
import time

if os.name == "nt":  # pragma: no cover — Windows-ветка
    import msvcrt
else:
    import fcntl


class LockTimeout(TimeoutError):
    """Лок не удалось взять за отведённое время."""


def _try_lock(fd: int) -> bool:
    try:
        if os.name == "nt":  # pragma: no cover — Windows-ветка
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except OSError:
        return False


def _unlock(fd: int) -> None:
    if os.name == "nt":  # pragma: no cover — Windows-ветка
        os.lseek(fd, 0, os.SEEK_SET)
        msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    else:
        fcntl.flock(fd, fcntl.LOCK_UN)


@contextlib.contextmanager
def file_lock(path: str, timeout: float = 120.0, poll: float = 0.05):
    """Эксклюзивный лок на файле `path` (файл создаётся при необходимости).

    `timeout` — сколько секунд ждать; по истечении поднимается LockTimeout.
    Лок снимается при выходе из блока, дескриптор закрывается всегда.
    """
    directory = os.path.dirname(os.path.abspath(path))
    os.makedirs(directory, exist_ok=True)
    fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o644)
    try:
        deadline = time.monotonic() + timeout
        while not _try_lock(fd):
            if time.monotonic() >= deadline:
                raise LockTimeout(f"could not acquire lock {path!r} in {timeout}s")
            time.sleep(poll)
        try:
            yield
        finally:
            _unlock(fd)
    finally:
        os.close(fd)
