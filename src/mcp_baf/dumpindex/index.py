"""Полнотекстовый индекс BSL-модулей на SQLite FTS5.

Порт dump/index.go из Go-версии (bleve -> SQLite FTS5):
- рекурсивный обход директории --dump и параллельное чтение .bsl файлов
  (ThreadPoolExecutor, чтение ограничено диском, поэтому потоков достаточно);
- индекс строится в фоновом потоке: сервер стартует сразу, поиск до
  готовности возвращает понятную ошибку (как в Go-версии);
- дисковый кэш: база SQLite сохраняется в кэш-каталоге; при повторном
  старте кэш открывается и инкрементально обновляется по diff манифеста
  (mtime+size каждого файла хранятся прямо в таблице docs);
- режим smart: BM25-ранжирование FTS5, BSL-синонимы разворачиваются на
  этапе запроса — токен заменяется на (токен OR синоним), поэтому поиск
  по английским именам находит русские и наоборот;
- режимы regex/exact: построчный скан содержимого модулей.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sqlite3
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from mcp_baf.dumpindex.cache import index_db_path
from mcp_baf.dumpindex.extroots import discover_extension_roots
from mcp_baf.dumpindex.modulenames import (
    nfc,
    parse_module_name,
    resolve_module_name,
)
from mcp_baf.dumpindex.synonyms import build_synonym_map

logger = logging.getLogger(__name__)

# Версия схемы кэша. Несовпадение -> кэш отбрасывается и строится заново.
# v2: имена модулей NFC-нормализованы — кэш, построенный до фикса на macOS,
# хранит NFD-ключи, которые NFC-запрос никогда не найдёт, поэтому он
# перестраивается (аналог bump dumpIndexSchemaVersion в Go-версии).
# v3: вложенные корни расширений (<обёртка>/<extension>/Configuration.xml)
# получают ext.<имя>-пространство (порт фикса feenlace/mcp-1c issue 46).
# Без подъёма версии тёплый кэш продолжал бы отдавать старые path-ключи.
SCHEMA_VERSION = 3

# Окно контекста вокруг найденной строки, в строках с каждой стороны.
CONTEXT_WINDOW = 2

# Токены для FTS5-запроса: буквы и цифры без подчёркивания — так же
# сегментирует идентификаторы токенизатор unicode61 самого FTS5.
_TOKEN_RE = re.compile(r"[^\W_]+")


@dataclass
class Match:
    """Одно совпадение поиска в BSL-модуле."""

    module: str   # человекочитаемое имя модуля
    line: int     # номер строки (с 1)
    context: str  # строки вокруг совпадения
    score: float = 0.0  # релевантность BM25 (только режим smart)


@dataclass
class SearchParams:
    query: str
    category: str = ""  # фильтр по типу метаданных, пусто = все
    module: str = ""    # фильтр по типу модуля, пусто = все
    mode: str = "smart"
    limit: int = 50


@dataclass
class _FileState:
    """Состояние одного .bsl файла на диске (для diff манифеста)."""

    abs_path: str
    mtime_ms: int
    size: int


class DumpIndex:
    """Индекс поиска по коду модулей из dump-выгрузки конфигурации.

    Строится асинхронно в фоновом потоке; до готовности search() бросает
    ошибку «индекс строится». Доступ к SQLite сериализуется блокировкой
    (sqlite3 не потокобезопасен по умолчанию).
    """

    def __init__(
        self,
        dump_dir: str,
        cache_dir: str = "",
        reindex: bool = False,
        use_cache: bool = True,
        show_progress: bool = False,
    ) -> None:
        self._dir = dump_dir
        self._db_path = index_db_path(dump_dir, cache_dir) if use_cache else ""
        self._reindex = reindex
        self._show_progress = show_progress
        self._db: sqlite3.Connection | None = None
        self._db_lock = threading.Lock()
        self._ready = threading.Event()
        self._build_error: Exception | None = None
        self._module_count = 0
        # rel_dir -> имя расширения из вложенного Configuration.xml;
        # заполняется в _build перед выводом ключей (см. dumpindex.extroots).
        self._ext_roots: dict[str, str] = {}
        self._thread = threading.Thread(
            target=self._build, name="dump-index-build", daemon=True
        )
        self._thread.start()

    # ── Построение индекса ──

    def _progress(self, message: str) -> None:
        if self._show_progress:
            print(f"[{time.strftime('%H:%M:%S')}] {message}", file=sys.stderr)

    def _build(self) -> None:
        try:
            # Карта вложенных корней расширений нужна до вывода любых
            # ключей (и на холодную сборку, и на diff кэша).
            self._ext_roots = discover_extension_roots(self._dir)

            if self._db_path and self._reindex and os.path.exists(self._db_path):
                os.remove(self._db_path)

            if self._db_path and not self._reindex and os.path.exists(self._db_path):
                try:
                    self._open_cache_and_diff()
                    self._finish_build(from_cache=True)
                    return
                except Exception as exc:  # noqa: BLE001 — кэш битый, перестраиваем
                    logger.warning("Cache load failed, rebuilding: %s", exc)
                    self._close_db()
                    os.remove(self._db_path)

            self._full_build()
            self._finish_build(from_cache=False)
        except Exception as exc:  # noqa: BLE001 — ошибка отдаётся из search()
            self._build_error = exc

    def _finish_build(self, from_cache: bool) -> None:
        assert self._db is not None
        self._module_count = self._db.execute(
            "SELECT count(*) FROM docs"
        ).fetchone()[0]
        self._ready.set()
        source = "из кэша" if from_cache else "построен"
        self._progress(f"Индекс {source}: {self._module_count} модулей")
        logger.info(
            "Index ready: %d modules (cache=%s)", self._module_count, from_cache
        )

    def _close_db(self) -> None:
        if self._db is not None:
            self._db.close()
            self._db = None

    def _connect(self) -> sqlite3.Connection:
        if self._db_path:
            os.makedirs(os.path.dirname(self._db_path), exist_ok=True)
            return sqlite3.connect(self._db_path, check_same_thread=False)
        return sqlite3.connect(":memory:", check_same_thread=False)

    def _create_schema(self, db: sqlite3.Connection) -> None:
        db.execute(
            "CREATE TABLE meta(key TEXT PRIMARY KEY, value TEXT)"
        )
        # mtime_ms и size образуют манифест для инкрементального diff
        # (аналог manifest.json в Go-версии).
        db.execute(
            "CREATE TABLE docs("
            "id INTEGER PRIMARY KEY, rel_path TEXT UNIQUE, name TEXT, "
            "category TEXT, module TEXT, mtime_ms INTEGER, size INTEGER, "
            "content TEXT)"
        )
        # Внешнее содержимое (content='docs') — FTS5 хранит только индекс,
        # текст модулей не дублируется.
        db.execute(
            "CREATE VIRTUAL TABLE fts USING fts5("
            "content, content='docs', content_rowid='id', "
            "tokenize='unicode61')"
        )
        db.execute(
            "INSERT INTO meta VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),)
        )
        db.execute(
            "INSERT INTO meta VALUES ('ext_roots', ?)", (self._ext_roots_key(),)
        )

    def _walk_files(self) -> dict[str, _FileState]:
        """Собирает состояние всех .bsl файлов: rel_path -> (путь, mtime, size)."""
        files: dict[str, _FileState] = {}
        for root, _dirs, names in os.walk(self._dir):
            for file_name in names:
                if not file_name.lower().endswith(".bsl"):
                    continue
                abs_path = os.path.join(root, file_name)
                if os.path.islink(abs_path):
                    continue  # симлинк может вести за пределы dump-корня
                try:
                    st = os.stat(abs_path)
                except OSError:
                    continue
                rel = os.path.relpath(abs_path, self._dir).replace("\\", "/")
                files[rel] = _FileState(
                    abs_path=abs_path,
                    mtime_ms=st.st_mtime_ns // 1_000_000,
                    size=st.st_size,
                )
        return files

    @staticmethod
    def _read_content(abs_path: str) -> str | None:
        try:
            # utf-8-sig срезает BOM, который 1С ставит в начало файла.
            with open(abs_path, encoding="utf-8-sig", errors="replace") as f:
                return f.read()
        except OSError:
            return None  # нечитаемые файлы пропускаются

    def _full_build(self) -> None:
        files = self._walk_files()
        self._progress(f"Индексация: найдено {len(files)} модулей...")

        def read_one(item: tuple[str, _FileState]) -> tuple[str, str] | None:
            rel, state = item
            content = self._read_content(state.abs_path)
            return None if content is None else (rel, content)

        workers = min(32, (os.cpu_count() or 4) * 4)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            contents = dict(filter(None, pool.map(read_one, files.items())))

        rows = []
        sort_key = lambda rel: resolve_module_name(rel, self._ext_roots)  # noqa: E731
        for rel in sorted(files, key=sort_key):
            if rel not in contents:
                continue
            state = files[rel]
            name = resolve_module_name(rel, self._ext_roots)
            parts = parse_module_name(name)
            rows.append((
                rel, name, parts.category, parts.module,
                state.mtime_ms, state.size, contents[rel],
            ))

        db = self._connect()
        self._create_schema(db)
        with db:
            db.executemany(
                "INSERT INTO docs(rel_path, name, category, module, "
                "mtime_ms, size, content) VALUES (?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            db.execute(
                "INSERT INTO fts(rowid, content) SELECT id, content FROM docs"
            )
        self._db = db

    def _ext_roots_key(self) -> str:
        return json.dumps(self._ext_roots, sort_keys=True, ensure_ascii=False)

    def _open_cache_and_diff(self) -> None:
        """Открывает кэш и инкрементально применяет изменения файлов."""
        # Соединение сразу сохраняется в self._db: при любой ошибке ниже
        # вызывающий код закроет его через _close_db перед удалением файла
        # (Windows не даёт удалить файл с открытым дескриптором).
        db = self._db = sqlite3.connect(self._db_path, check_same_thread=False)
        version = db.execute(
            "SELECT value FROM meta WHERE key = 'schema_version'"
        ).fetchone()
        if version is None or int(version[0]) != SCHEMA_VERSION:
            raise RuntimeError(f"cache schema version mismatch: {version}")
        # Имена модулей зависят от карты вложенных расширений: если манифест
        # добавили/убрали/переименовали, ключи в кэше устарели целиком.
        roots = db.execute(
            "SELECT value FROM meta WHERE key = 'ext_roots'"
        ).fetchone()
        if roots is None or roots[0] != self._ext_roots_key():
            raise RuntimeError("extension roots changed since cache was built")

        on_disk = self._walk_files()
        manifest = {
            rel: (doc_id, mtime_ms, size)
            for doc_id, rel, mtime_ms, size in db.execute(
                "SELECT id, rel_path, mtime_ms, size FROM docs"
            )
        }

        added = [rel for rel in on_disk if rel not in manifest]
        deleted = [rel for rel in manifest if rel not in on_disk]
        modified = [
            rel
            for rel, (_, mtime_ms, size) in manifest.items()
            if rel in on_disk
            and (on_disk[rel].mtime_ms != mtime_ms or on_disk[rel].size != size)
        ]

        if not (added or deleted or modified):
            return

        with db:
            for rel in deleted:
                doc_id, _, _ = manifest[rel]
                self._fts_delete(db, doc_id)
                db.execute("DELETE FROM docs WHERE id = ?", (doc_id,))

            for rel in modified:
                content = self._read_content(on_disk[rel].abs_path)
                if content is None:
                    continue
                doc_id, _, _ = manifest[rel]
                self._fts_delete(db, doc_id)
                db.execute(
                    "UPDATE docs SET mtime_ms = ?, size = ?, content = ? "
                    "WHERE id = ?",
                    (on_disk[rel].mtime_ms, on_disk[rel].size, content, doc_id),
                )
                db.execute(
                    "INSERT INTO fts(rowid, content) VALUES (?, ?)",
                    (doc_id, content),
                )

            for rel in added:
                content = self._read_content(on_disk[rel].abs_path)
                if content is None:
                    continue
                name = resolve_module_name(rel, self._ext_roots)
                parts = parse_module_name(name)
                cur = db.execute(
                    "INSERT INTO docs(rel_path, name, category, module, "
                    "mtime_ms, size, content) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (rel, name, parts.category, parts.module,
                     on_disk[rel].mtime_ms, on_disk[rel].size, content),
                )
                db.execute(
                    "INSERT INTO fts(rowid, content) VALUES (?, ?)",
                    (cur.lastrowid, content),
                )

        logger.info(
            "Incremental update: added=%d modified=%d deleted=%d",
            len(added), len(modified), len(deleted),
        )

    @staticmethod
    def _fts_delete(db: sqlite3.Connection, doc_id: int) -> None:
        """Удаляет документ из FTS5 с внешним содержимым.

        Команде 'delete' нужно старое содержимое — читаем его из docs
        до изменения строки.
        """
        row = db.execute(
            "SELECT content FROM docs WHERE id = ?", (doc_id,)
        ).fetchone()
        if row is not None:
            db.execute(
                "INSERT INTO fts(fts, rowid, content) VALUES ('delete', ?, ?)",
                (doc_id, row[0]),
            )

    # ── Состояние ──

    def ready(self) -> bool:
        return self._ready.is_set()

    def wait_ready(self, timeout: float | None = None) -> bool:
        return self._ready.wait(timeout)

    def module_count(self) -> int:
        return self._module_count if self._ready.is_set() else 0

    def build_error(self) -> Exception | None:
        return self._build_error

    def close(self) -> None:
        with self._db_lock:
            self._close_db()

    # ── Поиск ──

    def search(self, params: SearchParams) -> tuple[list[Match], int]:
        """Ищет совпадения в проиндексированных модулях. Диспетчер по mode."""
        if not self._ready.is_set():
            if self._build_error is not None:
                raise RuntimeError(f"index build failed: {self._build_error}")
            raise RuntimeError("search index is building, please retry")

        limit = params.limit
        if limit <= 0:
            limit = 50
        limit = min(limit, 500)
        # Аргументы поиска нормализуются в NFC, как и ключи индекса:
        # NFD-строка (например, скопированная из macOS-выгрузки) иначе
        # никогда не совпадёт с NFC-значениями в базе.
        params = SearchParams(
            query=nfc(params.query),
            category=nfc(params.category),
            module=nfc(params.module),
            mode=params.mode or "smart",
            limit=limit,
        )

        if params.mode == "smart":
            return self._search_smart(params)
        if params.mode == "regex":
            try:
                pattern = re.compile(params.query)
            except re.error as exc:
                raise ValueError(f"invalid regex {params.query!r}: {exc}") from exc
            return self._search_line_by_line(
                params, lambda line: pattern.search(line) is not None
            )
        if params.mode == "exact":
            needle = params.query.lower()
            return self._search_line_by_line(
                params, lambda line: needle in line.lower()
            )
        raise ValueError(f"unknown search mode: {params.mode!r}")

    def _search_smart(self, params: SearchParams) -> tuple[list[Match], int]:
        """Полнотекстовый поиск с BM25-ранжированием через FTS5."""
        tokens = _TOKEN_RE.findall(params.query.lower())
        if not tokens:
            return [], 0

        synonyms = build_synonym_map()
        match_parts = []
        for tok in tokens:
            syn = synonyms.get(tok)
            if syn:
                match_parts.append(f'("{tok}" OR "{syn}")')
            else:
                match_parts.append(f'"{tok}"')
        match_expr = " AND ".join(match_parts)

        filters = (
            "(:category = '' OR d.category = :category) "
            "AND (:module = '' OR d.module = :module)"
        )
        args = {
            "q": match_expr,
            "category": params.category,
            "module": params.module,
            "limit": params.limit,
        }

        with self._db_lock:
            assert self._db is not None
            total = self._db.execute(
                "SELECT count(*) FROM fts JOIN docs d ON d.id = fts.rowid "
                f"WHERE fts MATCH :q AND {filters}",
                args,
            ).fetchone()[0]
            hits = self._db.execute(
                "SELECT d.name, d.content, -bm25(fts) AS score "
                "FROM fts JOIN docs d ON d.id = fts.rowid "
                f"WHERE fts MATCH :q AND {filters} "
                "ORDER BY bm25(fts) LIMIT :limit",
                args,
            ).fetchall()

        # Расширенный набор токенов — запасной вариант, когда FTS5 нашёл
        # документ через синоним, а исходные токены в тексте не встречаются.
        expanded = list(tokens)
        for tok in tokens:
            syn = synonyms.get(tok)
            if syn:
                expanded.append(syn)

        plain_tokens = params.query.lower().split()
        matches = []
        for name, content, score in hits:
            lines = content.split("\n")
            line_num = _best_line(lines, plain_tokens)
            if line_num == 0 and len(expanded) > len(tokens):
                line_num = _first_line_with_any(lines, expanded)
            if line_num == 0:
                line_num = 1
            matches.append(
                Match(
                    module=name,
                    line=line_num,
                    context=_extract_context(lines, line_num - 1),
                    score=score,
                )
            )

        return matches, total

    def _search_line_by_line(
        self, params: SearchParams, match: "callable[[str], bool]"
    ) -> tuple[list[Match], int]:
        """Построчный поиск (режимы regex и exact)."""
        where = []
        args: list[str] = []
        if params.category:
            where.append("category = ?")
            args.append(params.category)
        if params.module:
            where.append("module = ?")
            args.append(params.module)
        sql = "SELECT name, content FROM docs"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY name"

        with self._db_lock:
            assert self._db is not None
            rows = self._db.execute(sql, args).fetchall()

        matches: list[Match] = []
        total = 0
        for name, content in rows:
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if match(line):
                    total += 1
                    if len(matches) < params.limit:
                        matches.append(
                            Match(
                                module=name,
                                line=i + 1,
                                context=_extract_context(lines, i),
                            )
                        )

        return matches, total


def _extract_context(lines: list[str], idx: int, window: int = CONTEXT_WINDOW) -> str:
    start = max(idx - window, 0)
    end = min(idx + window + 1, len(lines))
    return "\n".join(lines[start:end])


def _best_line(lines: list[str], tokens: list[str]) -> int:
    """Строка с наибольшим числом различных токенов запроса (0 — нет совпадений).

    При равенстве выигрывает первое вхождение, как в Go-версии.
    """
    best_line = 0
    best_score = 0
    for i, line in enumerate(lines):
        ll = line.lower()
        score = sum(1 for tok in tokens if tok in ll)
        if score > best_score:
            best_score = score
            best_line = i + 1
    return best_line


def _first_line_with_any(lines: list[str], tokens: list[str]) -> int:
    for i, line in enumerate(lines):
        ll = line.lower()
        if any(tok in ll for tok in tokens):
            return i + 1
    return 0
