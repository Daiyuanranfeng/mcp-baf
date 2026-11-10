"""Тесты дискового кэша индекса и инкрементального обновления."""

import os
import sqlite3
import subprocess
import sys
import threading
import time

import mcp_baf
from mcp_baf.dumpindex import DumpIndex, SearchParams
from mcp_baf.dumpindex.cache import cache_path, index_db_path

BUILD_TIMEOUT = 30
SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(mcp_baf.__file__)))

_CHILD = """
import sys
from mcp_baf.dumpindex import DumpIndex
idx = DumpIndex(sys.argv[1], cache_dir=sys.argv[2])
assert idx.wait_ready(60), idx.build_error()
print(idx.module_count())
idx.close()
"""


def mk_bsl(root, rel_path, content):
    path = root / rel_path.replace("/", "\\")
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8-sig")


def rm_bsl(root, rel_path):
    # Зеркало mk_bsl: на POSIX бэкслеши — часть имени одного файла,
    # на Windows pathlib разбирает их как разделители.
    os.remove(root / rel_path.replace("/", "\\"))


def build(dump_dir, cache_dir, reindex=False):
    idx = DumpIndex(str(dump_dir), cache_dir=str(cache_dir), reindex=reindex)
    assert idx.wait_ready(BUILD_TIMEOUT), idx.build_error()
    assert idx.build_error() is None
    return idx


def test_cache_file_created(tmp_path):
    dump, cache = tmp_path / "dump", tmp_path / "cache"
    mk_bsl(dump, "Catalogs/Тест/Ext/ObjectModule.bsl", "Процедура А()\nКонецПроцедуры\n")
    idx = build(dump, cache)
    idx.close()
    assert os.path.exists(index_db_path(str(dump), str(cache)))


def test_cache_reused_and_search_works(tmp_path):
    dump, cache = tmp_path / "dump", tmp_path / "cache"
    mk_bsl(dump, "Catalogs/Тест/Ext/ObjectModule.bsl", "Процедура А()\nКонецПроцедуры\n")
    build(dump, cache).close()

    # Второй запуск открывает кэш (без полной пересборки).
    idx = build(dump, cache)
    matches, total = idx.search(SearchParams(query="Процедура", mode="exact"))
    assert total == 1
    assert matches[0].module == "Справочник.Тест.МодульОбъекта"
    idx.close()


def test_incremental_add_modify_delete(tmp_path):
    dump, cache = tmp_path / "dump", tmp_path / "cache"
    mk_bsl(dump, "Catalogs/Старый/Ext/ObjectModule.bsl", "СтароеСодержимое = 1;\n")
    mk_bsl(dump, "Catalogs/Меняется/Ext/ObjectModule.bsl", "ДоИзменения = 1;\n")
    build(dump, cache).close()

    # mtime-гранулярность: гарантируем отличие метки времени.
    time.sleep(0.01)

    rm_bsl(dump, "Catalogs/Старый/Ext/ObjectModule.bsl")
    mk_bsl(dump, "Catalogs/Меняется/Ext/ObjectModule.bsl", "ПослеИзменения = 2;\n")
    mk_bsl(dump, "Catalogs/Новый/Ext/ObjectModule.bsl", "НовоеСодержимое = 3;\n")

    idx = build(dump, cache)
    assert idx.module_count() == 2

    _, total = idx.search(SearchParams(query="СтароеСодержимое", mode="exact"))
    assert total == 0
    _, total = idx.search(SearchParams(query="ДоИзменения", mode="exact"))
    assert total == 0
    m, total = idx.search(SearchParams(query="ПослеИзменения", mode="exact"))
    assert total == 1
    m, total = idx.search(SearchParams(query="НовоеСодержимое", mode="exact"))
    assert total == 1
    assert m[0].module == "Справочник.Новый.МодульОбъекта"

    # smart-режим тоже видит изменения (FTS обновлён, не только docs).
    m, total = idx.search(SearchParams(query="НовоеСодержимое"))
    assert total == 1
    idx.close()


def test_reindex_discards_cache(tmp_path):
    dump, cache = tmp_path / "dump", tmp_path / "cache"
    mk_bsl(dump, "Catalogs/Тест/Ext/ObjectModule.bsl", "Процедура А()\nКонецПроцедуры\n")
    build(dump, cache).close()

    # Портим кэш: --reindex должен пересоздать его, а не упасть.
    db_path = index_db_path(str(dump), str(cache))
    with open(db_path, "wb") as f:
        f.write(b"garbage")

    idx = build(dump, cache, reindex=True)
    assert idx.module_count() == 1
    idx.close()


def test_corrupt_cache_rebuilt_automatically(tmp_path):
    dump, cache = tmp_path / "dump", tmp_path / "cache"
    mk_bsl(dump, "Catalogs/Тест/Ext/ObjectModule.bsl", "Процедура А()\nКонецПроцедуры\n")
    build(dump, cache).close()

    db_path = index_db_path(str(dump), str(cache))
    with open(db_path, "wb") as f:
        f.write(b"garbage")

    idx = build(dump, cache)  # без --reindex: кэш битый -> пересборка
    assert idx.module_count() == 1
    idx.close()


def test_schema_version_mismatch_rebuilt(tmp_path):
    dump, cache = tmp_path / "dump", tmp_path / "cache"
    mk_bsl(dump, "Catalogs/Тест/Ext/ObjectModule.bsl", "Процедура А()\nКонецПроцедуры\n")
    build(dump, cache).close()

    db_path = index_db_path(str(dump), str(cache))
    db = sqlite3.connect(db_path)
    with db:
        db.execute("UPDATE meta SET value = '999' WHERE key = 'schema_version'")
    db.close()  # незакрытое соединение держит файл (Windows)

    idx = build(dump, cache)
    assert idx.module_count() == 1
    idx.close()


def test_cache_path_distinct_per_dump_dir(tmp_path):
    a = cache_path(str(tmp_path / "a"), str(tmp_path / "c"))
    b = cache_path(str(tmp_path / "b"), str(tmp_path / "c"))
    assert a != b


# ── Межпроцессная синхронизация кэша (issue #26) ──


def _mk_dump(dump):
    for i in range(4):
        mk_bsl(dump, f"Catalogs/Товар{i}/Ext/ObjectModule.bsl",
               f"Процедура Тест{i}()\nКонецПроцедуры\n")


def _assert_db_intact(dump_dir, cache_dir, expected):
    db_path = index_db_path(str(dump_dir), str(cache_dir))
    assert os.path.exists(db_path)
    db = sqlite3.connect(db_path)
    try:
        assert db.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert db.execute("SELECT count(*) FROM docs").fetchone()[0] == expected
        assert db.execute("SELECT count(*) FROM fts").fetchone()[0] == expected
    finally:
        db.close()


def test_concurrent_threads_share_one_index(tmp_path):
    dump, cache = tmp_path / "dump", tmp_path / "cache"
    _mk_dump(dump)

    results, errors = [], []

    def run():
        try:
            idx = build(dump, cache)
            results.append(idx.module_count())
            idx.close()
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=BUILD_TIMEOUT)

    assert not errors, errors
    assert results == [4] * 4
    _assert_db_intact(dump, cache, 4)


def test_concurrent_processes_share_one_index(tmp_path):
    dump, cache = tmp_path / "dump", tmp_path / "cache"
    _mk_dump(dump)

    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CHILD, str(dump), str(cache)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env,
        )
        for _ in range(3)
    ]
    outputs = []
    for proc in procs:
        out, err = proc.communicate(timeout=120)
        assert proc.returncode == 0, err
        outputs.append(out.strip())

    # Ни один процесс не потерял базу и не собрал её наполовину.
    assert outputs == ["4"] * 3, outputs
    _assert_db_intact(dump, cache, 4)


def test_index_lock_file_next_to_db(tmp_path):
    dump, cache = tmp_path / "dump", tmp_path / "cache"
    _mk_dump(dump)
    build(dump, cache).close()
    assert os.path.exists(index_db_path(str(dump), str(cache)) + ".lock")


def test_reindex_replaces_db_atomically(tmp_path):
    dump, cache = tmp_path / "dump", tmp_path / "cache"
    _mk_dump(dump)
    reader = build(dump, cache)

    # --reindex собирает новую базу и подменяет файл, а не удаляет старую:
    # уже открытый читатель продолжает работать (на POSIX держит старый inode,
    # на Windows — обновлённое содержимое через backup API).
    reindexed = build(dump, cache, reindex=True)
    assert reindexed.module_count() == 4
    _, total = reader.search(SearchParams(query="Тест0", mode="exact"))
    assert total == 1
    reader.close()
    reindexed.close()
    _assert_db_intact(dump, cache, 4)
