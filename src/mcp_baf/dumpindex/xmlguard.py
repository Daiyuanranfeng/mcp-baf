"""Защита XML-парсеров dump-выгрузки от опасных документов.

Выгрузка 1С (Form.xml, Configuration.xml) всегда содержит только
XML-декларацию и данные: DTD и ссылки на сущности в ней не встречаются
никогда. Документ с <!DOCTYPE или <!ENTITY — это либо битый файл, либо
попытка атаки на парсер (billion laughs / expansion-цепочки, внешние
сущности), поэтому такой вход отвергается целиком, а не парсится
«осторожно». Тот же подход, что в feenlace/mcp-1c («refuse unsupported»,
v1.23.x): отказ дешевле рискованного разбора.

Штатный xml.etree построен на expat, который по умолчанию не читает
внешние сущности, но внутренние определения/цепочки раскрывает — от
этого и защищает предварительная проверка байтов.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET

# Маркеры DTD в исходных байтах (регистр в XML-разметке не значим).
_FORBIDDEN_MARKERS = (b"<!doctype", b"<!entity")

# Разумный предел размера манифеста/формы: реальные файлы 1С укладываются
# в десятки килобайт; мегабайтный XML — уже подозрение.
MAX_XML_BYTES = 8 * 1024 * 1024


class UnsafeXML(ValueError):
    """XML содержит конструкции, которые парсер отвергает намеренно."""


def guard(data: bytes) -> bytes:
    """Проверяет байты XML и возвращает их же (для цепочек чтения).

    Бросает UnsafeXML на DTD/сущностях и на превышении размера.
    """
    if len(data) > MAX_XML_BYTES:
        raise UnsafeXML(
            f"XML слишком большой ({len(data)} байт > {MAX_XML_BYTES})"
        )
    lowered = data[: MAX_XML_BYTES].lower()
    for marker in _FORBIDDEN_MARKERS:
        if marker in lowered:
            raise UnsafeXML(
                "XML содержит запрещённую конструкцию DTD/сущностей "
                f"(маркер {marker.decode()!r}); выгрузка 1С таких не содержит"
            )
    return data


def parse_bytes(data: bytes) -> ET.Element:
    """safe-разбор байтов XML в корневой элемент."""
    return ET.fromstring(guard(data))


def parse_file(path: str) -> ET.Element:
    """Читает файл и разбирает его с проверкой guard()."""
    with open(path, "rb") as f:
        return parse_bytes(f.read())
