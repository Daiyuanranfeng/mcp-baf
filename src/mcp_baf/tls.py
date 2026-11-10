"""TLS для https-транспорту: свої cert/key або самопідписаний CA у каталозі.

Без явних mcp_baf_TLS_CERT/KEY сервер один раз генерує власний CA і
серверний сертифікат, підписаний ним, у <cache_dir>/tls/. Клієнти (hermes,
дашборд) довіряють `ca.crt`. Окремий CA, а не самопідписаний лист: Python 3.13+
перевіряє ланцюжок у режимі VERIFY_X509_STRICT, і лист-як-якір там падає.
"""

from __future__ import annotations

import contextlib
import datetime
import ipaddress
import os
import socket
import tempfile

from mcp_baf.filelock import file_lock

CA_CERT_NAME = "ca.crt"
CA_KEY_NAME = "ca.key"
SERVER_CERT_NAME = "server.crt"
SERVER_KEY_NAME = "server.key"
LOCK_NAME = ".lock"

# Лист перевыпускается заранее, чтобы старт после долгого простоя не поднял
# сервер с уже протухшим сертификатом. 30 дней — с запасом на отпуск/аптайм.
LEAF_RENEW_BEFORE_DAYS = 30
LEAF_VALIDITY_DAYS = 825
CA_VALIDITY_DAYS = 3650


def self_signed_hosts(*extra: str) -> list[str]:
    """SAN за замовчуванням: localhost, loopback і hostname контейнера/хоста."""
    hosts = ["localhost", "127.0.0.1", "::1", socket.gethostname()]
    for host in extra:
        host = host.strip()
        if host and host not in ("0.0.0.0", "::") and host not in hosts:
            hosts.append(host)
    return hosts


def _san(host: str):
    from cryptography import x509

    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)


def _bundle_valid(ca_path: str, cert_path: str, key_path: str) -> bool:
    """Комплект готов и согласован: ca подписывает server.crt, key — его пара.

    Проверка нужна, потому что каталог может остаться от прерванной
    генерации (например, после kill -9 между записями файлов).
    """
    for path in (ca_path, cert_path, key_path):
        try:
            if os.path.getsize(path) == 0:
                return False
        except OSError:
            return False
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization

        with open(ca_path, "rb") as fh:
            ca = x509.load_pem_x509_certificate(fh.read())
        with open(cert_path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        with open(key_path, "rb") as fh:
            key = serialization.load_pem_private_key(fh.read(), password=None)
    except Exception:  # noqa: BLE001 — битый/недописанный файл = перегенерация
        return False

    if cert.issuer != ca.subject:
        return False
    algorithm = cert.signature_hash_algorithm
    if algorithm is None:
        return False
    try:
        # Для EC-подписи cryptography ждёт объект ECDSA, для RSA — padding+hash:
        # signature_algorithm_parameters отдаёт именно то, что нужно ключу CA.
        ca.public_key().verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            cert.signature_algorithm_parameters,
        )
    except Exception:  # noqa: BLE001 — подпись не сходится
        return False
    # Ключ и лист должны быть одной парой, иначе TLS-handshake упадёт.
    try:
        key_pub = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        cert_pub = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    except Exception:  # noqa: BLE001
        return False
    return key_pub == cert_pub


def _expires_within(path: str, days: int) -> bool:
    """True, если сертификат в `path` просрочен или истекает раньше чем через `days`.

    Битый/отсутствующий файл тоже даёт True: перевыпуск в этом случае безопасен
    (лишняя генерация), а вот пропустить перевыпуск — значит отдать клиенту
    сертификат, который не пройдёт верификацию.
    """
    from cryptography import x509

    try:
        with open(path, "rb") as fh:
            cert = x509.load_pem_x509_certificate(fh.read())
        not_after = cert.not_valid_after_utc
    except Exception:  # noqa: BLE001
        return True
    deadline = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days)
    return not_after <= deadline


def _write_atomic(path: str, data: bytes, mode: int = 0o644) -> None:
    """Записать файл через временный + os.replace: читатель видит либо старое,
    либо целое новое содержимое, но не половину."""
    directory = os.path.dirname(path) or "."
    fd, tmp_path = tempfile.mkstemp(dir=directory, prefix=".tmp-tls-")
    try:
        if hasattr(os, "fchmod"):  # POSIX; на Windows прав доступу немає
            os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp_path, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(tmp_path)
        raise


def ensure_self_signed(directory: str, hosts: list[str]) -> tuple[str, str, str]:
    """(ca.crt, server.crt, server.key) у directory; генерує або перевипускає лист.

    Генерація йде під файловим локом `<directory>/.lock`: два процеси, що
    стартують одночасно, не перезапишуть один одному ca.crt/server.crt (інакше
    клієнт отримав би лист, підписаний чужим CA, і не пройшов верифікацію).

    Валідний комплект з запасом більше LEAF_RENEW_BEFORE_DAYS не чіпається.
    Якщо лист прострочений або до `notAfter` лишилось менше
    LEAF_RENEW_BEFORE_DAYS днів, лист перевипускається наявним CA (`ca.key`),
    а `ca.crt` лишається тим самим — клієнти, що йому довіряють, нічого не
    помічають. Якщо `ca.key` немає (комплект від версії без перевипуску) або
    CA сам прострочений/істекає — будується новий комплект, і клієнтам треба
    оновити `ca.crt`. Зміна hosts на валідний комплект не впливає: SAN
    оновляться при найближчому перевипуску, примусово — видаліть каталог.
    """
    ca_path = os.path.join(directory, CA_CERT_NAME)
    cert_path = os.path.join(directory, SERVER_CERT_NAME)
    key_path = os.path.join(directory, SERVER_KEY_NAME)
    ca_key_path = os.path.join(directory, CA_KEY_NAME)

    os.makedirs(directory, exist_ok=True)
    with file_lock(os.path.join(directory, LOCK_NAME)):
        # Повторная проверка уже под локом: второй процесс мог всё сделать,
        # пока мы ждали.
        if not _bundle_valid(ca_path, cert_path, key_path):
            _generate(directory, hosts, ca_path, cert_path, key_path, ca_key_path)
        elif _expires_within(ca_path, LEAF_RENEW_BEFORE_DAYS):
            # Перевыпуск листа на протухающем CA бессмысленен: новый лист
            # унаследует тот же срок. Строим комплект заново.
            _generate(directory, hosts, ca_path, cert_path, key_path, ca_key_path)
        elif _expires_within(cert_path, LEAF_RENEW_BEFORE_DAYS):
            if not _renew_leaf(ca_path, ca_key_path, cert_path, key_path, hosts):
                _generate(directory, hosts, ca_path, cert_path, key_path, ca_key_path)
    return ca_path, cert_path, key_path


def _renew_leaf(
    ca_path: str, ca_key_path: str, cert_path: str, key_path: str, hosts: list[str]
) -> bool:
    """Перевыпустить лист тем же CA. False — CA-ключ недоступен/не пара.

    `ca.crt` не трогаем: он остаётся якорем доверия у клиентов. Записи —
    атомарные (`os.replace`), вызов — под локом ensure_self_signed.
    """
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    try:
        with open(ca_path, "rb") as fh:
            ca = x509.load_pem_x509_certificate(fh.read())
        with open(ca_key_path, "rb") as fh:
            ca_key = serialization.load_pem_private_key(fh.read(), password=None)
    except Exception:  # noqa: BLE001 — нет ключа CA = перевыпуск невозможен
        return False

    der = serialization.Encoding.DER
    spki = serialization.PublicFormat.SubjectPublicKeyInfo
    try:
        if ca_key.public_key().public_bytes(der, spki) != ca.public_key().public_bytes(der, spki):
            return False  # ca.key от другого CA — подпись не сойдётся
        ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca.public_key())
        now = datetime.datetime.now(datetime.timezone.utc)
        key, cert = _build_leaf(now, ca_key, ca.subject, ca_ski, hosts)
    except Exception:  # noqa: BLE001
        return False

    _write_atomic(key_path, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ), mode=0o600)
    _write_atomic(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    return True


def _generate(
    directory: str, hosts: list[str], ca_path: str, cert_path: str, key_path: str,
    ca_key_path: str,
) -> None:
    from cryptography.hazmat.primitives import serialization

    now = datetime.datetime.now(datetime.timezone.utc)
    ca_key, ca_name, ca_ski, ca_cert = _build_ca(now)
    key, cert = _build_leaf(now, ca_key, ca_name, ca_ski, hosts)

    # Пишемо через os.replace: частковий файл ніколи не стає видимим.
    _write_atomic(key_path, key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ), mode=0o600)
    _write_atomic(cert_path, cert.public_bytes(serialization.Encoding.PEM))
    # ca.key зберігаємо, щоб наступний перевыпуск листа не ламав довіру до CA.
    _write_atomic(ca_key_path, ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ), mode=0o600)
    # ca.crt пишемо останнім: він замикає комплект (порядок збережено).
    _write_atomic(ca_path, ca_cert.public_bytes(serialization.Encoding.PEM))


def _build_ca(now: datetime.datetime):
    """Новий CA: (ключ, ім'я, SubjectKeyIdentifier, сертифікат)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "mcp-baf local CA")])
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key())
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name).issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=CA_VALIDITY_DAYS))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(ca_ski, critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    return ca_key, ca_name, ca_ski, ca_cert


def _build_leaf(now: datetime.datetime, ca_key, ca_name, ca_ski, hosts: list[str]):
    """Серверний лист, підписаний `ca_key`: (ключ, сертифікат)."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    cert = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])]))
        .issuer_name(ca_name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        # 825 днів — межа, яку ще приймають клієнти Apple/браузери для листа.
        .not_valid_after(now + datetime.timedelta(days=LEAF_VALIDITY_DAYS))
        .add_extension(x509.SubjectAlternativeName([_san(h) for h in hosts]), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(ca_ski), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    return key, cert
