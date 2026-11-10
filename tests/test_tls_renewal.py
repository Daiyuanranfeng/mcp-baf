"""Перевыпуск серверного листа по notAfter (issue #37).

Лист живёт 825 дней, но `ensure_self_signed` раньше проверял только связность
комплекта: протухший или почти протухший сертификат оставался на диске, и
сервер тихо поднимался с ним. Теперь лист перевыпускается заранее (за
LEAF_RENEW_BEFORE_DAYS дней) тем же CA, `ca.crt` не меняется.
"""

import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from mcp_baf.tls import (
    CA_CERT_NAME,
    CA_KEY_NAME,
    LEAF_RENEW_BEFORE_DAYS,
    SERVER_CERT_NAME,
    SERVER_KEY_NAME,
    _san,
    ensure_self_signed,
    self_signed_hosts,
)

HOSTS = self_signed_hosts("mcp-baf")
UTC = datetime.timezone.utc


def _digest(path: str) -> str:
    import hashlib

    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _load_cert(path: str):
    with open(path, "rb") as fh:
        return x509.load_pem_x509_certificate(fh.read())


def _load_ca_key(path: str):
    with open(path, "rb") as fh:
        return serialization.load_pem_private_key(fh.read(), password=None)


def _write(path: str, data: bytes, mode: int = 0o644) -> None:
    with open(path, "wb") as fh:
        fh.write(data)
    os.chmod(path, mode)


def _sign_leaf(ca_cert, ca_key, key, not_before, not_after, hosts=HOSTS):
    ca_ski = x509.SubjectKeyIdentifier.from_public_key(ca_cert.public_key())
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0])]))
        .issuer_name(ca_cert.subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
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


def _rewrite_leaf(directory: str, not_before, not_after, hosts=HOSTS) -> None:
    """Положить в каталог лист с заданными сроками, подписанный текущим CA."""
    ca = _load_cert(os.path.join(directory, CA_CERT_NAME))
    ca_key = _load_ca_key(os.path.join(directory, CA_KEY_NAME))
    key = ec.generate_private_key(ec.SECP256R1())
    cert = _sign_leaf(ca, ca_key, key, not_before, not_after, hosts)
    _write(os.path.join(directory, SERVER_KEY_NAME), key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ), mode=0o600)
    _write(os.path.join(directory, SERVER_CERT_NAME),
           cert.public_bytes(serialization.Encoding.PEM))


def _make_ca(days: int):
    """Новый самоподписанный CA с заданным сроком жизни."""
    now = datetime.datetime.now(UTC)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "short-lived CA")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=False, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False,
        ), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def _assert_bundle_consistent(directory: str) -> None:
    ca = _load_cert(os.path.join(directory, CA_CERT_NAME))
    cert = _load_cert(os.path.join(directory, SERVER_CERT_NAME))
    key = _load_ca_key(os.path.join(directory, SERVER_KEY_NAME))
    assert cert.issuer == ca.subject
    ca.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes, cert.signature_algorithm_parameters
    )
    der, spki = serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    assert key.public_key().public_bytes(der, spki) == cert.public_key().public_bytes(der, spki)


def _fresh_enough(path: str) -> bool:
    not_after = _load_cert(path).not_valid_after_utc
    return not_after > datetime.datetime.now(UTC) + datetime.timedelta(days=LEAF_RENEW_BEFORE_DAYS - 1)


def test_expired_leaf_regenerated_keeping_ca(tmp_path):
    directory = str(tmp_path)
    ca, cert, _key = ensure_self_signed(directory, HOSTS)
    ca_digest = _digest(ca)

    now = datetime.datetime.now(UTC)
    _rewrite_leaf(directory, now - datetime.timedelta(days=30), now - datetime.timedelta(days=1))
    expired_digest = _digest(cert)

    ensure_self_signed(directory, HOSTS)

    assert _digest(cert) != expired_digest, "просроченный лист остался на диске"
    assert _digest(ca) == ca_digest, "CA пересоздан, хотя должен был остаться"
    assert _fresh_enough(cert)
    _assert_bundle_consistent(directory)


def test_leaf_expiring_soon_regenerated_keeping_ca(tmp_path):
    directory = str(tmp_path)
    ca, cert, _key = ensure_self_signed(directory, HOSTS)
    ca_digest = _digest(ca)

    now = datetime.datetime.now(UTC)
    # Меньше LEAF_RENEW_BEFORE_DAYS, но ещё валиден — тихий отказ именно тут.
    _rewrite_leaf(directory, now - datetime.timedelta(days=5), now + datetime.timedelta(days=5))

    ensure_self_signed(directory, HOSTS)

    assert _digest(ca) == ca_digest
    assert _fresh_enough(cert)
    _assert_bundle_consistent(directory)
    # SAN перевыпущенного листа — из переданных hosts, не из старого листа.
    san = _load_cert(cert).extensions.get_extension_for_class(x509.SubjectAlternativeName)
    names = set(san.value.get_values_for_type(x509.DNSName))
    assert "mcp-baf" in names and "localhost" in names


def test_fresh_bundle_untouched(tmp_path):
    directory = str(tmp_path)
    ca, cert, key = ensure_self_signed(directory, HOSTS)
    ca_key = os.path.join(directory, CA_KEY_NAME)
    before = {p: _digest(p) for p in (ca, cert, key, ca_key)}
    not_after = _load_cert(cert).not_valid_after_utc

    ensure_self_signed(directory, HOSTS)

    assert {p: _digest(p) for p in (ca, cert, key, ca_key)} == before
    assert _load_cert(cert).not_valid_after_utc == not_after


def test_legacy_bundle_without_ca_key_rebuilds_ca(tmp_path):
    """Комплект от версии без ca.key: лист перевыпустить нечем → новый CA."""
    directory = str(tmp_path)
    ca, cert, _key = ensure_self_signed(directory, HOSTS)
    ca_digest = _digest(ca)

    now = datetime.datetime.now(UTC)
    _rewrite_leaf(directory, now - datetime.timedelta(days=30), now - datetime.timedelta(days=1))
    os.unlink(os.path.join(directory, CA_KEY_NAME))

    ensure_self_signed(directory, HOSTS)

    assert _digest(ca) != ca_digest
    assert os.path.exists(os.path.join(directory, CA_KEY_NAME))
    _assert_bundle_consistent(directory)
    assert _fresh_enough(cert)


def test_concurrent_renewal_produces_one_leaf(tmp_path):
    """Протухший лист + параллельный старт: перевыпуск ровно один, CA тот же."""
    import threading

    directory = str(tmp_path)
    ca, cert, _key = ensure_self_signed(directory, HOSTS)
    ca_digest = _digest(ca)
    now = datetime.datetime.now(UTC)
    _rewrite_leaf(directory, now - datetime.timedelta(days=30), now - datetime.timedelta(days=1))

    results, errors = [], []

    def run():
        try:
            _ca, cert_path, _k = ensure_self_signed(directory, HOSTS)
            results.append(_digest(cert_path))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, errors
    assert len(results) == 6
    assert len(set(results)) == 1, "параллельные старты перевыпустили лист больше одного раза"
    assert _digest(ca) == ca_digest
    assert _fresh_enough(cert)
    _assert_bundle_consistent(directory)


def test_ca_near_expiry_rebuilds_whole_bundle(tmp_path):
    """Протухающий CA: новый лист унаследовал бы его срок, поэтому новый комплект."""
    directory = str(tmp_path)
    ensure_self_signed(directory, HOSTS)
    ca_digest = _digest(os.path.join(directory, CA_CERT_NAME))

    ca_key, ca_cert = _make_ca(days=10)
    _write(os.path.join(directory, CA_CERT_NAME), ca_cert.public_bytes(serialization.Encoding.PEM))
    _write(os.path.join(directory, CA_KEY_NAME), ca_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ), mode=0o600)
    now = datetime.datetime.now(UTC)
    _rewrite_leaf(directory, now - datetime.timedelta(days=1), now + datetime.timedelta(days=9))

    ensure_self_signed(directory, HOSTS)

    assert _digest(os.path.join(directory, CA_CERT_NAME)) != ca_digest
    _assert_bundle_consistent(directory)
    assert _fresh_enough(os.path.join(directory, SERVER_CERT_NAME))
    assert _load_cert(os.path.join(directory, CA_CERT_NAME)).not_valid_after_utc > (
        datetime.datetime.now(UTC) + datetime.timedelta(days=LEAF_RENEW_BEFORE_DAYS)
    )
