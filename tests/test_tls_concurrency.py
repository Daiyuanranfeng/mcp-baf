"""Гонка генерации самоподписанного TLS-комплекта (issue #26).

Два процесса/потока, стартующие одновременно, не должны оставить в каталоге
ca.crt от одного процесса и server.crt от другого — иначе клиент не пройдёт
верификацию TLS.
"""

import hashlib
import os
import subprocess
import sys
import threading

import mcp_baf
from mcp_baf.tls import CA_CERT_NAME, SERVER_CERT_NAME, ensure_self_signed, self_signed_hosts

SRC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(mcp_baf.__file__)))
HOSTS = self_signed_hosts("mcp-baf")

_CHILD = """
import hashlib, sys
from mcp_baf.tls import ensure_self_signed, self_signed_hosts
d = sys.argv[1]
ca, cert, key = ensure_self_signed(d, self_signed_hosts("mcp-baf"))
print(hashlib.sha256(open(ca, "rb").read()).hexdigest(),
      hashlib.sha256(open(cert, "rb").read()).hexdigest())
"""


def _child_env():
    env = dict(os.environ)
    env["PYTHONPATH"] = SRC_DIR + os.pathsep + env.get("PYTHONPATH", "")
    return env


def _digest(path):
    with open(path, "rb") as fh:
        return hashlib.sha256(fh.read()).hexdigest()


def _assert_bundle_consistent(directory):
    """ca.crt подписывает server.crt, а server.key — пара к server.crt."""
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization

    with open(os.path.join(directory, CA_CERT_NAME), "rb") as fh:
        ca = x509.load_pem_x509_certificate(fh.read())
    with open(os.path.join(directory, SERVER_CERT_NAME), "rb") as fh:
        cert = x509.load_pem_x509_certificate(fh.read())
    with open(os.path.join(directory, "server.key"), "rb") as fh:
        key = serialization.load_pem_private_key(fh.read(), password=None)

    assert cert.issuer == ca.subject
    ca.public_key().verify(
        cert.signature, cert.tbs_certificate_bytes, cert.signature_algorithm_parameters
    )
    key_pub = key.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    cert_pub = cert.public_key().public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    assert key_pub == cert_pub


def test_concurrent_threads_share_one_bundle(tmp_path):
    directory = str(tmp_path)
    results = []
    errors = []

    def run():
        try:
            results.append(ensure_self_signed(directory, HOSTS))
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=run) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    assert not errors, errors
    assert len(results) == 8
    # Все потоки видят один и тот же комплект (перегенерации не было).
    assert {r[0] for r in results} == {os.path.join(directory, CA_CERT_NAME)}
    ca_digest = _digest(results[0][0])
    assert all(_digest(r[0]) == ca_digest for r in results)
    _assert_bundle_consistent(directory)


def test_concurrent_processes_share_one_bundle(tmp_path):
    directory = str(tmp_path)
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", _CHILD, directory],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=_child_env(),
        )
        for _ in range(3)
    ]
    outputs = []
    for proc in procs:
        out, err = proc.communicate(timeout=60)
        assert proc.returncode == 0, err
        outputs.append(out.strip())

    # У всех процессов одинаковые ca.crt и server.crt — значит, комплект
    # сгенерировал ровно один из них, остальные дождались лока.
    assert len(set(outputs)) == 1, outputs
    _assert_bundle_consistent(directory)
    assert os.path.exists(os.path.join(directory, ".lock"))


def test_existing_valid_bundle_not_regenerated(tmp_path):
    directory = str(tmp_path)
    ca, cert, key = ensure_self_signed(directory, HOSTS)
    before = {p: _digest(p) for p in (ca, cert, key)}

    ca2, cert2, key2 = ensure_self_signed(directory, HOSTS)
    assert (ca2, cert2, key2) == (ca, cert, key)
    assert {p: _digest(p) for p in (ca, cert, key)} == before


def test_incomplete_bundle_regenerated(tmp_path):
    directory = str(tmp_path)
    ca, cert, key = ensure_self_signed(directory, HOSTS)
    ca_digest = _digest(ca)

    # Прерванная генерация: ca.crt недописан, остальные файлы целы.
    with open(ca, "wb") as fh:
        fh.write(b"")

    ca2, cert2, key2 = ensure_self_signed(directory, HOSTS)
    assert _digest(ca2) != ca_digest
    _assert_bundle_consistent(directory)


def test_foreign_ca_not_trusted_after_regeneration(tmp_path):
    """ca.crt от чужого процесса (не подписывает server.crt) — перегенерация."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    directory = str(tmp_path)
    ca, cert, key = ensure_self_signed(directory, HOSTS)
    server_digest = _digest(cert)

    now = datetime.datetime.now(datetime.timezone.utc)
    foreign_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "foreign")])
    foreign = (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(foreign_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(foreign_key, hashes.SHA256())
    )
    with open(ca, "wb") as fh:
        fh.write(foreign.public_bytes(serialization.Encoding.PEM))

    ensure_self_signed(directory, HOSTS)
    _assert_bundle_consistent(directory)
    assert _digest(cert) != server_digest
