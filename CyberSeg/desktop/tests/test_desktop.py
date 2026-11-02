import datetime
import os
import sys

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import cyberseg_desktop as app  # noqa: E402


def make_ca() -> tuple[bytes, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CyberSeg CA local 192.168.1.50")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now).not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM), cert


@pytest.mark.parametrize("raw, expected", [
    ("192.168.1.50", "192.168.1.50"),
    (" https://192.168.1.50/ ", "192.168.1.50"),
    ("192.168.1.50:443", "192.168.1.50"),
    ("192.168.1.50:8443", "192.168.1.50:8443"),
])
def test_server_address_is_normalised(raw, expected):
    assert app.normalise_server(raw) == expected


@pytest.mark.parametrize("raw", ["", "servidor.local", "192.168.1.300", "192.168.1.50:99999"])
def test_invalid_server_addresses_are_rejected(raw):
    with pytest.raises(app.ConnectionProblem):
        app.normalise_server(raw)


def test_fingerprint_matches_the_certificate_and_openssl_format():
    pem, cert = make_ca()
    expected = cert.fingerprint(hashes.SHA256()).hex().upper()
    printed = app.fingerprint(pem)
    assert printed.replace(":", "") == expected
    assert len(printed.split(":")) == 32
    assert app.fingerprint(b"junk\n" + pem + b"\ntrailer") == printed  # tolerant of surrounding text


def test_non_certificate_downloads_are_rejected():
    with pytest.raises(app.ConnectionProblem):
        app.pem_to_der(b"<html>no es un certificado</html>")


def test_browser_lookup_prefers_the_first_installed(tmp_path):
    edge = tmp_path / "msedge.exe"
    chrome = tmp_path / "chrome.exe"
    chrome.write_text("")
    assert app.find_browser([str(edge), str(chrome)]) == str(chrome)
    edge.write_text("")
    assert app.find_browser([str(edge), str(chrome)]) == str(edge)
    assert app.find_browser([str(tmp_path / "missing.exe")]) is None


def test_config_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(app, "APP_DIR", tmp_path)
    monkeypatch.setattr(app, "CONFIG", tmp_path / "config.json")
    assert app.load_config() == {}
    app.save_config({"server": "192.168.1.50", "fingerprint": "AA"})
    assert app.load_config()["server"] == "192.168.1.50"


def test_cli_reports_unreachable_servers(capsys):
    assert app.main(["--check", "192.0.2.1"]) == 1  # TEST-NET address: never reachable
    assert "No se pudo contactar" in capsys.readouterr().err
