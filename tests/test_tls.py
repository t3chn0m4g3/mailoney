"""
Tests for TLS certificate handling.
"""
import os

import pytest
from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from mailoney.config import TlsConfig
from mailoney.tls import ensure_tls_material


def _certificate(path):
    return x509.load_pem_x509_certificate(path.read_bytes())


def _dns_sans(certificate):
    return certificate.extensions.get_extension_for_oid(
        ExtensionOID.SUBJECT_ALTERNATIVE_NAME
    ).value.get_values_for_type(x509.DNSName)


def test_tls_material_is_generated_and_reused(tmp_path):
    config = TlsConfig(
        cert_file=str(tmp_path / "log" / "tls" / "server.crt"),
        key_file=str(tmp_path / "log" / "tls" / "server.key"),
    )

    first = ensure_tls_material(config, "mail01.localdomain")
    assert first is not None
    cert_bytes = (tmp_path / "log" / "tls" / "server.crt").read_bytes()
    key_bytes = (tmp_path / "log" / "tls" / "server.key").read_bytes()

    second = ensure_tls_material(config, "mail01.localdomain")
    assert second == first
    assert (tmp_path / "log" / "tls" / "server.crt").read_bytes() == cert_bytes
    assert (tmp_path / "log" / "tls" / "server.key").read_bytes() == key_bytes

    certificate = x509.load_pem_x509_certificate(cert_bytes)
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert common_names[0].value == "mail01.localdomain"

    assert _dns_sans(certificate) == ["mail01.localdomain"]
    assert os.stat(tmp_path / "log" / "tls" / "server.key").st_mode & 0o777 == 0o600


def test_tls_material_regenerates_when_server_name_changes(tmp_path):
    cert_file = tmp_path / "log" / "tls" / "server.crt"
    key_file = tmp_path / "log" / "tls" / "server.key"
    config = TlsConfig(cert_file=str(cert_file), key_file=str(key_file))

    ensure_tls_material(config, "old.example.net")
    old_cert_bytes = cert_file.read_bytes()
    old_key_bytes = key_file.read_bytes()

    material = ensure_tls_material(config, "new.example.net")

    assert material is not None
    assert cert_file.read_bytes() != old_cert_bytes
    assert key_file.read_bytes() != old_key_bytes
    certificate = _certificate(cert_file)
    common_names = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    assert common_names[0].value == "new.example.net"
    assert _dns_sans(certificate) == ["new.example.net"]


def test_tls_material_rejects_mismatched_cert_when_auto_generate_is_disabled(tmp_path):
    cert_file = tmp_path / "log" / "tls" / "server.crt"
    key_file = tmp_path / "log" / "tls" / "server.key"
    generate_config = TlsConfig(cert_file=str(cert_file), key_file=str(key_file))
    strict_config = TlsConfig(
        auto_generate=False,
        cert_file=str(cert_file),
        key_file=str(key_file),
    )

    ensure_tls_material(generate_config, "old.example.net")

    with pytest.raises(ValueError, match="does not match server_name"):
        ensure_tls_material(strict_config, "new.example.net")
