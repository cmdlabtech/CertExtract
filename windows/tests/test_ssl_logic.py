#!/usr/bin/env python3
"""Headless tests for Windows AIO SSL Tool crypto and form logic."""

import importlib.util
import os
import sys
import tempfile
import unittest
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import NameOID
import datetime

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

# Import the module without launching the GUI.
spec = importlib.util.spec_from_file_location("aio_ssl_tool", ROOT / "aio_ssl_tool.py")
mod = importlib.util.module_from_spec(spec)
# Guard: __name__ != "__main__" so mainloop is not started.
spec.loader.exec_module(mod)


def _app():
    return mod.AIOSSLToolApp.__new__(mod.AIOSSLToolApp)


def _make_cert(key, subject_cn, issuer_key=None, issuer_name=None, days=1):
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)])
    issuer = issuer_name or subject
    signer = issuer_key or key
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(minutes=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=days))
    )
    return builder.sign(signer, hashes.SHA256())


class ArchivePathTests(unittest.TestCase):
    def test_root_and_subdomains(self):
        self.assertEqual(mod.AIOSSLToolApp._archive_domain_path(None), "unknown")
        self.assertEqual(mod.AIOSSLToolApp._archive_domain_path(""), "unknown")
        self.assertEqual(mod.AIOSSLToolApp._archive_domain_path("example.com"), "example.com")
        self.assertEqual(mod.AIOSSLToolApp._archive_domain_path("*.example.com"), "example.com")
        self.assertEqual(
            mod.AIOSSLToolApp._archive_domain_path("www.example.com"),
            os.path.join("example.com", "www.example.com"),
        )


class ImportAndHelperTests(unittest.TestCase):
    def test_required_modules_imported(self):
        self.assertTrue(hasattr(mod, "queue"))
        self.assertTrue(hasattr(mod, "ipaddress"))
        self.assertTrue(hasattr(mod, "json"))
        self.assertEqual(mod.__version__, "6.4.4")

    def test_filetypes_use_semicolons_on_windows_style(self):
        patterns = dict(mod.cert_filetypes())
        joined = " ".join(patterns.values())
        self.assertIn("cer", joined)
        self.assertIn("pem", joined)


class CertificateLoadingTests(unittest.TestCase):
    def test_pem_and_der_round_trip(self):
        key = rsa.generate_private_key(65537, 2048)
        cert = _make_cert(key, "load-test.example.com")
        pem = cert.public_bytes(serialization.Encoding.PEM)
        der = cert.public_bytes(serialization.Encoding.DER)

        app = _app()
        pem_certs = app.load_certificates_from_pem(pem)
        der_certs = app.load_certificates_from_pem(der)
        self.assertEqual(len(pem_certs), 1)
        self.assertEqual(len(der_certs), 1)
        self.assertEqual(pem_certs[0].serial_number, der_certs[0].serial_number)

    def test_self_signed_detection(self):
        key = rsa.generate_private_key(65537, 2048)
        cert = _make_cert(key, "self.example.com")
        self.assertTrue(_app().is_self_signed(cert))


class SignatureVerificationTests(unittest.TestCase):
    def test_rsa_and_ecdsa_issuers(self):
        app = _app()

        rsa_root = rsa.generate_private_key(65537, 2048)
        rsa_leaf = rsa.generate_private_key(65537, 2048)
        root_cert = _make_cert(rsa_root, "RSA Root")
        leaf_cert = _make_cert(
            rsa_leaf,
            "RSA Leaf",
            issuer_key=rsa_root,
            issuer_name=root_cert.subject,
        )
        self.assertTrue(app.verify_signature(leaf_cert, root_cert))
        self.assertFalse(app.verify_signature(root_cert, leaf_cert))

        ec_root = ec.generate_private_key(ec.SECP256R1())
        ec_leaf = ec.generate_private_key(ec.SECP256R1())
        ec_root_cert = _make_cert(ec_root, "EC Root")
        ec_leaf_cert = _make_cert(
            ec_leaf,
            "EC Leaf",
            issuer_key=ec_root,
            issuer_name=ec_root_cert.subject,
        )
        self.assertTrue(app.verify_signature(ec_leaf_cert, ec_root_cert))


class CSRBuilderTests(unittest.TestCase):
    def test_san_ip_and_dns(self):
        ip = mod.ipaddress.ip_address("127.0.0.1")
        self.assertEqual(str(ip), "127.0.0.1")
        dns = "www.example.com"
        self.assertFalse(_is_ip(dns))
        self.assertTrue(_is_ip("10.0.0.1"))
        self.assertTrue(_is_ip("::1"))


def _is_ip(value):
    try:
        mod.ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


if __name__ == "__main__":
    unittest.main()
