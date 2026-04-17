"""Core certificate loading and analysis."""

from __future__ import annotations

import socket
import ssl
from pathlib import Path
from typing import Optional

from cryptography import x509

from .rules import (
    _cert_not_after,
    _cert_not_before,
    check_algorithm,
    check_chain,
    check_expiry,
    check_san,
    check_self_signed,
)


def load_pem_certificate(path: str | Path) -> x509.Certificate:
    pem_data = Path(path).read_bytes()
    return x509.load_pem_x509_certificate(pem_data)


def load_domain_certificate(domain: str, port: int = 443, timeout: float = 5.0) -> x509.Certificate:
    context = ssl._create_unverified_context()
    with socket.create_connection((domain, port), timeout=timeout) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=domain) as tls_socket:
            der_cert = tls_socket.getpeercert(binary_form=True)
    return x509.load_der_x509_certificate(der_cert)


def _certificate_summary(cert: x509.Certificate) -> dict:
    return {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "not_before": _cert_not_before(cert).isoformat(),
        "not_after": _cert_not_after(cert).isoformat(),
        "signature_algorithm": getattr(cert.signature_hash_algorithm, "name", None),
    }


def analyze_certificate(cert: x509.Certificate, *, domain: Optional[str] = None, port: int = 443, timeout: float = 5.0) -> dict:
    issues = []
    for check in (
        check_expiry,
        check_self_signed,
        check_san,
        check_algorithm,
    ):
        issue = check(cert)
        if issue:
            issues.append(issue)

    chain_issue = check_chain(cert, domain=domain, port=port, timeout=timeout)
    if chain_issue:
        issues.append(chain_issue)

    result = {
        "valid": not issues,
        "issues": issues,
    }
    result.update(_certificate_summary(cert))
    return result


def analyze_domain(domain: str, port: int = 443, timeout: float = 5.0) -> dict:
    cert = load_domain_certificate(domain, port=port, timeout=timeout)
    return analyze_certificate(cert, domain=domain, port=port, timeout=timeout)


def analyze_pem_file(path: str | Path) -> dict:
    cert = load_pem_certificate(path)
    return analyze_certificate(cert)


def analyze_cert(domain: str, port: int = 443, timeout: float = 5.0) -> dict:
    """Analyze a certificate by fetching it from a domain."""
    return analyze_domain(domain, port=port, timeout=timeout)
