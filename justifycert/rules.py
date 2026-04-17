"""Certificate checks used by justifycert."""

from __future__ import annotations

import ssl
import socket
from datetime import datetime, timedelta, timezone
from typing import Optional

from cryptography import x509
from cryptography.x509.oid import ExtensionOID

EXPIRY_WARNING_DAYS = 30


def _issue(issue_type: str, severity: str, message: str) -> dict:
    return {
        "type": issue_type,
        "severity": severity,
        "message": message,
    }


def _cert_not_after(cert: x509.Certificate) -> datetime:
    not_after = getattr(cert, "not_valid_after_utc", None)
    if not_after is not None:
        return not_after
    not_after = cert.not_valid_after
    if not_after.tzinfo is None:
        return not_after.replace(tzinfo=timezone.utc)
    return not_after.astimezone(timezone.utc)


def _cert_not_before(cert: x509.Certificate) -> datetime:
    not_before = getattr(cert, "not_valid_before_utc", None)
    if not_before is not None:
        return not_before
    not_before = cert.not_valid_before
    if not_before.tzinfo is None:
        return not_before.replace(tzinfo=timezone.utc)
    return not_before.astimezone(timezone.utc)


def check_expiry(cert: x509.Certificate, warning_days: int = EXPIRY_WARNING_DAYS) -> Optional[dict]:
    now = datetime.now(timezone.utc)
    not_after = _cert_not_after(cert)
    if now > not_after:
        days = (now - not_after).days
        day_word = "day" if days == 1 else "days"
        return _issue("expired", "critical", f"Certificate expired {days} {day_word} ago — renew immediately")

    remaining = not_after - now
    if remaining <= timedelta(days=warning_days):
        days = max(0, remaining.days)
        day_word = "day" if days == 1 else "days"
        return _issue("expiring", "warning", f"Certificate expires in {days} {day_word} — renew soon")

    return None


def check_self_signed(cert: x509.Certificate) -> Optional[dict]:
    if cert.subject != cert.issuer:
        return None

    return _issue("self_signed", "critical", "Certificate is self-signed — replace it with a trusted certificate")


def check_san(cert: x509.Certificate) -> Optional[dict]:
    try:
        cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
    except x509.ExtensionNotFound:
        return _issue("missing_san", "warning", "Missing SAN extension — add the hostname to Subject Alternative Name")
    return None


def check_algorithm(cert: x509.Certificate) -> Optional[dict]:
    algorithm = getattr(cert.signature_hash_algorithm, "name", "").lower()
    if algorithm in {"sha1", "md5"}:
        return _issue(
            "weak_signature_algorithm",
            "critical",
            f"Weak signature algorithm {algorithm.upper()} — reissue with SHA-256 or stronger",
        )
    return None


def check_chain(
    cert: x509.Certificate,
    *,
    domain: Optional[str] = None,
    port: int = 443,
    timeout: float = 5.0,
) -> Optional[dict]:
    if not domain:
        return None

    context = ssl.create_default_context()
    context.check_hostname = False
    try:
        with socket.create_connection((domain, port), timeout=timeout) as raw_socket:
            with context.wrap_socket(raw_socket, server_hostname=domain):
                return None
    except ssl.SSLCertVerificationError as exc:
        return _issue(
            "chain",
            "critical",
            f"Certificate chain validation failed — check the issuing CA and intermediates ({exc.verify_message})",
        )
    except Exception as exc:
        return _issue("chain", "critical", f"Certificate chain validation failed — check the trust chain ({exc})")
