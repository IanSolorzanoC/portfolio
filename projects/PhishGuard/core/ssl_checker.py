"""SSL certificate inspection utilities."""

from __future__ import annotations

import logging
import socket
import ssl
from datetime import datetime, timezone

from core.models import SSLInfo

LOGGER = logging.getLogger(__name__)


def _flatten_name(name: tuple[tuple[tuple[str, str], ...], ...] | None) -> dict[str, str]:
    """Flatten OpenSSL name tuples into a simple dictionary."""
    result: dict[str, str] = {}
    if not name:
        return result

    for rdn in name:
        for key, value in rdn:
            result[key] = value
    return result


def _parse_expiry_days(certificate: dict[str, object]) -> int | None:
    """Compute remaining certificate lifetime in whole days."""
    not_after = certificate.get("notAfter")
    if not isinstance(not_after, str):
        return None

    try:
        expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z").replace(
            tzinfo=timezone.utc
        )
        now = datetime.now(tz=timezone.utc)
        return (expiry - now).days
    except ValueError:
        return None


def _is_self_signed(certificate: dict[str, object]) -> bool | None:
    """Best-effort self-signed inference from subject/issuer equality."""
    issuer = _flatten_name(certificate.get("issuer"))
    subject = _flatten_name(certificate.get("subject"))
    if not issuer or not subject:
        return None

    return issuer == subject


def _extract_issuer(certificate: dict[str, object]) -> str | None:
    """Extract issuer common name for display/evidence."""
    issuer = _flatten_name(certificate.get("issuer"))
    if not issuer:
        return None

    return issuer.get("commonName") or issuer.get("organizationName")


def _fetch_certificate(hostname: str, verify: bool, timeout: int) -> dict[str, object]:
    """Fetch peer certificate from hostname on port 443."""
    context = ssl.create_default_context() if verify else ssl._create_unverified_context()

    with socket.create_connection((hostname, 443), timeout=timeout) as tcp_socket:
        with context.wrap_socket(tcp_socket, server_hostname=hostname) as tls_socket:
            return tls_socket.getpeercert()


def inspect_ssl(hostname: str, timeout: int = 5) -> SSLInfo:
    """Inspect SSL certificate validity/trust, safely handling network failures."""
    if not hostname:
        return SSLInfo(checked=False, inspection_error="Hostname is empty.")

    ssl_info = SSLInfo(checked=True)

    try:
        certificate = _fetch_certificate(hostname, verify=True, timeout=timeout)
        ssl_info.valid = True
        ssl_info.trusted_issuer = True
        ssl_info.self_signed = _is_self_signed(certificate)
        ssl_info.expires_in_days = _parse_expiry_days(certificate)
        ssl_info.issuer = _extract_issuer(certificate)
        return ssl_info
    except ssl.SSLCertVerificationError as exc:
        ssl_info.valid = False
        ssl_info.trusted_issuer = False
        ssl_info.inspection_error = str(exc)
        LOGGER.debug("SSL verification failed for %s: %s", hostname, exc)
    except ssl.SSLError as exc:
        ssl_info.valid = False
        ssl_info.trusted_issuer = False
        ssl_info.inspection_error = str(exc)
        LOGGER.debug("SSL handshake failed for %s: %s", hostname, exc)
    except (socket.timeout, OSError) as exc:
        # Connectivity failures are treated as unknown SSL state, not invalid certs.
        ssl_info.valid = None
        ssl_info.trusted_issuer = None
        ssl_info.inspection_error = str(exc)
        LOGGER.debug("SSL connectivity failed for %s: %s", hostname, exc)

    # Best-effort unverified fetch to still gather expiry and self-signed evidence.
    try:
        certificate = _fetch_certificate(hostname, verify=False, timeout=timeout)
        ssl_info.self_signed = _is_self_signed(certificate)
        ssl_info.expires_in_days = _parse_expiry_days(certificate)
        ssl_info.issuer = _extract_issuer(certificate)
    except (socket.timeout, OSError, ssl.SSLError) as exc:
        LOGGER.debug("Fallback cert fetch failed for %s: %s", hostname, exc)

    return ssl_info
