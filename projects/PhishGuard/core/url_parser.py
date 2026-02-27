"""URL normalization and parsing helpers."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlparse

from core.models import ParsedURL
from utils.constants import SPECIAL_CHAR_PATTERN


def ensure_scheme(raw_url: str) -> str:
    """Ensure URL has an explicit HTTP/HTTPS scheme.

    Args:
        raw_url: User-supplied URL.

    Returns:
        URL with scheme if missing.
    """
    candidate = raw_url.strip()
    if not candidate:
        return candidate

    parsed = urlparse(candidate)
    if parsed.scheme:
        return candidate

    return f"http://{candidate}"


def _is_ip_address(hostname: str) -> bool:
    """Return True when hostname is an IPv4 or IPv6 literal."""
    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def parse_url(raw_url: str) -> ParsedURL:
    """Parse and normalize URL into structured fields.

    Args:
        raw_url: User-supplied URL string.

    Returns:
        ParsedURL object containing normalized URL metadata.
    """
    normalized_url = ensure_scheme(raw_url)
    parsed = urlparse(normalized_url)

    hostname = (parsed.hostname or "").strip().lower().rstrip(".")
    contains_punycode = "xn--" in hostname
    has_at_symbol = "@" in normalized_url
    is_ip = _is_ip_address(hostname)

    special_char_count = len(re.findall(SPECIAL_CHAR_PATTERN, normalized_url))

    return ParsedURL(
        original_url=raw_url,
        normalized_url=normalized_url,
        scheme=parsed.scheme.lower(),
        hostname=hostname,
        path=parsed.path or "",
        query=parsed.query or "",
        has_at_symbol=has_at_symbol,
        contains_punycode=contains_punycode,
        is_ip=is_ip,
        url_length=len(normalized_url),
        special_char_count=special_char_count,
    )