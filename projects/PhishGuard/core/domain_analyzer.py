"""Domain- and network-level analysis helpers."""

from __future__ import annotations

import logging
import re
from urllib.parse import urlparse

import requests

from core.models import DomainInfo, NetworkInfo, ParsedURL
from utils.constants import (
    ALLOWLISTED_DOMAINS,
    BRAND_KEYWORDS,
    DEFAULT_REQUEST_TIMEOUT,
    DEFAULT_USER_AGENT,
    HIGH_ENTROPY_THRESHOLD,
    IMPACT_BRAND_IN_PATH,
    IMPACT_BRAND_IN_SUBDOMAIN,
    LEGITIMATE_BRAND_DOMAINS,
)
from utils.entropy import shannon_entropy

LOGGER = logging.getLogger(__name__)
MULTIPART_TLDS = {"co.uk", "com.au", "co.jp", "com.br", "co.in"}
TOKEN_PATTERN = re.compile(r"[a-z0-9]+")


def _split_domain(hostname: str) -> tuple[str, str, str]:
    """Split hostname into base domain, subdomain, and TLD."""
    if not hostname or "." not in hostname:
        return hostname, "", ""

    labels = hostname.split(".")
    if len(labels) < 2:
        return hostname, "", ""

    tail = ".".join(labels[-2:])
    if tail in MULTIPART_TLDS and len(labels) >= 3:
        tld = tail
        base = f"{labels[-3]}.{tld}"
        subdomain = ".".join(labels[:-3])
        return base, subdomain, tld

    tld = labels[-1]
    base = f"{labels[-2]}.{tld}"
    subdomain = ".".join(labels[:-2])
    return base, subdomain, tld


def _tokenize(value: str) -> set[str]:
    """Return lowercase lexical tokens from host/path values."""
    return set(TOKEN_PATTERN.findall(value.lower()))


def analyze_domain(parsed_url: ParsedURL) -> DomainInfo:
    """Generate normalized domain features used by heuristic rules."""
    base_domain, subdomain, tld = _split_domain(parsed_url.hostname)
    subdomain_depth = 0 if not subdomain else len(subdomain.split("."))

    second_level_label = base_domain.split(".")[0] if base_domain else ""
    entropy_score = shannon_entropy(second_level_label)

    return DomainInfo(
        hostname=parsed_url.hostname,
        base_domain=base_domain,
        subdomain=subdomain,
        tld=tld.lower().lstrip("."),
        subdomain_depth=subdomain_depth,
        entropy=entropy_score,
        high_entropy=entropy_score >= HIGH_ENTROPY_THRESHOLD,
        is_allowlisted=base_domain in ALLOWLISTED_DOMAINS,
    )


def collect_network_info(url: str) -> NetworkInfo:
    """Collect redirect and HSTS metadata with safe exception handling."""
    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=DEFAULT_REQUEST_TIMEOUT,
            headers={"User-Agent": DEFAULT_USER_AGENT},
        )
        hsts_enabled = "strict-transport-security" in {
            key.lower() for key in response.headers.keys()
        }
        return NetworkInfo(
            redirect_count=len(response.history),
            hsts_enabled=hsts_enabled,
            fetch_error=None,
        )
    except requests.RequestException as exc:
        LOGGER.debug("Network info request failed for %s: %s", url, exc)
        return NetworkInfo(fetch_error=str(exc))


def detect_brand_impersonation(
    hostname: str,
    path: str,
    base_domain: str,
) -> tuple[int, str | None, str | None]:
    """Detect potential brand impersonation abuse in host/path.

    Returns:
        Tuple of (impact, brand, evidence). Impact is 0 when no finding exists.
    """
    host_tokens = _tokenize(hostname)
    path_tokens = _tokenize(path)

    for brand in BRAND_KEYWORDS:
        expected_domain = LEGITIMATE_BRAND_DOMAINS[brand]
        brand_in_host = brand in host_tokens
        brand_in_path = brand in path_tokens

        if not (brand_in_host or brand_in_path):
            continue

        # Legitimate brand domain should not trigger impersonation.
        if base_domain == expected_domain:
            continue

        if brand_in_host:
            evidence = (
                f"Brand keyword '{brand}' appears in hostname while base domain "
                f"is '{base_domain or 'unknown'}'."
            )
            return IMPACT_BRAND_IN_SUBDOMAIN, brand, evidence

        evidence = (
            f"Brand keyword '{brand}' appears in URL path while base domain "
            f"is '{base_domain or 'unknown'}'."
        )
        return IMPACT_BRAND_IN_PATH, brand, evidence

    return 0, None, None


def normalize_for_display(url: str) -> str:
    """Return URL in normalized display form with scheme and hostname case normalized."""
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    if not host:
        return url

    netloc = host
    if parsed.port:
        netloc = f"{host}:{parsed.port}"

    return parsed._replace(netloc=netloc).geturl()