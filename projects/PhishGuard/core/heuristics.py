"""Heuristic signal generation for phishing risk detection."""

from __future__ import annotations

from core.domain_analyzer import detect_brand_impersonation
from core.models import AnalysisContext, Signal
from utils.constants import (
    HIGH_RISK_TLDS,
    IMPACT_ALLOWLISTED_DOMAIN,
    IMPACT_AT_SYMBOL,
    IMPACT_HIGH_ENTROPY,
    IMPACT_HIGH_RISK_TLD,
    IMPACT_HSTS_PRESENT,
    IMPACT_INVALID_SSL,
    IMPACT_IP_IN_URL,
    IMPACT_KEYWORD_CAP,
    IMPACT_NO_HTTPS,
    IMPACT_PUNYCODE,
    IMPACT_REDIRECTS_HIGH,
    IMPACT_REDIRECTS_MEDIUM,
    IMPACT_SELF_SIGNED_SSL,
    IMPACT_SENSITIVE_KEYWORD,
    IMPACT_SPECIAL_CHARS_HIGH,
    IMPACT_SPECIAL_CHARS_LOW,
    IMPACT_SPECIAL_CHARS_MEDIUM,
    IMPACT_SSL_EXPIRING_SOON,
    IMPACT_SUBDOMAIN_HIGH,
    IMPACT_SUBDOMAIN_MEDIUM,
    IMPACT_URL_LENGTH_HIGH,
    IMPACT_URL_LENGTH_MEDIUM,
    IMPACT_URL_SHORTENER,
    IMPACT_VALID_TRUSTED_SSL,
    SSL_EXPIRY_SOON_DAYS,
    SENSITIVE_KEYWORDS,
    URL_SHORTENERS,
)


def generate_risk_signals(context: AnalysisContext) -> list[Signal]:
    """Generate positive risk signals across tier A/B/C heuristics."""
    parsed = context.parsed_url
    domain = context.domain_info
    network = context.network_info
    ssl_info = context.ssl_info

    signals: list[Signal] = []

    # Tier A: strong signals
    if parsed.is_ip:
        signals.append(
            Signal(
                id="ip_in_url",
                description="URL uses an IP address instead of a domain.",
                tier="A",
                impact=IMPACT_IP_IN_URL,
                evidence=f"Hostname '{parsed.hostname}' is an IP literal.",
            )
        )

    if parsed.has_at_symbol:
        signals.append(
            Signal(
                id="at_symbol",
                description="'@' symbol appears in URL.",
                tier="A",
                impact=IMPACT_AT_SYMBOL,
                evidence="'@' found in URL, often used to obscure real destination.",
            )
        )

    if parsed.contains_punycode:
        signals.append(
            Signal(
                id="punycode",
                description="Punycode pattern detected in hostname.",
                tier="A",
                impact=IMPACT_PUNYCODE,
                evidence=f"Hostname '{parsed.hostname}' contains 'xn--'.",
            )
        )

    if network.redirect_count > 3:
        signals.append(
            Signal(
                id="redirect_chain_high",
                description="Excessive redirect chain detected.",
                tier="A",
                impact=IMPACT_REDIRECTS_HIGH,
                evidence=f"{network.redirect_count} redirects observed.",
            )
        )
    elif 2 <= network.redirect_count <= 3:
        signals.append(
            Signal(
                id="redirect_chain_medium",
                description="Multiple redirects detected.",
                tier="A",
                impact=IMPACT_REDIRECTS_MEDIUM,
                evidence=f"{network.redirect_count} redirects observed.",
            )
        )

    if parsed.scheme != "https":
        signals.append(
            Signal(
                id="no_https",
                description="URL does not use HTTPS.",
                tier="A",
                impact=IMPACT_NO_HTTPS,
                evidence=f"Scheme is '{parsed.scheme or 'none'}'.",
            )
        )

    # Tier B: moderate signals
    if ssl_info.checked and ssl_info.valid is False:
        signals.append(
            Signal(
                id="invalid_ssl",
                description="SSL certificate failed validation.",
                tier="B",
                impact=IMPACT_INVALID_SSL,
                evidence=ssl_info.inspection_error or "TLS verification failed.",
            )
        )

    if ssl_info.self_signed is True:
        signals.append(
            Signal(
                id="self_signed_ssl",
                description="Self-signed SSL certificate detected.",
                tier="B",
                impact=IMPACT_SELF_SIGNED_SSL,
                evidence=f"Issuer '{ssl_info.issuer or 'unknown'}' appears self-signed.",
            )
        )

    if ssl_info.expires_in_days is not None and ssl_info.expires_in_days < SSL_EXPIRY_SOON_DAYS:
        signals.append(
            Signal(
                id="ssl_expiring_soon",
                description="SSL certificate expires soon.",
                tier="B",
                impact=IMPACT_SSL_EXPIRING_SOON,
                evidence=f"Certificate expires in {ssl_info.expires_in_days} day(s).",
            )
        )

    if domain.tld in HIGH_RISK_TLDS:
        signals.append(
            Signal(
                id="high_risk_tld",
                description="Domain uses a high-risk TLD.",
                tier="B",
                impact=IMPACT_HIGH_RISK_TLD,
                evidence=f"TLD '.{domain.tld}' is in high-risk list.",
            )
        )

    if parsed.url_length > 120:
        signals.append(
            Signal(
                id="url_length_high",
                description="URL length is unusually long.",
                tier="B",
                impact=IMPACT_URL_LENGTH_HIGH,
                evidence=f"URL length is {parsed.url_length} characters.",
            )
        )
    elif parsed.url_length > 75:
        signals.append(
            Signal(
                id="url_length_medium",
                description="URL length is longer than typical.",
                tier="B",
                impact=IMPACT_URL_LENGTH_MEDIUM,
                evidence=f"URL length is {parsed.url_length} characters.",
            )
        )

    if domain.subdomain_depth >= 4:
        signals.append(
            Signal(
                id="subdomain_depth_high",
                description="Very deep subdomain chain detected.",
                tier="B",
                impact=IMPACT_SUBDOMAIN_HIGH,
                evidence=f"Subdomain depth is {domain.subdomain_depth}.",
            )
        )
    elif domain.subdomain_depth == 3:
        signals.append(
            Signal(
                id="subdomain_depth_medium",
                description="Deep subdomain chain detected.",
                tier="B",
                impact=IMPACT_SUBDOMAIN_MEDIUM,
                evidence=f"Subdomain depth is {domain.subdomain_depth}.",
            )
        )

    if domain.high_entropy:
        signals.append(
            Signal(
                id="high_entropy_domain",
                description="Domain label entropy is high.",
                tier="B",
                impact=IMPACT_HIGH_ENTROPY,
                evidence=f"Entropy score is {domain.entropy:.2f}.",
            )
        )

    brand_impact, brand, brand_evidence = detect_brand_impersonation(
        hostname=domain.hostname,
        path=parsed.path,
        base_domain=domain.base_domain,
    )
    if brand_impact > 0:
        signals.append(
            Signal(
                id="brand_impersonation",
                description="Potential brand impersonation detected.",
                tier="B",
                impact=brand_impact,
                evidence=brand_evidence or f"Brand keyword '{brand}' observed in suspicious context.",
            )
        )

    # Tier C: weak signals
    url_lower = parsed.normalized_url.lower()
    matched_keywords = [keyword for keyword in SENSITIVE_KEYWORDS if keyword in url_lower]
    if matched_keywords:
        keyword_impact = min(
            IMPACT_SENSITIVE_KEYWORD * len(matched_keywords),
            IMPACT_KEYWORD_CAP,
        )
        signals.append(
            Signal(
                id="sensitive_keywords",
                description="Sensitive phishing-related keywords found.",
                tier="C",
                impact=keyword_impact,
                evidence=f"Keywords: {', '.join(matched_keywords)}.",
            )
        )

    special_char_impact = 0
    if parsed.special_char_count >= 15:
        special_char_impact = IMPACT_SPECIAL_CHARS_HIGH
    elif parsed.special_char_count >= 10:
        special_char_impact = IMPACT_SPECIAL_CHARS_MEDIUM
    elif parsed.special_char_count >= 5:
        special_char_impact = IMPACT_SPECIAL_CHARS_LOW

    if special_char_impact > 0:
        signals.append(
            Signal(
                id="special_char_excess",
                description="URL contains an elevated number of special characters.",
                tier="C",
                impact=special_char_impact,
                evidence=f"Detected {parsed.special_char_count} special characters.",
            )
        )

    if domain.base_domain in URL_SHORTENERS:
        signals.append(
            Signal(
                id="url_shortener",
                description="URL shortener domain detected.",
                tier="C",
                impact=IMPACT_URL_SHORTENER,
                evidence=f"Base domain '{domain.base_domain}' is a known shortener.",
            )
        )

    return signals


def generate_counterweight_signals(context: AnalysisContext) -> list[Signal]:
    """Generate negative-impact counterweights to reduce false positives."""
    signals: list[Signal] = []
    domain = context.domain_info
    network = context.network_info
    ssl_info = context.ssl_info

    if ssl_info.valid is True and ssl_info.trusted_issuer is True:
        signals.append(
            Signal(
                id="trusted_ssl",
                description="Valid SSL certificate from trusted issuer.",
                tier="B",
                impact=IMPACT_VALID_TRUSTED_SSL,
                evidence=f"Issuer: {ssl_info.issuer or 'trusted CA'}.",
            )
        )

    if network.hsts_enabled:
        signals.append(
            Signal(
                id="hsts_present",
                description="HSTS header present.",
                tier="B",
                impact=IMPACT_HSTS_PRESENT,
                evidence="Strict-Transport-Security header observed.",
            )
        )

    if domain.is_allowlisted:
        signals.append(
            Signal(
                id="allowlisted_domain",
                description="Domain is in allowlist.",
                tier="B",
                impact=IMPACT_ALLOWLISTED_DOMAIN,
                evidence=f"Base domain '{domain.base_domain}' is explicitly allowlisted.",
            )
        )

    return signals