"""Application constants for PhishGuard heuristics and scoring."""

from __future__ import annotations

from typing import Final

# Tier A signals
IMPACT_IP_IN_URL: Final[int] = 30
IMPACT_AT_SYMBOL: Final[int] = 35
IMPACT_PUNYCODE: Final[int] = 25
IMPACT_REDIRECTS_MEDIUM: Final[int] = 10
IMPACT_REDIRECTS_HIGH: Final[int] = 20
IMPACT_NO_HTTPS: Final[int] = 20

# Tier B signals
IMPACT_INVALID_SSL: Final[int] = 25
IMPACT_SELF_SIGNED_SSL: Final[int] = 20
IMPACT_SSL_EXPIRING_SOON: Final[int] = 10
IMPACT_HIGH_RISK_TLD: Final[int] = 8
IMPACT_URL_LENGTH_MEDIUM: Final[int] = 5
IMPACT_URL_LENGTH_HIGH: Final[int] = 10
IMPACT_SUBDOMAIN_MEDIUM: Final[int] = 5
IMPACT_SUBDOMAIN_HIGH: Final[int] = 10
IMPACT_HIGH_ENTROPY: Final[int] = 10
IMPACT_BRAND_IN_PATH: Final[int] = 20
IMPACT_BRAND_IN_SUBDOMAIN: Final[int] = 25

# Tier C signals
IMPACT_SENSITIVE_KEYWORD: Final[int] = 3
IMPACT_KEYWORD_CAP: Final[int] = 10
IMPACT_SPECIAL_CHARS_LOW: Final[int] = 2
IMPACT_SPECIAL_CHARS_MEDIUM: Final[int] = 4
IMPACT_SPECIAL_CHARS_HIGH: Final[int] = 6
IMPACT_SPECIAL_CHAR_CAP: Final[int] = 8
IMPACT_URL_SHORTENER: Final[int] = 8

# Counterweights
IMPACT_VALID_TRUSTED_SSL: Final[int] = -8
IMPACT_HSTS_PRESENT: Final[int] = -8
IMPACT_ALLOWLISTED_DOMAIN: Final[int] = -35

# Scoring gates
TIER_C_DEFAULT_CAP: Final[int] = 26
TIER_C_NO_TIER_A_CAP: Final[int] = 8
MAX_RISK_SCORE: Final[int] = 100
MIN_RISK_SCORE: Final[int] = 0

# Confidence model
BASE_CONFIDENCE: Final[float] = 0.30
CONF_TIER_A: Final[float] = 0.15
CONF_TIER_B: Final[float] = 0.08
CONF_TIER_C: Final[float] = 0.03
MAX_CONFIDENCE: Final[float] = 0.95

# Classification thresholds
LOW_MAX: Final[int] = 24
MEDIUM_MAX: Final[int] = 49
HIGH_MAX: Final[int] = 74

# Domain and lexical heuristics
HIGH_ENTROPY_THRESHOLD: Final[float] = 3.50
SSL_EXPIRY_SOON_DAYS: Final[int] = 7
SPECIAL_CHAR_PATTERN: Final[str] = r"[^a-zA-Z0-9:/?&.=_%\-]"

HIGH_RISK_TLDS: Final[set[str]] = {"xyz", "top", "click", "tk"}
SENSITIVE_KEYWORDS: Final[tuple[str, ...]] = (
    "login",
    "verify",
    "secure",
    "update",
    "password",
)

BRAND_KEYWORDS: Final[tuple[str, ...]] = (
    "paypal",
    "microsoft",
    "google",
    "apple",
    "netflix",
    "amazon",
    "meta",
    "instagram",
    "whatsapp",
    "binance",
)

LEGITIMATE_BRAND_DOMAINS: Final[dict[str, str]] = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "google": "google.com",
    "apple": "apple.com",
    "netflix": "netflix.com",
    "amazon": "amazon.com",
    "meta": "meta.com",
    "instagram": "instagram.com",
    "whatsapp": "whatsapp.com",
    "binance": "binance.com",
}

ALLOWLISTED_DOMAINS: Final[set[str]] = {
    "google.com",
    "microsoft.com",
    "apple.com",
    "github.com",
    "amazon.com",
}

URL_SHORTENERS: Final[set[str]] = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "rebrand.ly",
    "cutt.ly",
    "shorturl.at",
}

DEFAULT_REQUEST_TIMEOUT: Final[int] = 8
DEFAULT_USER_AGENT: Final[str] = "PhishGuard/1.0 (+https://localhost/phishguard)"