"""Data models for PhishGuard analysis pipeline."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal

Tier = Literal["A", "B", "C"]
RiskClassification = Literal["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass(slots=True)
class ParsedURL:
    """Normalized URL components used during heuristic analysis."""

    original_url: str
    normalized_url: str
    scheme: str
    hostname: str
    path: str
    query: str
    has_at_symbol: bool
    contains_punycode: bool
    is_ip: bool
    url_length: int
    special_char_count: int


@dataclass(slots=True)
class DomainInfo:
    """Domain decomposition and lexical properties."""

    hostname: str
    base_domain: str
    subdomain: str
    tld: str
    subdomain_depth: int
    entropy: float
    high_entropy: bool
    is_allowlisted: bool


@dataclass(slots=True)
class NetworkInfo:
    """Network-derived metadata such as redirects and HSTS headers."""

    redirect_count: int = 0
    hsts_enabled: bool = False
    fetch_error: str | None = None


@dataclass(slots=True)
class SSLInfo:
    """SSL certificate inspection result."""

    checked: bool = False
    valid: bool | None = None
    trusted_issuer: bool | None = None
    self_signed: bool | None = None
    expires_in_days: int | None = None
    issuer: str | None = None
    inspection_error: str | None = None


@dataclass(slots=True)
class Signal:
    """Single heuristic signal contributing to risk score."""

    id: str
    description: str
    tier: Tier
    impact: int
    evidence: str

    def to_dict(self) -> dict[str, str | int]:
        """Serialize signal into API-safe dictionary."""
        return {
            "id": self.id,
            "description": self.description,
            "tier": self.tier,
            "impact": self.impact,
            "evidence": self.evidence,
        }


@dataclass(slots=True)
class AnalysisContext:
    """Container for all intermediate analysis artifacts."""

    parsed_url: ParsedURL
    domain_info: DomainInfo
    network_info: NetworkInfo
    ssl_info: SSLInfo


@dataclass(slots=True)
class ThreatReport:
    """Final analysis output."""

    url: str
    risk_score: int
    classification: RiskClassification
    confidence: float
    signals_detected: list[Signal] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        """Serialize final report to a JSON-compatible dictionary."""
        return {
            "url": self.url,
            "risk_score": self.risk_score,
            "classification": self.classification,
            "confidence": round(self.confidence, 4),
            "signals_detected": [signal.to_dict() for signal in self.signals_detected],
        }