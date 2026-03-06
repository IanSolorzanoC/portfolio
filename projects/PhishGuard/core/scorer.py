"""Scoring engine and orchestration for PhishGuard."""

from __future__ import annotations

import logging

from core.domain_analyzer import analyze_domain, collect_network_info
from core.heuristics import generate_counterweight_signals, generate_risk_signals
from core.models import AnalysisContext, RiskClassification, Signal, ThreatReport
from core.ssl_checker import inspect_ssl
from core.url_parser import parse_url
from utils.constants import (
    BASE_CONFIDENCE,
    HIGH_MAX,
    LOW_MAX,
    MAX_CONFIDENCE,
    MAX_RISK_SCORE,
    MEDIUM_MAX,
    MIN_RISK_SCORE,
    TIER_C_DEFAULT_CAP,
    TIER_C_NO_TIER_A_CAP,
)

LOGGER = logging.getLogger(__name__)


class PhishGuardAnalyzer:
    """Main URL threat analyzer using deterministic heuristic scoring."""

    def analyze(self, url: str) -> ThreatReport:
        """Analyze a URL and return a structured risk report.

        Args:
            url: URL to inspect.

        Returns:
            ThreatReport with risk score, confidence, and detected signals.
        """
        parsed = parse_url(url)
        domain = analyze_domain(parsed)
        network = collect_network_info(parsed.normalized_url)
        ssl_info = inspect_ssl(parsed.hostname) if parsed.hostname else inspect_ssl("")

        context = AnalysisContext(
            parsed_url=parsed,
            domain_info=domain,
            network_info=network,
            ssl_info=ssl_info,
        )

        risk_signals = generate_risk_signals(context)
        counterweight_signals = generate_counterweight_signals(context)

        adjusted_risk_signals = self._apply_tier_c_gate(risk_signals)
        risk_score = self._compute_score(adjusted_risk_signals, counterweight_signals)
        classification = self._classify(risk_score)

        all_signals = adjusted_risk_signals + counterweight_signals
        confidence = self._compute_confidence(all_signals, risk_score)

        return ThreatReport(
            url=parsed.normalized_url,
            risk_score=risk_score,
            classification=classification,
            confidence=confidence,
            signals_detected=all_signals,
        )

    def _apply_tier_c_gate(self, signals: list[Signal]) -> list[Signal]:
        """Apply tier C cap and no-tier-A gate for false-positive reduction."""
        adjusted = [
            Signal(
                id=signal.id,
                description=signal.description,
                tier=signal.tier,
                impact=signal.impact,
                evidence=signal.evidence,
            )
            for signal in signals
        ]

        has_tier_a = any(signal.tier == "A" and signal.impact > 0 for signal in adjusted)
        tier_c_cap = TIER_C_DEFAULT_CAP if has_tier_a else TIER_C_NO_TIER_A_CAP

        tier_c_indices = [
            index
            for index, signal in enumerate(adjusted)
            if signal.tier == "C" and signal.impact > 0
        ]
        tier_c_total = sum(adjusted[index].impact for index in tier_c_indices)

        if tier_c_total <= tier_c_cap:
            return adjusted

        reduction_needed = tier_c_total - tier_c_cap

        # Deterministic reduction from newest/least critical weak signals first.
        for index in reversed(tier_c_indices):
            if reduction_needed <= 0:
                break

            signal = adjusted[index]
            reducible = min(signal.impact, reduction_needed)
            signal.impact -= reducible
            reduction_needed -= reducible

        return [signal for signal in adjusted if signal.impact != 0]

    def _compute_score(self, risk_signals: list[Signal], counterweights: list[Signal]) -> int:
        """Compute final bounded risk score."""
        total = sum(signal.impact for signal in risk_signals)
        total += sum(signal.impact for signal in counterweights)

        return max(MIN_RISK_SCORE, min(MAX_RISK_SCORE, total))

    def _classify(self, score: int) -> RiskClassification:
        """Map numeric score into severity class."""
        if score <= LOW_MAX:
            return "LOW"
        if score <= MEDIUM_MAX:
            return "MEDIUM"
        if score <= HIGH_MAX:
            return "HIGH"
        return "CRITICAL"

    def _compute_confidence(self, signals: list[Signal], risk_score: int) -> float:
        """Compute confidence from evidence strength and distance from class boundaries."""
        if not signals:
            return BASE_CONFIDENCE

        evidence_count = len(signals)
        evidence_strength = sum(abs(signal.impact) for signal in signals)

        boundaries = (LOW_MAX, MEDIUM_MAX, HIGH_MAX)
        nearest_boundary_distance = min(abs(risk_score - boundary) for boundary in boundaries)
        normalized_margin = min(1.0, nearest_boundary_distance / 25.0)

        confidence = (
            BASE_CONFIDENCE
            + min(0.30, evidence_count * 0.08)
            + min(0.25, evidence_strength / 80.0)
            + 0.10 * normalized_margin
        )
        return min(MAX_CONFIDENCE, round(confidence, 4))


def analyze_url(url: str) -> ThreatReport:
    """Convenience function to run the default analyzer."""
    analyzer = PhishGuardAnalyzer()
    return analyzer.analyze(url)
