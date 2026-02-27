"""Streamlit interface for PhishGuard URL threat analysis."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import streamlit as st

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.scorer import analyze_url

COLOR_MAP = {
    "LOW": "#2E8B57",
    "MEDIUM": "#E3B505",
    "HIGH": "#F57C00",
    "CRITICAL": "#C62828",
}


def render_classification_badge(classification: str) -> None:
    """Render color-coded classification badge."""
    color = COLOR_MAP.get(classification, "#666666")
    st.markdown(
        (
            f"<div style='padding:8px 12px;border-radius:8px;"
            f"background:{color};color:white;font-weight:600;display:inline-block;'>"
            f"{classification}</div>"
        ),
        unsafe_allow_html=True,
    )


def main() -> None:
    """Render Streamlit app."""
    st.set_page_config(page_title="PhishGuard", page_icon="shield", layout="centered")
    st.title("PhishGuard")
    st.caption("Automated URL Threat Analyzer")

    url = st.text_input("URL", placeholder="https://example.com")

    if st.button("Analyze", type="primary"):
        if not url.strip():
            st.error("Please enter a URL.")
            return

        with st.spinner("Analyzing URL..."):
            report = analyze_url(url).to_dict()

        score = int(report["risk_score"])
        classification = str(report["classification"])
        confidence = float(report["confidence"])

        st.metric(label="Risk Score", value=f"{score}/100")
        st.progress(min(max(score, 0), 100) / 100)
        render_classification_badge(classification)
        st.metric(label="Confidence", value=f"{confidence * 100:.1f}%")

        with st.expander("Technical Details", expanded=True):
            signals = report.get("signals_detected", [])
            if isinstance(signals, list) and signals:
                for signal in signals:
                    if not isinstance(signal, dict):
                        continue
                    st.markdown(
                        f"**{signal.get('id', 'unknown')}** | "
                        f"Tier {signal.get('tier', '?')} | "
                        f"Impact {signal.get('impact', 0):+d}"
                    )
                    st.write(signal.get("description", ""))
                    st.caption(f"Evidence: {signal.get('evidence', 'N/A')}")
            else:
                st.write("No signals detected.")

        json_blob = json.dumps(report, indent=2)
        st.download_button(
            label="Export JSON",
            data=json_blob,
            file_name="phishguard_report.json",
            mime="application/json",
        )
        st.code(json_blob, language="json")


if __name__ == "__main__":
    main()