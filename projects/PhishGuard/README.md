# PhishGuard

PhishGuard is a production-style Python 3.11+ URL threat analyzer that detects phishing risk using a deterministic heuristic engine with weighted scoring, tiered signals, risk gates, and counterweights for false-positive reduction.

## Features

- Modular architecture with clear separation of concerns
- Tiered heuristic scoring (A/B/C)
- Brand impersonation detection with domain normalization
- SSL/TLS inspection using `ssl` + `socket`
- Redirect and HSTS inspection using `requests`
- Confidence scoring model with bounded output
- CLI interface for automation
- Streamlit web UI for interactive use
- Safe exception handling for unreachable hosts and network issues

## Project Structure

```text
phishguard/
├── core/
│   ├── __init__.py
│   ├── url_parser.py
│   ├── ssl_checker.py
│   ├── domain_analyzer.py
│   ├── heuristics.py
│   ├── scorer.py
│   └── models.py
├── interfaces/
│   ├── __init__.py
│   ├── cli.py
│   └── streamlit_app.py
├── utils/
│   ├── __init__.py
│   ├── entropy.py
│   └── constants.py
├── examples/
│   └── sample_urls.txt
├── requirements.txt
├── README.md
└── pyproject.toml
```

## Architecture

- `core/models.py`
  - Typed dataclasses for parsed URL data, SSL/network metadata, signals, and final report schema.
- `core/url_parser.py`
  - URL normalization and structured parsing via `urllib.parse`.
- `core/domain_analyzer.py`
  - Domain decomposition (base/subdomain/TLD), entropy calculation, redirect/HSTS collection, brand impersonation detection.
- `core/ssl_checker.py`
  - Certificate validation and fallback unverified certificate inspection to detect self-signed/expiry signals safely.
- `core/heuristics.py`
  - Tiered positive signal generation plus counterweight generation.
- `core/scorer.py`
  - Orchestrates analysis and applies deterministic scoring, gates, classification, and confidence.
- `interfaces/cli.py`
  - Command-line entrypoint with human-readable or JSON output.
- `interfaces/streamlit_app.py`
  - Streamlit dashboard with score visualization and technical breakdown.
- `utils/entropy.py`
  - Manual Shannon entropy implementation.
- `utils/constants.py`
  - Centralized thresholds, lists, and scoring weights.

## Scoring Model

### Tier A (Strong)

- IP instead of domain: `+30`
- `@` symbol in URL: `+35`
- Punycode (`xn--`): `+25`
- Redirects 2-3: `+10`
- Redirects >3: `+20`
- No HTTPS: `+20`

### Tier B (Moderate)

- Invalid SSL: `+25`
- Self-signed SSL: `+20`
- SSL expires in <7 days: `+10`
- High-risk TLD (`.xyz`, `.top`, `.click`, `.tk`): `+8`
- URL length >75: `+5`
- URL length >120: `+10`
- Subdomain depth 3: `+5`
- Subdomain depth 4+: `+10`
- High entropy domain label: `+10`
- Brand impersonation in suspicious context: `+20` or `+25`

### Tier C (Weak)

- Sensitive keywords (`login`, `verify`, `secure`, `update`, `password`): `+3` each, capped at `+10`
- Excessive special characters: `+2`, `+4`, or `+6` (bounded)
- URL shortener domain: `+8`

## Brand Impersonation Logic

Monitored brands:

- `paypal`, `microsoft`, `google`, `apple`, `netflix`, `amazon`, `meta`, `instagram`, `whatsapp`, `binance`

Behavior:

- If a brand keyword appears in hostname/path but the base domain is not the legitimate brand domain, PhishGuard adds impersonation risk.
- Legitimate brand domains do not trigger impersonation.

Examples:

- `paypal-login.xyz` -> suspicious
- `accounts.google.com` -> not suspicious (base domain `google.com`)

## False Positive Mitigation

Counterweights:

- Valid SSL from trusted issuer: `-8`
- HSTS header present: `-8`
- Allowlisted base domains (`google.com`, `microsoft.com`, `apple.com`, `github.com`, `amazon.com`): `-35`

Gate:

- If no Tier A signals are present, Tier C total contribution is capped at `+8`.

## Output Schema

```json
{
  "url": "...",
  "risk_score": 0,
  "classification": "LOW",
  "confidence": 0.3,
  "signals_detected": [
    {
      "id": "...",
      "description": "...",
      "tier": "A",
      "impact": 30,
      "evidence": "..."
    }
  ]
}
```

Risk classification:

- `0-24`: LOW
- `25-49`: MEDIUM
- `50-74`: HIGH
- `75-100`: CRITICAL

## Confidence Model

```text
confidence = 0.30
           + 0.15 * (# Tier A signals)
           + 0.08 * (# Tier B signals)
           + 0.03 * (# Tier C signals)
confidence is capped at 0.95
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate  # Windows PowerShell: .venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## CLI Usage

```bash
python interfaces/cli.py --url https://example.com
python interfaces/cli.py --url https://example.com --json
python interfaces/cli.py --url https://example.com --verbose
```

## Streamlit Usage

```bash
streamlit run interfaces/streamlit_app.py
```

UI includes:

- URL input field
- Analyze button
- Risk score metric and progress bar
- Color-coded classification badge
- Confidence display
- Expandable technical signal details
- JSON export

## Example URLs

Use `examples/sample_urls.txt` for quick local testing.

## Security and Reliability Notes

- All network and SSL operations are wrapped with safe exception handling.
- Unreachable hosts and TLS failures do not crash analysis.
- Scoring logic is deterministic and centralized.
- No paid external APIs are required in v1.

## Future Roadmap

- VirusTotal integration
- WHOIS analysis
- ML-based classifier
- Async analysis engine
- API mode (FastAPI)