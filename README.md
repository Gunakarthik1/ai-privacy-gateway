# Enterprise AI Gateway & Data Privacy Firewall

A production-grade proxy gateway between client applications and upstream LLM providers. Intercepts every request and response to enforce privacy, security, and usage policies before any data leaves the enterprise network.

## What It Does

| Layer | Function |
|---|---|
| **PII Inspector** | Detects and masks SSNs, emails, credit cards, phone numbers, API keys, IPs, names, dates of birth using regex + Luhn validation |
| **Injection Detector** | Classifies prompt injection, jailbreak attempts, role overrides, and data exfiltration with confidence scoring |
| **Rate Limiter** | Per-API-key token bucket (capacity 100, refill 10/sec) with in-memory state and thread-safety |
| **Budget Enforcer** | Role-based daily token limits (free: 10k, standard: 100k, enterprise: unlimited) backed by SQLite |
| **Audit Logger** | Full structured audit trail of every request stored in SQLite with threat aggregation |
| **Proxy Gateway** | FastAPI orchestrating the full pipeline with simulated upstream LLM responses |
| **Dashboard** | Single-file enterprise security console with real-time PII highlighting, pipeline visualization, and threat feed |

## Quick Start

### Local development (no Docker)

```bash
# Install dependencies
cd gateway
pip install -r requirements.txt

# Start the gateway
cd ..
uvicorn gateway.main:app --reload --host 0.0.0.0 --port 8000
```

Then open `frontend/index.html` in your browser (or serve it with any static file server).

### Docker Compose

```bash
docker-compose up --build
```

- Gateway API: http://localhost:8000
- Dashboard: http://localhost:3000

## API Reference

### `POST /api/proxy/chat`
Full pipeline proxy request.
```json
{
  "api_key": "demo-standard-key",
  "role": "standard",
  "messages": [{"role": "user", "content": "My SSN is 123-45-6789"}],
  "model": "gpt-4o",
  "max_tokens": 512
}
```

### `POST /api/inspect`
Scan text for PII without forwarding anywhere.
```json
{ "text": "Contact john@example.com at 555-867-5309" }
```

### `GET /api/audit/logs?limit=50`
Recent audit entries.

### `GET /api/audit/threats`
Aggregate threat counters.

### `GET /api/keys/{api_key}/stats`
Rate limit and budget statistics for a key.

### `GET /api/health`
Health check.

## Demo API Keys

| Key | Role | Daily Limit |
|---|---|---|
| `demo-free-key` | free | 10,000 tokens |
| `demo-standard-key` | standard | 100,000 tokens |
| `demo-enterprise-key` | enterprise | unlimited |

## Pipeline Stages

```
Client Request
    │
    ▼
[1] Rate Limit Check      ── 429 if bucket empty
    │
    ▼
[2] Budget Check          ── 402 if daily limit exceeded
    │
    ▼
[3] Injection Detection   ── 400 if CRITICAL risk
    │
    ▼
[4] PII Masking           ── replaces sensitive values with [TYPE_REDACTED]
    │
    ▼
[5] Upstream LLM Call     ── sends masked prompt (simulated in demo)
    │
    ▼
[6] PII Unmasking         ── restores original values in response
    │
    ▼
[7] Audit Logging         ── persists full record to SQLite
    │
    ▼
Client Response
```

## Detected PII Types

- `SSN` — `\b\d{3}-\d{2}-\d{4}\b`
- `EMAIL` — standard email regex
- `PHONE` — US phone formats (dashes, parens, plain)
- `CREDIT_CARD` — 13–19 digit sequences, Luhn-validated
- `API_KEY` — `sk-`, `Bearer`, `AIza`, `ghp_`, `xoxb-`, `ya29.` prefixes
- `IP_ADDRESS` — IPv4 dotted-decimal
- `NAME` — capitalized two-word sequences near "my name is", "I am", "signed by"
- `DOB` — date patterns near "born on", "date of birth", "DOB"

## Injection Risk Levels

| Level | Confidence | Action |
|---|---|---|
| low | < 30% | Allowed |
| medium | 30–55% | Allowed with flag |
| high | 55–85% | Allowed with flag |
| critical | > 85% | **Blocked (400)** |

## Running Tests

```bash
pip install pytest
pytest tests/ -v
```

## Project Structure

```
ai-privacy-gateway/
├── gateway/
│   ├── main.py          # FastAPI proxy orchestrator
│   ├── inspector.py     # PII detection + masking (regex + Luhn)
│   ├── injection.py     # Prompt injection classifier
│   ├── rate_limiter.py  # Token-bucket rate limiter
│   ├── budget.py        # Role-based budget enforcer (SQLite)
│   ├── audit.py         # Audit logger (SQLite)
│   ├── models.py        # Pydantic schemas
│   └── requirements.txt
├── frontend/
│   └── index.html       # Enterprise security dashboard
├── tests/
│   ├── test_inspector.py
│   ├── test_rate_limiter.py
│   └── test_injection.py
├── docker-compose.yml
├── Dockerfile
├── nginx.conf
└── .gitignore
```
