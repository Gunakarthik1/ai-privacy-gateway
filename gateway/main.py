"""
Enterprise AI Gateway & Data Privacy Firewall
FastAPI proxy server — full pipeline implementation.
"""

import pathlib
import time
import random
import hashlib
from typing import List, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from .inspector import PIIInspector
from .injection import InjectionDetector
from .rate_limiter import TokenBucketRateLimiter
from .budget import BudgetEnforcer
from .audit import AuditLogger
from .models import (
    ProxyChatRequest,
    ProxyChatResponse,
    InspectRequest,
    PIIScanReport,
    PIIMaskResult,
    KeyStatsResponse,
    PipelineStage,
    InjectionResult,
    RiskLevel,
    AuditEntry,
    ThreatSummary,
)


# ---------------------------------------------------------------------------
# Application bootstrap
# ---------------------------------------------------------------------------

app = FastAPI(
    title="Enterprise AI Gateway & Data Privacy Firewall",
    version="1.0.0",
    description="PII masking, rate limiting, prompt injection detection, and audit logging proxy for LLM providers.",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

_FRONTEND = pathlib.Path(__file__).parent.parent / "frontend"
if _FRONTEND.exists():
    app.mount("/static", StaticFiles(directory=str(_FRONTEND)), name="static")

@app.get("/", include_in_schema=False)
async def index():
    return FileResponse(str(_FRONTEND / "index.html"))

# Singleton service instances
_inspector = PIIInspector()
_injection_detector = InjectionDetector()
_rate_limiter = TokenBucketRateLimiter()
_budget_enforcer = BudgetEnforcer()
_audit_logger = AuditLogger()

# ---------------------------------------------------------------------------
# Pre-configured demo API keys
# ---------------------------------------------------------------------------

DEMO_KEYS = {
    "demo-free-key": "free",
    "demo-standard-key": "standard",
    "demo-enterprise-key": "enterprise",
}

# ---------------------------------------------------------------------------
# Upstream LLM simulator
# ---------------------------------------------------------------------------

_MOCK_RESPONSES = [
    "I've reviewed your request and here's my analysis: the information provided "
    "has been processed securely through the enterprise gateway. All sensitive data "
    "remains protected within your network perimeter.",

    "Thank you for your query. Based on the context provided, I can offer the "
    "following insights while maintaining strict data privacy protocols as configured "
    "by your enterprise security policy.",

    "Your request has been processed. The gateway has verified that all data handling "
    "complies with the configured privacy and security policies. Here is my response "
    "to your question based on the available information.",

    "I understand your request. Let me provide a comprehensive response: the system "
    "is functioning within the defined security parameters, and I can assist you with "
    "your query while ensuring all enterprise policies are respected.",

    "Processing complete. The enterprise firewall has verified the integrity of this "
    "interaction. I'm ready to assist — please feel free to ask follow-up questions "
    "and I'll continue to provide accurate, policy-compliant responses.",

    "Acknowledged. The privacy gateway has processed your submission. I can confirm "
    "that your request is within scope and I'm providing this response in full "
    "compliance with the applicable data handling rules.",
]


def _simulate_upstream(messages: List, model: str) -> str:
    """Return a deterministic-ish mock LLM response."""
    seed_text = "".join(m.content for m in messages)
    idx = int(hashlib.md5(seed_text.encode()).hexdigest(), 16) % len(_MOCK_RESPONSES)
    base = _MOCK_RESPONSES[idx]
    word_count = len(seed_text.split())
    return f"{base} (Model: {model} | Processed {word_count} input words)"


def _estimate_tokens(text: str) -> int:
    """Rough token estimate: ~4 chars per token."""
    return max(1, len(text) // 4)


def _make_stage(name: str, status: str, detail: str, duration_ms: float) -> PipelineStage:
    return PipelineStage(stage=name, status=status, detail=detail, duration_ms=round(duration_ms, 2))


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "AI Privacy Gateway", "version": "1.0.0"}


@app.post("/api/proxy/chat", response_model=ProxyChatResponse)
async def proxy_chat(req: ProxyChatRequest):
    """
    Full pipeline:
      rate limit → budget check → injection detect → PII mask →
      simulate upstream → unmask response → audit log → return
    """
    pipeline_stages: List[PipelineStage] = []
    overall_start = time.perf_counter()
    action = "allowed"
    audit_id: Optional[int] = None

    # ------------------------------------------------------------------ 0. Resolve role
    api_key = req.api_key
    role = DEMO_KEYS.get(api_key, req.role)

    # ------------------------------------------------------------------ 1. Rate limit
    t0 = time.perf_counter()
    allowed, remaining, retry_ms = _rate_limiter.check(api_key)
    rl_ms = (time.perf_counter() - t0) * 1000

    if not allowed:
        pipeline_stages.append(_make_stage(
            "Rate Limit", "blocked",
            f"Token bucket exhausted. Retry after {retry_ms}ms. Key: {api_key}",
            rl_ms,
        ))
        action = "blocked"
        _audit_logger.log(
            api_key=api_key, prompt="[rate-limited]",
            pii_entities_detected=0, injection_risk="low",
            tokens_in=0, tokens_out=0,
            latency_ms=(time.perf_counter() - overall_start) * 1000,
            action="blocked", upstream_model=req.model,
        )
        raise HTTPException(
            status_code=429,
            detail={"error": "rate_limit_exceeded", "retry_after_ms": retry_ms},
        )

    pipeline_stages.append(_make_stage(
        "Rate Limit", "passed",
        f"Tokens remaining: {remaining}/{_rate_limiter._capacity}",
        rl_ms,
    ))

    # ------------------------------------------------------------------ 2. Budget check
    full_prompt = " ".join(m.content for m in req.messages)
    estimated_tokens = _estimate_tokens(full_prompt)

    t0 = time.perf_counter()
    budget_result = _budget_enforcer.check_budget(api_key, role, estimated_tokens)
    budget_ms = (time.perf_counter() - t0) * 1000

    if not budget_result.allowed:
        pipeline_stages.append(_make_stage(
            "Budget", "blocked", budget_result.reason or "Budget exceeded", budget_ms
        ))
        action = "blocked"
        _audit_logger.log(
            api_key=api_key, prompt=full_prompt,
            pii_entities_detected=0, injection_risk="low",
            tokens_in=estimated_tokens, tokens_out=0,
            latency_ms=(time.perf_counter() - overall_start) * 1000,
            action="blocked", upstream_model=req.model,
        )
        raise HTTPException(
            status_code=402,
            detail={"error": "budget_exceeded", "reason": budget_result.reason},
        )

    budget_summary = _budget_enforcer.get_usage_summary(api_key, role)
    pipeline_stages.append(_make_stage(
        "Budget", "passed",
        f"Role: {role} | Used today: {budget_summary.used_today:,} tokens"
        + (f" / {budget_summary.limit:,}" if not budget_summary.is_unlimited else " (unlimited)"),
        budget_ms,
    ))

    # ------------------------------------------------------------------ 3. Injection detection
    t0 = time.perf_counter()
    injection_result: InjectionResult = _injection_detector.classify(full_prompt)
    inj_ms = (time.perf_counter() - t0) * 1000

    if injection_result.risk_level == RiskLevel.CRITICAL:
        pipeline_stages.append(_make_stage(
            "Injection Scan", "blocked",
            f"CRITICAL injection detected. Confidence: {injection_result.confidence:.0%}. "
            f"Patterns: {', '.join(injection_result.matched_patterns)}",
            inj_ms,
        ))
        action = "blocked"
        _audit_logger.log(
            api_key=api_key, prompt=full_prompt,
            pii_entities_detected=0,
            injection_risk=injection_result.risk_level.value,
            tokens_in=estimated_tokens, tokens_out=0,
            latency_ms=(time.perf_counter() - overall_start) * 1000,
            action="blocked", upstream_model=req.model,
            matched_patterns=injection_result.matched_patterns,
        )
        raise HTTPException(
            status_code=400,
            detail={
                "error": "injection_detected",
                "risk_level": injection_result.risk_level.value,
                "confidence": injection_result.confidence,
                "matched_patterns": injection_result.matched_patterns,
            },
        )

    inj_detail = (
        f"Risk: {injection_result.risk_level.value} | Confidence: {injection_result.confidence:.0%}"
        if injection_result.is_injection
        else f"Clean | Confidence: {injection_result.confidence:.0%}"
    )
    pipeline_stages.append(_make_stage("Injection Scan", "passed", inj_detail, inj_ms))

    # ------------------------------------------------------------------ 4. PII masking
    t0 = time.perf_counter()
    masked_prompt, pii_entities = _inspector.mask(full_prompt)
    pii_ms = (time.perf_counter() - t0) * 1000

    pii_count = len(pii_entities)
    pii_detail = (
        f"{pii_count} entities masked: "
        + ", ".join({e.entity_type for e in pii_entities})
        if pii_count > 0
        else "No PII detected"
    )

    if pii_count > 0:
        action = "masked"

    pipeline_stages.append(_make_stage(
        "PII Mask",
        "masked" if pii_count > 0 else "clean",
        pii_detail,
        pii_ms,
    ))

    # ------------------------------------------------------------------ 5. Upstream call (simulated)
    t0 = time.perf_counter()
    # Replace the last user message with the masked version for upstream
    masked_messages = list(req.messages)
    if masked_messages:
        last = masked_messages[-1]
        masked_messages[-1] = type(last)(role=last.role, content=masked_prompt)

    raw_response = _simulate_upstream(masked_messages, req.model)
    upstream_ms = (time.perf_counter() - t0) * 1000

    tokens_out = _estimate_tokens(raw_response)
    pipeline_stages.append(_make_stage(
        "Upstream LLM", "success",
        f"Model: {req.model} | Response: {tokens_out} tokens | Latency: {upstream_ms:.0f}ms",
        upstream_ms,
    ))

    # ------------------------------------------------------------------ 6. Unmask response
    t0 = time.perf_counter()
    final_response = _inspector.unmask(raw_response, pii_entities)
    unmask_ms = (time.perf_counter() - t0) * 1000

    pipeline_stages.append(_make_stage(
        "PII Unmask", "complete",
        f"Restored {pii_count} PII placeholder(s) in response",
        unmask_ms,
    ))

    # ------------------------------------------------------------------ 7. Record usage & audit
    total_tokens = estimated_tokens + tokens_out
    _budget_enforcer.record_usage(api_key, role, total_tokens)

    latency_total = (time.perf_counter() - overall_start) * 1000
    audit_id = _audit_logger.log(
        api_key=api_key,
        prompt=full_prompt,
        pii_entities_detected=pii_count,
        injection_risk=injection_result.risk_level.value,
        tokens_in=estimated_tokens,
        tokens_out=tokens_out,
        latency_ms=latency_total,
        action=action,
        upstream_model=req.model,
        matched_patterns=injection_result.matched_patterns if injection_result.matched_patterns else None,
    )

    return ProxyChatResponse(
        response=final_response,
        pipeline_stages=pipeline_stages,
        pii_masked=pii_count > 0,
        pii_entities=pii_entities,
        injection_result=injection_result,
        tokens_in=estimated_tokens,
        tokens_out=tokens_out,
        action=action,
        audit_id=audit_id,
    )


@app.post("/api/inspect", response_model=PIIScanReport)
async def inspect_text(req: InspectRequest):
    """Scan text for PII without forwarding anywhere."""
    return _inspector.scan_only(req.text)


@app.get("/api/audit/logs", response_model=List[AuditEntry])
async def get_audit_logs(limit: int = 50):
    return _audit_logger.get_recent_logs(limit=min(limit, 200))


@app.get("/api/audit/threats", response_model=ThreatSummary)
async def get_threat_summary():
    return _audit_logger.get_threat_summary()


@app.get("/api/keys/{api_key}/stats", response_model=KeyStatsResponse)
async def get_key_stats(api_key: str):
    role = DEMO_KEYS.get(api_key, "standard")
    return KeyStatsResponse(
        rate_limit=_rate_limiter.get_stats(api_key),
        budget=_budget_enforcer.get_usage_summary(api_key, role),
    )


@app.get("/api/demo-keys")
async def list_demo_keys():
    """List pre-configured demo API keys and their roles."""
    return [{"api_key": k, "role": v} for k, v in DEMO_KEYS.items()]
