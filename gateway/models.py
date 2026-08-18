from pydantic import BaseModel, Field
from typing import Optional, List, Any
from datetime import datetime
from enum import Enum


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Action(str, Enum):
    ALLOWED = "allowed"
    BLOCKED = "blocked"
    MASKED = "masked"


class PIIEntity(BaseModel):
    entity_type: str
    original_value: str
    replacement: str
    start: int
    end: int


class PIIMaskResult(BaseModel):
    masked_text: str
    entities: List[PIIEntity]
    entity_count: int


class PIIScanReport(BaseModel):
    original_text: str
    entities: List[PIIEntity]
    entity_count: int
    entity_types: List[str]
    risk_score: float


class InjectionResult(BaseModel):
    is_injection: bool
    confidence: float
    matched_patterns: List[str]
    risk_level: RiskLevel


class RateLimitResult(BaseModel):
    allowed: bool
    remaining: int
    retry_after_ms: int


class RateLimitStats(BaseModel):
    api_key: str
    requests_made: int
    requests_blocked: int
    current_tokens: float
    capacity: int
    refill_rate: float


class BudgetResult(BaseModel):
    allowed: bool
    reason: Optional[str] = None


class BudgetSummary(BaseModel):
    api_key: str
    role: str
    used_today: int
    limit: int
    percent_used: float
    is_unlimited: bool


class AuditEntry(BaseModel):
    id: Optional[int] = None
    api_key: str
    timestamp: datetime
    prompt_hash: str
    pii_entities_detected: int
    injection_risk: str
    tokens_in: int
    tokens_out: int
    latency_ms: float
    action: str
    upstream_model: str
    matched_patterns: Optional[str] = None


class ThreatSummary(BaseModel):
    total_requests: int
    blocked: int
    masked: int
    injection_attempts: int
    pii_detected_count: int


class ChatMessage(BaseModel):
    role: str = Field(..., description="user or assistant")
    content: str


class ProxyChatRequest(BaseModel):
    api_key: str
    role: str = "standard"
    messages: List[ChatMessage]
    model: str = "gpt-4o"
    max_tokens: int = 512


class PipelineStage(BaseModel):
    stage: str
    status: str
    detail: str
    duration_ms: float


class ProxyChatResponse(BaseModel):
    response: str
    pipeline_stages: List[PipelineStage]
    pii_masked: bool
    pii_entities: List[PIIEntity]
    injection_result: InjectionResult
    tokens_in: int
    tokens_out: int
    action: str
    audit_id: Optional[int] = None


class InspectRequest(BaseModel):
    text: str


class KeyStatsResponse(BaseModel):
    rate_limit: RateLimitStats
    budget: BudgetSummary
