"""
Pydantic v2 schemas — request validation and response serialisation.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ── Auth ──────────────────────────────────────────────────────────────────

class RegisterRequest(BaseModel):
    email: EmailStr
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_\-]+$")
    password: str = Field(min_length=8, max_length=128)

    @field_validator("password")
    @classmethod
    def password_strength(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        return v


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int   # seconds


class RefreshRequest(BaseModel):
    refresh_token: str


class UserResponse(BaseModel):
    id: uuid.UUID
    email: str
    username: str
    role: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}


# ── Image Upload ──────────────────────────────────────────────────────────

class UploadResponse(BaseModel):
    job_id: str
    filename: str
    size_bytes: int
    mime_type: str
    status: str = "uploaded"
    message: str = "Image uploaded successfully"


# ── Processing ───────────────────────────────────────────────────────────

class ModulesConfig(BaseModel):
    adversarial: bool = True
    deepfake: bool = True
    watermark: bool = True
    profiling: bool = True
    anti_scraping: bool = False
    data_poisoning: bool = False


class ProcessRequest(BaseModel):
    job_id: str
    protection_level: str = Field(default="basic", pattern="^(basic|advanced|maximum)$")
    modules: ModulesConfig = Field(default_factory=ModulesConfig)


class ProgressStep(BaseModel):
    step: int
    name: str
    status: str   # waiting | running | done | error
    duration_ms: Optional[float] = None


class ProcessStatusResponse(BaseModel):
    job_id: str
    status: str
    progress_pct: int
    steps: List[ProgressStep]
    message: str


# ── Results ───────────────────────────────────────────────────────────────

class AIInsight(BaseModel):
    attribute: str
    result: str
    confidence: float
    blocked: bool


class ThreatEvent(BaseModel):
    type: str         # blocked | neutralized | detected
    description: str
    timestamp_ms: float


class PrivacyMetrics(BaseModel):
    recognition_block_pct: float
    deepfake_immunity_pct: float
    ssim_score: float              # structural similarity (image quality)
    watermark_strength_pct: float
    scraping_resistance_pct: float
    perceptual_fidelity_pct: float
    overall_privacy_score: float


class ProcessResultResponse(BaseModel):
    job_id: str
    status: str
    protection_level: str
    modules_used: List[str]
    privacy_metrics: PrivacyMetrics
    ai_insights: List[AIInsight]
    threat_log: List[ThreatEvent]
    processing_time_ms: float
    protected_image_url: str
    original_image_url: str
    created_at: datetime


# ── Reports ───────────────────────────────────────────────────────────────

class ReportSummary(BaseModel):
    job_id: str
    protection_level: str
    privacy_score: float
    processing_time_ms: float
    created_at: datetime
    original_filename: str


class ReportListResponse(BaseModel):
    items: List[ReportSummary]
    total: int
    page: int
    per_page: int


# ── Health ────────────────────────────────────────────────────────────────

class ServiceStatus(BaseModel):
    name: str
    status: str     # ok | degraded | down
    latency_ms: Optional[float] = None
    detail: Optional[str] = None


class HealthResponse(BaseModel):
    status: str     # healthy | degraded | unhealthy
    version: str
    uptime_seconds: float
    services: List[ServiceStatus]
    timestamp: datetime


# ── Generic ───────────────────────────────────────────────────────────────

class MessageResponse(BaseModel):
    message: str
    detail: Optional[Any] = None


class ErrorResponse(BaseModel):
    error: str
    message: str
    request_id: Optional[str] = None
