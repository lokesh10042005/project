"""
SQLAlchemy ORM models for PostgreSQL.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Enum, Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.database import Base
from app.core.security import UserRole


def _utcnow():
    return datetime.now(timezone.utc)


# ── User ──────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        Enum(UserRole, name="user_role"), default=UserRole.USER, nullable=False
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    # Relationships
    image_jobs: Mapped[list["ImageJob"]] = relationship(back_populates="user", lazy="select")

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"


# ── Image processing job ──────────────────────────────────────────────────

class ImageJob(Base):
    __tablename__ = "image_jobs"
    __table_args__ = (
        Index("ix_image_jobs_user_status", "user_id", "status"),
        Index("ix_image_jobs_created", "created_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    job_id: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    status: Mapped[str] = mapped_column(
        String(32), default="pending", nullable=False
    )  # pending | processing | completed | failed

    # Input metadata
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    original_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str] = mapped_column(String(64), nullable=False)

    # Configuration
    protection_level: Mapped[str] = mapped_column(String(32), default="basic")
    modules_config: Mapped[str] = mapped_column(Text, default="{}")  # JSON string

    # Output metrics
    privacy_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    recognition_block_pct: Mapped[float | None] = mapped_column(Float, nullable=True)
    ssim_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    processing_time_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Storage paths
    input_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    output_path: Mapped[str | None] = mapped_column(String(512), nullable=True)

    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    user: Mapped["User | None"] = relationship(back_populates="image_jobs")

    def __repr__(self):
        return f"<ImageJob {self.job_id} [{self.status}]>"
