from __future__ import annotations

from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class Source(Base):
    __tablename__ = "sources"
    __table_args__ = (UniqueConstraint("type", name="uq_sources_type"),)

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    type: Mapped[str] = mapped_column(String(80), nullable=False)
    base_url: Mapped[str | None] = mapped_column(Text)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    policy_status: Mapped[str] = mapped_column(String(80), default="ALLOWED", nullable=False)
    auth_type: Mapped[str] = mapped_column(String(80), default="none", nullable=False)
    trust_level: Mapped[str] = mapped_column(String(80), default="unknown", nullable=False)
    notes: Mapped[str | None] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    candidates: Mapped[list["AppCandidate"]] = relationship(back_populates="source")


class AppCandidate(Base):
    __tablename__ = "app_candidates"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id"))
    package_name: Mapped[str | None] = mapped_column(String(255))
    app_name: Mapped[str | None] = mapped_column(String(255))
    developer: Mapped[str | None] = mapped_column(String(255))
    version_name: Mapped[str | None] = mapped_column(String(120))
    version_code: Mapped[str | None] = mapped_column(String(120))
    license: Mapped[str | None] = mapped_column(String(255))
    source_url: Mapped[str | None] = mapped_column(Text)
    download_url: Mapped[str | None] = mapped_column(Text)
    checksum: Mapped[str | None] = mapped_column(String(255))
    policy_status: Mapped[str] = mapped_column(String(80), default="UNKNOWN", nullable=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    source: Mapped[Source | None] = relationship(back_populates="candidates")
    artifacts: Mapped[list["Artifact"]] = relationship(back_populates="candidate")


class Artifact(Base):
    __tablename__ = "artifacts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    source_id: Mapped[int | None] = mapped_column(ForeignKey("sources.id"))
    candidate_id: Mapped[int | None] = mapped_column(ForeignKey("app_candidates.id"))
    local_path: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    mime_type: Mapped[str | None] = mapped_column(String(255))
    package_name: Mapped[str | None] = mapped_column(String(255))
    version_name: Mapped[str | None] = mapped_column(String(120))
    version_code: Mapped[str | None] = mapped_column(String(120))
    provenance_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    candidate: Mapped[AppCandidate | None] = relationship(back_populates="artifacts")
    analyses: Mapped[list["Analysis"]] = relationship(back_populates="artifact")


class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    artifact_id: Mapped[int | None] = mapped_column(ForeignKey("artifacts.id"))
    mode: Mapped[str] = mapped_column(String(40), nullable=False)
    status: Mapped[str] = mapped_column(String(80), nullable=False, default="running")
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    output_dir: Mapped[str] = mapped_column(Text, nullable=False)
    summary_json: Mapped[str] = mapped_column(Text, nullable=False, default="{}")

    artifact: Mapped[Artifact | None] = relationship(back_populates="analyses")
    findings: Mapped[list["Finding"]] = relationship(back_populates="analysis")
    features: Mapped[list["Feature"]] = relationship(back_populates="analysis")
    screens: Mapped[list["Screen"]] = relationship(back_populates="analysis")


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id"), nullable=False)
    category: Mapped[str] = mapped_column(String(120), nullable=False)
    severity: Mapped[str] = mapped_column(String(40), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)

    analysis: Mapped[Analysis] = relationship(back_populates="findings")


class Feature(Base):
    __tablename__ = "features"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    evidence_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    analysis: Mapped[Analysis] = relationship(back_populates="features")


class Screen(Base):
    __tablename__ = "screens"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    analysis_id: Mapped[int] = mapped_column(ForeignKey("analyses.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    source: Mapped[str] = mapped_column(String(80), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    analysis: Mapped[Analysis] = relationship(back_populates="screens")
    ui_elements: Mapped[list["UIElement"]] = relationship(back_populates="screen")


class UIElement(Base):
    __tablename__ = "ui_elements"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    screen_id: Mapped[int] = mapped_column(ForeignKey("screens.id"), nullable=False)
    element_type: Mapped[str] = mapped_column(String(120), nullable=False)
    visible_text: Mapped[str | None] = mapped_column(Text)
    resource_id: Mapped[str | None] = mapped_column(String(255))
    action_guess: Mapped[str | None] = mapped_column(Text)
    confidence: Mapped[float] = mapped_column(Float, default=0.0, nullable=False)
    evidence_refs: Mapped[str] = mapped_column(Text, nullable=False, default="[]")

    screen: Mapped[Screen] = relationship(back_populates="ui_elements")
