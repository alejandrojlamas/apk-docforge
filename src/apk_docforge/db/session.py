from __future__ import annotations

from contextlib import contextmanager
from typing import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from apk_docforge.config import get_settings
from apk_docforge.db.models import Base


def make_engine(db_url: str | None = None):
    url = db_url or get_settings().db_url
    connect_args = {"check_same_thread": False} if url.startswith("sqlite") else {}
    return create_engine(url, connect_args=connect_args)


engine = None
SessionLocal = None


def get_engine():
    global engine, SessionLocal
    if engine is None:
        engine = make_engine()
        SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    return engine


def reset_engine() -> None:
    global engine, SessionLocal
    if engine is not None:
        engine.dispose()
    engine = None
    SessionLocal = None


def init_db() -> None:
    Base.metadata.create_all(bind=get_engine())


@contextmanager
def session_scope() -> Iterator[Session]:
    init_db()
    assert SessionLocal is not None
    session = SessionLocal()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()
