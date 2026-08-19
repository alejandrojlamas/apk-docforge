from __future__ import annotations

from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from apk_docforge import __version__
from apk_docforge.api.middleware import LoopbackClientMiddleware, UploadRequestLimitMiddleware
from apk_docforge.api.routes import router
from apk_docforge.config import LOCAL_TRUSTED_HOSTS, get_settings
from apk_docforge.db.session import init_db


WEB_DIR = Path(__file__).resolve().parents[1] / "web" / "minimal_static_ui"


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    init_db()
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    application = FastAPI(title="apk-docforge", version=__version__, lifespan=lifespan)
    application.include_router(router)
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.api_allowed_origin_list,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Accept", "Content-Type"],
    )
    application.add_middleware(UploadRequestLimitMiddleware)
    application.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=list(LOCAL_TRUSTED_HOSTS),
        www_redirect=False,
    )
    application.add_middleware(LoopbackClientMiddleware)

    if WEB_DIR.exists():
        application.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

    @application.get("/", include_in_schema=False)
    def web_app() -> FileResponse:
        return FileResponse(WEB_DIR / "index.html")

    return application


app = create_app()
