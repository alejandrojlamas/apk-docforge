from __future__ import annotations

from ipaddress import ip_address

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from apk_docforge.config import get_settings


MULTIPART_OVERHEAD_BYTES = 1024 * 1024


class _UploadBodyTooLarge(Exception):
    pass


class LoopbackClientMiddleware:
    """Reject HTTP clients that did not connect from a loopback address."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        client = scope.get("client")
        try:
            is_loopback = bool(client) and ip_address(client[0]).is_loopback
        except (TypeError, ValueError):
            is_loopback = False
        if not is_loopback:
            await _error_response(403, "Remote API clients are not supported.", scope, receive, send)
            return
        await self.app(scope, receive, send)


class UploadRequestLimitMiddleware:
    """Reject oversized upload bodies before and while multipart parsing."""

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") != "/api/upload":
            await self.app(scope, receive, send)
            return

        max_request_bytes = get_settings().max_upload_bytes + MULTIPART_OVERHEAD_BYTES
        content_lengths = [
            value.decode("latin-1")
            for key, value in scope.get("headers", [])
            if key.lower() == b"content-length"
        ]
        if len(content_lengths) > 1:
            await _error_response(400, "Multiple Content-Length headers are not allowed.", scope, receive, send)
            return
        if content_lengths:
            try:
                declared_length = int(content_lengths[0])
            except ValueError:
                await _error_response(400, "Content-Length must be a non-negative integer.", scope, receive, send)
                return
            if declared_length < 0:
                await _error_response(400, "Content-Length must be a non-negative integer.", scope, receive, send)
                return
            if declared_length > max_request_bytes:
                await _error_response(413, "Upload request exceeds the configured size limit.", scope, receive, send)
                return

        received_bytes = 0
        body_too_large = False
        response_messages: list[Message] = []

        async def limited_receive() -> Message:
            nonlocal body_too_large, received_bytes
            message = await receive()
            if message["type"] == "http.request":
                received_bytes += len(message.get("body", b""))
                if received_bytes > max_request_bytes:
                    body_too_large = True
                    raise _UploadBodyTooLarge
            return message

        async def buffered_send(message: Message) -> None:
            response_messages.append(message)

        try:
            await self.app(scope, limited_receive, buffered_send)
        except _UploadBodyTooLarge:
            body_too_large = True

        if body_too_large:
            await _error_response(413, "Upload request exceeds the configured size limit.", scope, receive, send)
            return
        for message in response_messages:
            await send(message)


async def _error_response(
    status_code: int,
    detail: str,
    scope: Scope,
    receive: Receive,
    send: Send,
) -> None:
    response = JSONResponse({"detail": detail}, status_code=status_code)
    await response(scope, receive, send)
