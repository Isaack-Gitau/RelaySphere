from collections.abc import Iterable

from starlette.types import ASGIApp, Receive, Scope, Send


class OriginValidationMiddleware:
    """Reject state-changing authentication requests from untrusted origins."""

    def __init__(
        self,
        app: ASGIApp,
        allowed_origins: Iterable[str],
        auth_prefix: str,
    ) -> None:
        self.app = app
        self.allowed_origins = frozenset(allowed_origins)
        self.auth_prefix = auth_prefix.rstrip("/")

    async def __call__(
        self,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        if scope["type"] == "http":
            method = scope.get("method", "").upper()
            path = scope.get("path", "")

            is_auth_route = path == self.auth_prefix or path.startswith(f"{self.auth_prefix}/")

            if method in {"POST", "PUT", "PATCH", "DELETE"} and is_auth_route:
                origin_headers = [
                    value for name, value in scope.get("headers", []) if name == b"origin"
                ]

                if len(origin_headers) != 1:
                    await self._reject(send)
                    return

                try:
                    origin = origin_headers[0].decode("ascii")
                except UnicodeDecodeError:
                    await self._reject(send)
                    return

                if not origin or origin not in self.allowed_origins:
                    await self._reject(send)
                    return

        await self.app(scope, receive, send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = b'{"detail":"Untrusted request origin."}'
        await send(
            {
                "type": "http.response.start",
                "status": 403,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode()),
                ],
            }
        )
        await send(
            {
                "type": "http.response.body",
                "body": body,
            }
        )
