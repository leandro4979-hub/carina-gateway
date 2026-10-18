from __future__ import annotations

import hmac
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from uuid import uuid4

import github_carina_gateway as github_gateway
from github_carina_gateway import (
    DispatchError,
    PayloadParseError,
    SecurityDecision,
    SignatureVerificationError,
)
from model_router import (
    Capability,
    FatalProviderError,
    LLMRequest,
    ModelRouter,
    RetryableProviderError,
    VerificationError,
    providers_from_environment,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 51001
MAX_BODY_BYTES = int(os.environ.get("CARINA_MAX_BODY_BYTES", str(1_048_576)))


def _json_bytes(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, separators=(",", ":")).encode("utf-8")


def _bearer_token(header: str | None) -> str | None:
    if not header:
        return None
    scheme, separator, token = header.partition(" ")
    if not separator or scheme.lower() != "bearer" or not token:
        return None
    return token


def _validate_messages(value: Any) -> list[dict[str, Any]]:
    if not isinstance(value, list) or not value:
        raise ValueError("'messages' must be a non-empty array")

    validated: list[dict[str, Any]] = []
    for index, item in enumerate(value):
        if not isinstance(item, dict):
            raise ValueError(f"messages[{index}] must be an object")
        role = item.get("role")
        content = item.get("content")
        if role not in {"system", "user", "assistant", "tool"}:
            raise ValueError(f"messages[{index}].role is invalid")
        if not isinstance(content, (str, list)):
            raise ValueError(f"messages[{index}].content must be a string or array")
        validated.append(item)
    return validated


def create_server(
    host: str,
    port: int,
    gateway_token: str,
    router: ModelRouter | Any,
) -> ThreadingHTTPServer:
    if not gateway_token:
        raise ValueError("CARINA_GATEWAY_TOKEN is required")

    class CARINARequestHandler(BaseHTTPRequestHandler):
        server_version = "CARINA/1"
        sys_version = ""

        def log_message(self, format: str, *args: Any) -> None:
            sys.stderr.write(
                "%s - - [%s] %s\n"
                % (self.address_string(), self.log_date_time_string(), format % args)
            )

        def _send_json(
            self,
            status: int,
            payload: dict[str, Any],
            extra_headers: dict[str, str] | None = None,
        ) -> None:
            body = _json_bytes(payload)
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            if extra_headers:
                for key, value in extra_headers.items():
                    self.send_header(key, value)
            self.end_headers()
            self.wfile.write(body)

        def _read_body(self) -> bytes | None:
            raw_length = self.headers.get("Content-Length")
            if raw_length is None:
                self._send_json(411, {"error": "content_length_required"})
                return None
            try:
                length = int(raw_length)
            except ValueError:
                self._send_json(400, {"error": "invalid_content_length"})
                return None

            if length < 0:
                self._send_json(400, {"error": "invalid_content_length"})
                return None
            if length > MAX_BODY_BYTES:
                self._send_json(413, {"error": "request_too_large"})
                return None
            return self.rfile.read(length)

        def _read_json_object(self) -> dict[str, Any] | None:
            body = self._read_body()
            if body is None:
                return None
            try:
                payload = json.loads(body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                self._send_json(400, {"error": "invalid_json"})
                return None
            if not isinstance(payload, dict):
                self._send_json(400, {"error": "json_body_must_be_object"})
                return None
            return payload

        def _authorized(self) -> bool:
            supplied = _bearer_token(self.headers.get("Authorization"))
            if supplied is None or not hmac.compare_digest(supplied, gateway_token):
                self._send_json(
                    401,
                    {"error": "unauthorized"},
                    {"WWW-Authenticate": "Bearer"},
                )
                return False
            return True

        def do_GET(self) -> None:
            if self.path == "/health":
                self._send_json(
                    200,
                    {
                        "status": "ok",
                        "service": "carina-gateway",
                        "version": 1,
                    },
                )
                return
            self._send_json(404, {"error": "not_found"})

        def do_POST(self) -> None:
            if self.path == "/github/webhook":
                self._handle_webhook()
                return
            if self.path == "/v1/chat/completions":
                self._handle_chat()
                return
            self._send_json(404, {"error": "not_found"})

        def _handle_webhook(self) -> None:
            body = self._read_body()
            if body is None:
                return

            event_type = self.headers.get(github_gateway.GITHUB_EVENT_HEADER, "")
            delivery_id = self.headers.get(github_gateway.GITHUB_DELIVERY_HEADER, "")
            signature = self.headers.get(github_gateway.GITHUB_SIGNATURE_HEADER, "")

            if not event_type or not delivery_id:
                self._send_json(400, {"error": "missing_github_headers"})
                return

            try:
                result = github_gateway.handle_github_event(
                    event_type=event_type,
                    delivery_id=delivery_id,
                    raw_signature=signature,
                    raw_body=body,
                )
            except SignatureVerificationError:
                self._send_json(401, {"error": "invalid_signature"})
                return
            except PayloadParseError:
                self._send_json(400, {"error": "invalid_payload"})
                return
            except DispatchError:
                self._send_json(500, {"error": "dispatch_failed"})
                return
            except Exception:
                self._send_json(500, {"error": "internal_error"})
                return

            payload = {
                "dispatch_id": result.dispatch_id,
                "decision": result.decision.value,
                "routed_to": result.routed_to,
                "message": result.message,
            }
            if result.decision == SecurityDecision.DENY:
                self._send_json(403, payload)
            elif result.decision == SecurityDecision.APPROVAL_REQUIRED:
                self._send_json(202, payload)
            else:
                self._send_json(200, payload)

        def _handle_chat(self) -> None:
            if not self._authorized():
                return

            payload = self._read_json_object()
            if payload is None:
                return

            try:
                messages = _validate_messages(payload.get("messages"))
                capability = Capability(payload.get("capability", "text"))
            except (ValueError, TypeError) as exc:
                self._send_json(400, {"error": "invalid_request", "message": str(exc)})
                return

            model_value = payload.get("model", "auto")
            if not isinstance(model_value, str):
                self._send_json(
                    400,
                    {"error": "invalid_request", "message": "'model' must be a string"},
                )
                return
            model = None if model_value == "auto" else model_value

            temperature = payload.get("temperature")
            max_tokens = payload.get("max_tokens")
            if temperature is not None and not isinstance(temperature, (int, float)):
                self._send_json(
                    400,
                    {"error": "invalid_request", "message": "'temperature' must be numeric"},
                )
                return
            if max_tokens is not None and (
                not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens <= 0
            ):
                self._send_json(
                    400,
                    {"error": "invalid_request", "message": "'max_tokens' must be a positive integer"},
                )
                return

            request = LLMRequest(
                messages=messages,
                model=model,
                capability=capability,
                temperature=float(temperature) if temperature is not None else None,
                max_tokens=max_tokens,
            )

            try:
                result = router.complete(request)
            except RetryableProviderError:
                self._send_json(503, {"error": "providers_unavailable"})
                return
            except (VerificationError, FatalProviderError):
                self._send_json(502, {"error": "provider_failure"})
                return
            except Exception:
                self._send_json(500, {"error": "internal_error"})
                return

            self._send_json(
                200,
                {
                    "id": f"chatcmpl-{uuid4().hex}",
                    "object": "chat.completion",
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": result.text,
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "carina": {
                        "provider": result.provider,
                        "model": result.model,
                    },
                },
            )

    return ThreadingHTTPServer((host, port), CARINARequestHandler)


def main() -> int:
    host = os.environ.get("CARINA_HOST", DEFAULT_HOST)
    try:
        port = int(os.environ.get("CARINA_PORT", str(DEFAULT_PORT)))
    except ValueError:
        print("CARINA_PORT must be an integer", file=sys.stderr)
        return 2

    gateway_token = os.environ.get("CARINA_GATEWAY_TOKEN", "")
    if not gateway_token:
        print("CARINA_GATEWAY_TOKEN is required; refusing to start insecurely.", file=sys.stderr)
        return 2

    router = ModelRouter(providers_from_environment())
    server = create_server(host, port, gateway_token, router)

    print(f"CARINA Gateway listening on http://{host}:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
