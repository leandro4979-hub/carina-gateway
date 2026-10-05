from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Mapping

from github_carina_gateway import (
    DispatchError,
    GatewayError,
    IntakeAuthorizationError,
    PayloadParseError,
    SQLiteIntakeLedger,
    SignatureVerificationError,
    handle_github_event,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 51002
DEFAULT_MAX_BODY_BYTES = 1_048_576
WEBHOOK_PATH = "/github/webhook"
HEALTH_PATH = "/health"


class ReceiverConfigError(RuntimeError):
    """Required receiver configuration is missing or unsafe."""


def _header(headers: Mapping[str, str], name: str) -> str:
    for key, value in headers.items():
        if key.lower() == name.lower():
            return str(value)
    return ""


def process_webhook(
    headers: Mapping[str, str],
    raw_body: bytes,
    *,
    ledger: SQLiteIntakeLedger,
    webhook_secret: str,
    max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
) -> tuple[int, dict]:
    """
    Process one GitHub webhook request through the CARINA intake boundary.

    This function persists only read-only intake evidence. It exposes no
    authorization or execution transition.
    """
    secret = str(webhook_secret or "").strip()
    if not secret:
        raise ReceiverConfigError("GITHUB_WEBHOOK_SECRET is required.")

    if len(raw_body) > max_body_bytes:
        raise PayloadParseError(
            f"Webhook body exceeds {max_body_bytes} bytes."
        )

    event_type = _header(headers, "X-GitHub-Event").strip()
    delivery_id = _header(headers, "X-GitHub-Delivery").strip()
    signature = _header(headers, "X-Hub-Signature-256").strip()

    if not event_type:
        raise PayloadParseError("X-GitHub-Event is required.")
    if not delivery_id:
        raise PayloadParseError("X-GitHub-Delivery is required.")

    result = handle_github_event(
        event_type=event_type,
        delivery_id=delivery_id,
        raw_signature=signature,
        raw_body=raw_body,
        intake_sink=ledger.append,
        webhook_secret=secret,
    )

    return 202, {
        "ok": True,
        "delivery_id": delivery_id,
        "decision": result.decision.value,
        "routed_to": result.routed_to,
        "message": result.message,
    }


class CarinaWebhookHandler(BaseHTTPRequestHandler):
    server_version = "CARINAGitHubGateway/1.0"

    def _json(self, status: int, payload: dict) -> None:
        encoded = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802
        if self.path != HEALTH_PATH:
            self._json(404, {"ok": False, "error": "not_found"})
            return

        self._json(
            200,
            {
                "service": "CARINAGitHubGateway",
                "ok": True,
                "port": self.server.server_port,
                "authority": "CARINA_ONLY",
            },
        )

    def do_POST(self) -> None:  # noqa: N802
        if self.path != WEBHOOK_PATH:
            self._json(404, {"ok": False, "error": "not_found"})
            return

        length_text = self.headers.get("Content-Length", "")
        try:
            length = int(length_text)
        except ValueError:
            self._json(400, {"ok": False, "error": "invalid_content_length"})
            return

        if length < 0 or length > self.server.max_body_bytes:
            self._json(413, {"ok": False, "error": "payload_too_large"})
            return

        raw_body = self.rfile.read(length)

        try:
            status, payload = process_webhook(
                dict(self.headers.items()),
                raw_body,
                ledger=self.server.intake_ledger,
                webhook_secret=self.server.webhook_secret,
                max_body_bytes=self.server.max_body_bytes,
            )
            self._json(status, payload)
        except SignatureVerificationError:
            self._json(401, {"ok": False, "error": "invalid_signature"})
        except PayloadParseError as exc:
            self._json(400, {"ok": False, "error": "invalid_payload", "detail": str(exc)})
        except IntakeAuthorizationError:
            self._json(403, {"ok": False, "error": "authorization_boundary"})
        except DispatchError as exc:
            self._json(422, {"ok": False, "error": "dispatch_rejected", "detail": str(exc)})
        except GatewayError:
            self._json(403, {"ok": False, "error": "gateway_rejected"})

    def log_message(self, format: str, *args) -> None:
        # Use the gateway's structured logging instead of BaseHTTPRequestHandler stderr.
        return


class CarinaWebhookServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        address: tuple[str, int],
        *,
        webhook_secret: str,
        intake_ledger: SQLiteIntakeLedger,
        max_body_bytes: int = DEFAULT_MAX_BODY_BYTES,
    ):
        secret = str(webhook_secret or "").strip()
        if not secret:
            raise ReceiverConfigError("GITHUB_WEBHOOK_SECRET is required.")

        super().__init__(address, CarinaWebhookHandler)
        self.webhook_secret = secret
        self.intake_ledger = intake_ledger
        self.max_body_bytes = max_body_bytes


def run_server() -> None:
    secret = str(os.environ.get("GITHUB_WEBHOOK_SECRET", "")).strip()
    if not secret:
        raise ReceiverConfigError(
            "GITHUB_WEBHOOK_SECRET must be set; the receiver will not start with a fallback secret."
        )

    host = os.environ.get("CARINA_GATEWAY_HOST", DEFAULT_HOST)
    port = int(os.environ.get("CARINA_GATEWAY_PORT", str(DEFAULT_PORT)))
    ledger_path = Path(
        os.environ.get(
            "CARINA_INTAKE_LEDGER_PATH",
            "~/.carina/github-intake.sqlite3",
        )
    ).expanduser()

    ledger = SQLiteIntakeLedger(ledger_path)
    server = CarinaWebhookServer(
        (host, port),
        webhook_secret=secret,
        intake_ledger=ledger,
    )

    print(f"CARINA GitHub gateway listening on http://{host}:{port}{WEBHOOK_PATH}")
    print(f"Read-only intake ledger: {ledger_path}")
    server.serve_forever()


if __name__ == "__main__":
    run_server()
