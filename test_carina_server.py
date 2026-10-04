from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import threading
import unittest
from contextlib import contextmanager

import github_carina_gateway as github_gateway
from carina_server import create_server
from model_router import (
    Capability,
    FatalProviderError,
    LLMRequest,
    LLMResponse,
    ModelRouter,
    Provider,
    ProviderConfig,
    RetryableProviderError,
)


class StaticRouter:
    def __init__(self, response: LLMResponse | Exception):
        self.response = response
        self.requests: list[LLMRequest] = []

    def complete(self, request: LLMRequest) -> LLMResponse:
        self.requests.append(request)
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0

    def post_json(self, url, payload, headers, timeout):
        self.calls += 1
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def make_provider(name: str, transport: FakeTransport) -> Provider:
    return Provider(
        ProviderConfig(
            name=name,
            base_url=f"https://{name}.example/v1",
            model=f"{name}-model",
            api_key="test",
            capabilities=frozenset({Capability.TEXT}),
        ),
        transport=transport,
    )


@contextmanager
def running_server(router, token="test-token"):
    server = create_server("127.0.0.1", 0, token, router)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def request(port, method, path, body=None, headers=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    try:
        payload = None if body is None else body
        conn.request(method, path, body=payload, headers=headers or {})
        response = conn.getresponse()
        raw = response.read()
        data = json.loads(raw) if raw else None
        return response.status, data
    finally:
        conn.close()


def signed_webhook(body: bytes, secret: str) -> str:
    digest = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


class CARINAServerTests(unittest.TestCase):
    def test_health(self):
        router = StaticRouter(
            LLMResponse(provider="fake", model="fake-model", text="ok", raw={})
        )
        with running_server(router) as port:
            status, data = request(port, "GET", "/health")
        self.assertEqual(status, 200)
        self.assertEqual(
            data,
            {"status": "ok", "service": "carina-gateway", "version": 1},
        )

    def test_unknown_route(self):
        router = StaticRouter(
            LLMResponse(provider="fake", model="fake-model", text="ok", raw={})
        )
        with running_server(router) as port:
            status, data = request(port, "GET", "/nope")
        self.assertEqual(status, 404)
        self.assertEqual(data["error"], "not_found")

    def test_missing_bearer_token(self):
        router = StaticRouter(
            LLMResponse(provider="fake", model="fake-model", text="ok", raw={})
        )
        body = json.dumps({
            "model": "auto",
            "messages": [{"role": "user", "content": "hello"}],
        }).encode()
        with running_server(router) as port:
            status, _ = request(
                port,
                "POST",
                "/v1/chat/completions",
                body,
                {"Content-Type": "application/json", "Content-Length": str(len(body))},
            )
        self.assertEqual(status, 401)

    def test_wrong_bearer_token(self):
        router = StaticRouter(
            LLMResponse(provider="fake", model="fake-model", text="ok", raw={})
        )
        body = json.dumps({
            "model": "auto",
            "messages": [{"role": "user", "content": "hello"}],
        }).encode()
        with running_server(router) as port:
            status, _ = request(
                port,
                "POST",
                "/v1/chat/completions",
                body,
                {
                    "Authorization": "Bearer wrong",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                },
            )
        self.assertEqual(status, 401)

    def test_oversized_request(self):
        router = StaticRouter(
            LLMResponse(provider="fake", model="fake-model", text="ok", raw={})
        )
        with running_server(router) as port:
            status, data = request(
                port,
                "POST",
                "/v1/chat/completions",
                b"",
                {
                    "Authorization": "Bearer test-token",
                    "Content-Type": "application/json",
                    "Content-Length": str(1_048_577),
                },
            )
        self.assertEqual(status, 413)
        self.assertEqual(data["error"], "request_too_large")

    def test_malformed_json(self):
        router = StaticRouter(
            LLMResponse(provider="fake", model="fake-model", text="ok", raw={})
        )
        body = b"{bad"
        with running_server(router) as port:
            status, data = request(
                port,
                "POST",
                "/v1/chat/completions",
                body,
                {
                    "Authorization": "Bearer test-token",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                },
            )
        self.assertEqual(status, 400)
        self.assertEqual(data["error"], "invalid_json")

    def test_valid_chat_request(self):
        router = StaticRouter(
            LLMResponse(
                provider="fake",
                model="fake-model",
                text="hello back",
                raw={},
            )
        )
        body = json.dumps({
            "model": "auto",
            "messages": [{"role": "user", "content": "hello"}],
            "capability": "text",
        }).encode()
        with running_server(router) as port:
            status, data = request(
                port,
                "POST",
                "/v1/chat/completions",
                body,
                {
                    "Authorization": "Bearer test-token",
                    "Content-Type": "application/json",
                    "Content-Length": str(len(body)),
                },
            )
        self.assertEqual(status, 200)
        self.assertEqual(data["choices"][0]["message"]["content"], "hello back")
        self.assertEqual(data["carina"]["provider"], "fake")
        self.assertIsNone(router.requests[0].model)

    def test_retryable_router_falls_back(self):
        first = FakeTransport([(429, b'{"error":"rate limited"}')])
        second = FakeTransport([
            (
                200,
                json.dumps({
                    "choices": [{"message": {"content": "fallback ok"}}]
                }).encode(),
            )
        ])
        router = ModelRouter([
            make_provider("first", first),
            make_provider("second", second),
        ])

        result = router.complete(
            LLMRequest(messages=[{"role": "user", "content": "hello"}])
        )
        self.assertEqual(result.provider, "second")
        self.assertEqual(first.calls, 1)
        self.assertEqual(second.calls, 1)

    def test_fatal_router_does_not_fallback(self):
        first = FakeTransport([(401, b'{"error":"bad key"}')])
        second = FakeTransport([
            (
                200,
                json.dumps({
                    "choices": [{"message": {"content": "must not run"}}]
                }).encode(),
            )
        ])
        router = ModelRouter([
            make_provider("first", first),
            make_provider("second", second),
        ])

        with self.assertRaises(FatalProviderError):
            router.complete(
                LLMRequest(messages=[{"role": "user", "content": "hello"}])
            )
        self.assertEqual(second.calls, 0)

    def test_webhook_valid_signature_allow(self):
        old_secret = github_gateway.WEBHOOK_SECRET
        github_gateway.WEBHOOK_SECRET = "test-secret"
        try:
            payload = {
                "action": "opened",
                "sender": {"login": "human"},
                "repository": {"full_name": "owner/repo"},
            }
            body = json.dumps(payload).encode()
            headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "delivery-1",
                "X-Hub-Signature-256": signed_webhook(body, "test-secret"),
            }
            router = StaticRouter(
                LLMResponse(provider="fake", model="fake-model", text="ok", raw={})
            )
            with running_server(router) as port:
                status, data = request(port, "POST", "/github/webhook", body, headers)
            self.assertEqual(status, 200)
            self.assertEqual(data["decision"], "ALLOW")
        finally:
            github_gateway.WEBHOOK_SECRET = old_secret

    def test_webhook_invalid_signature(self):
        old_secret = github_gateway.WEBHOOK_SECRET
        github_gateway.WEBHOOK_SECRET = "test-secret"
        try:
            payload = {
                "action": "opened",
                "sender": {"login": "human"},
                "repository": {"full_name": "owner/repo"},
            }
            body = json.dumps(payload).encode()
            headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "delivery-2",
                "X-Hub-Signature-256": signed_webhook(body, "wrong-secret"),
            }
            router = StaticRouter(
                LLMResponse(provider="fake", model="fake-model", text="ok", raw={})
            )
            with running_server(router) as port:
                status, _ = request(port, "POST", "/github/webhook", body, headers)
            self.assertEqual(status, 401)
        finally:
            github_gateway.WEBHOOK_SECRET = old_secret

    def test_webhook_denied(self):
        old_secret = github_gateway.WEBHOOK_SECRET
        github_gateway.WEBHOOK_SECRET = "test-secret"
        try:
            payload = {
                "action": "pushed",
                "sender": {"login": "github-actions"},
                "repository": {"full_name": "owner/repo"},
            }
            body = json.dumps(payload).encode()
            headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-GitHub-Event": "push",
                "X-GitHub-Delivery": "delivery-3",
                "X-Hub-Signature-256": signed_webhook(body, "test-secret"),
            }
            router = StaticRouter(
                LLMResponse(provider="fake", model="fake-model", text="ok", raw={})
            )
            with running_server(router) as port:
                status, data = request(port, "POST", "/github/webhook", body, headers)
            self.assertEqual(status, 403)
            self.assertEqual(data["decision"], "DENY")
        finally:
            github_gateway.WEBHOOK_SECRET = old_secret

    def test_webhook_approval_required(self):
        old_secret = github_gateway.WEBHOOK_SECRET
        github_gateway.WEBHOOK_SECRET = "test-secret"
        try:
            payload = {
                "action": "opened",
                "sender": {"login": "dependabot[bot]"},
                "repository": {"full_name": "owner/repo"},
            }
            body = json.dumps(payload).encode()
            headers = {
                "Content-Type": "application/json",
                "Content-Length": str(len(body)),
                "X-GitHub-Event": "pull_request",
                "X-GitHub-Delivery": "delivery-4",
                "X-Hub-Signature-256": signed_webhook(body, "test-secret"),
            }
            router = StaticRouter(
                LLMResponse(provider="fake", model="fake-model", text="ok", raw={})
            )
            with running_server(router) as port:
                status, data = request(port, "POST", "/github/webhook", body, headers)
            self.assertEqual(status, 202)
            self.assertEqual(data["decision"], "APPROVAL_REQUIRED")
        finally:
            github_gateway.WEBHOOK_SECRET = old_secret


if __name__ == "__main__":
    unittest.main()
