import json
import unittest

from model_router import (
    Capability,
    FatalProviderError,
    LLMRequest,
    ModelRouter,
    Provider,
    ProviderConfig,
    RetryableProviderError,
    VerificationError,
)


class FakeTransport:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = []

    def post_json(self, url, payload, headers, timeout):
        self.calls.append((url, payload, headers, timeout))
        if not self.responses:
            raise AssertionError("unexpected transport call")
        result = self.responses.pop(0)
        if isinstance(result, Exception):
            raise result
        return result


def openai_provider(name, transport, capabilities=None):
    return Provider(
        ProviderConfig(
            name=name,
            base_url=f"https://{name}.example/v1",
            model="test-model",
            api_key="secret",
            capabilities=frozenset(capabilities or {Capability.TEXT}),
        ),
        transport=transport,
    )


class ModelRouterTests(unittest.TestCase):
    def setUp(self):
        self.request = LLMRequest(
            messages=[{"role": "user", "content": "hello"}]
        )

    def test_returns_first_successful_provider(self):
        transport = FakeTransport(
            [(200, json.dumps({
                "choices": [{"message": {"content": "ok"}}]
            }).encode())]
        )
        router = ModelRouter([openai_provider("groq", transport)])

        result = router.complete(self.request)

        self.assertEqual(result.provider, "groq")
        self.assertEqual(result.text, "ok")
        self.assertEqual(len(transport.calls), 1)

    def test_429_falls_through_to_next_provider(self):
        first = FakeTransport([(429, b'{"error":"rate limited"}')])
        second = FakeTransport(
            [(200, json.dumps({
                "choices": [{"message": {"content": "fallback"}}]
            }).encode())]
        )
        router = ModelRouter([
            openai_provider("groq", first),
            openai_provider("cerebras", second),
        ])

        result = router.complete(self.request)

        self.assertEqual(result.provider, "cerebras")
        self.assertEqual(result.text, "fallback")

    def test_500_falls_through_to_next_provider(self):
        first = FakeTransport([(503, b"unavailable")])
        second = FakeTransport(
            [(200, json.dumps({
                "choices": [{"message": {"content": "recovered"}}]
            }).encode())]
        )
        router = ModelRouter([
            openai_provider("groq", first),
            openai_provider("openrouter", second),
        ])

        result = router.complete(self.request)

        self.assertEqual(result.provider, "openrouter")

    def test_401_is_fatal_and_does_not_fall_through(self):
        first = FakeTransport([(401, b'{"error":"bad key"}')])
        second = FakeTransport(
            [(200, json.dumps({
                "choices": [{"message": {"content": "must not run"}}]
            }).encode())]
        )
        router = ModelRouter([
            openai_provider("groq", first),
            openai_provider("cerebras", second),
        ])

        with self.assertRaises(FatalProviderError):
            router.complete(self.request)

        self.assertEqual(len(second.calls), 0)

    def test_invalid_json_is_verification_failure_and_stops(self):
        first = FakeTransport([(200, b"not-json")])
        second = FakeTransport(
            [(200, json.dumps({
                "choices": [{"message": {"content": "must not run"}}]
            }).encode())]
        )
        router = ModelRouter([
            openai_provider("groq", first),
            openai_provider("cerebras", second),
        ])

        with self.assertRaises(VerificationError):
            router.complete(self.request)

        self.assertEqual(len(second.calls), 0)

    def test_missing_content_is_verification_failure(self):
        transport = FakeTransport([(200, b'{"choices":[]}')])
        router = ModelRouter([openai_provider("groq", transport)])

        with self.assertRaises(VerificationError):
            router.complete(self.request)

    def test_all_retryable_failures_surface_aggregate_error(self):
        first = FakeTransport([(429, b"rate limited")])
        second = FakeTransport([(503, b"down")])
        router = ModelRouter([
            openai_provider("groq", first),
            openai_provider("cerebras", second),
        ])

        with self.assertRaises(RetryableProviderError) as ctx:
            router.complete(self.request)

        message = str(ctx.exception)
        self.assertIn("groq", message)
        self.assertIn("cerebras", message)

    def test_capability_routing_skips_ineligible_provider(self):
        text_only = FakeTransport(
            [(200, json.dumps({
                "choices": [{"message": {"content": "wrong"}}]
            }).encode())]
        )
        vision = FakeTransport(
            [(200, json.dumps({
                "choices": [{"message": {"content": "vision-ok"}}]
            }).encode())]
        )
        router = ModelRouter([
            openai_provider("groq", text_only, {Capability.TEXT}),
            openai_provider("gemini", vision, {Capability.TEXT, Capability.VISION}),
        ])

        result = router.complete(
            LLMRequest(
                messages=[{"role": "user", "content": "inspect image"}],
                capability=Capability.VISION,
            )
        )

        self.assertEqual(result.provider, "gemini")
        self.assertEqual(len(text_only.calls), 0)

    def test_no_capable_provider_fails_closed(self):
        router = ModelRouter([
            openai_provider("groq", FakeTransport([]), {Capability.TEXT})
        ])

        with self.assertRaises(FatalProviderError):
            router.complete(
                LLMRequest(
                    messages=[{"role": "user", "content": "inspect image"}],
                    capability=Capability.VISION,
                )
            )


if __name__ == "__main__":
    unittest.main()
