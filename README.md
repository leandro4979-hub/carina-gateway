# carina-gateway

GitHub CARINA Dispatcher Gateway — security-policy webhook intake plus a fail-closed multi-provider model router.

## Existing gateway

Run the webhook/security debug scenarios:

```bash
python3 github_carina_gateway.py
python3 test_gateway.py
```

## Provider router

The provider order is:

```text
Ollama (local)
  -> Groq
  -> Cerebras
  -> OpenRouter
```

Gemini is also registered when configured and is eligible for vision-capability requests.

The router only falls through on retryable failures such as HTTP 429, 5xx, timeout, or network errors. Authentication failures, other client errors, malformed JSON, and invalid provider responses fail closed.

### Environment

Ollama is enabled by default:

```bash
export OLLAMA_URL=http://127.0.0.1:11434
export OLLAMA_MODEL=gpt-oss:20b
```

Cloud providers are enabled only when their keys are present:

```bash
export GROQ_API_KEY=...
export CEREBRAS_API_KEY=...
export OPENROUTER_API_KEY=...
export GEMINI_OPENAI_API_KEY=...
```

Optional model overrides:

```bash
export GROQ_MODEL=openai/gpt-oss-120b
export CEREBRAS_MODEL=gpt-oss-120b
export OPENROUTER_MODEL=openai/gpt-oss-20b:free
export GEMINI_MODEL=gemini-2.5-flash
```

Never commit provider keys to the repository.

### Test

```bash
python3 -m unittest -v test_model_router.py
```

The first batch tests success, 429/5xx fallback, fatal 401 handling, verification failures, aggregate retryable failures, and capability routing.
