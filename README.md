# carina-gateway

GitHub → CARINA intake gateway with webhook signature verification, fail-closed policy checks, and a read-only evidence ledger.

## Intake boundary

GitHub is an **evidence and coordination source**, never an execution authority.

```text
GitHub webhook
      ↓
HMAC verification
      ↓
security policy
      ↓
INTENT / EVIDENCE / DECISION
      ↓
read-only SQLite intake ledger
      ↓
CARINA human / policy decision
      ↓
CARINA-only authorization
```

The bridge can represent only:

- `INTENT`
- `EVIDENCE`
- `DECISION`

It cannot create `AUTHORIZED`, grant authority, or mutate CARINA execution state. Any record that attempts to do so is rejected before persistence. The SQLite schema also constrains the stored phase to those three values.

## Portfolio mapping

The profile repository issue forms map into intake records as follows:

| GitHub event | CARINA intake phase |
| --- | --- |
| `[Idea]` opened or reopened | `INTENT` |
| `[Idea]` edited | `EVIDENCE` |
| `[Collaboration]` opened, edited, or reopened | `DECISION` |
| `[Proof]` | not intake; belongs to verification |
| ordinary issue | ignored |

GitHub Actions actors remain denied by the existing policy rule, so automation-generated labels or comments do not become authority-bearing evidence.

## Durable intake ledger

Use `SQLiteIntakeLedger` as the sink passed to `handle_github_event`:

```python
from github_carina_gateway import SQLiteIntakeLedger, handle_github_event

ledger = SQLiteIntakeLedger("./carina-intake.sqlite3")

result = handle_github_event(
    event_type="issues",
    delivery_id=delivery_id,
    raw_signature=signature,
    raw_body=body,
    intake_sink=ledger.append,
)
```

GitHub delivery IDs are part of each record ID, and the database primary key makes webhook re-delivery idempotent.

The intake database is intentionally separate from an execution-state database. CARINA must explicitly evaluate and authorize any later action through its own policy/state machinery.

## Verification

Run both suites:

```bash
python -m unittest discover -p "test*.py" -v
python test_gateway.py
```

CI runs both commands on pull requests and pushes to `main`.

## Security notes

- Set `GITHUB_WEBHOOK_SECRET` before importing/running the gateway.
- Never use the development fallback secret in a deployed receiver.
- Signature verification uses HMAC-SHA256 and constant-time comparison.
- Unknown events default to `DENY`.
- GitHub intake records are immutable evidence; they are not approval tokens.


## Run the webhook receiver

The included receiver is localhost-first and fails closed if no webhook secret is configured.

```bash
export GITHUB_WEBHOOK_SECRET='replace-with-a-strong-random-secret'
export CARINA_GATEWAY_HOST='127.0.0.1'
export CARINA_GATEWAY_PORT='51002'
export CARINA_INTAKE_LEDGER_PATH="$HOME/.carina/github-intake.sqlite3"

python carina_gateway_server.py
```

Endpoints:

```text
GET  /health
POST /github/webhook
```

The receiver deliberately exposes **no authorization endpoint**.

To receive GitHub.com webhooks, the receiver must be reachable from GitHub over HTTPS through infrastructure you control (for example, a reverse proxy or secure tunnel). Configure the repository webhook to send **Issues** events to `/github/webhook` and use the exact same secret as `GITHUB_WEBHOOK_SECRET`.

Do not expose the SQLite file or the CARINA control service directly to the public internet.

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


## Persistent HTTP gateway

The branch also contains a standard-library HTTP server:

```bash
export CARINA_GATEWAY_TOKEN=dev-local-secret
export GITHUB_WEBHOOK_SECRET=dev-github-secret
python3 carina_server.py
```

Default listener:

```text
http://127.0.0.1:51001
```

Health check:

```bash
curl -i http://127.0.0.1:51001/health
```

Server tests:

```bash
python3 -m unittest -v test_carina_server.py
```
