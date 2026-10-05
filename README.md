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
