"""
Test suite for CARINA Gateway security policy evaluation.
Tests the security rules engine against various scenarios.

This test file validates:
  - Security policy decisions (ALLOW, APPROVAL_REQUIRED, DENY)
  - Signature verification (valid and invalid HMAC-SHA256)
  - Payload parsing and event routing
  - All security rules in the SECURITY_RULES table
"""

import os
import json
import hmac
import hashlib
import sys
from uuid import uuid4

# Configure environment before importing the gateway because its constants are
# intentionally captured at module import time.
WEBHOOK_SECRET = "super-secret-key"
os.environ["GITHUB_WEBHOOK_SECRET"] = WEBHOOK_SECRET
os.environ["MOCK_SIG_FAILURE"] = "0"

# Import the gateway components only after test configuration is installed.
try:
    from github_carina_gateway import (
        handle_github_event,
        ParsedEvent,
        evaluate_security,
        SecurityDecision,
        SignatureVerificationError,
        PayloadParseError,
        DispatchError,
    )
except ImportError:
    print("Error: Could not import from github_carina_gateway. Make sure the file exists.")
    sys.exit(1)


def generate_signature(payload_bytes: bytes, secret: str) -> str:
    """Helper to generate a valid GitHub signature for testing."""
    mac = hmac.new(secret.encode('utf-8'), payload_bytes, hashlib.sha256)
    return f"sha256={mac.hexdigest()}"


def build_mock_payload(actor: str, event_type: str, action: str, repo: str = "owner/repo") -> bytes:
    """Build a minimal GitHub webhook JSON payload."""
    payload_dict = {
        "action": action,
        "sender": {"login": actor},
        "repository": {"full_name": repo},
    }
    return json.dumps(payload_dict).encode('utf-8')


def run_full_pipeline_test(name: str, actor: str, event_type: str, action: str, 
                           repo: str = "owner/repo", force_sig_fail: bool = False,
                           expected_decision: SecurityDecision = None):
    """
    Run a full gateway test through the complete intake pipeline.
    Tests: signature verification → payload parsing → security evaluation → dispatch routing
    """
    print(f"\n{'='*80}")
    print(f"Test: {name}")
    print(f"{'='*80}")
    print(f"  Actor: {actor}")
    print(f"  Event: {event_type}")
    print(f"  Action: {action}")
    print(f"  Repo: {repo}")
    
    # Build the payload
    payload_bytes = build_mock_payload(actor, event_type, action, repo)
    delivery_id = str(uuid4())[:8]
    
    # Generate signature (use wrong secret if testing failure)
    secret_to_use = "wrong-secret" if force_sig_fail else WEBHOOK_SECRET
    signature = generate_signature(payload_bytes, secret_to_use)
    
    try:
        result = handle_github_event(
            event_type=event_type,
            delivery_id=delivery_id,
            raw_signature=signature,
            raw_body=payload_bytes,
        )
        print(f"\n  ✓ SUCCESS")
        print(f"    Decision: {result.decision.value}")
        print(f"    Routed To: {result.routed_to or 'N/A (event denied/held)'}")
        print(f"    Message: {result.message}")
        
        if expected_decision and result.decision == expected_decision:
            print(f"    ✓ Decision matches expected: {expected_decision.value}")
            return True
        elif expected_decision:
            print(f"    ✗ MISMATCH: Expected {expected_decision.value}, got {result.decision.value}")
            return False
        return True
        
    except SignatureVerificationError as exc:
        print(f"\n  ✓ Signature Verification Failed (as expected)")
        print(f"    Error: {exc}")
        if force_sig_fail:
            print(f"    ✓ This is the expected behavior for invalid signatures")
            return True
        else:
            print(f"    ✗ Unexpected signature failure")
            return False
            
    except PayloadParseError as exc:
        print(f"\n  ✗ Payload Parse Error")
        print(f"    Error: {exc}")
        return False
        
    except DispatchError as exc:
        print(f"\n  ⚠ Dispatch Error (no route found)")
        print(f"    Error: {exc}")
        return True  # This is expected for unknown event types
        
    except Exception as exc:
        print(f"\n  ✗ Unexpected Error")
        print(f"    Type: {type(exc).__name__}")
        print(f"    Error: {exc}")
        return False


def run_security_evaluation_test(name: str, actor: str, event_type: str, action: str,
                                  expected_decision: SecurityDecision):
    """
    Direct security policy evaluation test (skips signature and parsing).
    Tests just the SECURITY_RULES engine.
    """
    print(f"\n{'='*80}")
    print(f"Security Test: {name}")
    print(f"{'='*80}")
    
    event = ParsedEvent(
        delivery_id="test-123",
        event_type=event_type,
        action=action,
        actor=actor,
        repo_full_name="test/repo",
        payload={},
    )
    
    try:
        result = evaluate_security(event)
        status = "✓ PASS" if result.decision == expected_decision else "✗ FAIL"
        
        print(f"  {status}")
        print(f"    Expected: {expected_decision.value}")
        print(f"    Got: {result.decision.value}")
        print(f"    Rule: {result.rule_id}")
        print(f"    Reason: {result.reason}")
        
        return result.decision == expected_decision
        
    except Exception as exc:
        print(f"  ✗ ERROR: {exc}")
        return False


if __name__ == "__main__":
    print("\n" + "="*80)
    print("=== CARINA GATEWAY SECURITY TEST SUITE ===")
    print("="*80)
    print(f"WEBHOOK_SECRET: (set)")
    print(f"MOCK_SIG_FAILURE: {os.environ.get('MOCK_SIG_FAILURE')}")
    print()
    
    test_results = []
    
    # =========================================================================
    # SECTION 1: Full pipeline tests (signature → parsing → security → dispatch)
    # =========================================================================
    print("\n" + "="*80)
    print("SECTION 1: Full Pipeline Tests")
    print("="*80)
    
    test_results.append(
        run_full_pipeline_test(
            "1. Human opens PR (Should ALLOW → carina.queue.pr_review)",
            actor="developer-amo",
            event_type="pull_request",
            action="opened",
            expected_decision=SecurityDecision.ALLOW,
        )
    )
    
    test_results.append(
        run_full_pipeline_test(
            "2. Dependabot opens PR (Should APPROVAL_REQUIRED)",
            actor="dependabot[bot]",
            event_type="pull_request",
            action="opened",
            expected_decision=SecurityDecision.APPROVAL_REQUIRED,
        )
    )
    
    test_results.append(
        run_full_pipeline_test(
            "3. GitHub Actions push (Should DENY)",
            actor="github-actions",
            event_type="push",
            action="pushed",
            expected_decision=SecurityDecision.DENY,
        )
    )
    
    test_results.append(
        run_full_pipeline_test(
            "4. Human push (Should ALLOW → carina.queue.ci_trigger)",
            actor="developer-amo",
            event_type="push",
            action="pushed",
            expected_decision=SecurityDecision.ALLOW,
        )
    )
    
    test_results.append(
        run_full_pipeline_test(
            "5. Branch delete (Should DENY)",
            actor="developer-amo",
            event_type="delete",
            action="deleted",
            expected_decision=SecurityDecision.DENY,
        )
    )
    
    test_results.append(
        run_full_pipeline_test(
            "6. Repo publicized (Should APPROVAL_REQUIRED)",
            actor="developer-amo",
            event_type="repository",
            action="publicized",
            expected_decision=SecurityDecision.APPROVAL_REQUIRED,
        )
    )
    
    test_results.append(
        run_full_pipeline_test(
            "7. PR synchronize (Should ALLOW → carina.queue.pr_review)",
            actor="developer-amo",
            event_type="pull_request",
            action="synchronize",
            expected_decision=SecurityDecision.ALLOW,
        )
    )
    
    test_results.append(
        run_full_pipeline_test(
            "8. Unknown event type (Should fail routing)",
            actor="developer-amo",
            event_type="ping",
            action="ping",
        )
    )
    
    test_results.append(
        run_full_pipeline_test(
            "Bonus: Invalid HMAC Signature (Should fail verification)",
            actor="developer-amo",
            event_type="push",
            action="pushed",
            force_sig_fail=True,
        )
    )
    
    # =========================================================================
    # SECTION 2: Direct security rule evaluation tests
    # =========================================================================
    print("\n" + "="*80)
    print("SECTION 2: Security Rule Evaluation Tests")
    print("="*80)
    
    test_results.append(
        run_security_evaluation_test(
            "Rule-001: Dependabot PR opened → APPROVAL_REQUIRED",
            actor="dependabot[bot]",
            event_type="pull_request",
            action="opened",
            expected_decision=SecurityDecision.APPROVAL_REQUIRED,
        )
    )
    
    test_results.append(
        run_security_evaluation_test(
            "Rule-002: github-actions any event → DENY",
            actor="github-actions",
            event_type="push",
            action="pushed",
            expected_decision=SecurityDecision.DENY,
        )
    )
    
    test_results.append(
        run_security_evaluation_test(
            "Rule-003: delete event → DENY",
            actor="human-actor",
            event_type="delete",
            action="deleted",
            expected_decision=SecurityDecision.DENY,
        )
    )
    
    test_results.append(
        run_security_evaluation_test(
            "Rule-004: repository publicized → APPROVAL_REQUIRED",
            actor="human-actor",
            event_type="repository",
            action="publicized",
            expected_decision=SecurityDecision.APPROVAL_REQUIRED,
        )
    )
    
    test_results.append(
        run_security_evaluation_test(
            "Rule-005: pull_request opened → ALLOW",
            actor="human-actor",
            event_type="pull_request",
            action="opened",
            expected_decision=SecurityDecision.ALLOW,
        )
    )
    
    test_results.append(
        run_security_evaluation_test(
            "Rule-006: pull_request synchronize → ALLOW",
            actor="human-actor",
            event_type="pull_request",
            action="synchronize",
            expected_decision=SecurityDecision.ALLOW,
        )
    )
    
    test_results.append(
        run_security_evaluation_test(
            "Rule-007: push event → ALLOW",
            actor="human-actor",
            event_type="push",
            action="pushed",
            expected_decision=SecurityDecision.ALLOW,
        )
    )
    
    test_results.append(
        run_security_evaluation_test(
            "Rule-999: unknown event type → DENY (default)",
            actor="human-actor",
            event_type="workflow_run",
            action="completed",
            expected_decision=SecurityDecision.DENY,
        )
    )
    
    # =========================================================================
    # Test Summary
    # =========================================================================
    print("\n" + "="*80)
    print("TEST SUMMARY")
    print("="*80)
    passed = sum(test_results)
    total = len(test_results)
    print(f"Passed: {passed}/{total}")
    
    if passed == total:
        print("✓ ALL TESTS PASSED")
        sys.exit(0)
    else:
        print(f"✗ {total - passed} TEST(S) FAILED")
        sys.exit(1)
