"""
Trust Zone Boundary Enforcement Middleware
Deployed on TZ-2 Payment API (AWS EKS)

Enforces: mTLS identity verification, SPIFFE workload authentication
(format + allowlist), OAuth bearer token validation, IAM authentication,
canonical cross-zone request signing, replay protection, rate limiting,
and structured JSON audit logging.

Design notes
------------
* Every key declared in ZONE_POLICY is enforced by `authorize()`. A
  regression test pins this contract so future edits to the policy
  table cannot silently weaken posture.
* Verifiers (OAuth, IAM), the signer, the replay cache, and the rate
  limiter are injected behind small Protocols / ABCs so production
  deployments can swap in HSM- or KMS-backed signing (TZ-6) and
  Redis-backed replay/rate state without touching the enforcer.
* Signatures are computed over a canonical JSON encoding that includes
  source zone, target zone, action, request_id, ms-precision timestamp,
  nonce, and a SHA-256 digest of the payload. The format is versioned
  ("v": 1) so the scheme can migrate without ambiguity.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import re
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from functools import wraps
from typing import Any, Callable, Optional, Protocol


# ============================================================================
# Trust zones
# ============================================================================
class TrustZone(Enum):
    TZ1_EDGE    = "tz1-public-edge"
    TZ2_APP     = "tz2-application-services"
    TZ3_DATA    = "tz3-cloud-data"
    TZ4_TRANSIT = "tz4-transit-bridge"
    TZ5_CORE    = "tz5-core-processing"
    TZ6_HSM     = "tz6-hsm-regulatory"


# ============================================================================
# Authorization decision (structured, not bool)
# ============================================================================
class DenyReason(Enum):
    NO_POLICY            = "no_policy_for_route"
    ACTION_NOT_ALLOWED   = "action_not_allowed"
    MTLS_REQUIRED        = "mtls_not_verified"
    SPIFFE_REQUIRED      = "spiffe_id_missing"
    SPIFFE_INVALID       = "spiffe_id_invalid_format"
    SPIFFE_NOT_ALLOWED   = "spiffe_id_not_in_allowlist"
    OAUTH_REQUIRED       = "oauth_token_missing_or_invalid"
    IAM_REQUIRED         = "iam_auth_missing_or_invalid"
    SIGNATURE_REQUIRED   = "request_signature_missing"
    SIGNATURE_INVALID    = "request_signature_invalid"
    PAYLOAD_TOO_LARGE    = "payload_exceeds_max_size"
    TIMESTAMP_STALE      = "timestamp_outside_window"
    REPLAY_DETECTED      = "request_id_already_seen"
    RATE_LIMIT_EXCEEDED  = "rate_limit_exceeded"


@dataclass(frozen=True)
class AuthorizationDecision:
    allowed: bool
    reason: Optional[DenyReason] = None
    detail: Optional[str] = None


# ============================================================================
# Pluggable verifiers (so production can swap in real implementations
# and tests can supply fakes)
# ============================================================================
class OAuthVerifier(Protocol):
    def verify(self, token: str, action: str) -> bool: ...


class IAMVerifier(Protocol):
    def verify(self, principal_arn: str, action: str) -> bool: ...


# ============================================================================
# Signer abstraction
# ============================================================================
class Signer(ABC):
    """Abstract signer. The HMAC implementation is suitable when both
    sides of the boundary live within the same security domain. For
    crossings into TZ-5 / TZ-6, plug in an asymmetric HSM- or
    KMS-backed implementation so the receiving zone never holds key
    material capable of forgery."""

    @abstractmethod
    def sign(self, message: bytes) -> str: ...

    @abstractmethod
    def verify(self, message: bytes, signature: str) -> bool: ...


class HMACSigner(Signer):
    """Symmetric HMAC-SHA256 signer."""

    MIN_KEY_BYTES = 32

    def __init__(self, signing_key: bytes) -> None:
        if len(signing_key) < self.MIN_KEY_BYTES:
            raise ValueError(
                f"signing key must be at least {self.MIN_KEY_BYTES} bytes"
            )
        self._signing_key = signing_key

    def sign(self, message: bytes) -> str:
        return hmac.new(
            self._signing_key, message, hashlib.sha256
        ).hexdigest()

    def verify(self, message: bytes, signature: str) -> bool:
        if not isinstance(signature, str) or not signature:
            return False
        expected = self.sign(message)
        return hmac.compare_digest(expected, signature)


# ============================================================================
# Replay cache
# ============================================================================
class ReplayCache(Protocol):
    """Tracks recently seen request IDs. Production should back this
    with Redis or DynamoDB so the cache is shared across pods."""
    def seen(self, request_id: str) -> bool: ...
    def remember(self, request_id: str, ttl_seconds: int) -> None: ...


class InMemoryReplayCache:
    """Single-process replay cache; dev / test only."""

    def __init__(self) -> None:
        self._store: dict[str, float] = {}

    def _gc(self, now: float) -> None:
        if len(self._store) > 10_000:
            self._store = {k: v for k, v in self._store.items() if v > now}

    def seen(self, request_id: str) -> bool:
        now = time.time()
        self._gc(now)
        expiry = self._store.get(request_id)
        return expiry is not None and expiry > now

    def remember(self, request_id: str, ttl_seconds: int) -> None:
        self._store[request_id] = time.time() + ttl_seconds


# ============================================================================
# Rate limiter
# ============================================================================
class RateLimiter(Protocol):
    def allow(self, route_key: str, limit_rps: int) -> bool: ...


class TokenBucketLimiter:
    """Per-route token bucket. Single-process; replace with a Redis-
    backed limiter for multi-pod deployments."""

    def __init__(self) -> None:
        # route_key -> (last_refill_ts, current_tokens)
        self._buckets: dict[str, tuple[float, float]] = {}

    def allow(self, route_key: str, limit_rps: int) -> bool:
        if limit_rps <= 0:
            return False
        now = time.time()
        last_ts, tokens = self._buckets.get(
            route_key, (now, float(limit_rps))
        )
        elapsed = max(0.0, now - last_ts)
        tokens = min(float(limit_rps), tokens + elapsed * limit_rps)
        if tokens < 1.0:
            self._buckets[route_key] = (now, tokens)
            return False
        self._buckets[route_key] = (now, tokens - 1.0)
        return True


# ============================================================================
# Cross-zone authorization policy
# ============================================================================
ZONE_POLICY: dict[tuple[TrustZone, TrustZone], dict[str, Any]] = {
    (TrustZone.TZ1_EDGE, TrustZone.TZ2_APP): {
        "allowed_actions": [
            "payment.initiate", "payment.status", "account.balance",
        ],
        "require_mtls":     True,
        "require_oauth":    True,
        "max_request_size": 1_048_576,   # 1 MB
        "rate_limit_rps":   5_000,
    },
    (TrustZone.TZ2_APP, TrustZone.TZ3_DATA): {
        "allowed_actions": ["db.read", "db.write", "cache.read"],
        "require_mtls":      True,
        "require_iam_auth":  True,
        "rate_limit_rps":    20_000,
    },
    (TrustZone.TZ2_APP, TrustZone.TZ4_TRANSIT): {
        "allowed_actions": [
            "ledger.post", "ledger.query",
            "token.create", "token.resolve",
        ],
        "require_mtls":     True,
        "require_spiffe":   True,
        "allowed_spiffe_ids": frozenset({
            "spiffe://fintech.internal/tz2/payment-api",
            "spiffe://fintech.internal/tz2/ledger-client",
        }),
        "request_signing":  True,
        "rate_limit_rps":   2_000,
    },
}


# Keys we know how to enforce. Used for the regression check that
# guards against silent policy drift.
_ENFORCED_KEYS: frozenset[str] = frozenset({
    "allowed_actions", "require_mtls", "require_oauth", "require_iam_auth",
    "require_spiffe", "allowed_spiffe_ids", "request_signing",
    "max_request_size", "rate_limit_rps",
})


def _validate_policy_table() -> None:
    for route, policy in ZONE_POLICY.items():
        unknown = set(policy) - _ENFORCED_KEYS
        if unknown:
            raise RuntimeError(
                f"ZONE_POLICY {route} contains unenforced keys: {unknown}. "
                "Either implement enforcement or remove from the policy."
            )


_validate_policy_table()


# SPIFFE ID format: spiffe://trust-domain/path[/path...]
_SPIFFE_RE = re.compile(
    r"^spiffe://[a-zA-Z0-9._-]+(?:/[a-zA-Z0-9._\-]+)+$"
)


# ============================================================================
# Request object (frozen — fields can't be mutated post-construction)
# ============================================================================
@dataclass(frozen=True)
class ZoneCrossingRequest:
    source_zone:        TrustZone
    target_zone:        TrustZone
    action:             str
    request_id:         str
    payload_bytes:      int
    caller_spiffe:      Optional[str] = None
    mtls_verified:      bool = False
    oauth_token:        Optional[str] = None
    iam_principal_arn:  Optional[str] = None
    signature:          Optional[str] = None
    nonce:              Optional[str] = None
    timestamp:          float = field(default_factory=time.time)

    def __post_init__(self) -> None:
        if not self.request_id:
            raise ValueError("request_id is required")
        if self.payload_bytes < 0:
            raise ValueError("payload_bytes must be non-negative")


# ============================================================================
# Canonical signing payload
# ============================================================================
def _canonical_message(
    req: ZoneCrossingRequest,
    payload_digest: str,
) -> bytes:
    """Deterministic encoding for signing. Sorted-keys JSON eliminates
    delimiter-injection ambiguity; all fields that determine
    authorization are bound into the signature."""
    blob = {
        "v":   1,
        "src": req.source_zone.value,
        "dst": req.target_zone.value,
        "act": req.action,
        "rid": req.request_id,
        "ts":  int(req.timestamp * 1000),
        "non": req.nonce or "",
        "pld": payload_digest,
    }
    return json.dumps(blob, sort_keys=True, separators=(",", ":")).encode()


# ============================================================================
# Enforcer
# ============================================================================
class TrustZoneBoundaryEnforcer:
    """Application-layer enforcement of cross-zone security policies."""

    MAX_TIMESTAMP_SKEW = 300   # seconds
    REPLAY_WINDOW      = 600   # seconds

    def __init__(
        self,
        signer: Signer,
        oauth_verifier: Optional[OAuthVerifier] = None,
        iam_verifier: Optional[IAMVerifier] = None,
        replay_cache: Optional[ReplayCache] = None,
        rate_limiter: Optional[RateLimiter] = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._signer = signer
        self._oauth = oauth_verifier
        self._iam = iam_verifier
        self._replay = replay_cache or InMemoryReplayCache()
        self._rate = rate_limiter or TokenBucketLimiter()
        self._now = clock
        self._audit = logging.getLogger("trust_zone.audit")

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def authorize(
        self,
        req: ZoneCrossingRequest,
        actual_payload: bytes,
    ) -> AuthorizationDecision:
        """Authorize a cross-zone request.

        `actual_payload` is the real bytes about to be processed; size
        and signature checks both run against this rather than the
        self-reported `payload_bytes` field on the request.
        """
        route = (req.source_zone, req.target_zone)
        policy = ZONE_POLICY.get(route)

        if policy is None:
            return self._deny(req, DenyReason.NO_POLICY)

        if req.action not in policy["allowed_actions"]:
            return self._deny(
                req, DenyReason.ACTION_NOT_ALLOWED,
                detail=f"action={req.action}",
            )

        # Timestamp freshness — protects against replay of old captures
        skew = abs(self._now() - req.timestamp)
        if skew > self.MAX_TIMESTAMP_SKEW:
            return self._deny(
                req, DenyReason.TIMESTAMP_STALE, detail=f"skew={skew:.0f}s",
            )

        # Replay detection — request_id must not be reused inside window
        if self._replay.seen(req.request_id):
            return self._deny(req, DenyReason.REPLAY_DETECTED)

        if policy.get("require_mtls") and not req.mtls_verified:
            return self._deny(req, DenyReason.MTLS_REQUIRED)

        if policy.get("require_spiffe"):
            if not req.caller_spiffe:
                return self._deny(req, DenyReason.SPIFFE_REQUIRED)
            if not _SPIFFE_RE.match(req.caller_spiffe):
                return self._deny(
                    req, DenyReason.SPIFFE_INVALID,
                    detail=f"spiffe={req.caller_spiffe}",
                )
            allowed_ids = policy.get("allowed_spiffe_ids")
            if allowed_ids and req.caller_spiffe not in allowed_ids:
                return self._deny(
                    req, DenyReason.SPIFFE_NOT_ALLOWED,
                    detail=f"spiffe={req.caller_spiffe}",
                )

        if policy.get("require_oauth"):
            if (not req.oauth_token
                    or self._oauth is None
                    or not self._oauth.verify(req.oauth_token, req.action)):
                return self._deny(req, DenyReason.OAUTH_REQUIRED)

        if policy.get("require_iam_auth"):
            if (not req.iam_principal_arn
                    or self._iam is None
                    or not self._iam.verify(
                        req.iam_principal_arn, req.action)):
                return self._deny(req, DenyReason.IAM_REQUIRED)

        # Size check against the actual payload, not the self-reported value
        actual_size = len(actual_payload)
        max_size = policy.get("max_request_size")
        if max_size and actual_size > max_size:
            return self._deny(
                req, DenyReason.PAYLOAD_TOO_LARGE,
                detail=f"size={actual_size},max={max_size}",
            )

        if policy.get("request_signing"):
            if not req.signature:
                return self._deny(req, DenyReason.SIGNATURE_REQUIRED)
            if not self._verify_signature(req, actual_payload):
                return self._deny(req, DenyReason.SIGNATURE_INVALID)

        rps = policy.get("rate_limit_rps")
        if rps and not self._rate.allow(
            f"{req.source_zone.value}->{req.target_zone.value}", rps
        ):
            return self._deny(req, DenyReason.RATE_LIMIT_EXCEEDED)

        # All checks passed — record for replay protection and approve
        self._replay.remember(req.request_id, self.REPLAY_WINDOW)
        self._allow(req)
        return AuthorizationDecision(allowed=True)

    def sign_request(
        self,
        req: ZoneCrossingRequest,
        payload: bytes,
    ) -> str:
        """Generate a signature binding source zone, target zone, action,
        request_id, ms-precision timestamp, nonce, and a SHA-256 digest
        of the payload."""
        digest = hashlib.sha256(payload).hexdigest()
        return self._signer.sign(_canonical_message(req, digest))

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------
    def _verify_signature(
        self,
        req: ZoneCrossingRequest,
        payload: bytes,
    ) -> bool:
        if not req.signature:
            return False
        digest = hashlib.sha256(payload).hexdigest()
        message = _canonical_message(req, digest)
        try:
            return self._signer.verify(message, req.signature)
        except Exception:
            return False

    def _deny(
        self,
        req: ZoneCrossingRequest,
        reason: DenyReason,
        detail: Optional[str] = None,
    ) -> AuthorizationDecision:
        self._emit_audit("DENIED", req, reason=reason.value, detail=detail)
        return AuthorizationDecision(
            allowed=False, reason=reason, detail=detail
        )

    def _allow(self, req: ZoneCrossingRequest) -> None:
        self._emit_audit("ALLOWED", req)

    def _emit_audit(
        self,
        decision: str,
        req: ZoneCrossingRequest,
        reason: Optional[str] = None,
        detail: Optional[str] = None,
    ) -> None:
        event: dict[str, Any] = {
            "ts":         int(self._now() * 1000),
            "decision":   decision,
            "src_zone":   req.source_zone.value,
            "dst_zone":   req.target_zone.value,
            "action":     req.action,
            "request_id": req.request_id,
            "spiffe":     req.caller_spiffe,
            "mtls":       req.mtls_verified,
        }
        if reason:
            event["reason"] = reason
        if detail:
            event["detail"] = detail
        try:
            self._audit.info(json.dumps(event, sort_keys=True))
        except Exception:
            # Never silently swallow an audit failure
            logging.getLogger(__name__).error(
                "audit emission failed for request_id=%s", req.request_id,
            )


# ============================================================================
# Decorator for handler functions
# ============================================================================
def boundary_enforced(
    enforcer: TrustZoneBoundaryEnforcer,
) -> Callable[[Callable], Callable]:
    """Decorator that runs `authorize()` before invoking the handler.
    Wrapped function signature: (req, payload, *args, **kwargs)."""

    def deco(fn: Callable) -> Callable:
        @wraps(fn)
        def wrapped(
            req: ZoneCrossingRequest,
            payload: bytes,
            *args: Any,
            **kwargs: Any,
        ) -> Any:
            decision = enforcer.authorize(req, payload)
            if not decision.allowed:
                reason = decision.reason.value if decision.reason else "unknown"
                msg = f"zone crossing denied: {reason}"
                if decision.detail:
                    msg += f" ({decision.detail})"
                raise PermissionError(msg)
            return fn(req, payload, *args, **kwargs)
        return wrapped
    return deco


# ============================================================================
# Helper: build a fresh request with generated request_id and nonce
# ============================================================================
def new_request(
    source_zone: TrustZone,
    target_zone: TrustZone,
    action: str,
    payload_bytes: int,
    **kwargs: Any,
) -> ZoneCrossingRequest:
    return ZoneCrossingRequest(
        source_zone=source_zone,
        target_zone=target_zone,
        action=action,
        request_id=str(uuid.uuid4()),
        nonce=uuid.uuid4().hex,
        payload_bytes=payload_bytes,
        **kwargs,
    )


# ============================================================================
# Smoke tests — exercise the contract end-to-end
# ============================================================================
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(message)s")

    class _FakeOAuth:
        def verify(self, token: str, action: str) -> bool:
            return token == "good-token"

    class _FakeIAM:
        def verify(self, principal_arn: str, action: str) -> bool:
            return principal_arn.startswith("arn:aws:iam::123456789012:role/")

    enforcer = TrustZoneBoundaryEnforcer(
        signer=HMACSigner(b"x" * 32),
        oauth_verifier=_FakeOAuth(),
        iam_verifier=_FakeIAM(),
    )

    payload = b'{"amount": 100, "currency": "USD"}'

    # 1. Happy path: TZ-1 -> TZ-2 with mTLS + valid OAuth
    req = new_request(
        TrustZone.TZ1_EDGE, TrustZone.TZ2_APP, "payment.initiate",
        payload_bytes=len(payload),
        mtls_verified=True, oauth_token="good-token",
    )
    d = enforcer.authorize(req, payload)
    assert d.allowed, f"expected allow, got {d}"
    print("OK  TZ-1 -> TZ-2 happy path")

    # 2. Same caller, bad OAuth
    req = new_request(
        TrustZone.TZ1_EDGE, TrustZone.TZ2_APP, "payment.initiate",
        payload_bytes=len(payload),
        mtls_verified=True, oauth_token="forged",
    )
    d = enforcer.authorize(req, payload)
    assert (not d.allowed and d.reason == DenyReason.OAUTH_REQUIRED), d
    print("OK  bad OAuth rejected")

    # 3. Action not in policy
    req = new_request(
        TrustZone.TZ1_EDGE, TrustZone.TZ2_APP, "payment.refund",
        payload_bytes=len(payload),
        mtls_verified=True, oauth_token="good-token",
    )
    d = enforcer.authorize(req, payload)
    assert (not d.allowed and d.reason == DenyReason.ACTION_NOT_ALLOWED), d
    print("OK  unknown action rejected")

    # 4. Replay: same request_id twice
    req = new_request(
        TrustZone.TZ1_EDGE, TrustZone.TZ2_APP, "payment.initiate",
        payload_bytes=len(payload),
        mtls_verified=True, oauth_token="good-token",
    )
    enforcer.authorize(req, payload)
    d = enforcer.authorize(req, payload)
    assert (not d.allowed and d.reason == DenyReason.REPLAY_DETECTED), d
    print("OK  replay rejected")

    # 5. TZ-2 -> TZ-3 IAM enforcement
    req = new_request(
        TrustZone.TZ2_APP, TrustZone.TZ3_DATA, "db.read",
        payload_bytes=len(payload),
        mtls_verified=True,
        iam_principal_arn="arn:aws:iam::123456789012:role/payments-app",
    )
    d = enforcer.authorize(req, payload)
    assert d.allowed, d
    print("OK  TZ-2 -> TZ-3 IAM auth honored")

    req = new_request(
        TrustZone.TZ2_APP, TrustZone.TZ3_DATA, "db.read",
        payload_bytes=len(payload),
        mtls_verified=True,
        iam_principal_arn="arn:aws:iam::999999999999:role/intruder",
    )
    d = enforcer.authorize(req, payload)
    assert (not d.allowed and d.reason == DenyReason.IAM_REQUIRED), d
    print("OK  unknown IAM principal rejected")

    # 6. TZ-2 -> TZ-4 with signing
    spiffe = "spiffe://fintech.internal/tz2/ledger-client"
    req = new_request(
        TrustZone.TZ2_APP, TrustZone.TZ4_TRANSIT, "ledger.post",
        payload_bytes=len(payload),
        mtls_verified=True, caller_spiffe=spiffe,
    )
    sig = enforcer.sign_request(req, payload)
    # signature lives on the request, so rebuild with it
    req_signed = ZoneCrossingRequest(
        source_zone=req.source_zone, target_zone=req.target_zone,
        action=req.action, request_id=req.request_id,
        payload_bytes=req.payload_bytes, mtls_verified=True,
        caller_spiffe=spiffe, signature=sig, nonce=req.nonce,
        timestamp=req.timestamp,
    )
    d = enforcer.authorize(req_signed, payload)
    assert d.allowed, d
    print("OK  TZ-2 -> TZ-4 signature accepted")

    # 7. Tampered payload — same signature, different bytes
    d = enforcer.authorize(req_signed, payload + b"!")
    # First failure could be REPLAY (same request_id reused). Use a
    # fresh request with the tamper-detected payload.
    req2 = new_request(
        TrustZone.TZ2_APP, TrustZone.TZ4_TRANSIT, "ledger.post",
        payload_bytes=len(payload),
        mtls_verified=True, caller_spiffe=spiffe,
    )
    sig2 = enforcer.sign_request(req2, payload)
    req2_signed = ZoneCrossingRequest(
        source_zone=req2.source_zone, target_zone=req2.target_zone,
        action=req2.action, request_id=req2.request_id,
        payload_bytes=req2.payload_bytes, mtls_verified=True,
        caller_spiffe=spiffe, signature=sig2, nonce=req2.nonce,
        timestamp=req2.timestamp,
    )
    d = enforcer.authorize(req2_signed, payload + b"!")
    assert (not d.allowed and d.reason == DenyReason.SIGNATURE_INVALID), d
    print("OK  tampered payload rejected")

    # 8. SPIFFE not in allowlist
    req = new_request(
        TrustZone.TZ2_APP, TrustZone.TZ4_TRANSIT, "ledger.post",
        payload_bytes=len(payload),
        mtls_verified=True,
        caller_spiffe="spiffe://fintech.internal/attacker/svc",
    )
    sig = enforcer.sign_request(req, payload)
    req_signed = ZoneCrossingRequest(
        source_zone=req.source_zone, target_zone=req.target_zone,
        action=req.action, request_id=req.request_id,
        payload_bytes=req.payload_bytes, mtls_verified=True,
        caller_spiffe=req.caller_spiffe, signature=sig, nonce=req.nonce,
        timestamp=req.timestamp,
    )
    d = enforcer.authorize(req_signed, payload)
    assert (not d.allowed and d.reason == DenyReason.SPIFFE_NOT_ALLOWED), d
    print("OK  SPIFFE allowlist enforced")

    # 9. Stale timestamp
    req = ZoneCrossingRequest(
        source_zone=TrustZone.TZ1_EDGE, target_zone=TrustZone.TZ2_APP,
        action="payment.initiate", request_id=str(uuid.uuid4()),
        payload_bytes=len(payload), mtls_verified=True,
        oauth_token="good-token",
        timestamp=time.time() - 3600,  # 1 hour old
    )
    d = enforcer.authorize(req, payload)
    assert (not d.allowed and d.reason == DenyReason.TIMESTAMP_STALE), d
    print("OK  stale timestamp rejected")

    # 10. Oversize payload
    big = b"A" * 2_000_000
    req = new_request(
        TrustZone.TZ1_EDGE, TrustZone.TZ2_APP, "payment.initiate",
        payload_bytes=len(big),
        mtls_verified=True, oauth_token="good-token",
    )
    d = enforcer.authorize(req, big)
    assert (not d.allowed and d.reason == DenyReason.PAYLOAD_TOO_LARGE), d
    print("OK  oversize payload rejected")

    # 11. Unknown route — deny by default
    req = new_request(
        TrustZone.TZ3_DATA, TrustZone.TZ1_EDGE, "leak.everything",
        payload_bytes=0,
    )
    d = enforcer.authorize(req, b"")
    assert (not d.allowed and d.reason == DenyReason.NO_POLICY), d
    print("OK  unknown route denied")

    print("\nAll smoke tests passed.")