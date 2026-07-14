from __future__ import annotations

import hmac
import json
from dataclasses import replace
from datetime import datetime, timezone
from hashlib import sha256

from .models import DelegationEnvelope


class EnvelopeSigner:
    def __init__(self, secret: str) -> None:
        if not secret:
            raise ValueError("secret must not be empty")
        self.secret = secret.encode("utf-8")

    def sign(self, envelope: DelegationEnvelope) -> DelegationEnvelope:
        return replace(envelope, signature=self._signature(envelope))

    def verify(self, envelope: DelegationEnvelope) -> bool:
        if not envelope.signature:
            return False
        expected = self._signature(envelope)
        return hmac.compare_digest(expected, envelope.signature)

    def _signature(self, envelope: DelegationEnvelope) -> str:
        payload = json.dumps(
            envelope.to_dict(include_signature=False),
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(self.secret, payload, sha256).hexdigest()


def envelope_is_expired(envelope: DelegationEnvelope) -> bool:
    expires_at = parse_utc(envelope.expires_at)
    return expires_at <= datetime.now(timezone.utc)


def parse_utc(value: str) -> datetime:
    normalized = value.replace("Z", "+00:00")
    parsed = datetime.fromisoformat(normalized)
    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)
