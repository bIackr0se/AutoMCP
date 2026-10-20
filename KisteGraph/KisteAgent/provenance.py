"""Authenticate retrieval evidence stored in client-writable graph channels."""

import hashlib
import hmac
import json
import os
import secrets
from typing import Any

from langchain_core.runnables import RunnableConfig

_configured_key = os.environ.get("KISTE_PROVENANCE_KEY")
if _configured_key is not None:
    # A shared 256-bit key keeps receipts usable across restarts and workers.
    _KEY = bytes.fromhex(_configured_key)
    if len(_KEY) != 32:
        raise ValueError("KISTE_PROVENANCE_KEY must be 32 random bytes encoded as hex")
else:
    _KEY = secrets.token_bytes(32)


def seal(kind: str, evidence: Any, config: RunnableConfig) -> str | None:
    """Sign evidence for this thread, after the server retrieves it."""
    thread = config.get("configurable", {}).get("thread_id")
    if not thread:
        return None
    payload = json.dumps(
        [kind, str(thread), evidence], sort_keys=True, separators=(",", ":")
    )
    signature = hmac.new(_KEY, payload.encode(), hashlib.sha256).hexdigest()
    return json.dumps([payload, signature])


def unseal(kind: str, receipt: Any, config: RunnableConfig) -> Any:
    """Verify evidence without trusting any other graph-state channel."""
    if not isinstance(receipt, str):
        return None
    try:
        payload, signature = json.loads(receipt)
        if not isinstance(payload, str) or not isinstance(signature, str):
            return None
        expected = hmac.new(_KEY, payload.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(signature, expected):
            return None
        receipt_kind, thread, evidence = json.loads(payload)
        if receipt_kind != kind or thread != str(
            config.get("configurable", {}).get("thread_id")
        ):
            return None
        return evidence
    except (ValueError, TypeError):
        return None
