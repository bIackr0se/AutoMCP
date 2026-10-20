"""Opt-in API identities and thread ownership for the local LangGraph runtime."""

import hmac
import json
import os
from functools import cache
from typing import Any, cast

from langgraph_sdk import Auth

auth = Auth()


@cache
def _tokens() -> dict[str, dict[str, Any]] | None:
    raw = os.environ.get("KISTE_API_TOKENS")
    if raw is None:
        return None
    try:
        tokens = json.loads(raw)
        if not isinstance(tokens, dict) or not tokens:
            raise ValueError("empty token map")
        for token, user in tokens.items():
            if (
                not token
                or not isinstance(user, dict)
                or not isinstance(user.get("identity"), str)
                or not user["identity"]
            ):
                raise ValueError("invalid token identity")
            if not isinstance(user.get("reviewer", False), bool):
                raise ValueError("invalid reviewer flag")
        return tokens
    except (ValueError, TypeError) as exc:
        raise Auth.exceptions.HTTPException(
            status_code=503, detail="Invalid KISTE_API_TOKENS configuration"
        ) from exc


@auth.authenticate
async def authenticate(authorization: str | None) -> Auth.types.MinimalUserDict:
    """Resolve server-configured bearer tokens, or preserve single-user dev mode."""
    tokens = _tokens()
    if tokens is None:
        return {"identity": "local", "permissions": []}
    scheme, _, supplied = (authorization or "").partition(" ")
    if scheme.lower() == "bearer" and supplied:
        for token, user in tokens.items():
            if hmac.compare_digest(supplied.encode(), token.encode()):
                return {
                    "identity": user["identity"],
                    "permissions": ["review"] if user.get("reviewer") else [],
                }
    raise Auth.exceptions.HTTPException(
        status_code=401, detail="Valid bearer token required"
    )


def _local() -> bool:
    return _tokens() is None


def _owner(ctx: Auth.types.AuthContext) -> dict[str, str]:
    return {"owner": ctx.user.identity}


@auth.on
async def default_policy(ctx: Auth.types.AuthContext, value: dict[str, Any]) -> bool:
    """Preserve local behavior and deny unhandled operations in token mode."""
    return _local()


@auth.on(resources=["assistants"], actions=["read", "search"])
async def read_assistants(ctx: Auth.types.AuthContext, value: Any) -> bool:
    """Let authenticated clients discover and invoke the configured graph."""
    return True


@auth.on.threads.create
async def create_thread(
    *, ctx: Auth.types.AuthContext, value: Auth.types.ThreadsCreate
) -> Auth.types.FilterType | bool:
    """Overwrite caller-provided ownership on creation."""
    if not _local():
        value.setdefault("metadata", {})["owner"] = ctx.user.identity
        return _owner(ctx)
    return True


@auth.on(resources=["threads"], actions=["read", "search"])
async def read_thread(
    ctx: Auth.types.AuthContext, value: Any
) -> Auth.types.FilterType | bool:
    """Scope owner reads and let explicit reviewers inspect pending work."""
    return True if _local() or "review" in ctx.permissions else _owner(ctx)


@auth.on(resources=["threads"], actions=["update", "delete"])
async def modify_thread(
    ctx: Auth.types.AuthContext, value: Any
) -> Auth.types.FilterType | bool:
    """Keep state, metadata and deletion owner-scoped."""
    if _local():
        return True
    if "metadata" in value and value["metadata"] is not None:
        value["metadata"]["owner"] = ctx.user.identity
    return _owner(ctx)


async def _review_checkpoint(thread_id: Any) -> dict[str, Any] | None:
    """Read the authoritative interrupt through the installed local runtime."""
    # The dev runtime publishes these operations without typing metadata.
    from langgraph_runtime.database import connect  # type: ignore[import-untyped]
    from langgraph_runtime.ops import Threads  # type: ignore[import-untyped]

    async with connect() as conn:
        snapshot = await Threads.State.get(
            conn, config={"configurable": {"thread_id": str(thread_id)}}
        )
    if tuple(snapshot.next) != ("review_gate_S",):
        return None
    values = [
        item.get("value") if isinstance(item, dict) else item.value
        for task in snapshot.tasks
        for item in task.interrupts
    ]
    if not any(
        isinstance(item, dict) and item.get("review_required") is True
        for item in values
    ):
        return None
    return cast(dict[str, Any] | None, snapshot.config)


@auth.on.threads.create_run
async def create_run(
    *, ctx: Auth.types.AuthContext, value: Auth.types.RunsCreate
) -> Auth.types.FilterType | bool:
    """Preserve owner resumes and bind cross-owner review to its checkpoint."""
    if _local():
        return True
    value.setdefault("metadata", {})["owner"] = ctx.user.identity
    kwargs = value.get("kwargs") or {}
    command = kwargs.get("command") or {}
    configurable = (kwargs.get("config") or {}).get("configurable") or {}
    # Cross-owner approval carries only the resume, with no scheduling,
    # cancellation or execution controls. Owners keep ordinary run semantics.
    if (
        "review" in ctx.permissions
        and value.get("thread_id")
        and not value.get("after_seconds")
        and value.get("multitask_strategy") in (None, "reject", "enqueue")
        and value.get("if_not_exists") != "create"
        and isinstance(command, dict)
        and set(command) == {"resume"}
        and kwargs.get("input") is None
        # create_valid_run merges request checkpoints into configurable before
        # this hook; kwargs.checkpoint covers direct callback callers as well.
        and not any(
            configurable.get(key)
            for key in ("thread_id", "checkpoint_ns", "checkpoint_id", "checkpoint_map")
        )
        and not any(
            kwargs.get(key)
            for key in (
                "interrupt_before",
                "interrupt_after",
                "webhook",
                "checkpoint",
                "context",
                "feedback_keys",
            )
        )
    ):
        checkpoint = await _review_checkpoint(value["thread_id"])
        if checkpoint:
            config = kwargs.setdefault("config", {})
            config.setdefault("configurable", {}).update(checkpoint["configurable"])
            return True
    return _owner(ctx)
