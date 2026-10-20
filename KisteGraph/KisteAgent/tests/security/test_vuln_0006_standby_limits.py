import asyncio
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

pytestmark = pytest.mark.anyio


@pytest.fixture
def limits(agent, monkeypatch):
    monkeypatch.setattr(agent, "STANDBY_TIMEOUT_SECONDS", 0.01, raising=False)
    monkeypatch.setattr(agent, "STANDBY_POLL_SECONDS", 0.001, raising=False)
    monkeypatch.setattr(agent, "STANDBY_MAX_CONCURRENT", 1, raising=False)
    original_sleep = asyncio.sleep

    async def sleep(seconds):
        await original_sleep(min(seconds, 0.001))

    monkeypatch.setattr(agent.asyncio, "sleep", sleep)


async def run_standby(agent, monkeypatch, name):
    async def route(*args):
        return AIMessage(
            content="",
            tool_calls=[{"name": "standby_mode", "args": {}, "id": "standby"}],
        )

    monkeypatch.setattr(agent, "llm_with_tools", SimpleNamespace(ainvoke=route))
    graph = agent.builder.compile(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": name}}
    await graph.ainvoke({"messages": []}, config)
    task = asyncio.create_task(graph.ainvoke(Command(resume="standby"), config))
    return graph, config, task


async def finish(task, budget=0.15):
    done, _ = await asyncio.wait({task}, timeout=budget)
    if task not in done:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    return task in done


async def test_timeout_terminates_compiled_graph(agent, monkeypatch, limits):
    async def unchanged(state):
        return {"_id": "same"}

    monkeypatch.setattr(agent, "last_alert", unchanged)
    graph, config, task = await run_standby(agent, monkeypatch, "timeout")
    assert await finish(task), "Standby did not terminate within its configured timeout"
    result = task.result()
    assert result["standby_status"] == "timeout"
    assert (await graph.aget_state(config)).next == ()
    assert not result.get("__interrupt__"), (
        "Timeout reached analysis/review or the menu"
    )
    assert result.get("pending_standby_alert") is None


async def test_capacity_exit_terminates_compiled_graph(agent, monkeypatch, limits):
    entered = asyncio.Event()
    release = asyncio.Event()

    async def slow_poll(state):
        entered.set()
        await release.wait()
        return {"_id": "same"}

    monkeypatch.setattr(agent, "STANDBY_TIMEOUT_SECONDS", 1)
    monkeypatch.setattr(agent, "last_alert", slow_poll)
    _, _, first = await run_standby(agent, monkeypatch, "holder")
    await asyncio.wait_for(entered.wait(), 0.2)
    try:
        graph, config, second = await run_standby(agent, monkeypatch, "overflow")
        assert await finish(second), (
            "Concurrent standby exceeded capacity instead of terminating"
        )
        assert second.result()["standby_status"] == "capacity"
        assert (await graph.aget_state(config)).next == ()
        assert not second.result().get("__interrupt__")
    finally:
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)
        release.set()


async def test_poll_timeout_and_cancellation_release_capacity(
    agent, monkeypatch, limits
):
    async def hung(state):
        await asyncio.Event().wait()

    monkeypatch.setattr(agent, "last_alert", hung)
    task = asyncio.create_task(
        agent.wait_alerts({"messages": []}, {"configurable": {"thread_id": "release"}})
    )
    assert await finish(task), "An Elasticsearch poll escaped the overall timeout"
    assert task.result()["standby_status"] == "timeout"
    task = asyncio.create_task(
        agent.wait_alerts({"messages": []}, {"configurable": {"thread_id": "release"}})
    )
    await asyncio.sleep(0)
    task.cancel()
    await asyncio.gather(task, return_exceptions=True)

    async def changed(state):
        changed.calls += 1
        return {"_id": str(changed.calls)}

    changed.calls = 0
    monkeypatch.setattr(agent, "last_alert", changed)
    result = await agent.wait_alerts(
        {"messages": []}, {"configurable": {"thread_id": "release"}}
    )
    assert result["standby_status"] == "alert"
