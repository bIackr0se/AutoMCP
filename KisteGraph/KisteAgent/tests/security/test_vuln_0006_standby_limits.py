import asyncio

import pytest

pytestmark = pytest.mark.anyio


@pytest.fixture
def limits(agent, monkeypatch, fast_sleep):
    monkeypatch.setattr(agent, "STANDBY_TIMEOUT_SECONDS", 0.01, raising=False)
    monkeypatch.setattr(agent, "STANDBY_POLL_SECONDS", 0.001, raising=False)
    monkeypatch.setattr(agent, "STANDBY_MAX_CONCURRENT", 1, raising=False)


async def finish(task, budget=0.15):
    done, _ = await asyncio.wait({task}, timeout=budget)
    if task not in done:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
    return task in done


async def test_timeout_terminates_compiled_graph(elastic, compile_resume, limits):
    async def unchanged(**kwargs):
        return {"hits": {"hits": []}}

    elastic(unchanged)
    graph, config, task = await compile_resume(
        thread="timeout",
        state={
            "messages": [],
            "originating_provenance": "old",
            "standby_provenance": "old",
        },
    )
    assert await finish(task), "Standby did not terminate within its configured timeout"
    result = task.result()
    assert result["standby_status"] == "timeout"
    assert (await graph.aget_state(config)).next == ()
    assert not result.get("__interrupt__"), (
        "Timeout reached analysis/review or the menu"
    )
    assert result["standby_provenance"] is None
    assert result["originating_provenance"] is None


async def test_capacity_exit_terminates_compiled_graph(
    agent, monkeypatch, elastic, compile_resume, limits
):
    entered = asyncio.Event()
    release = asyncio.Event()

    async def slow_poll(**kwargs):
        entered.set()
        await release.wait()
        return {"hits": {"hits": []}}

    monkeypatch.setattr(agent, "STANDBY_TIMEOUT_SECONDS", 1)
    elastic(slow_poll)
    _, _, first = await compile_resume(thread="holder")
    await asyncio.wait_for(entered.wait(), 0.2)
    try:
        graph, config, second = await compile_resume(
            thread="overflow",
            state={
                "messages": [],
                "originating_provenance": "old",
                "standby_provenance": "old",
            },
        )
        assert await finish(second), (
            "Concurrent standby exceeded capacity instead of terminating"
        )
        assert second.result()["standby_status"] == "capacity"
        assert second.result()["standby_provenance"] is None
        assert second.result()["originating_provenance"] is None
        assert (await graph.aget_state(config)).next == ()
        assert not second.result().get("__interrupt__")
    finally:
        first.cancel()
        await asyncio.gather(first, return_exceptions=True)
        release.set()


async def test_poll_timeout_and_cancellation_release_capacity(
    agent, elastic, hit, limits
):
    async def hung(**kwargs):
        await asyncio.Event().wait()

    elastic(hung)
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

    async def changed(**kwargs):
        changed.calls += 1
        return {"hits": {"hits": [] if changed.calls == 1 else [hit("new")]}}

    changed.calls = 0
    elastic(changed)
    result = await agent.wait_alerts(
        {"messages": []}, {"configurable": {"thread_id": "release"}}
    )
    assert result["standby_status"] == "alert"
