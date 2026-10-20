import asyncio
import json
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

pytestmark = pytest.mark.anyio


def hit(identity, severity="low", timestamp="2026-10-20T10:00:00Z"):
    return {
        "_id": identity,
        "_index": ".internal.alerts-security.alerts-default-1",
        "_source": {
            "kibana.alert.rule.execution.timestamp": timestamp,
            "kibana.alert.rule.name": "same rule",
            "kibana.alert.rule.parameters.severity": severity,
            "source.ip": "8.8.8.8",
        },
    }


@pytest.fixture
def elastic(agent, monkeypatch):
    def install(search):
        @asynccontextmanager
        async def client(state):
            yield SimpleNamespace(search=search)

        monkeypatch.setattr(agent, "get_elastic_client", client)

    return install


async def test_document_identity_distinguishes_same_execution(agent, elastic):
    hits = iter([hit("first"), hit("second")])

    async def search(**kwargs):
        return {"hits": {"hits": [next(hits)]}}

    elastic(search)
    first = await agent.last_alert({"messages": []})
    second = await agent.last_alert({"messages": []})
    assert first != second, (
        "Distinct Elasticsearch documents collapse to identical rule metadata"
    )


@pytest.mark.parametrize("severity", ["medium", "low", "critical"])
@pytest.mark.parametrize("same_execution", [False, True])
@pytest.mark.parametrize("missing", [False, True])
async def test_compiled_graph_analyzes_waking_document_under_churn(
    agent, monkeypatch, elastic, severity, same_execution, missing
):
    polls = 0
    trigger = hit("trigger", severity)
    analyzed = []

    async def search(index, body):
        nonlocal polls
        if body.get("size") == 1 and "ids" not in json.dumps(body):
            polls += 1
            return {
                "hits": {
                    "hits": [
                        hit(
                            "old",
                            severity,
                            timestamp="2026-10-20T10:00:00Z"
                            if same_execution
                            else "2026-10-19",
                        )
                        if polls == 1
                        else trigger
                    ]
                }
            }
        if "ids" in json.dumps(body):
            assert "trigger" in json.dumps(body)
            return {"hits": {"hits": [] if missing else [trigger]}}
        if "terms" in json.dumps(body):
            return {"hits": {"hits": [hit("reserved", "high")]}}
        return {
            "hits": {
                "hits": [
                    hit(f"noise-{i}", timestamp=f"2026-10-20T10:00:0{i}Z")
                    for i in range(3)
                ]
            }
        }

    async def route(*args):
        return AIMessage(
            content="", tool_calls=[{"name": "standby_mode", "args": {}, "id": "wait"}]
        )

    async def analyze(messages):
        analyzed.append(messages[-1].content)
        return AIMessage(content="verdict")

    elastic(search)
    monkeypatch.setattr(agent, "llm_with_tools", SimpleNamespace(ainvoke=route))
    monkeypatch.setattr(agent, "get_llm", lambda: SimpleNamespace(ainvoke=analyze))
    monkeypatch.setattr(agent, "STANDBY_POLL_SECONDS", 0.001, raising=False)
    original_sleep = asyncio.sleep

    async def short_sleep(seconds):
        await original_sleep(0.001)

    monkeypatch.setattr(agent.asyncio, "sleep", short_sleep)
    graph = agent.builder.compile(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": severity}}
    await graph.ainvoke({"messages": []}, config)
    result = await graph.ainvoke(Command(resume="standby"), config)
    if missing:
        assert analyzed == []
        assert result["standby_status"] == "retrieval_error"
        assert (await graph.aget_state(config)).next == ()
        assert not result.get("__interrupt__")
        return
    assert any('"trigger"' in text for text in analyzed), (
        "The waking alert was evicted before analysis"
    )
    query = next(
        m.content
        for m in result["messages"]
        if str(m.content).startswith("Elastic Query Result:")
    )
    data = json.loads(query.split("\n", 1)[1])["data"]
    assert data["hits_returned"] <= 3
    assert any(
        a["kibana.alert.rule.parameters.severity"] == "high" for a in data["alerts"]
    )
    assert result["__interrupt__"][0].value["review_required"] is True
    assert (await graph.aget_state(config)).next == ("review_gate_S",)


async def test_empty_and_unchanged_identity_remain_equal(agent, elastic):
    async def search(**kwargs):
        return {"hits": {"hits": []}}

    elastic(search)
    assert await agent.last_alert({"messages": []}) == await agent.last_alert(
        {"messages": []}
    )
