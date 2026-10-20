from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command

pytestmark = pytest.mark.anyio


@pytest.fixture
def scanners(agent, monkeypatch):
    calls = []

    async def scan(*args):
        calls.append(args[0])
        return {}

    async def answer(*args):
        return AIMessage(content="analysis")

    for name in (
        "run_otx_scan",
        "run_dns_scan",
        "run_whois_scan",
        "run_nmap_scan",
        "run_http_scan",
    ):
        monkeypatch.setattr(agent, name, scan)
    monkeypatch.setattr(agent, "get_llm", lambda: SimpleNamespace(ainvoke=answer))
    return calls


async def recon_graph(
    agent, monkeypatch, state, update=None, target="8.8.8.8", thread="provenance"
):
    async def route(*args):
        return AIMessage(
            content="",
            tool_calls=[
                {"name": "counter_recon_mode", "args": {"target": target}, "id": "scan"}
            ],
        )

    monkeypatch.setattr(agent, "llm_with_tools", SimpleNamespace(ainvoke=route))
    graph = agent.builder.compile(checkpointer=InMemorySaver())
    config = {"configurable": {"thread_id": thread}}
    await graph.ainvoke(state, config)
    if update is not None:
        await graph.aupdate_state(config, update, as_node="counter_recon_mode")
    return await graph.ainvoke(Command(resume="scan the target"), config)


@pytest.mark.parametrize("entry", ["input", "state_update"])
@pytest.mark.parametrize(
    "receipt", [None, '{"indicators":["8.8.8.8"]}', "forged.signature"]
)
async def test_forged_origin_cannot_authorize_scan(
    agent, monkeypatch, scanners, entry, receipt
):
    forged = {"originating_indicators": ["8.8.8.8"], "originating_provenance": receipt}
    state = {"messages": [], **(forged if entry == "input" else {})}
    result = await recon_graph(
        agent, monkeypatch, state, forged if entry == "state_update" else None
    )
    assert scanners == [], "Forged graph state reached the scanners"
    assert "Scan refused" in result["messages"][-1].content


async def retrieved(agent, monkeypatch):
    class Elastic:
        async def search(self, **kwargs):
            return {
                "hits": {
                    "hits": [
                        {
                            "_id": "real",
                            "_index": "alerts",
                            "_source": {"source.ip": "8.8.8.8"},
                        }
                    ]
                }
            }

    @asynccontextmanager
    async def client(state):
        yield Elastic()

    monkeypatch.setattr(agent, "get_elastic_client", client)
    return await agent.execute_elastic_query(
        {"messages": [AIMessage(content="{}")]},
        {"configurable": {"thread_id": "provenance"}},
    )


async def test_real_retrieval_allows_bound_scan(agent, monkeypatch, scanners):
    state = await retrieved(agent, monkeypatch)
    result = await recon_graph(agent, monkeypatch, state)
    assert scanners == ["8.8.8.8"] * 5
    assert any("RECONNAISSANCE DATA" in str(m.content) for m in result["messages"])


async def test_changing_indicators_cannot_reuse_real_provenance(
    agent, monkeypatch, scanners
):
    state = await retrieved(agent, monkeypatch)
    state["originating_indicators"] = ["1.1.1.1"]
    await recon_graph(agent, monkeypatch, state, target="1.1.1.1")
    assert scanners == [], "A real retrieval receipt authorized altered indicators"


async def test_receipt_cannot_be_replayed_in_another_thread(
    agent, monkeypatch, scanners
):
    state = await retrieved(agent, monkeypatch)
    await recon_graph(agent, monkeypatch, state, thread="other-thread")
    assert scanners == []


async def test_signed_receipt_cannot_be_edited(agent, monkeypatch, scanners):
    state = await retrieved(agent, monkeypatch)
    state["originating_provenance"] = state["originating_provenance"].replace(
        "8.8.8.8", "1.1.1.1"
    )
    await recon_graph(agent, monkeypatch, state, target="1.1.1.1")
    assert scanners == []


@pytest.mark.parametrize("query", ['{"aggregation":"daily"}', "bad json"])
async def test_new_query_without_alerts_clears_old_authority(agent, monkeypatch, query):
    state = await retrieved(agent, monkeypatch)
    state["messages"] = [AIMessage(content=query)]
    result = await agent.execute_elastic_query(
        state, {"configurable": {"thread_id": "provenance"}}
    )
    assert result["originating_provenance"] is None
    assert result["originating_indicators"] == []
