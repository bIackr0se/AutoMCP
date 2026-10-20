from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage

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


@pytest.fixture
def recon_graph(compile_resume):
    async def run(state, update=None, target="8.8.8.8", thread="provenance"):
        _, _, task = await compile_resume(
            tool="counter_recon_mode",
            args={"target": target},
            state=state,
            update=update,
            thread=thread,
            resume="scan the target",
        )
        return await task

    return run


@pytest.mark.parametrize("entry", ["input", "state_update"])
@pytest.mark.parametrize(
    "receipt", [None, '{"indicators":["8.8.8.8"]}', "forged.signature"]
)
async def test_forged_origin_cannot_authorize_scan(
    recon_graph, scanners, entry, receipt
):
    forged = {"originating_indicators": ["8.8.8.8"], "originating_provenance": receipt}
    state = {"messages": [], **(forged if entry == "input" else {})}
    result = await recon_graph(state, forged if entry == "state_update" else None)
    assert scanners == [], "Forged graph state reached the scanners"
    assert "Scan refused" in result["messages"][-1].content


@pytest.fixture
async def retrieved(agent, elastic, hit):
    async def search(**kwargs):
        return {"hits": {"hits": [hit("real")]}}

    elastic(search)
    return await agent.execute_elastic_query(
        {"messages": [AIMessage(content="{}")]},
        {"configurable": {"thread_id": "provenance"}},
    )


async def test_real_retrieval_allows_bound_scan(retrieved, recon_graph, scanners):
    result = await recon_graph(retrieved)
    assert scanners == ["8.8.8.8"] * 5
    assert any("RECONNAISSANCE DATA" in str(m.content) for m in result["messages"])


async def test_changing_indicators_cannot_reuse_real_provenance(
    retrieved, recon_graph, scanners
):
    state = retrieved
    state["originating_indicators"] = ["1.1.1.1"]
    await recon_graph(state, target="1.1.1.1")
    assert scanners == [], "A real retrieval receipt authorized altered indicators"


async def test_receipt_cannot_be_replayed_in_another_thread(
    retrieved, recon_graph, scanners
):
    state = retrieved
    await recon_graph(state, thread="other-thread")
    assert scanners == []


async def test_signed_receipt_cannot_be_edited(retrieved, recon_graph, scanners):
    state = retrieved
    state["originating_provenance"] = state["originating_provenance"].replace(
        "8.8.8.8", "1.1.1.1"
    )
    await recon_graph(state, target="1.1.1.1")
    assert scanners == []


@pytest.mark.parametrize("query", ['{"aggregation":"daily"}', "bad json"])
async def test_new_query_without_alerts_clears_old_authority(agent, retrieved, query):
    state = retrieved
    state["messages"] = [AIMessage(content=query)]
    result = await agent.execute_elastic_query(
        state, {"configurable": {"thread_id": "provenance"}}
    )
    assert result["originating_provenance"] is None
    assert "originating_indicators" not in result
    assert result["standby_provenance"] is None
    assert result["standby_status"] == (
        "retrieval_error" if query == "bad json" else None
    )
