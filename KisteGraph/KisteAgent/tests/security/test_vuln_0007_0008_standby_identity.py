import json
from types import SimpleNamespace

import pytest
from elastic_transport import ApiResponseMeta, NodeConfig
from elasticsearch import NotFoundError
from langchain_core.messages import AIMessage

pytestmark = pytest.mark.anyio


@pytest.fixture
def analyzed(agent, monkeypatch):
    texts = []

    async def analyze(messages):
        texts.append(messages[-1].content)
        return AIMessage(content="verdict")

    monkeypatch.setattr(agent, "get_llm", lambda: SimpleNamespace(ainvoke=analyze))
    return texts


@pytest.fixture
def churn(elastic, hit):
    def install(severity="low", same_execution=True, missing=False):
        polls = 0
        trigger = hit("trigger", severity)
        old = hit(
            "old",
            severity,
            timestamp=(
                "2026-10-20T10:00:00Z" if same_execution else "2026-10-19T10:00:00Z"
            ),
        )

        async def search(index, body):
            nonlocal polls
            assert "aggs" not in body, "Polling must not aggregate the whole index"
            if body.get("_source") is False:
                assert body["track_total_hits"] is True
                return {
                    "hits": {"hits": [old], "total": {"value": 1, "relation": "eq"}}
                }
            if body.get("size") == 1:
                polls += 1
                return {"hits": {"hits": [old if polls == 1 else trigger]}}
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

        async def get(index, id, _source_includes):
            assert (index, id) == (trigger["_index"], trigger["_id"])
            assert "source.ip" in _source_includes
            if missing:
                raise NotFoundError(
                    "missing",
                    meta=ApiResponseMeta(
                        404, "1.1", {}, 0, NodeConfig("http", "localhost", 9200)
                    ),
                    body={},
                )
            return trigger

        elastic(search, get)

    return install


async def test_document_identity_distinguishes_same_execution(agent, elastic, hit):
    hits = iter([hit("first"), hit("second")])

    async def search(**kwargs):
        return {"hits": {"hits": [next(hits)]}}

    elastic(search)
    first = await agent.last_alert({"messages": []})
    second = await agent.last_alert({"messages": []})
    assert first != second
    assert first == agent.project_hit(hit("first"))


@pytest.mark.parametrize("severity", ["medium", "low", "critical"])
@pytest.mark.parametrize("same_execution", [False, True])
async def test_compiled_graph_analyzes_waking_document_under_churn(
    churn, analyzed, compile_resume, fast_sleep, severity, same_execution
):
    churn(severity, same_execution)
    graph, config, task = await compile_resume(thread=severity)
    result = await task
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
    assert result["standby_provenance"] is None
    assert result["__interrupt__"][0].value["review_required"] is True
    assert (await graph.aget_state(config)).next == ("review_gate_S",)


async def test_missing_waking_document_stops_without_analysis(
    churn, analyzed, compile_resume, fast_sleep
):
    churn(missing=True)
    graph, config, task = await compile_resume(
        state={
            "messages": [],
            "originating_provenance": "old",
            "standby_provenance": "old",
        }
    )
    result = await task
    assert analyzed == []
    assert result["standby_status"] == "retrieval_error"
    assert result["originating_provenance"] is None
    assert result["standby_provenance"] is None
    assert "no longer available" in result["messages"][-1].content
    assert (await graph.aget_state(config)).next == ()
    assert not result.get("__interrupt__")


async def test_empty_and_unchanged_identity_remain_equal(agent, elastic):
    async def search(**kwargs):
        return {"hits": {"hits": []}}

    elastic(search)
    assert await agent.last_alert({"messages": []}) == await agent.last_alert(
        {"messages": []}
    )


@pytest.mark.parametrize("relation", ["eq", "gte"])
async def test_truncated_baseline_requires_newer_execution(
    agent, monkeypatch, elastic, hit, fast_sleep, relation
):
    monkeypatch.setattr(agent, "STANDBY_BATCH_LIMIT", 1)
    old, unseen = hit("z-old"), hit("a-unseen")
    newer = hit("new-execution", timestamp="2026-10-20T10:00:01Z")
    polls = 0

    async def search(index, body):
        nonlocal polls
        assert "aggs" not in body
        if body.get("_source") is False:
            assert body["size"] == 1
            assert body["track_total_hits"] is True
            return {
                "hits": {"hits": [old], "total": {"value": 2, "relation": relation}}
            }
        if "query" not in body:
            return {"hits": {"hits": [old]}}
        bounds = body["query"]["bool"]["filter"][0]["range"][agent._EXECUTION_TIMESTAMP]
        assert bounds == {"gt": old["_source"][agent._EXECUTION_TIMESTAMP]}
        assert body["query"]["bool"]["must_not"] == [{"ids": {"values": ["z-old"]}}]
        polls += 1
        candidate = unseen if polls == 1 else newer
        docs = (
            [candidate]
            if candidate["_source"][agent._EXECUTION_TIMESTAMP] > bounds["gt"]
            else []
        )
        return {"hits": {"hits": docs}}

    elastic(search)
    config = {"configurable": {"thread_id": "truncated"}}
    result = await agent.wait_alerts({"messages": []}, config)
    assert polls == 2
    assert (
        agent.unseal("standby", result["standby_provenance"], config)["_id"]
        == "new-execution"
    )


async def test_same_execution_lower_uuid_pins_new_document(
    agent, monkeypatch, hit, elastic, compile_resume, fast_sleep
):
    # A query-aware fake keeps the old top hit first even after the insertion.
    build, install = hit, elastic
    old, new = build("z-old"), build("a-new")
    snapshots = 0
    pinned = []
    analyzed = []

    async def search(index, body):
        nonlocal snapshots
        if body.get("_source") is False:
            return {"hits": {"hits": [old], "total": {"value": 1, "relation": "eq"}}}
        if "kibana.alert.uuid" in body.get("_source", []):
            snapshots += 1
            docs = [old] if snapshots == 1 else [old, new]
            clauses = body.get("query", {}).get("bool", {})
            for clause in clauses.get("filter", []):
                if "range" in clause:
                    bounds = clause["range"]["kibana.alert.rule.execution.timestamp"]
                    docs = [
                        d
                        for d in docs
                        if all(
                            d["_source"]["kibana.alert.rule.execution.timestamp"] >= v
                            if op == "gte"
                            else d["_source"]["kibana.alert.rule.execution.timestamp"]
                            > v
                            for op, v in bounds.items()
                        )
                    ]
            for clause in clauses.get("must_not", []):
                docs = [d for d in docs if d["_id"] not in clause["ids"]["values"]]
            return {
                "hits": {
                    "hits": docs[: body["size"]],
                    "total": {"value": len(docs), "relation": "eq"},
                },
                "aggregations": {
                    "latest_execution_batch": {"buckets": [{"doc_count": snapshots}]}
                },
            }
        if "ids" in json.dumps(body):  # HEAD's pinned-document search
            identity = body["query"]["bool"]["filter"][0]["ids"]["values"][0]
            pinned.append(identity)
            return {"hits": {"hits": [old if identity == old["_id"] else new]}}
        if "terms" in json.dumps(body):
            return {"hits": {"hits": []}}
        return {"hits": {"hits": [build(f"noise-{i}") for i in range(3)]}}

    async def get(index, id, _source_includes):
        pinned.append(id)
        assert index == new["_index"]
        return new if id == new["_id"] else old

    async def analyze(messages):
        analyzed.append(messages[-1].content)
        return AIMessage(content="verdict")

    install(search, get)
    monkeypatch.setattr(agent, "get_llm", lambda: SimpleNamespace(ainvoke=analyze))
    graph, config, task = await compile_resume(thread="lower-uuid")
    result = await task
    assert pinned == ["a-new"], (
        f"Pinned the old top hit instead of the insertion: {pinned}"
    )
    assert any('"a-new"' in text for text in analyzed)
    assert result["standby_status"] == "retrieved"
    assert (await graph.aget_state(config)).next == ("review_gate_S",)


async def test_baseline_excludes_every_existing_id(agent, elastic, hit):
    old, second = hit("z-old"), hit("b-old")
    calls = []

    async def search(index, body):
        calls.append(body)
        assert "aggs" not in body
        if body.get("_source") is False:
            assert body["query"] == {
                "term": {
                    agent._EXECUTION_TIMESTAMP: old["_source"][
                        agent._EXECUTION_TIMESTAMP
                    ]
                }
            }
            assert body["size"] == agent.STANDBY_BATCH_LIMIT
            assert body["track_total_hits"] is True
            return {
                "hits": {"hits": [old, second], "total": {"value": 2, "relation": "eq"}}
            }
        if "query" in body:
            assert body["size"] == 1
            assert body["query"] == {
                "bool": {
                    "filter": [
                        {
                            "range": {
                                agent._EXECUTION_TIMESTAMP: {
                                    "gte": old["_source"][agent._EXECUTION_TIMESTAMP]
                                }
                            }
                        }
                    ],
                    "must_not": [{"ids": {"values": ["b-old", "z-old"]}}],
                }
            }
            return {"hits": {"hits": []}}
        return {"hits": {"hits": [old]}}

    elastic(search)
    baseline = await agent.standby_baseline({"messages": []})
    assert baseline["truncated"] is False
    assert await agent.last_alert({"messages": []}, baseline=baseline) is None
    assert len(calls) == 3


@pytest.mark.parametrize("exit_path", ["parse", "search", "unverified", "poll"])
async def test_error_exits_clear_all_retrieval_state(agent, elastic, exit_path):
    async def broken(**kwargs):
        raise RuntimeError("backend unavailable")

    elastic(broken)
    state = {
        "messages": [AIMessage(content="bad json" if exit_path == "parse" else "{}")],
        "originating_provenance": "stale-origin",
        "standby_provenance": "stale-standby",
        "standby_status": "alert",
    }
    config = {"configurable": {"thread_id": "error-reset"}}
    if exit_path == "unverified":
        result = await agent.execute_standby_query(state, config)
    elif exit_path == "poll":
        result = await agent.wait_alerts(state, config)
    else:
        result = await agent.execute_elastic_query(state, config)
    if exit_path == "poll":
        # A standby stop leaves an earlier retrieval's scan receipt in place.
        assert "originating_provenance" not in result
    else:
        assert result["originating_provenance"] is None
    assert result["standby_provenance"] is None
    assert result["standby_status"] == (
        "error" if exit_path == "poll" else "retrieval_error"
    )
