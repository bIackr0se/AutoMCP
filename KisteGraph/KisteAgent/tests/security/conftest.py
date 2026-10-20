import asyncio
import importlib
from contextlib import asynccontextmanager
from types import SimpleNamespace

import pytest
from langchain_core.messages import AIMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.types import Command


@pytest.fixture
def agent(monkeypatch):
    monkeypatch.setenv("LLM_BACKEND", "ollama")
    return importlib.import_module("agent")


@pytest.fixture
def hit():
    def build(identity, severity="low", timestamp="2026-10-20T10:00:00Z"):
        return {
            "_id": identity,
            "_index": ".internal.alerts-security.alerts-default-1",
            "_source": {
                "kibana.alert.rule.execution.timestamp": timestamp,
                "kibana.alert.uuid": identity,
                "kibana.alert.rule.name": "same rule",
                "kibana.alert.rule.parameters.severity": severity,
                "source.ip": "8.8.8.8",
            },
        }

    return build


@pytest.fixture
def elastic(agent, monkeypatch):
    def install(search, get=None):
        @asynccontextmanager
        async def client(state):
            yield SimpleNamespace(search=search, get=get)

        monkeypatch.setattr(agent, "get_elastic_client", client)

    return install


@pytest.fixture
def fast_sleep(agent, monkeypatch):
    original_sleep = asyncio.sleep

    async def sleep(seconds):
        await original_sleep(min(seconds, 0.001))

    monkeypatch.setattr(agent.asyncio, "sleep", sleep)
    monkeypatch.setattr(agent, "STANDBY_POLL_SECONDS", 0.001)


@pytest.fixture
def single_tool(agent, monkeypatch):
    def install(name, args=None):
        async def route(*messages):
            return AIMessage(
                content="",
                tool_calls=[{"name": name, "args": args or {}, "id": "tool"}],
            )

        monkeypatch.setattr(agent, "llm_with_tools", SimpleNamespace(ainvoke=route))

    return install


@pytest.fixture
def compile_resume(agent, single_tool):
    async def start(
        tool="standby_mode",
        args=None,
        state=None,
        update=None,
        thread="standby",
        resume="standby",
    ):
        single_tool(tool, args)
        graph = agent.builder.compile(checkpointer=InMemorySaver())
        config = {"configurable": {"thread_id": thread}}
        await graph.ainvoke(state if state is not None else {"messages": []}, config)
        if update is not None:
            await graph.aupdate_state(config, update, as_node=tool)
        task = asyncio.create_task(graph.ainvoke(Command(resume=resume), config))
        return graph, config, task

    return start
