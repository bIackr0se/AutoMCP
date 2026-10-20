import importlib

import pytest


@pytest.fixture
def agent(monkeypatch):
    monkeypatch.setenv("LLM_BACKEND", "ollama")
    return importlib.import_module("agent")
