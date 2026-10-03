import importlib.util
import json
import sys
from pathlib import Path

import pytest
from langgraph.pregel import Pregel


def _load_configured_graph(monkeypatch: pytest.MonkeyPatch) -> object:
    project_root = Path(__file__).parents[2]
    config = json.loads((project_root / "langgraph.json").read_text())
    module_path, graph_name = config["graphs"]["kiste_agent"].split(":", 1)
    spec = importlib.util.spec_from_file_location(
        "kiste_agent_deployed", project_root / module_path
    )
    if spec is None or spec.loader is None:
        raise ImportError(f"Cannot load configured graph module: {module_path}")

    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return getattr(module, graph_name)


def test_deployed_graph_compiles(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LLM_BACKEND", "ollama")

    assert isinstance(_load_configured_graph(monkeypatch), Pregel)
