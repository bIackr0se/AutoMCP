import json
import os
import socket
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import httpx
import pytest

PROJECT = Path(__file__).resolve().parents[2]
TOKENS = {
    "owner-token": {"identity": "owner"},
    "peer-token": {"identity": "peer"},
    "reviewer-token": {"identity": "reviewer", "reviewer": True},
}


def headers(identity):
    return {"Authorization": f"Bearer {identity}-token"}


@pytest.fixture(scope="module")
def api(tmp_path_factory, request):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    temp = tmp_path_factory.mktemp("api")

    class Ollama(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Type", "application/x-ndjson")
            self.end_headers()
            self.wfile.write(
                (
                    json.dumps(
                        {
                            "model": "qwen2.5:3b",
                            "created_at": "2026-10-20T00:00:00Z",
                            "message": {
                                "role": "assistant",
                                "content": "ordinary response",
                            },
                            "done": True,
                        }
                    )
                    + "\n"
                ).encode()
            )

        def log_message(self, *args):
            pass

    ollama = ThreadingHTTPServer(("127.0.0.1", 0), Ollama)
    worker = threading.Thread(target=ollama.serve_forever, daemon=True)
    worker.start()
    env = {
        **os.environ,
        "LLM_BACKEND": "ollama",
        "KISTE_API_TOKENS": json.dumps(TOKENS),
        "LANGSMITH_TRACING": "false",
        "LANGGRAPH_DISABLE_FILE_PERSISTENCE": "true",
        "OLLAMA_HOST": f"http://127.0.0.1:{ollama.server_port}",
    }
    if not getattr(request, "param", True):
        env.pop("KISTE_API_TOKENS", None)
    log = (temp / "server.log").open("w+")
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "langgraph_cli",
            "dev",
            "--config",
            str(PROJECT / "langgraph.json"),
            "--no-browser",
            "--no-reload",
            "--port",
            str(port),
        ],
        cwd=PROJECT,
        env=env,
        stdout=log,
        stderr=subprocess.STDOUT,
    )
    client = httpx.Client(base_url=f"http://127.0.0.1:{port}", timeout=20)
    try:
        for _ in range(200):
            if process.poll() is not None:
                log.seek(0)
                pytest.fail(f"API startup failed: {log.read()}")
            try:
                if client.get("/ok", headers=headers("owner")).status_code == 200:
                    break
            except httpx.TransportError:
                pass
            time.sleep(0.05)
        else:
            log.seek(0)
            pytest.fail(f"API did not start: {log.read()}")
        yield client
    finally:
        client.close()
        process.terminate()
        process.wait(timeout=10)
        log.close()
        ollama.shutdown()
        ollama.server_close()
        worker.join()


def new_thread(api):
    response = api.post(
        "/threads", headers=headers("owner"), json={"metadata": {"owner": "peer"}}
    )
    response.raise_for_status()
    return response.json()["thread_id"]


def test_auth_handler_registered():
    config = json.loads((PROJECT / "langgraph.json").read_text())
    assert config.get("auth", {}).get("path"), (
        "No server authentication handler is registered"
    )


def test_peer_cannot_read_or_resume_owner_review(api):
    thread = new_thread(api)
    initial = api.post(
        f"/threads/{thread}/runs/wait",
        headers=headers("owner"),
        json={"assistant_id": "kiste_agent", "input": {"messages": []}},
    )
    initial.raise_for_status()
    seed = api.post(
        f"/threads/{thread}/state",
        headers=headers("owner"),
        json={
            "values": {"messages": [{"type": "ai", "content": "review this verdict"}]},
            "as_node": "query_analyzer_S",
        },
    )
    seed.raise_for_status()
    paused = api.post(
        f"/threads/{thread}/runs/wait",
        headers=headers("owner"),
        json={"assistant_id": "kiste_agent", "input": None},
    )
    paused.raise_for_status()
    foreign = api.get(f"/threads/{thread}/state", headers=headers("peer"))
    assert foreign.status_code == 404, "A peer read the owner's pending review"
    response = api.post(
        f"/threads/{thread}/runs/wait",
        headers=headers("peer"),
        json={"assistant_id": "kiste_agent", "command": {"resume": "approved"}},
    )
    assert response.status_code in (403, 404)


def test_owner_and_explicit_reviewer_can_approve(api):
    for identity in ("owner", "reviewer"):
        thread = new_thread(api)
        api.post(
            f"/threads/{thread}/runs/wait",
            headers=headers("owner"),
            json={"assistant_id": "kiste_agent", "input": {"messages": []}},
        ).raise_for_status()
        api.post(
            f"/threads/{thread}/state",
            headers=headers("owner"),
            json={
                "values": {"messages": [{"type": "ai", "content": "verdict"}]},
                "as_node": "query_analyzer_S",
            },
        ).raise_for_status()
        api.post(
            f"/threads/{thread}/runs/wait",
            headers=headers("owner"),
            json={"assistant_id": "kiste_agent", "input": None},
        ).raise_for_status()
        result = api.post(
            f"/threads/{thread}/runs/wait",
            headers=headers(identity),
            json={"assistant_id": "kiste_agent", "command": {"resume": "approved"}},
        )
        result.raise_for_status()
        assert "[Reviewed by operator]" in result.text


def test_authentication_required_in_token_mode(api):
    assert api.post("/threads", json={}).status_code == 401
    assert (
        api.post(
            "/threads", json={}, headers={"Authorization": "Bearer unknown"}
        ).status_code
        == 401
    )


def test_owner_metadata_cannot_be_reassigned(api):
    thread = new_thread(api)
    result = api.patch(
        f"/threads/{thread}",
        headers=headers("owner"),
        json={"metadata": {"owner": "peer"}},
    )
    result.raise_for_status()
    assert api.get(f"/threads/{thread}", headers=headers("peer")).status_code == 404
    assert api.get(f"/threads/{thread}", headers=headers("owner")).status_code == 200


def test_create_existing_thread_is_owner_scoped(api):
    thread = new_thread(api)
    payload = {"thread_id": thread, "if_exists": "do_nothing"}
    own = api.post("/threads", headers=headers("owner"), json=payload)
    own.raise_for_status()
    assert own.json()["thread_id"] == thread
    assert own.json()["metadata"]["owner"] == "owner"

    foreign = api.post("/threads", headers=headers("peer"), json=payload)
    assert foreign.status_code == 409, foreign.text
    assert api.get(f"/threads/{thread}", headers=headers("peer")).status_code == 404
    assert api.get(f"/threads/{thread}", headers=headers("owner")).json() == own.json()


@pytest.mark.parametrize(
    "extra",
    [
        {"after_seconds": 60},
        {"interrupt_before": ["review_gate_S"]},
        {"checkpoint": {"checkpoint_ns": "other"}},
        {"checkpoint_id": "00000000-0000-0000-0000-000000000001"},
    ],
    ids=["after_seconds", "interrupt_before", "checkpoint", "checkpoint_id"],
)
def test_reviewer_cannot_attach_run_controls_to_approval(api, extra):
    thread = new_thread(api)
    api.post(
        f"/threads/{thread}/runs/wait",
        headers=headers("owner"),
        json={"assistant_id": "kiste_agent", "input": {"messages": []}},
    ).raise_for_status()
    api.post(
        f"/threads/{thread}/state",
        headers=headers("owner"),
        json={
            "values": {"messages": [{"type": "ai", "content": "verdict"}]},
            "as_node": "query_analyzer_S",
        },
    ).raise_for_status()
    api.post(
        f"/threads/{thread}/runs/wait",
        headers=headers("owner"),
        json={"assistant_id": "kiste_agent", "input": None},
    ).raise_for_status()
    payload = {"assistant_id": "kiste_agent", "command": {"resume": "approved"}}
    runs_before = api.get(f"/threads/{thread}/runs", headers=headers("owner")).json()
    response = api.post(
        f"/threads/{thread}/runs",
        headers=headers("reviewer"),
        json={**payload, **extra},
    )
    assert response.status_code in (403, 404), response.text
    assert (
        api.get(f"/threads/{thread}/runs", headers=headers("owner")).json()
        == runs_before
    )
    approved = api.post(
        f"/threads/{thread}/runs/wait",
        headers=headers("reviewer"),
        json=payload,
    )
    approved.raise_for_status()
    assert "[Reviewed by operator]" in approved.text


def test_reviewer_cannot_resume_foreign_menu_or_start_run(api):
    thread = new_thread(api)
    api.post(
        f"/threads/{thread}/runs/wait",
        headers=headers("owner"),
        json={"assistant_id": "kiste_agent", "input": {"messages": []}},
    ).raise_for_status()
    result = api.post(
        f"/threads/{thread}/runs/wait",
        headers=headers("reviewer"),
        json={"assistant_id": "kiste_agent", "command": {"resume": "approved"}},
    )
    assert result.status_code in (403, 404)
    result = api.post(
        f"/threads/{thread}/runs/wait",
        headers=headers("reviewer"),
        json={"assistant_id": "kiste_agent", "input": {"messages": []}},
    )
    assert result.status_code in (403, 404)


def test_owner_can_resume_ordinary_menu(api):
    thread = new_thread(api)
    api.post(
        f"/threads/{thread}/runs/wait",
        headers=headers("owner"),
        json={"assistant_id": "kiste_agent", "input": {"messages": []}},
    ).raise_for_status()
    result = api.post(
        f"/threads/{thread}/runs/wait",
        headers=headers("owner"),
        json={"assistant_id": "kiste_agent", "command": {"resume": "hello"}},
    )
    result.raise_for_status()
    assert "ordinary response" in result.text


@pytest.mark.parametrize("api", [False], indirect=True)
def test_unconfigured_local_api_and_menu_still_work(api):
    result = api.post("/threads", json={})
    result.raise_for_status()
    thread = result.json()["thread_id"]
    initial = api.post(
        f"/threads/{thread}/runs/wait",
        json={"assistant_id": "kiste_agent", "input": {"messages": []}},
    )
    initial.raise_for_status()
    assert "Main Menu" in initial.text
    resumed = api.post(
        f"/threads/{thread}/runs/wait",
        json={"assistant_id": "kiste_agent", "command": {"resume": "hello"}},
    )
    resumed.raise_for_status()
    assert "ordinary response" in resumed.text
