# KisteAgent (CoAnalyst)

A LangGraph agent that triages Elastic Security alerts, correlates threat
intel, and performs gated counter-reconnaissance against the source of an
attack. Exposed both as a LangGraph graph (`agent.py:graph`) and, via the
same file, an MCP tool server (`mcp.server.fastmcp.FastMCP`).

Background and the accepted-paper security posture are in the [repo-level
README](../../README.md).

## Modes

The router (`assistant` node) reads the conversation and dispatches to one of:

- **`chat_mode`**: explain or interpret already-retrieved data, general Q&A.
- **`custom_query_mode`**: fetch new data from Elasticsearch
  (`generate_elastic_query` -> `execute_elastic_query` -> `query_analyzer`).
- **`counter_recon_mode`**: active recon (nmap, WHOIS, DNS, HTTP, OTX)
  against a validated external target.
- **`standby_mode`**: continuous polling (`wait_alerts`) that analyzes new
  alerts as they land, gated by a human-review interrupt before the verdict
  is kept (see Security posture below).

Every path returns to `assistant`, which blocks on `interrupt()` for the next
operator command. There is no unattended action loop beyond the standby
polling itself.

## Security posture

This agent is the subject of a SHIELD-AI 2026 paper that found three
vulnerabilities in its agentic layer (target selection, alert retrieval,
summarization) and implemented one matched mitigation per vulnerability.
All three are wired into the deployed graph, in [`mitigations.py`](mitigations.py):

- **M1** (`validate_scan_target`): a counter-recon target is only scanned if
  every address it resolves to falls outside a deny-list (private, loopback,
  link-local, cloud-metadata, protected-segment ranges, including IPv6
  encodings of a denied IPv4) and it resolves onto the indicator of an alert
  that actually triggered the investigation. A scan with no originating
  alert is refused.
- **M2** (`severity_aware_retain`): alert retrieval keeps a high-severity
  reserve alongside the recency window, so a critical alert cannot be
  evicted by benign volume.
- **M3** (`build_analyzer_messages`): the analyst LLM's trusted instruction
  stays in the system role; untrusted alert content goes in the user role
  inside a per-call random delimiter, so an instruction planted in alert
  data cannot be read as guidance. On the autonomous standby path, an
  additional review gate (`review_gate_S`) blocks with the verdict itself
  and requires an explicit operator confirmation before it is kept; a
  rejected or non-affirmative response discards it.

Set `_OT_SEGMENTS` in `mitigations.py` to the deployment's actual protected
ranges before running against a real network.

## Configuration

Environment variables (a `.env` file next to `agent.py` is loaded automatically):

| Variable | Purpose | Default |
|---|---|---|
| `ES_HOST` | Elasticsearch URL | `https://10.10.0.5:9200` |
| `ES_USERNAME` / `ES_PASSWORD` | Elasticsearch basic auth | none |
| `ES_API_KEY` | Elasticsearch API key, if used instead of basic auth | none |
| `ES_VERIFY_CERTS` | TLS certificate verification | `true` |
| `ES_CA_CERT` | CA bundle path for a self-signed cluster | none |
| `LLM_BACKEND` | `ollama` or `groq` | prompts if unset |
| `GROQ_API_KEY` | required if `LLM_BACKEND=groq` | none |
| `OTX_API_KEY` | AlienVault OTX key for counter-recon threat-intel lookups | none, feature fails closed |

`ES_VERIFY_CERTS` defaults to `true`. Most Elastic Security quick-start
installs generate a self-signed CA (typically `http_ca.crt`), so pointing
this agent at one without setting `ES_CA_CERT` will fail every ES call
(`execute_elastic_query` returns an error message; standby mode's
`wait_alerts` logs "Error checking last alert" and polls forever without
ever detecting an alert). Set `ES_CA_CERT` to that cluster's CA bundle
rather than falling back to `ES_VERIFY_CERTS=false`.

## Development

```bash
uv sync                       # install from the lockfile
uv run langgraph dev          # serve the graph locally (LangGraph Studio)
make test                     # unit tests
make integration_tests        # integration tests (needs live ES/LLM backends)
```

`src/agent/` is the untouched LangGraph starter-template package (a
single-node stub graph), kept only because `pyproject.toml`'s build config
packages it as `kiste-agent`'s source layout. `tests/` currently exercises
that stub, not `agent.py`; real coverage of the deployed graph is open work.
