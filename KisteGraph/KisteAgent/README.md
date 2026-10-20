# KisteAgent (CoAnalyst)

A LangGraph agent that triages Elastic Security alerts, correlates threat
intel, and performs gated counter-reconnaissance against the source of an
attack. The configured execution entry point is the LangGraph graph (`agent.py:graph`).
The module initializes a FastMCP instance but provides no tool registrations or
server launcher; use the LangGraph entry point for this runtime.

Background and the accepted-paper security posture are in the [repo-level
README](../../README.md).

## Try the credential-free workbench

From the repository root, run `python3 -m workbench`. The [root guide](../../README.md#try-the-evidence-workbench) describes the synthetic replay and its limits.

## Modes

The router (`assistant` node) reads the conversation and dispatches to one of:

- **`chat_mode`**: explain or interpret already-retrieved data, general Q&A.
- **`custom_query_mode`**: fetch new data from Elasticsearch
  (`generate_elastic_query` -> `execute_elastic_query` -> `query_analyzer`).
- **`counter_recon_mode`**: active recon (nmap, WHOIS, DNS, HTTP, OTX)
  against a validated external target.
- **`standby_mode`**: bounded polling (`wait_alerts`) that analyzes new
  alerts as they land, gated by a human-review interrupt before the verdict
  is kept (see Security posture below).

Completed analysis returns to `assistant`, which blocks on `interrupt()` for
the next operator command. Standby timeout, capacity and retrieval-error exits
end the run without analysis or review. Start a new run to monitor again.

## Security posture

This agent is the subject of a SHIELD-AI 2026 paper that found three
vulnerabilities in its agentic layer (target selection, alert retrieval,
summarization) and implemented one matched mitigation per vulnerability.
All three are wired into the deployed graph, in [`mitigations.py`](mitigations.py); retention now lives in the shared
[`alert_retention.py`](alert_retention.py) and is re-exported for existing callers:

- **M1** (`validate_scan_target`): a counter-recon target is only scanned if
  every address it resolves to is global unicast and outside the protected
  segments, including checks on IPv4 addresses embedded in IPv6. The target
  must match an indicator from a server-signed alert retrieval in the same
  thread. Public graph channels, including `originating_indicators`, do not
  grant scan authority. A new query replaces the stored receipt; aggregates,
  empty results and query errors clear it.
- **M2** (`severity_aware_retain`): alert retrieval keeps a high-severity
  reserve alongside the recency window, so a critical alert cannot be
  evicted by benign volume. Standby also reserves the exact waking document
  (`_index` and `_id`) in the three-alert result. If that document disappears
  or cannot be fetched, the run ends without analyzing a different window.
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
| `KISTE_API_TOKENS` | JSON map of bearer tokens to identities and optional reviewer grants, described below | unset, single-user local mode |
| `KISTE_PROVENANCE_KEY` | 32 random bytes encoded as 64 hex characters, shared by server processes to verify retrieval receipts | random process-local key |
| `STANDBY_TIMEOUT_SECONDS` | Maximum wait for one standby session, including Elasticsearch calls | one poll interval less than the LangGraph server's `BG_JOB_TIMEOUT_SECS` (`86400`) |
| `STANDBY_POLL_SECONDS` | Delay between alert checks | `5` |
| `STANDBY_MAX_CONCURRENT` | Per-process standby limit, clamped below `N_JOBS_PER_WORKER` to retain an ordinary worker slot | half of `N_JOBS_PER_WORKER` (default `10`) |

By default standby ends just before the server would stop the run itself, so it
returns a timeout status. Time settings must be finite and positive.
A process with only one worker has no standby capacity. Polling compares
document identity, with a stable alert-UUID sort and latest-execution batch
count to detect insertions in the same rule execution.

Use one `KISTE_PROVENANCE_KEY` across processes and restarts when existing
retrieval receipts must remain usable. Keep it in server environment settings,
outside graph state and source control. Without it, a server restart requires
a fresh alert retrieval before counter-recon can run.

`ES_VERIFY_CERTS` defaults to `true`. Most Elastic Security quick-start
installs generate a self-signed CA (typically `http_ca.crt`), so pointing
this agent at one without setting `ES_CA_CERT` will fail every ES call
(`execute_elastic_query` returns an error message; standby ends with an error).
Set `ES_CA_CERT` to that cluster's CA bundle
rather than falling back to `ES_VERIFY_CERTS=false`.

### API access and review ownership

With `KISTE_API_TOKENS` unset, `uv run langgraph dev` and Studio keep the
single-user local behavior: requests need no token and share access to threads.
Bind this mode to loopback for use by one local operator.

Set `KISTE_API_TOKENS` before starting the server to enable identity checks:

```text
KISTE_API_TOKENS={"<owner-secret>":{"identity":"operator-a"},"<peer-secret>":{"identity":"operator-b"},"<review-secret>":{"identity":"reviewer","reviewer":true}}
```

Replace each placeholder with a separate random secret. Clients send
`Authorization: Bearer <secret>`, including Studio's custom auth headers when
token mode is enabled. An empty or malformed token map refuses access.

The server stamps thread ownership from the token identity. Owners can read,
update, delete, run and resume their own threads, including ordinary menu
interrupts and their own reviews. An explicit reviewer can read threads and
resume another owner's pending `review_gate_S` interrupt. That resume is bound
to the checked review checkpoint. Review permission does not permit foreign
menu resumes, new runs or state changes. Unhandled API operations are denied
in token mode. Studio has no separate authentication bypass.
Create new threads after enabling token mode; earlier shared threads have no
authenticated owner.

The reviewer check uses the installed LangGraph in-memory runtime's state
reader. This policy supports the documented `langgraph dev` runtime; changes
to that runtime must pass the endpoint tests below.

## Development

```bash
uv sync                       # install from the lockfile
uv run langgraph dev          # serve the graph locally (LangGraph Studio)
make test                     # unit and security regression tests
make integration_tests        # integration tests (needs live ES/LLM backends)
LLM_BACKEND=ollama LANGSMITH_TEST_TRACKING=false uv run python -m pytest tests/
```

`src/agent/` is the untouched LangGraph starter-template package (a
single-node stub graph), kept only because `pyproject.toml`'s build config
packages it as `kiste-agent`'s source layout.

`tests/unit_tests/test_configuration.py` reads `langgraph.json`, imports its
`./agent.py:graph` target with `LLM_BACKEND=ollama`, and asserts that the
exported graph is compiled (a `Pregel` instance). It does not start a LangGraph
server, invoke the graph, or call Elasticsearch, LLM, MCP, or other backend
services. `tests/security/` covers target validation, forged graph state,
compiled standby routing, bounded retrieval and the configured development
API. API tests run a loopback server and a deterministic local model responder;
Elasticsearch and scanner calls are controlled test doubles. Disable LangSmith
test tracking as shown above to run without uploading test results.
