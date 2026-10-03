# AutoMCP

**CoAnalyst is a research analyst for OT/IT security alerts.** Built with
LangGraph, it retrieves Elastic Security records, analyzes the selected evidence,
and places a human review gate on its standby verdicts.

AutoMCP is the repository name; CoAnalyst is the system; `KisteAgent` is its
runtime directory.

## Try the evidence workbench

What reaches the analyst when the context window has only three places?
Advance a fictional shift, watch an older critical record leave the recent
window, then switch on the severity reserve. Inspect the newer record that
gives up its slot before keeping or discarding a prewritten sample verdict.

With **Python 3.10+**, from a clone or downloaded source archive:

```bash
python3 -m workbench
```

Open **http://127.0.0.1:8765**. Stop with `Ctrl-C`.
No dependency installation, credentials, model, or Elasticsearch is needed.
The demo serves only its named assets and fictional records on loopback.

The retention step calls the **same function used by CoAnalyst**,
[`severity_aware_retain`](KisteGraph/KisteAgent/alert_retention.py).
The input queries are local stand-ins, and the verdict is prewritten. The
review controls stay in the page; they illustrate a decision without running
the operational graph or sending anything to a provider.

```text
                    Three context slots, at the end of this fixture

Recency only        [ A-022 · low ] [ A-021 · low ] [ A-020 · low ]
Severity reserve    [ A-022 · low ] [ A-021 · low ] [ A-017 · critical ]
                                                   ↑ older record retained
```

Use `python3 -m workbench --port 8766` if the default port is occupied.
For machine-readable evidence, `python3 -m workbench --export` prints the
selection at every replay step as JSON.

## Choose a path

| | Evidence workbench | Research runtime |
|---|---|---|
| Purpose | Inspect retention and a sample review decision | Analyze alerts from a configured Elastic cluster |
| Data | Six fixed fictional records | Deployment-specific alert index |
| Services | None | Elasticsearch and an LLM backend |
| Entry point | `python3 -m workbench` | [`langgraph.json`](KisteGraph/KisteAgent/langgraph.json) → `agent.py:graph` |
| Verification here | Helper, HTTP boundary, browser interactions | Configured graph compilation; live integrations need the operator’s services |

The runtime is **source-based**. The current `kiste-agent` package metadata
still packages a LangGraph starter module, so a wheel is not a runnable
CoAnalyst distribution. Use the configured graph and the
[runtime guide](KisteGraph/KisteAgent/README.md).

## How the analyst is organized

```text
operator request → assistant router
                         ├─ explain existing evidence
                         ├─ query → retrieve → analyze
                         ├─ standby → retrieve → analyze → human review
                         └─ gated investigation
                                      ↓
                           return to the operator
```

The standby review node is [`review_gate_S`](KisteGraph/KisteAgent/agent.py).
A rejected verdict is removed from the conversation state. The workbench uses
its own in-page illustration of that decision.

Three defensive boundaries in the source:

- **Target validation (M1):** binds an investigation target to originating alert
  indicators and checks its resolved addresses against protected ranges.
- **Severity-aware retention (M2):** gives the reserve inclusion priority, then
  fills remaining slots from recent records and sorts the result newest first.
  It merges supplied inputs; it does not itself infer severity.
- **Instruction/data separation (M3):** keeps trusted analysis instructions in
  the system role and alert content in a separately delimited user message.
  The standby path also requires explicit human review.

See [the runtime security posture](KisteGraph/KisteAgent/README.md#security-posture)
and [private reporting](SECURITY.md). These source mechanisms and the fictional
replay do not establish a measured detection or mitigation effect.

## Source map

| Start here | Responsibility |
|---|---|
| [`workbench/`](workbench) | Local synthetic demo, explicit HTTP routes, browser assets |
| [`alert_retention.py`](KisteGraph/KisteAgent/alert_retention.py) | Dependency-free merge shared by demo and runtime |
| [`agent.py`](KisteGraph/KisteAgent/agent.py) | Runtime state, router, retrieval, analysis, and review nodes |
| [`mitigations.py`](KisteGraph/KisteAgent/mitigations.py) | Defensive boundaries and compatibility exports |
| [`tests/`](tests) | Workbench behavior and browser flows |
| [`runtime tests`](KisteGraph/KisteAgent/tests/unit_tests) | Load the graph declared in `langgraph.json` |
| [`CONTRIBUTING.md`](CONTRIBUTING.md) | Checks, fixture contract, and change boundaries |

## Verify it

The dependency-free gate:

```bash
python3 -m unittest discover -s tests -v
```

For browser checks, install **Node.js 24+**, then:

```bash
npm ci
npx playwright install chromium
npm run test:browser
```

Chromium exercises the complete replay/review/reset flow, keyboard controls,
load failure and retry, and reflow at 1440, 390, and 320 CSS pixels.
The [Verify workflow](.github/workflows/verify.yml) also runs the existing
configured-graph compile test with locked runtime dependencies. Live
Elasticsearch, model responses, and operational outcomes are separate checks.

## Publications

- **WFCS 2026 (Work-in-Progress):** *CoAnalyst: An Agentic, LLM-based
  Cybersecurity Analyst for Industrial Control Systems*, Çil, Rahmani,
  Sikora.
- **SHIELD-AI 2026 (ECML PKDD Workshop):** *When the Analyst Scans for the
  Attacker: Subverting Agentic LLM Security Operations in OT Networks*,
  Rahmani, Çil, Sikora.

Earlier MCP servers and the first CLI prototype are preserved at
[`legacy-pre-cleanup-2026-07-09`](https://github.com/bIackr0se/AutoMCP/tree/legacy-pre-cleanup-2026-07-09).
The configured LangGraph runtime lives in `KisteGraph/KisteAgent`.

MIT licensed. See [LICENSE](LICENSE) and the retained
[LangChain starter license](KisteGraph/KisteAgent/LICENSE).
