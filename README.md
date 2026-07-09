# AutoMCP / CoAnalyst

An agentic LLM analyst for OT/IT alert triage, built on LangGraph and the Model
Context Protocol. CoAnalyst reads security alerts out of an Elastic SIEM,
correlates them against MITRE ATT&CK and threat intel, and can drive
human-gated response and counter-reconnaissance against the source of an
attack.

The implementation lives in [`KisteGraph/KisteAgent`](KisteGraph/KisteAgent),
see that directory's README for architecture, setup, and the security posture.

## Publications

- **WFCS 2026 (Work-in-Progress):** *CoAnalyst: An Agentic, LLM-based
  Cybersecurity Analyst for Industrial Control Systems*, Çil, Rahmani,
  Sikora. Introduces the system.
- **SHIELD-AI 2026 (ECML PKDD Workshop):** *When the Analyst Scans for the
  Attacker: Subverting Agentic LLM Security Operations in OT Networks*,
  Rahmani, Çil, Sikora. Red-teams CoAnalyst's own agentic layer: three
  vulnerabilities in target selection, alert retrieval, and summarization,
  and one matched mitigation per vulnerability, evaluated on the live
  pipeline. The mitigations from that paper (M1-M3) are implemented in
  [`mitigations.py`](KisteGraph/KisteAgent/mitigations.py) and wired into
  the deployed agent.

## Repository layout

```
KisteGraph/KisteAgent/   The agent: LangGraph state machine, MCP tool server,
                          security mitigations, tests.
```

Everything else that used to live here (three standalone Assistants/ MCP
servers and an earlier CLI prototype, `security_assistant_v1/`) predates
the LangGraph rewrite and is superseded by `KisteGraph/KisteAgent`. That
history is preserved at tag `legacy-pre-cleanup-2026-07-09` rather than
deleted outright.
