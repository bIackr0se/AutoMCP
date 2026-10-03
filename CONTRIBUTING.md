# Contributing

Start with the [source map](README.md#source-map). The workbench and the research
runtime have different data and service contracts.

## Workbench changes

The workbench runs on Python 3.10+ using the standard library. Its fixture is
fixed synthetic data in `workbench/assets/alerts.json`. Keep real alert records,
credentials, internal hostnames, and operational transcripts out of fixtures.

The local projection builds a recent window and a high-severity reserve for
each prefix of that fixture. Both strategies call `severity_aware_retain`.
Its input records use the Elastic-style severity field, while all timestamps
in this fixture have the same UTC format. The merge deduplicates identical
record content, gives reserve records inclusion priority, and sorts selected
records by its existing timestamp lookup. It does not normalize timestamps,
validate severity, or infer a verdict.

Run from the repository root:

```bash
python3 -m unittest discover -s tests -v
npm ci
npx playwright install chromium
npm run test:browser
```

The browser suite starts its own loopback server on port 8767. It saves
screenshots and failing traces in `test-results/`. Inspect actual desktop and
phone renders after layout changes, including an expanded raw-record view.

Keep the server route allowlist explicit. It must not serve the repository
root or turn into a file browser. A missing or invalid fixture must surface as
an error, with recovery possible after the fixture is restored.

## Shared retention changes

`KisteGraph/KisteAgent/alert_retention.py` has no third-party dependencies.
`mitigations.py` re-exports its symbols for the runtime. Preserve this identity
and check the configured graph after a shared-helper change:

```bash
cd KisteGraph/KisteAgent
uv sync --locked --python 3.11
uv run --locked make test
```

The compile test does not contact live services. Integration tests require
a configured research deployment and are not part of the credential-free gate.
The repository currently contains a starter package alongside the configured
runtime; changes to distribution or live graph behavior need their own consumer
verification.

Send a focused pull request with the behavior changed and the checks run.
Report missing live coverage plainly. Do not include private source data or
research evidence in a public PR.
