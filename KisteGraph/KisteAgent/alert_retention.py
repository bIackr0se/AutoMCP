"""Dependency-free alert selection shared by CoAnalyst and its synthetic workbench."""

import json

# Deployment-specific lowercase values; see the SCHEMA note in mitigations.py.
_HIGH_SEVERITIES = ["critical", "high"]


def _dig(alert, *path):
    """Pull a possibly-nested or dotted field from an Elasticsearch _source dict.
    Handles both the nested form {"host": {"ip": ...}} and the dotted form
    {"host.ip": ...} that different _source projections can return."""
    if not isinstance(alert, dict):
        return None
    dotted = ".".join(path)
    if dotted in alert:
        return alert[dotted]
    cur = alert
    for key in path:
        if isinstance(cur, dict) and key in cur:
            cur = cur[key]
        else:
            return None
    return cur


def _alert_timestamp(alert):
    """Best-effort execution timestamp of an alert for ordering, tolerant of the
    dotted vs nested _source shapes Elasticsearch can return. '' if absent so such
    entries sort last."""
    if not isinstance(alert, dict):
        return ""
    for path in (
        ("kibana.alert.rule.execution.timestamp",),
        ("kibana.alert.rule.execution", "timestamp"),
        ("kibana", "alert", "rule", "execution", "timestamp"),
        ("@timestamp",),
    ):
        v = _dig(alert, *path)
        if v:
            return str(v)
    return ""


def severity_aware_retain(recent_alerts, reserve_alerts, size=3):
    """M2. Merge a recency-sorted set with a high-severity reserve so a critical
    alert is not displaced by benign volume. `reserve_alerts` come from one extra
    bounded query filtered to high-severity alerts; `recent_alerts` are the
    most-recent `size`. The reserve takes INCLUSION priority (so a critical is not
    evicted), then recents fill the remainder, deduped and capped at `size`. The
    selected set is finally returned in reverse-chronological order, so promoting a
    reserve alert does not reorder the view (preserving the time ordering the
    downstream analyst relies on for correlation)."""
    seen, selected = set(), []
    for a in list(reserve_alerts) + list(recent_alerts):
        key = a if isinstance(a, str) else json.dumps(a, sort_keys=True, default=str)
        if key in seen:
            continue
        seen.add(key)
        selected.append(a)
        if len(selected) >= size:
            break
    selected.sort(key=_alert_timestamp, reverse=True)
    return selected
