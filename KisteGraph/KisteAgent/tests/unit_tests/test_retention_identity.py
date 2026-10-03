"""Verify that the operational compatibility exports use the shared helper."""

import alert_retention
import mitigations


def test_retention_exports_are_shared():
    assert mitigations.severity_aware_retain is alert_retention.severity_aware_retain
    assert mitigations._dig is alert_retention._dig
    assert mitigations._HIGH_SEVERITIES is alert_retention._HIGH_SEVERITIES
    assert mitigations._alert_timestamp is alert_retention._alert_timestamp
