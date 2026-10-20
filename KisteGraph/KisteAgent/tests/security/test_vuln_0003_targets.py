import ipaddress

import pytest

import mitigations


@pytest.mark.parametrize(
    "target",
    [
        "100.64.0.1",
        "100.127.255.254",
        "224.0.0.1",
        "64:ff9b::6440:1",
        "::ffff:100.64.0.1",
    ],
)
def test_non_global_target_is_refused(target):
    allowed, reason, pinned = mitigations.validate_scan_target(target, [target])
    assert not allowed, f"Non-global scan allowed: {target} ({reason})"
    assert pinned is None


@pytest.mark.parametrize(
    "target", ["10.10.0.50", "127.0.0.1", "169.254.169.254", "::1", "64:ff9b::a0a:32"]
)
def test_existing_denials_still_apply(target):
    assert mitigations.validate_scan_target(target, [target])[0] is False


def test_global_target_is_allowed_and_pinned():
    assert mitigations.validate_scan_target("8.8.8.8", ["8.8.8.8"]) == (
        True,
        "allowed",
        ipaddress.ip_address("8.8.8.8"),
    )


def test_global_protected_segment_still_denied(monkeypatch):
    monkeypatch.setattr(
        mitigations, "_OT_SEGMENTS", [ipaddress.ip_network("8.8.8.0/24")]
    )
    assert mitigations.validate_scan_target("8.8.8.8", ["8.8.8.8"])[0] is False


def test_domain_with_mixed_answers_is_refused(monkeypatch):
    monkeypatch.setattr(
        mitigations,
        "_resolve_targets",
        lambda _: [ipaddress.ip_address("8.8.8.8"), ipaddress.ip_address("100.64.0.2")],
    )
    assert mitigations.validate_scan_target("example.test", ["8.8.8.8"])[0] is False
