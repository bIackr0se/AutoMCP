import importlib
import json

import pytest


@pytest.fixture
def token_config(monkeypatch):
    auth = importlib.import_module("auth")
    auth._tokens.cache_clear()
    monkeypatch.delenv("KISTE_API_TOKENS", raising=False)
    yield auth
    auth._tokens.cache_clear()


@pytest.mark.parametrize("local", [False, True])
def test_token_configuration_is_cached_for_process(token_config, monkeypatch, local):
    expected = None if local else {"secret": {"identity": "owner"}}
    if not local:
        monkeypatch.setenv("KISTE_API_TOKENS", json.dumps(expected))
    first = token_config._tokens()
    monkeypatch.setenv("KISTE_API_TOKENS", "invalid replacement")
    assert token_config._tokens() is first
    assert first == expected
    assert token_config._tokens.cache_info().misses == 1


@pytest.mark.parametrize(
    "raw",
    [
        "bad json",
        "{}",
        "[]",
        '{"secret":{}}',
        '{"secret":{"identity":"owner","reviewer":"yes"}}',
    ],
)
def test_bad_token_configuration_still_returns_503(token_config, monkeypatch, raw):
    monkeypatch.setenv("KISTE_API_TOKENS", raw)
    with pytest.raises(token_config.Auth.exceptions.HTTPException) as error:
        token_config._tokens()
    assert error.value.status_code == 503
