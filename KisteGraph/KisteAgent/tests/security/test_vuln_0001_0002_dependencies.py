from importlib.metadata import version

import pytest
from packaging.version import Version


@pytest.mark.parametrize(
    "package,minimum", [("langgraph-sdk", "0.4.4"), ("mcp", "1.30.0")]
)
def test_dependency_floor(package, minimum):
    assert Version(version(package)) >= Version(minimum), (
        f"{package} is below {minimum}"
    )


def test_protocol_imports_still_work():
    from langgraph_sdk import Auth
    from mcp.server.fastmcp import FastMCP

    assert Auth().on is not None
    assert FastMCP("normal").name == "normal"
