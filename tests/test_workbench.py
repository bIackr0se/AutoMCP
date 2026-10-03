"""Check shared selection semantics and the real local HTTP boundary."""

import copy
import http.client
import json
import subprocess
import sys
import threading
import unittest
from unittest.mock import patch

from workbench.__main__ import Handler, ThreadingHTTPServer, retention, snapshot


class RetentionTests(unittest.TestCase):
    def test_shift_excludes_then_preserves_critical(self):
        data = snapshot()
        self.assertTrue(data["synthetic"])
        frames = data["frames"]
        self.assertEqual(frames[2]["recent"], frames[2]["retained"])
        self.assertNotIn("A-017", [a["id"] for a in frames[3]["recent"]])
        self.assertIn("A-017", [a["id"] for a in frames[3]["retained"]])
        self.assertEqual(
            [a["id"] for a in frames[-1]["retained"]], ["A-022", "A-021", "A-017"]
        )

    def test_reserve_query_standin_is_bounded_to_two(self):
        alerts = copy.deepcopy(snapshot()["alerts"])
        for alert in alerts[:3]:
            alert["kibana.alert.rule.parameters.severity"] = "high"
        with patch("pathlib.Path.read_text", return_value=json.dumps(alerts)):
            final = snapshot()["frames"][-1]["retained"]
        self.assertEqual([a["id"] for a in final], ["A-022", "A-019", "A-018"])

    def test_content_deduplication_and_reserve_priority(self):
        old = {"id": "same", "@timestamp": "2026-06-01T08:00:00Z"}
        new = {"id": "same", "@timestamp": "2026-06-01T09:00:00Z"}
        self.assertEqual(
            retention.severity_aware_retain([old, new], [copy.deepcopy(old)], 3),
            [new, old],
        )
        self.assertEqual(retention.severity_aware_retain([new], [old], 1), [old])
        self.assertEqual(retention.severity_aware_retain([], [], 3), [])

    def test_source_shapes_and_missing_timestamp(self):
        dotted = {"kibana.alert.rule.execution.timestamp": "b"}
        nested = {"kibana": {"alert": {"rule": {"execution": {"timestamp": "c"}}}}}
        partial = {"kibana.alert.rule.execution": {"timestamp": "a"}}
        fallback = {"@timestamp": "d"}
        self.assertEqual(
            retention.severity_aware_retain(
                [{}, partial, dotted, nested, fallback], [], 5
            ),
            [fallback, nested, dotted, partial, {}],
        )
        self.assertEqual(
            retention._dig({"host.ip": "example"}, "host", "ip"), "example"
        )
        self.assertEqual(
            retention._dig({"host": {"ip": "example"}}, "host", "ip"), "example"
        )
        self.assertIsNone(retention._dig(None, "host", "ip"))

    def test_demo_does_not_load_operational_dependencies(self):
        probe = (
            "import sys; from workbench.__main__ import snapshot; snapshot(); "
            "assert not set(sys.modules) & "
            '{"langchain_core", "langgraph", "elasticsearch", '
            '"requests", "mcp", "agent", "mitigations"}'
        )
        subprocess.run([sys.executable, "-c", probe], check=True)


class ServerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join()

    def request(self, path, method="GET", headers=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.server.server_port)
        conn.request(method, path, headers=headers or {})
        response = conn.getresponse()
        status, headers, body = (
            response.status,
            dict(response.getheaders()),
            response.read(),
        )
        conn.close()
        return status, headers, body

    def test_real_get_and_head(self):
        status, headers, body = self.request("/api/case")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body), snapshot())
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertIn("frame-ancestors 'none'", headers["Content-Security-Policy"])
        status, _, body = self.request("/", "HEAD")
        self.assertEqual((status, body), (200, b""))
        for path in ["/", "/app.js", "/style.css"]:
            self.assertEqual(self.request(path)[0], 200)

    def test_other_paths_and_foreign_host_are_denied(self):
        for path in [
            "/.env",
            "/agent.py",
            "/../README.md",
            "/assets/alerts.json",
            "/api/case?source=live",
        ]:
            self.assertEqual(self.request(path)[0], 404)
        self.assertEqual(self.request("/", headers={"Host": "foreign.example"})[0], 403)
        self.assertEqual(self.request("/api/case", "POST")[0], 501)
        self.assertEqual(self.server.server_address[0], "127.0.0.1")

    def test_missing_fixture_is_a_failure(self):
        with patch(
            "workbench.__main__.snapshot",
            side_effect=FileNotFoundError("fixture absent"),
        ):
            status, _, body = self.request("/api/case")
        self.assertEqual(status, 500)
        self.assertIn(b"Synthetic case unavailable", body)
        self.assertEqual(self.request("/api/case")[0], 200)

    def test_invalid_fixture_fails(self):
        with patch("pathlib.Path.read_text", return_value="not json"):
            with self.assertRaises(ValueError):
                snapshot()


if __name__ == "__main__":
    unittest.main()
