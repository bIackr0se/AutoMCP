"""Run the synthetic workbench without loading the operational agent."""

import argparse
import importlib.util
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ASSETS = Path(__file__).parent / "assets"
spec = importlib.util.spec_from_file_location(
    "alert_retention", ROOT / "KisteGraph/KisteAgent/alert_retention.py"
)
retention = importlib.util.module_from_spec(spec)
spec.loader.exec_module(retention)


def snapshot():
    """Apply the deployed retention function to a fixed fictional alert window."""
    alerts = json.loads((ASSETS / "alerts.json").read_text(encoding="utf-8"))
    frames = []
    for count in range(1, len(alerts) + 1):
        window = alerts[:count]
        recent = sorted(window, key=retention._alert_timestamp, reverse=True)[:3]
        # Mirror the runtime's bounded high-severity query (size=2).
        reserve = sorted(
            (
                a
                for a in window
                if retention._dig(
                    a, "kibana", "alert", "rule", "parameters", "severity"
                )
                in retention._HIGH_SEVERITIES
            ),
            key=retention._alert_timestamp,
            reverse=True,
        )[:2]
        frames.append(
            {
                "recent": retention.severity_aware_retain(recent, [], size=3),
                "retained": retention.severity_aware_retain(recent, reserve, size=3),
            }
        )
    return {"synthetic": True, "capacity": 3, "alerts": alerts, "frames": frames}


class Handler(BaseHTTPRequestHandler):
    """Serve only the named demo assets and synthetic projection."""

    def do_HEAD(self):
        self.do_GET(head_only=True)

    def do_GET(self, head_only=False):
        allowed_hosts = {
            f"127.0.0.1:{self.server.server_port}",
            f"localhost:{self.server.server_port}",
        }
        if self.headers.get("Host") not in allowed_hosts:
            self.send_error(403, "Use the loopback address printed in the terminal.")
            return
        routes = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/style.css": ("style.css", "text/css; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
        }
        if self.path == "/api/case":
            try:
                body = json.dumps(snapshot()).encode()
            except (OSError, ValueError, KeyError, TypeError) as error:
                self.send_error(
                    500,
                    "Synthetic case unavailable. Check workbench/assets/alerts.json.",
                )
                print(f"Synthetic case unavailable: {error}", file=sys.stderr)
                return
            mime = "application/json; charset=utf-8"
        elif self.path in routes:
            filename, mime = routes[self.path]
            body = (ASSETS / filename).read_bytes()
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", mime)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; connect-src 'self'; "
            "frame-ancestors 'none'; base-uri 'none'",
        )
        self.end_headers()
        if not head_only:
            self.wfile.write(body)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--port", type=int, default=8765, help="Loopback port (default: 8765)"
    )
    parser.add_argument(
        "--export",
        action="store_true",
        help="Print the synthetic selection as JSON, then exit",
    )
    args = parser.parse_args()
    if args.export:
        print(json.dumps(snapshot(), indent=2))
        return
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    except (OSError, OverflowError) as error:
        parser.exit(1, f"Cannot open local workbench: {error}. Try --port 8766.\n")
    print(
        f"AutoMCP synthetic workbench: http://127.0.0.1:{server.server_port}\n"
        "Ctrl-C to stop. No Elasticsearch or model is connected.",
        flush=True,
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
