from __future__ import annotations

"""stdlib HTTP collector for Germany VPS — shortlist + Iran probe ingest.

Run on the DE VPS (not Cloudflare Worker):

    export PULSE_PROBE_SECRET='long-random'
    export PULSE_REPO_ROOT=/opt/PulseConfigs
    python -m pulseconfigs.collector --host 0.0.0.0 --port 8787

Endpoints:
  GET  /health
  GET  /candidates?limit=50
  GET  /top5.txt
  POST /probes/iran   Authorization: Bearer <secret>
"""

import argparse
import json
import os
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from pulseconfigs.iran_rank import load_iran_probes, merge_probe_reports
from pulseconfigs.index import write_json


def _repo_root() -> Path:
    return Path(os.environ.get("PULSE_REPO_ROOT") or Path.cwd()).resolve()


def _secret() -> str:
    return os.environ.get("PULSE_PROBE_SECRET") or ""


class CollectorHandler(BaseHTTPRequestHandler):
    server_version = "PulseCollector/1.0"

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("%s - %s\n" % (self.address_string(), fmt % args))

    def _send(self, code: int, body: bytes, content_type: str = "application/json") -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_json(self, code: int, data: object) -> None:
        self._send(code, json.dumps(data, ensure_ascii=False).encode("utf-8") + b"\n")

    def _auth_ok(self) -> bool:
        secret = _secret()
        if not secret:
            return False
        auth = self.headers.get("Authorization") or ""
        if auth == f"Bearer {secret}":
            return True
        return (self.headers.get("X-Pulse-Secret") or "") == secret

    def do_GET(self) -> None:  # noqa: N802
        root = _repo_root()
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        qs = parse_qs(parsed.query)

        if path in {"/", "/health"}:
            probes = load_iran_probes(root / "probes" / "iran.json")
            self._send_json(
                200,
                {
                    "ok": True,
                    "service": "pulseconfigs-collector",
                    "repo": str(root),
                    "iran_updated_at": probes.get("updated_at") or "",
                    "iran_probe_count": len(probes.get("probes") or {}),
                },
            )
            return

        if path == "/candidates":
            limit = 50
            try:
                limit = max(1, min(200, int((qs.get("limit") or ["50"])[0])))
            except ValueError:
                pass
            cand_path = root / "candidates.json"
            if cand_path.exists():
                try:
                    data = json.loads(cand_path.read_text(encoding="utf-8"))
                    rows = (data.get("candidates") or [])[:limit]
                    self._send_json(200, {"candidates": rows, "limit": limit})
                    return
                except Exception as exc:  # noqa: BLE001
                    self._send_json(500, {"error": str(exc)})
                    return
            # Fallback: plain candidates.txt
            txt = root / "candidates.txt"
            if txt.exists():
                lines = [ln.strip() for ln in txt.read_text(encoding="utf-8").splitlines() if ln.strip()]
                rows = [{"raw": ln, "fingerprint": ""} for ln in lines[:limit]]
                self._send_json(200, {"candidates": rows, "limit": limit})
                return
            self._send_json(404, {"error": "candidates not published yet"})
            return

        # Static publish artifacts (mirror helpers)
        rel = path.lstrip("/")
        if ".." in rel:
            self._send_json(400, {"error": "bad path"})
            return
        file_path = root / rel
        if file_path.is_file():
            data = file_path.read_bytes()
            ctype = "text/plain; charset=utf-8"
            if rel.endswith(".json"):
                ctype = "application/json"
            elif rel.endswith(".yaml") or rel.endswith(".yml"):
                ctype = "text/yaml; charset=utf-8"
            self._send(200, data, ctype)
            return

        self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        root = _repo_root()
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"

        if path != "/probes/iran":
            self._send_json(404, {"error": "not found"})
            return
        if not self._auth_ok():
            self._send_json(401, {"error": "unauthorized"})
            return

        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send_json(400, {"error": "invalid json"})
            return

        reports = payload.get("reports") if isinstance(payload, dict) else None
        if reports is None and isinstance(payload, list):
            reports = payload
        if reports is None and isinstance(payload, dict) and payload.get("fingerprint"):
            reports = [payload]
        if not isinstance(reports, list):
            self._send_json(400, {"error": "expected reports list"})
            return

        probes_path = root / "probes" / "iran.json"
        doc = load_iran_probes(probes_path)
        merged = merge_probe_reports(doc, reports)
        write_json(probes_path, merged)
        self._send_json(
            200,
            {
                "ok": True,
                "accepted": len(reports),
                "total_fingerprints": len(merged.get("probes") or {}),
                "updated_at": merged.get("updated_at"),
            },
        )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="PulseConfigs Germany VPS collector")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args(argv)
    if not _secret():
        print("WARNING: PULSE_PROBE_SECRET is empty — POST /probes/iran will reject", file=sys.stderr)
    httpd = ThreadingHTTPServer((args.host, args.port), CollectorHandler)
    print(f"[collector] listening on http://{args.host}:{args.port} root={_repo_root()}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[collector] stopped")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
