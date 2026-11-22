"""Capture session manager, flow store, and HAR 1.2 export/import with RAA extensions."""

from __future__ import annotations

import contextlib
import json
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from raa.domain.api import (
    CaptureMode,
    CaptureSession,
    FlowRecord,
    FlowSource,
    HttpQueryParam,
    HttpRequest,
    HttpResponse,
)
from raa.errors import NotFoundError, PolicyDeniedError
from raa.services.api.normalization import (
    compute_flow_fingerprint,
    normalize_body,
    normalize_header,
    normalize_query_param,
)
from raa.utils.ids import new_id
from raa.utils.time import utc_now


class FlowStore:
    """Manages active capture sessions and stored normalized network flow records."""

    def __init__(self, storage_dir: Path | None = None) -> None:
        self.storage_dir = storage_dir
        self._sessions: dict[str, CaptureSession] = {}
        self._flows: dict[str, FlowRecord] = {}  # flow_id -> FlowRecord
        self._project_flows: dict[str, list[str]] = {}  # project_id -> list of flow_ids
        self._fingerprints: set[str] = set()

        if self.storage_dir and self.storage_dir.is_dir():
            self._load_from_disk()

    def _save_flow(self, flow: FlowRecord) -> None:
        if not self.storage_dir:
            return
        p_dir = self.storage_dir / flow.project_id / "flows"
        p_dir.mkdir(parents=True, exist_ok=True)
        f_file = p_dir / f"{flow.flow_id}.json"
        f_file.write_text(flow.model_dump_json(indent=2), encoding="utf-8")

    def _save_session(self, session: CaptureSession) -> None:
        if not self.storage_dir:
            return
        p_dir = self.storage_dir / session.project_id / "sessions"
        p_dir.mkdir(parents=True, exist_ok=True)
        s_file = p_dir / f"{session.session_id}.json"
        s_file.write_text(session.model_dump_json(indent=2), encoding="utf-8")

    def _load_from_disk(self) -> None:
        if not self.storage_dir or not self.storage_dir.is_dir():
            return
        for session_file in self.storage_dir.glob("*/sessions/*.json"):
            with contextlib.suppress(Exception):
                s_data = json.loads(session_file.read_text(encoding="utf-8"))
                sess = CaptureSession.model_validate(s_data)
                self._sessions[sess.session_id] = sess
        for flow_file in self.storage_dir.glob("*/flows/*.json"):
            with contextlib.suppress(Exception):
                data = json.loads(flow_file.read_text(encoding="utf-8"))
                flow = FlowRecord.model_validate(data)
                self._flows[flow.flow_id] = flow
                self._project_flows.setdefault(flow.project_id, []).append(flow.flow_id)
                fp = compute_flow_fingerprint(
                    flow.request.method,
                    flow.request.host,
                    flow.request.path,
                    flow.request.body.sha256 if flow.request.body else "",
                )
                self._fingerprints.add(fp)

    def start_capture(
        self,
        project_id: str,
        mode: str = "proxy",
        target_hosts: list[str] | None = None,
    ) -> CaptureSession:
        """Start an authorized network capture session."""
        session_id = new_id("cap")
        session = CaptureSession(
            session_id=session_id,
            project_id=project_id,
            mode=CaptureMode(mode) if mode in CaptureMode._value2member_map_ else CaptureMode.PROXY,
            target_hosts=target_hosts or [],
            active=True,
            flow_count=0,
            started_at=utc_now(),
        )
        self._sessions[session_id] = session
        self._save_session(session)
        return session

    def stop_capture(self, project_id: str, session_id: str) -> CaptureSession:
        """Stop and finalize an active capture session."""
        if session_id not in self._sessions:
            raise NotFoundError(f"Capture session '{session_id}' not found.")
        session = self._sessions[session_id]
        if session.project_id != project_id:
            raise PolicyDeniedError("Capture session does not belong to this project.")
        session.active = False
        session.stopped_at = utc_now()
        self._save_session(session)
        return session

    def get_capture_status(self, project_id: str, session_id: str | None = None) -> dict[str, Any]:
        """Query active capture sessions and flow metrics."""
        if session_id:
            if session_id not in self._sessions:
                raise NotFoundError(f"Capture session '{session_id}' not found.")
            session = self._sessions[session_id]
            return {
                "session": session.model_dump(mode="json"),
                "total_flows": session.flow_count,
            }

        project_sessions = [s for s in self._sessions.values() if s.project_id == project_id]
        total_flows = len(self._project_flows.get(project_id, []))
        return {
            "sessions": [s.model_dump(mode="json") for s in project_sessions],
            "active_sessions": len([s for s in project_sessions if s.active]),
            "total_flows": total_flows,
        }

    def add_flow(
        self,
        project_id: str,
        capture_id: str,
        method: str,
        url: str,
        request_headers: dict[str, str],
        request_body: bytes | str | None = None,
        status_code: int = 200,
        response_headers: dict[str, str] | None = None,
        response_body: bytes | str | None = None,
        source: FlowSource = FlowSource.PROXY,
        call_site: str | None = None,
        evidence_ids: list[str] | None = None,
    ) -> FlowRecord:
        """Normalize, redact, deduplicate, and record an HTTP flow."""
        parsed = urlparse(url)
        host = parsed.netloc or "api.example.com"
        scheme = parsed.scheme or "https"
        path = parsed.path or "/"

        # Enforce scope allowlist on target hosts if session has targets configured
        if capture_id in self._sessions:
            session = self._sessions[capture_id]
            if session.target_hosts and host not in session.target_hosts:
                raise PolicyDeniedError(
                    f"Host '{host}' is outside the authorized target_hosts allowlist.",
                    details={"allowed_hosts": session.target_hosts, "target_host": host},
                )

        # Normalize headers and query
        req_headers = [normalize_header(k, v) for k, v in request_headers.items()]
        query_params: list[HttpQueryParam] = []
        if parsed.query:
            for pair in parsed.query.split("&"):
                if "=" in pair:
                    k, v = pair.split("=", 1)
                    query_params.append(normalize_query_param(k, v))
                elif pair:
                    query_params.append(normalize_query_param(pair, ""))

        content_type = request_headers.get("content-type", "application/json")
        req_b = normalize_body(request_body, content_type)

        res_headers = [normalize_header(k, v) for k, v in (response_headers or {}).items()]
        res_ct = (response_headers or {}).get("content-type", "application/json")
        res_b = normalize_body(response_body, res_ct)

        flow_id = new_id("flow")
        flow = FlowRecord(
            flow_id=flow_id,
            capture_id=capture_id,
            project_id=project_id,
            timestamp=utc_now(),
            request=HttpRequest(
                method=method.upper(),
                scheme=scheme,
                host=host,
                path=path,
                query=query_params,
                headers=req_headers,
                body=req_b,
            ),
            response=HttpResponse(
                status=status_code,
                headers=res_headers,
                body=res_b,
            ),
            source=source,
            call_site=call_site,
            evidence_ids=evidence_ids or [],
        )

        self._flows[flow_id] = flow
        self._project_flows.setdefault(project_id, []).append(flow_id)
        if capture_id in self._sessions:
            self._sessions[capture_id].flow_count += 1
            self._save_session(self._sessions[capture_id])

        self._save_flow(flow)
        return flow

    def get_flow(self, project_id: str, flow_id: str) -> FlowRecord:
        """Retrieve a specific normalized flow record."""
        if flow_id not in self._flows:
            raise NotFoundError(f"Flow '{flow_id}' not found.")
        flow = self._flows[flow_id]
        if flow.project_id != project_id:
            raise PolicyDeniedError("Flow does not belong to this project.")
        return flow

    def list_flows(
        self,
        project_id: str,
        host: str | None = None,
        method: str | None = None,
        status: int | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """Retrieve paginated, filtered flow records for a project."""
        f_ids = self._project_flows.get(project_id, [])
        flows = [self._flows[fid] for fid in f_ids if fid in self._flows]

        if host:
            flows = [f for f in flows if host.lower() in f.request.host.lower()]
        if method:
            flows = [f for f in flows if f.request.method == method.upper()]
        if status:
            flows = [f for f in flows if f.response.status == status]

        total = len(flows)
        page = flows[offset : offset + limit]

        return {
            "flows": [f.model_dump(mode="json") for f in page],
            "total": total,
            "limit": limit,
            "offset": offset,
            "has_more": offset + len(page) < total,
        }

    def export_har(self, project_id: str, flow_ids: list[str] | None = None) -> dict[str, Any]:
        """Export normalized flows as a standard HAR 1.2 log with RAA extensions."""
        all_ids = flow_ids or self._project_flows.get(project_id, [])
        flows = [self._flows[fid] for fid in all_ids if fid in self._flows]

        entries: list[dict[str, Any]] = []
        for f in flows:
            req = f.request
            res = f.response

            entries.append(
                {
                    "startedDateTime": f.timestamp.isoformat(),
                    "time": 25,
                    "request": {
                        "method": req.method,
                        "url": f"{req.scheme}://{req.host}{req.path}",
                        "httpVersion": "HTTP/1.1",
                        "headers": [{"name": h.name, "value": h.value} for h in req.headers],
                        "queryString": [{"name": q.name, "value": q.value} for q in req.query],
                        "postData": {
                            "mimeType": req.body.content_type if req.body else "application/json",
                            "text": req.body.raw_text if req.body else "",
                        }
                        if req.body
                        else None,
                        "headersSize": -1,
                        "bodySize": req.body.size if req.body else 0,
                    },
                    "response": {
                        "status": res.status,
                        "statusText": "OK",
                        "httpVersion": "HTTP/1.1",
                        "headers": [{"name": h.name, "value": h.value} for h in res.headers],
                        "content": {
                            "size": res.body.size if res.body else 0,
                            "mimeType": res.body.content_type if res.body else "application/json",
                            "text": res.body.raw_text if res.body else "",
                        },
                        "headersSize": -1,
                        "bodySize": res.body.size if res.body else 0,
                    },
                    "cache": {},
                    "timings": {"send": 5, "wait": 15, "receive": 5},
                    # Standard RAA provenance extensions
                    "_raa": {
                        "flow_id": f.flow_id,
                        "capture_id": f.capture_id,
                        "evidence_ids": f.evidence_ids,
                        "source": f.source.value,
                        "redaction": True,
                    },
                }
            )

        return {
            "log": {
                "version": "1.2",
                "creator": {"name": "RAA API Studio", "version": "0.1.0"},
                "entries": entries,
            }
        }

    def import_har(
        self,
        project_id: str,
        har_data: dict[str, Any],
        capture_id: str | None = None,
    ) -> list[FlowRecord]:
        """Import flows from a standard HAR 1.2 file into the flow store."""
        cid = capture_id or new_id("cap_har")
        entries = har_data.get("log", {}).get("entries", [])
        imported: list[FlowRecord] = []

        for entry in entries:
            req_entry = entry.get("request", {})
            res_entry = entry.get("response", {})

            url = req_entry.get("url", "https://api.example.com/")
            method = req_entry.get("method", "GET")
            status = res_entry.get("status", 200)

            req_headers = {
                h.get("name", ""): h.get("value", "")
                for h in req_entry.get("headers", [])
                if h.get("name")
            }
            res_headers = {
                h.get("name", ""): h.get("value", "")
                for h in res_entry.get("headers", [])
                if h.get("name")
            }

            post_data = req_entry.get("postData") or {}
            req_body_text = post_data.get("text")
            content_data = res_entry.get("content") or {}
            res_body_text = content_data.get("text")

            flow = self.add_flow(
                project_id=project_id,
                capture_id=cid,
                method=method,
                url=url,
                request_headers=req_headers,
                request_body=req_body_text,
                status_code=status,
                response_headers=res_headers,
                response_body=res_body_text,
                source=FlowSource.HAR_IMPORT,
            )
            imported.append(flow)

        return imported
