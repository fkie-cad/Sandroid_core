"""An in-memory stand-in for the privacy scan service (lens tests).

``FakePrivacy`` has the query API the lenses use (``hits*``, ``tags_for_*``,
``add_listener``/``remove_listener``, ``is_active``) over a list of real
:class:`~sandroid.services.privacy_scan.HitRecord` s; ``add(hit)`` delivers a
hit to the listeners from a worker thread, like the scan worker does.
``install(monkeypatch, hits)`` patches ``get_privacy_scan_service``.
"""

from __future__ import annotations

import threading
import time

from sandroid.services import privacy_scan
from sandroid.services.privacy_scan import HitRecord

#: Glyphs the new privacy UI must never draw.
GLYPHS = "■▲◆●✓✗⚑⌁"


class FakePrivacy:
    def __init__(self, hits=(), *, active: bool = True) -> None:
        self._hits = list(hits)
        self.is_active = active
        self.listeners: list = []

    def hits(self, *, marker_id=None):
        return [h for h in self._hits if marker_id in (None, h.marker_id)]

    def hits_for_flow(self, flow_id):
        return [h for h in self._hits if h.flow_id == flow_id]

    def hits_for_file(self, device_path):
        return [h for h in self._hits if h.device_path == device_path]

    def hits_between(self, t0, t1):
        return [h for h in self._hits if h.t is not None and t0 <= h.t <= t1]

    def tags_for_flow(self, flow_id):
        return privacy_scan._tags(self.hits_for_flow(flow_id))

    def tags_for_file(self, device_path):
        return privacy_scan._tags(self.hits_for_file(device_path))

    def add_listener(self, cb) -> None:
        if cb not in self.listeners:
            self.listeners.append(cb)

    def remove_listener(self, cb) -> None:
        if cb in self.listeners:
            self.listeners.remove(cb)

    def add(self, hit) -> None:
        """Record ``hit`` and call the listeners on a worker thread."""
        self._hits.append(hit)
        listeners = list(self.listeners)

        def run() -> None:
            for cb in listeners:
                cb(hit)

        worker = threading.Thread(target=run, name="privacy-scan-fake")
        worker.start()
        worker.join()


def install(monkeypatch, hits=(), *, active: bool = True) -> FakePrivacy:
    fake = FakePrivacy(hits, active=active)
    monkeypatch.setattr(privacy_scan, "get_privacy_scan_service", lambda: fake)
    return fake


def flow_hit(
    flow_id: str,
    label: str = "Advertising ID",
    tag: str = "Ad ID",
    *,
    marker_id: str | None = None,
    party: str = "third",
    recipient: str = "Meta",
    host: str = "graph.facebook.com",
    path: str = "/v19.0/218934/activities",
    part: str = "req.body",
    transform: str = "sha256(lower(value))",
    confidence: str = "high",
    snippet=("event=INSTALL&advertiser_id=", "3b9f0c1d", "&os=android"),
    t: float | None = None,
    tl_seq: int | None = None,
    net_seq: int | None = None,
    direction: str = "sent",
    offsets=(28,),
) -> HitRecord:
    return HitRecord(
        v=1,
        at=time.time(),
        t=t if t is not None else time.time(),
        fp="fp1",
        engine=1,
        marker_id=marker_id or label.lower().replace(" ", "_"),
        label=label,
        tag=tag,
        kind="uuid",
        transform=transform,
        confidence=confidence,
        part=part,
        direction=direction,
        count=1,
        offsets=tuple(offsets),
        snippet=tuple(snippet),
        source={
            "type": "flow",
            "flow_id": flow_id,
            "flow_seq": None,
            "net_seq": net_seq,
            "host": host,
            "method": "POST",
            "path": path,
            "app": "de.fittrack.pro",
        },
        recipient={"label": recipient, "party": party, "host": host},
        tl_seq=tl_seq,
        encoded=transform != "value",
    )


def file_hit(
    device_path: str,
    label: str = "Email",
    tag: str = "Email",
    *,
    version: str = "v001_x",
    snippet=('<string name="mail">', "jane.canary@example.org", "</string>"),
    transform: str = "value",
    t: float | None = None,
    tl_seq: int | None = None,
    pull_seq: int | None = None,
) -> HitRecord:
    return HitRecord(
        v=1,
        at=time.time(),
        t=t if t is not None else time.time(),
        fp="fp1",
        engine=1,
        marker_id=label.lower().replace(" ", "_"),
        label=label,
        tag=tag,
        kind="email",
        transform=transform,
        confidence="high",
        part="file:" + device_path.rsplit("/", 1)[-1],
        direction="stored",
        count=1,
        offsets=(10,),
        snippet=tuple(snippet),
        source={
            "type": "file",
            "device_path": device_path,
            "version": version,
            "member": device_path.rsplit("/", 1)[-1],
            "pull_seq": pull_seq,
        },
        recipient=None,
        tl_seq=tl_seq,
    )
