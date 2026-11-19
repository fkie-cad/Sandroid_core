"""Tests for the shared row-annotation registry and feed."""

from __future__ import annotations

import threading

from sandroid.tui.row_annotations import (
    Annotation,
    AnnotationFeed,
    RowAnnotationProvider,
    RowAnnotationRegistry,
)


class _Provider:
    def __init__(self, source, priority, keys, tint=None, filt=None):
        self.source = source
        self._priority = priority
        self._keys = set(keys)
        self._tint = tint
        self._filt = filt
        self._rev = 0

    @property
    def revision(self):
        return self._rev

    def bump(self):
        self._rev += 1

    def annotations_for(self, lens, key):
        if lens == "network" and key in self._keys:
            return [
                Annotation(
                    self.source,
                    self.source,
                    tint_role=self._tint,
                    priority=self._priority,
                )
            ]
        return []

    def filter_predicate(self, lens):
        if self._filt is None or lens != "network":
            return None
        return lambda k: k in self._filt


def test_provider_protocol():
    assert isinstance(_Provider("x", 1, []), RowAnnotationProvider)


def test_merge_priority_and_tint():
    reg = RowAnnotationRegistry()
    reg.register(_Provider("ai", 50, {"f1", "f2"}, tint="accent"))
    reg.register(_Provider("privacy", 100, {"f2"}, tint="warn"))
    assert [a.source for a in reg.annotations_for("network", "f2")] == ["privacy", "ai"]
    assert reg.tint_role_for("network", "f1") == "accent"
    assert reg.tint_role_for("network", "f2") == "warn"
    assert reg.tint_role_for("network", "f3") is None
    assert reg.tint_for("network", "f1") == ("accent", 0.13)
    assert reg.annotations_for("files", "f1") == []


def test_filters_compose():
    reg = RowAnnotationRegistry()
    reg.register(_Provider("a", 1, (), filt={"f1", "f2"}))
    reg.register(_Provider("b", 2, (), filt={"f2", "f3"}))
    assert reg.passes("network", "f2")
    assert not reg.passes("network", "f1")
    assert reg.passes("files", "anything")


def test_revision_moves_with_providers():
    reg = RowAnnotationRegistry()
    p = _Provider("a", 1, ())
    reg.register(p)
    r0 = reg.revision
    p.bump()
    assert reg.revision != r0
    r1 = reg.revision
    reg.unregister("a")
    assert reg.revision != r1


def test_broken_provider_is_ignored():
    class Bad(_Provider):
        def annotations_for(self, lens, key):
            raise RuntimeError

        def filter_predicate(self, lens):
            raise RuntimeError

    reg = RowAnnotationRegistry()
    reg.register(Bad("bad", 1, ()))
    assert reg.annotations_for("network", "f1") == []
    assert reg.passes("network", "f1")


def test_notify_any_thread_and_listener_errors():
    reg = RowAnnotationRegistry()
    seen = []
    reg.subscribe(lambda lens, keys: seen.append((lens, keys)))
    reg.subscribe(lambda lens, keys: 1 / 0)
    t = threading.Thread(target=reg.notify, args=("network", ["f1"]))
    t.start()
    t.join()
    reg.notify(None, None)
    assert seen == [("network", frozenset({"f1"})), (None, None)]


class _Owner:
    is_attached = True

    def set_timer(self, wait, fn):
        raise RuntimeError("no timer outside an app")


def test_feed_collects_and_filters_by_lens():
    reg = RowAnnotationRegistry()
    flushed = []
    feed = AnnotationFeed(_Owner(), "network", flushed.append, reg=reg, refresh_s=0)
    feed.attach()  # outside a loop: post() fails, so nothing is stuck
    reg.notify("files", ["/sdcard/a"])
    reg.notify("network", ["f1"])
    assert feed._posted is False
    feed._flush()
    assert flushed == [{"f1"}]
    reg.notify(None, None)
    feed._flush()
    assert flushed[-1] is None
    feed.detach()
    reg.notify("network", ["f2"])
    feed._flush()
    assert flushed[-1] is None


def test_feed_stale_post_unblocks(monkeypatch):
    reg = RowAnnotationRegistry()
    feed = AnnotationFeed(_Owner(), "network", lambda k: None, reg=reg)
    posts = []

    class UI:
        def post(self, fn, *a):
            posts.append(fn)
            return True

    feed._ui = UI()
    reg.subscribe(feed.on_change)
    reg.notify("network", ["f1"])
    reg.notify("network", ["f2"])
    assert len(posts) == 1  # second waits for the pending hop
    feed._posted_at -= 10  # the hop was lost (owner unmounted)
    reg.notify("network", ["f3"])
    assert len(posts) == 2
