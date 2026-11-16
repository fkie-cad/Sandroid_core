"""Curated system/GMS noise filter + consistent file-change logging.

The path lists are the real results of the 2.1 phase-2 live test on a Play
image (ground-truth run 20261116_171021_af03b8 and Wikipedia run
20261116_173858_df1034), before this filter existed.
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock

from test_engine import FakeToolbox, _classes, _make_engine

from sandroid.analysis.changedfiles import ChangedFiles
from sandroid.analysis.deletedfiles import DeletedFiles
from sandroid.analysis.filters import (
    DEFAULT_SYSTEM_NOISE_PATTERNS,
    SystemNoiseFilter,
    path_belongs_to_package,
)
from sandroid.analysis.run_config import RunConfig

GT_CHANGED = [
    "/data/data/com.google.android.apps.wellbeing/databases/bedtime",
    "/data/data/de.fkie.ground_truth/databases/GroundTruth.db-shm",
    "/data/data/de.fkie.ground_truth/databases/GroundTruth.db",
    "/data/data/de.fkie.ground_truth/databases/GroundTruth.db-wal",
    "/data/data/de.fkie.ground_truth/files/GroundTruth.xml",
]
GT_NEW = [
    "/data/data/com.google.android.calendar/files/flight_records/5313_1794845481",
    "/data/data/com.google.android.deskclock/files/flight_records/5432_1794845482",
    "/data/data/de.fkie.ground_truth/files/file_1.txt",
    "/data/data/com.google.android.gms/files/clearcut/0/CALENDAR_ANDROID_PRIMES/"
    "-1199520153/1794845481779.NONE",
    "/data/data/com.google.android.gms/files/clearcut/0/DESKCLOCK_ANDROID_PRIMES/"
    "1477745451/1794845482129.NONE",
]

WIKI_APP = [
    "/data/data/org.wikipedia/cache/okhttp-cache/journal",
    "/data/data/org.wikipedia/cache/okhttp-cache/22c7c83cfc3fbb18e92382df7ad9cbae.1",
    "/data/data/org.wikipedia/databases/wikipedia.db-shm",
    "/data/data/org.wikipedia/cache/coil3_disk_cache/journal",
    "/data/data/org.wikipedia/no_backup/androidx.work.workdb-shm",
    "/data/data/org.wikipedia/shared_prefs/org.wikipedia_preferences.xml",
    "/data/data/org.wikipedia/cache/okhttp-cache/22c7c83cfc3fbb18e92382df7ad9cbae.0",
    "/data/data/org.wikipedia/no_backup/androidx.work.workdb",
    "/data/data/org.wikipedia/no_backup/androidx.work.workdb-wal",
    "/data/data/org.wikipedia/databases/wikipedia.db",
    "/data/data/org.wikipedia/databases/wikipedia.db-wal",
    # System-owned, but named after the target app -> must stay visible.
    "/data/system_ce/0/shortcut_service/packages/org.wikipedia.xml",
    "/data/system_ce/0/shortcut_service/packages/org.wikipedia.xml.reservecopy",
]
WIKI_NOISE = [
    "/data/misc/apexdata/com.android.tethering/netstats/xt.1794841827250-",
    "/data/system/users/0/package-restrictions.xml.reservecopy",
    "/data/misc/apexdata/com.android.tethering/netstats/uid.1794841827345-",
    "/data/misc/apexdata/com.android.permission/access.abx",
    "/data/system/users/0/package-restrictions.xml",
    "/data/data/com.android.providers.calendar/shared_prefs/sanity.xml",
    "/data/user_de/0/com.google.android.inputmethod.latin/shared_prefs/"
    "com.google.android.inputmethod.latin_preferences.xml",
    "/data/system_ce/0/recent_tasks/508_task.xml",
    "/data/data/com.google.android.apps.nexuslauncher/databases/app_icons.db",
    "/data/data/com.google.android.gms/shared_prefs/com.google.android.gms.safetynet.xml",
    "/data/data/com.google.android.as/databases/nasa_ps_db-wal",
    "/data/misc_de/0/apexdata/com.android.permission/access.abx.reservecopy",
    "/data/data/com.google.android.webview/app_webview/webview_metrics_bridge_logs",
    "/data/data/com.google.android.inputmethod.latin/shared_prefs/"
    "com.google.android.inputmethod.latindelight_problem.xml",
    "/data/system/users/0/appwidgets.xml",
    "/data/data/com.google.android.gms/databases/metadata.db-journal",
    "/data/data/com.google.android.gms/databases/metadata.db",
    "/data/data/com.google.android.as/databases/nasa_ps_db-shm",
    "/data/data/com.google.android.as/databases/nasa_ps_db",
    "/data/misc/apexdata/com.android.permission/access.abx.reservecopy",
    "/data/misc_de/0/apexdata/com.android.permission/access.abx",
    "/data/misc_de/0/apexdata/com.android.permission/roles.xml",
    "/data/misc_de/0/apexdata/com.android.permission/roles.xml.reservecopy",
    "/data/data/com.google.android.webview/shared_prefs/variations_prefs.xml",
    "/data/data/com.google.android.gms/files/autofill/shared/AutofillLocalSettings.pb.lock",
]


def test_wikipedia_run_keeps_only_app_evidence():
    noise_filter = SystemNoiseFilter(protected_packages=("org.wikipedia",))

    kept, filtered = noise_filter.split(WIKI_APP + WIKI_NOISE)

    assert kept == WIKI_APP
    assert set(filtered) == set(WIKI_NOISE)
    assert all(
        pattern in DEFAULT_SYSTEM_NOISE_PATTERNS for pattern in filtered.values()
    )


def test_ground_truth_run_without_spotlight():
    noise_filter = SystemNoiseFilter()

    changed, _ = noise_filter.split(GT_CHANGED)
    new, hidden_new = noise_filter.split(GT_NEW)

    assert changed == GT_CHANGED[1:]
    assert new == ["/data/data/de.fkie.ground_truth/files/file_1.txt"]
    assert len(hidden_new) == 4


def test_target_app_is_never_filtered_even_if_a_pattern_matches():
    """Analysing a Google app itself must not hide its own files."""
    gms_file = "/data/data/com.google.android.gms/databases/metadata.db"
    flight = "/data/data/com.google.android.calendar/files/flight_records/1_2"

    assert SystemNoiseFilter().match(gms_file) == "/data/*/com.google.android.gms/*"
    protected = SystemNoiseFilter(
        protected_packages=("com.google.android.gms", "com.google.android.calendar")
    )
    assert protected.match(gms_file) is None
    assert protected.match(flight) is None


def test_opt_out_and_extra_patterns():
    path = "/data/data/com.google.android.gms/databases/metadata.db"
    assert SystemNoiseFilter(enabled=False).split([path]) == ([path], {})

    custom = SystemNoiseFilter(patterns=("/data/*/com.example.sync/*",))
    assert custom.match("/data/user/0/com.example.sync/files/x") is not None
    assert custom.match(path) is None


def test_path_belongs_to_package():
    pkg = "org.wikipedia"
    assert path_belongs_to_package("/data/data/org.wikipedia/files/a", pkg)
    assert path_belongs_to_package("/data/app/~~x==/org.wikipedia-1==/base.apk", pkg)
    assert path_belongs_to_package("/data/system_ce/0/x/org.wikipedia.xml", pkg)
    assert not path_belongs_to_package("/data/data/org.wikipediax/files/a", pkg)
    assert not path_belongs_to_package("/data/data/org.wikipedia/files/a", "")


def _changed_files_gatherer(files: list[str]) -> ChangedFiles:
    forensic = MagicMock()
    forensic.get_noise_files.return_value = {}
    forensic.exclude_whitelist.side_effect = lambda paths: paths
    gatherer = ChangedFiles(forensic_service=forensic)
    gatherer.fileListList = [list(files), list(files)]
    return gatherer


def test_changed_files_hides_noise_but_remembers_it():
    gatherer = _changed_files_gatherer(GT_CHANGED)

    assert sorted(gatherer.process_data()) == sorted(GT_CHANGED)
    assert gatherer.filtered_noise == {}

    gatherer.system_noise_filter = SystemNoiseFilter()
    kept = gatherer.process_data()
    # Idempotent: return_data() and pretty_print() both call process_data().
    assert gatherer.process_data() == kept

    assert sorted(kept) == sorted(GT_CHANGED[1:])
    assert gatherer.filtered_noise == {
        GT_CHANGED[0]: "/data/*/com.google.android.apps.wellbeing/*"
    }


def test_deleted_candidates_are_debug_only(caplog, monkeypatch):
    """The dry run's -wal/-shm/.NONE deletions used to flood the log."""
    published: list[object] = []
    monkeypatch.setattr(
        "sandroid.core.events.events.TypedEvent.publish",
        lambda self: published.append(self),
        raising=False,
    )
    baseline = dict.fromkeys(GT_NEW, 1)
    toolbox = MagicMock()
    toolbox.is_dry_run.return_value = True
    toolbox.fetch_changed_files.return_value = {}
    gatherer = DeletedFiles(forensic_service=MagicMock())
    monkeypatch.setattr(gatherer, "_get_toolbox", lambda: toolbox)
    monkeypatch.setattr(gatherer, "_get_baseline", lambda: baseline)

    with caplog.at_level(logging.DEBUG, logger="sandroid.analysis.deletedfiles"):
        gatherer.gather()

    assert gatherer.noise_deleted_files == set(GT_NEW)
    assert published == []
    assert not [r for r in caplog.records if r.levelno >= logging.INFO]


class _SpotlightToolbox(FakeToolbox):
    def get_spotlight_application(self):
        return ("org.wikipedia", "org.wikipedia.main.MainActivity")


def test_engine_wires_filter_and_reports_filtered_noise(caplog):
    config = RunConfig(
        number_of_runs=2,
        noise_filter=False,
        network=False,
        processes=False,
        sockets=False,
        show_deleted=True,
        noise_patterns=["/data/*/com.example.sync/*"],
        protected_packages=["com.example.keep"],
    )
    engine = _make_engine(config, toolbox=_SpotlightToolbox(), classes=_classes())

    with caplog.at_level(logging.INFO, logger="sandroid.analysis.engine"):
        result = engine.run()

    noise_filter = engine.gatherers["changed_files"].system_noise_filter
    assert noise_filter is engine.gatherers["deleted_files"].system_noise_filter
    assert noise_filter.protected_packages == ("org.wikipedia", "com.example.keep")
    assert noise_filter.patterns[-1] == "/data/*/com.example.sync/*"

    (report,) = result.other_data["Filtered Noise"]
    assert report["enabled"] is True
    assert report["protected_packages"] == ["org.wikipedia", "com.example.keep"]
    assert report["Changed Files"] == {}
    assert report["Deleted Files"] == {}

    summary = [
        r.getMessage() for r in caplog.records if "File changes:" in r.getMessage()
    ]
    assert summary == [
        "File changes: 1 changed, 1 new, 0 deleted "
        "(0 system-noise file(s) hidden, see Other Data -> Filtered Noise)"
    ]


def test_run_config_noise_settings_override_config():
    config = RunConfig(
        system_noise_filter=False, noise_patterns=["/x/*"], protected_packages=["a.b"]
    )
    assert config.noise_settings() == (False, ["/x/*"], ["a.b"])
