"""Unit tests for sandroid.core.adb_dumpsys.

Per the design note in ``adb_dumpsys.py``'s own module docstring, neither
``list_services`` nor ``get_activity_stack`` has an existing verified
precedent in this codebase -- so these fixtures are built to look like real,
multi-line ``dumpsys activity services``/``dumpsys activity activities``
output (ServiceRecord/TaskRecord/ActivityRecord blocks with the surrounding
noise lines a real dump includes), not trivial one-liners, to give the
regex-based block parsing real scrutiny.
"""

from __future__ import annotations

from sandroid.core.adb_dumpsys import get_activity_stack, list_services

# ---------------------------------------------------------------------------
# list_services
# ---------------------------------------------------------------------------

DUMPSYS_SERVICES_DEVICE_WIDE = """\
ACTIVITY MANAGER SERVICES (dumpsys activity services)
  User 0 active services:
  * ServiceRecord{a1b2c3d u0 com.example.app/.MyForegroundService}
    intent={cmp=com.example.app/.MyForegroundService}
    packageName=com.example.app
    processName=com.example.app
    baseDir=/data/app/com.example.app-1/base.apk
    app=ProcessRecord{5e6f7a8 12345:com.example.app/u0a123}
    createTime=-2m3s startingBgTimeout=--
    lastActivity=-1m58s restartTime=-2m3s createdFromFg=true
    startRequested=true delayedStop=false stopIfKilled=false callStart=true lastStartId=1

  * ServiceRecord{b2c3d4e u0 com.example.other/.bg.SyncService}
    intent={cmp=com.example.other/.bg.SyncService}
    packageName=com.example.other
    processName=com.example.other:bg
    app=ProcessRecord{9h8g7f6 12399:com.example.other:bg/u0a456}
    createTime=-5m10s
    startRequested=false delayedStop=true stopIfKilled=false

  * ServiceRecord{c3d4e5f u10 com.example.work/.WorkProfileService}
    intent={cmp=com.example.work/.WorkProfileService}
    packageName=com.example.work
    processName=com.example.work

  Connection bindings to services:
"""


def test_list_services_device_wide_parses_every_block():
    def fake_send(command):
        assert command == "shell dumpsys activity services"
        return DUMPSYS_SERVICES_DEVICE_WIDE, ""

    services = list_services(fake_send)

    assert len(services) == 3

    first = services[0]
    assert first["record_id"] == "a1b2c3d"
    assert first["user"] == "u0"
    assert first["component"] == "com.example.app/.MyForegroundService"
    assert first["package_name"] == "com.example.app"
    assert first["process_name"] == "com.example.app"
    assert first["pid"] == 12345


def test_list_services_normal_block_fields():
    def fake_send(_command):
        return DUMPSYS_SERVICES_DEVICE_WIDE, ""

    services = list_services(fake_send)
    second = services[1]

    assert second["record_id"] == "b2c3d4e"
    assert second["user"] == "u0"
    assert second["component"] == "com.example.other/.bg.SyncService"
    assert second["package_name"] == "com.example.other"
    assert second["process_name"] == "com.example.other:bg"
    assert second["pid"] == 12399


def test_list_services_process_name_defaults_from_processrecord_when_absent():
    """A block whose app=ProcessRecord line supplies the process name."""
    output = """\
  * ServiceRecord{feed001 u0 com.example.foo/.FooService}
    packageName=com.example.foo
    app=ProcessRecord{cafe002 555:com.example.foo/u0a999}
"""

    def fake_send(_command):
        return output, ""

    services = list_services(fake_send)

    assert len(services) == 1
    assert services[0]["pid"] == 555
    assert services[0]["process_name"] == "com.example.foo/u0a999"


def test_list_services_block_with_no_process_record_has_null_pid():
    services = list_services(
        lambda _c: (DUMPSYS_SERVICES_DEVICE_WIDE, ""),
    )
    third = services[2]

    assert third["record_id"] == "c3d4e5f"
    assert third["pid"] is None
    assert third["process_name"] == "com.example.work"


def test_list_services_package_filtered_mode_sends_scoped_command():
    captured = {}

    def fake_send(command):
        captured["command"] = command
        return (
            "  * ServiceRecord{b2c3d4e u0 com.example.other/.bg.SyncService}\n"
            "    packageName=com.example.other\n"
            "    processName=com.example.other:bg\n"
            "    app=ProcessRecord{9h8g7f6 12399:com.example.other:bg/u0a456}\n"
        ), ""

    services = list_services(fake_send, package_name="com.example.other")

    assert captured["command"] == "shell dumpsys activity services com.example.other"
    assert len(services) == 1
    assert services[0]["package_name"] == "com.example.other"
    assert services[0]["pid"] == 12399


def test_list_services_package_filtered_mode_quotes_the_package_name():
    """Belt-and-braces: shlex.quote is applied even for an unusual package arg."""
    captured = {}

    def fake_send(command):
        captured["command"] = command
        return "", ""

    list_services(fake_send, package_name="com.example; rm -rf /")

    assert captured["command"] == (
        "shell dumpsys activity services 'com.example; rm -rf /'"
    )


def test_list_services_empty_output_returns_empty_list():
    assert list_services(lambda _c: ("", "")) == []


def test_list_services_no_matching_blocks_returns_empty_list():
    output = "ACTIVITY MANAGER SERVICES (dumpsys activity services)\n  (nothing)\n"
    assert list_services(lambda _c: (output, "")) == []


# ---------------------------------------------------------------------------
# get_activity_stack
# ---------------------------------------------------------------------------

DUMPSYS_ACTIVITIES = """\
ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
  Displays:
  Display #0
    Stack #0: type=standard mode=fullscreen
      isSleeping=false
      mBounds=Rect(0, 0 - 1080, 2400)
      Task=TaskRecord{f1e2d3c #1 A=com.example.app.taskaffinity U=0 sz=1}
      * TaskRecord{f1e2d3c #1 A=com.example.app.taskaffinity U=0 sz=1}
        userId=0 effectiveUid=u0a123 mCallingUid=u0a123 mUserSetupComplete=true
        affinity=com.example.app.taskaffinity
        * Hist #0: ActivityRecord{a1b2c3d u0 com.example.app/.MainActivity t1}
            packageName=com.example.app processName=com.example.app
            intent={act=android.intent.action.MAIN cmp=com.example.app/.MainActivity}
      Task=TaskRecord{a9b8c7d #2}
      * TaskRecord{a9b8c7d #2}
        userId=0 effectiveUid=u0a456
        * Hist #0: ActivityRecord{b2c3d4e u0 com.example.other/.other.DetailActivity t2}
            packageName=com.example.other processName=com.example.other
        * Hist #1: ActivityRecord{c3d4e5f u10 com.example.other/.other.SecondaryActivity t2}
            packageName=com.example.other processName=com.example.other:work
"""


def test_get_activity_stack_groups_activities_under_their_task():
    stack = get_activity_stack(lambda _c: (DUMPSYS_ACTIVITIES, ""))

    assert len(stack) == 2

    task1, task2 = stack
    assert task1["task_id"] == 1
    assert task1["affinity"] == "com.example.app.taskaffinity"
    assert task1["activities"] == [
        {"component": "com.example.app/.MainActivity", "user": "u0"}
    ]

    assert task2["task_id"] == 2
    assert task2["affinity"] is None
    assert task2["activities"] == [
        {"component": "com.example.other/.other.DetailActivity", "user": "u0"},
        {"component": "com.example.other/.other.SecondaryActivity", "user": "u10"},
    ]


def test_get_activity_stack_preserves_first_seen_task_order():
    stack = get_activity_stack(lambda _c: (DUMPSYS_ACTIVITIES, ""))

    assert [task["task_id"] for task in stack] == [1, 2]


def test_get_activity_stack_sends_expected_command():
    captured = {}

    def fake_send(command):
        captured["command"] = command
        return DUMPSYS_ACTIVITIES, ""

    get_activity_stack(fake_send)

    assert captured["command"] == "shell dumpsys activity activities"


def test_get_activity_stack_empty_output_returns_empty_list():
    assert get_activity_stack(lambda _c: ("", "")) == []


def test_get_activity_stack_no_matching_records_returns_empty_list():
    output = "ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)\n  (nothing)\n"
    assert get_activity_stack(lambda _c: (output, "")) == []


def test_get_activity_stack_task_without_activities_still_included():
    """An empty task (no ActivityRecord lines under it) still appears, empty."""
    output = "      Task=TaskRecord{deadbee #7}\n      * TaskRecord{deadbee #7}\n"

    stack = get_activity_stack(lambda _c: (output, ""))

    assert stack == [{"task_id": 7, "affinity": None, "activities": []}]


def test_get_activity_stack_summary_line_not_double_counted():
    """Regression: summary lines echoing an activity must not re-count it.

    Real ``dumpsys activity activities`` output also names the currently
    focused activity on trailing summary lines (e.g.
    ``mFocusedActivity: ActivityRecord{...}``). Only the canonical
    ``* Hist #N:`` per-task listing is authoritative, so such echoes must
    not append a second, duplicate entry to the task.
    """
    output = (
        "      Task=TaskRecord{f1e2d3c #1}\n"
        "      * TaskRecord{f1e2d3c #1}\n"
        "        * Hist #0: ActivityRecord{a1b2c3d u0 com.example.app/.MainActivity t1}\n"
        "  mFocusedActivity: ActivityRecord{a1b2c3d u0 com.example.app/.MainActivity t1}\n"
    )

    stack = get_activity_stack(lambda _c: (output, ""))

    assert len(stack) == 1
    assert stack[0]["activities"] == [
        {"component": "com.example.app/.MainActivity", "user": "u0"},
    ]


# Captured from a live API 35 emulator (``dumpsys activity activities``),
# trimmed of the per-activity config noise. On that device the launcher's
# single ActivityRecord was echoed 9 times: mLastPausedActivity,
# topResumedActivity, the canonical ``* Hist #1:`` line, "Resumed:",
# "ResumedActivity:", deepestLastOrientationSource, mFocusedApp, the bare
# ``* ActivityRecord`` line in the "Application tokens in top down Z order"
# section, and mSystemBarColorApps -- 18 ActivityRecord lines total for the 4
# real activities on screen. Note the modern format prints ``Task{...}`` (not
# ``TaskRecord{...}``), so tasks here are discovered purely from their Hist
# activity lines.
DUMPSYS_ACTIVITIES_MULTISECTION = """\
ACTIVITY MANAGER ACTIVITIES (dumpsys activity activities)
Display #0 (activities from top to bottom):
  * Task{6137770 #1 type=home U=0 visible=true visibleRequested=true mode=fullscreen sz=1}
    * Task{c91736e #5 type=home I=com.google.android.apps.nexuslauncher/.NexusLauncherActivity U=0 rootTaskId=1 sz=2}
      mLastPausedActivity: ActivityRecord{153529581 u0 com.google.android.apps.nexuslauncher/.NexusLauncherActivity t5}
      isSleeping=false
      topResumedActivity=ActivityRecord{153529581 u0 com.google.android.apps.nexuslauncher/.NexusLauncherActivity t5}
      * Hist  #1: ActivityRecord{153529581 u0 com.google.android.apps.nexuslauncher/.NexusLauncherActivity t5}
        packageName=com.google.android.apps.nexuslauncher processName=com.google.android.apps.nexuslauncher
        state=RESUMED delayedResume=false finishing=false
      * TaskFragment{1a838e2 mode=multi-window organizerUid=10182 organizerProc=com.google.android.apps.nexuslauncher}

  * Task{cda5923 #413 type=standard I=com.google.android.contacts/... U=0 visible=false sz=1}
    mLastPausedActivity: ActivityRecord{225086343 u0 com.google.android.contacts/com.android.contacts.activities.PeopleActivity t413}
    * Hist  #0: ActivityRecord{225086343 u0 com.google.android.contacts/com.android.contacts.activities.PeopleActivity t413}
      packageName=com.google.android.contacts processName=com.google.android.contacts
      state=STOPPED delayedResume=false finishing=false

  Resumed activities in task display areas (from top to bottom):
    Resumed: ActivityRecord{153529581 u0 com.google.android.apps.nexuslauncher/.NexusLauncherActivity t5}

  ResumedActivity: ActivityRecord{153529581 u0 com.google.android.apps.nexuslauncher/.NexusLauncherActivity t5}

ActivityTaskSupervisor state:
  deepestLastOrientationSource=ActivityRecord{153529581 u0 com.google.android.apps.nexuslauncher/.NexusLauncherActivity t5}
  mFocusedApp=ActivityRecord{153529581 u0 com.google.android.apps.nexuslauncher/.NexusLauncherActivity t5}

      Application tokens in top down Z order:
      * Task{6137770 #1 type=home U=0 visible=true sz=1}
        * Task{c91736e #5 type=home I=com.google.android.apps.nexuslauncher/.NexusLauncherActivity U=0 rootTaskId=1 sz=2}
          * ActivityRecord{153529581 u0 com.google.android.apps.nexuslauncher/.NexusLauncherActivity t5}
          * TaskFragment{1a838e2 mode=multi-window organizerUid=10182}
      * Task{cda5923 #413 type=standard U=0 visible=false sz=1}
        * ActivityRecord{225086343 u0 com.google.android.contacts/com.android.contacts.activities.PeopleActivity t413}
  mSystemBarColorApps={ActivityRecord{153529581 u0 com.google.android.apps.nexuslauncher/.NexusLauncherActivity t5}}
"""


def test_get_activity_stack_dedups_activity_echoed_across_subsections():
    """Regression for the live-measured 9x-inflation bug.

    The launcher's ActivityRecord appears on 9 lines across the dump's
    sub-sections; the contacts one on several. Only the ``* Hist #N:``
    canonical listing must be counted, so each task ends up with exactly one
    activity and nothing is duplicated.
    """
    stack = get_activity_stack(lambda _c: (DUMPSYS_ACTIVITIES_MULTISECTION, ""))

    # Exactly the two tasks that had a Hist listing, no Z-order/summary noise.
    assert [task["task_id"] for task in stack] == [5, 413]

    launcher, contacts = stack
    assert launcher["activities"] == [
        {
            "component": "com.google.android.apps.nexuslauncher/.NexusLauncherActivity",
            "user": "u0",
        }
    ]
    assert contacts["activities"] == [
        {
            "component": (
                "com.google.android.contacts/"
                "com.android.contacts.activities.PeopleActivity"
            ),
            "user": "u0",
        }
    ]

    # The whole dump has 18 ActivityRecord lines for these 2 activities;
    # the parser must yield 2 total, not 18.
    assert sum(len(task["activities"]) for task in stack) == 2
