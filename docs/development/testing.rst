Testing
=======

The suite lives in ``tests/`` and mirrors the package layout (``tests/core``,
``tests/ai``, ``tests/tui``, ...). It is run with one entry point,
``tools/test.sh``, by developers, agents and CI alike. CI runs it on Python
3.12 and 3.13 for every push and pull request against ``main`` and ``dev``
(``.github/workflows/tests.yml``); a nightly workflow looks for flaky tests
(``.github/workflows/nightly.yml``).

Running Tests
-------------

``tools/test.sh`` needs `uv <https://docs.astral.sh/uv/>`_ and Python 3.13
(``SANDROID_TEST_PYTHON`` selects another interpreter). It builds a shared,
dependency-only venv under ``~/.cache/sandroid-tests`` (keyed by the
dependencies in ``pyproject.toml``, ``tools/test-constraints.txt`` -- which
pins Textual 8.2.8 -- and the Python version) and puts this checkout's
``src/`` on ``PYTHONPATH``, so it always tests the tree it lives in, also from
a git worktree.

.. code-block:: bash

   tools/test.sh                       # quick: parallel (-n 4); skips slow, perf, quarantine
   tools/test.sh full                  # merge gate: parallel pass, then the perf tests serially
   tools/test.sh tests/core/test_x.py  # paths or node ids: serial, starts in seconds
   tools/test.sh tests/tui -n 2        # paths with 2 workers
   tools/test.sh full -n 2 -- -x       # fewer workers; pytest options after --
   tools/test.sh --update-slow         # rewrite tests/slow_tests.txt from the last full run

Modes:

``quick`` (default)
   One parallel pass without the ``slow``, ``perf`` and ``quarantine`` tests:
   the check to run while working.
``full``
   The merge gate: a parallel pass without the ``perf`` and ``quarantine``
   tests, then the ``perf`` tests serially (their wall-clock budgets would
   not hold next to other workers).
paths / node ids
   Just these, serially unless ``-n`` is given.

Every run is hermetic: pytest runs under ``env -i`` with a throwaway
``HOME`` and ``TMPDIR``, ``ANDROID_HOME`` pointing nowhere and stub
``adb``/``emulator``/``frida``/... scripts first on ``PATH`` (calls that reach
them are listed at the end of the run). JUnit XML and the logs of the last ten
runs are kept in ``.test-results/`` (``.test-results/latest/`` is the newest).

Exit codes
~~~~~~~~~~

==== ==========================================================================
``0`` all selected tests passed
``1`` tests failed (or pytest could not run)
``3`` flaky: tests failed in the run and passed when rerun once, alone and
      serially
==== ==========================================================================

Flaky tests
~~~~~~~~~~~

When at most 20 tests fail, ``tools/test.sh`` reruns them once, serially. If
they pass then, the run exits ``3`` and the tests are appended to
``~/.cache/sandroid-tests/flakes.jsonl`` (time, node id, worktree, branch,
commit, mode, workers). There are no further retries.

- A ``3`` is not a pass. Report the flaky test; merging on ``3`` is fine only
  when the test is unrelated to the change.
- A test that keeps flaking gets
  ``@pytest.mark.quarantine(reason="...", issue="#123")`` (both arguments
  are required) until the issue is fixed. ``tools/test.sh`` deselects
  quarantined tests in every mode.
- In CI a ``3`` is a warning on the job, not a failure. The nightly workflow
  runs ``full`` twice and the quarantined tests five times and lists, in its
  job summary, every test that failed on a first try and every quarantined
  test that now passes every run (a candidate to unquarantine).

Markers
~~~~~~~

``slow``
   Applied from ``tests/slow_tests.txt``: the node ids of the tests that took
   over 0.5 s in the parallel pass of the last ``full`` run. ``quick`` skips
   them. After a ``full`` run, ``tools/test.sh --update-slow`` rewrites the
   list (``SANDROID_TEST_SLOW_S`` changes the 0.5 s threshold; a JUnit file may
   be given instead of the last run's); commit the result. A test can also
   be marked ``@pytest.mark.slow`` directly.
``perf``
   Wall-clock budgets. ``full`` runs them serially after the parallel pass;
   ``quick`` skips them.
``quarantine(reason, issue)``
   A known-flaky test, deselected by ``tools/test.sh`` (see above).
``requires_device``
   Needs real hardware; skipped unless pytest runs with ``--allow-device``.

Workers and slots
~~~~~~~~~~~~~~~~~

``-n N`` is a request. All runs on a host share a budget of worker slots
(``SANDROID_TEST_SLOTS``, default 8, lock directories in
``~/.cache/sandroid-tests/slots``): a run waits up to
``SANDROID_TEST_SLOT_WAIT`` seconds (default 20) for its ``N`` slots, then
starts with what is free, at least one. Never pass ``-n auto`` on a shared
host; ``tools/test.sh`` accepts it only when ``CI`` is set, where it means one
worker per CPU and no slot budget.

Plain ``pytest`` in a venv with ``pip install -e ".[dev,full]"`` still works,
but it is neither hermetic nor parallel; ``tests/conftest.py`` refuses to run
when ``sandroid`` is imported from outside this checkout's ``src/``.

Test Isolation
--------------

Tests must **never** act on a real device, even when a developer has an
emulator attached. ``tests/conftest.py`` enforces this for every test:

- ``subprocess`` calls (``run``/``Popen``/``check_output``, ``os.popen``,
  ``asyncio`` subprocesses) to ``adb``, ``emulator``, ``frida*``,
  ``objection``, ``fritap``, ``mitmdump``/``mitmweb``, ``pkill``/``killall``,
  ``iptables``, ``gost`` ... are recorded and replaced by a process that exits
  with status 1 and prints nothing (the same as a missing ``adb``);
- ``frida.get_usb_device()``, ``get_device()``, ``get_device_manager()``,
  ``attach()``, ``spawn()`` ... raise ``frida.InvalidOperationError``;
- socket connections to the adb server (5037), emulator console/adb ports
  (5554-5685) and frida-server (27042/27043) on localhost are refused;
- the session runs with a temporary ``HOME``/XDG directories and working
  directory, ``ANDROID_HOME``/``ANDROID_SDK_ROOT`` pointing nowhere, and
  without ``SANDROID_*`` / API-key environment variables, so tests neither
  read your ``~/.config/sandroid`` nor leave ``./results`` behind.

Blocked calls are listed in the terminal summary ("sandroid device guard").
They indicate a test that reaches the device layer without mocking it; fix
the test by mocking ``Adb.send_adb_command`` or the relevant service.

.. code-block:: bash

   # Turn every blocked device call into a test error
   SANDROID_TESTS_STRICT_DEVICE=1 tools/test.sh full

   # Also append blocked calls to a file
   SANDROID_TESTS_BLOCKED_LOG=/tmp/blocked.log tools/test.sh tests/core

Tests that really need hardware are marked ``@pytest.mark.requires_device``;
they are skipped unless pytest runs with ``--allow-device`` (and only those
tests then run without the guard).

Tests on one xdist worker share a process, so ``tests/conftest.py`` also
resets the process-wide state a test may leave behind, before and after every
test: the service singletons (``sandroid.services`` and ``ServiceRegistry``),
the ``get_config()`` cache, the TUI controller registry, the session timeline
and AndroidFridaManager's patched launcher. Each test gets its own Files-lens
watchlist directory. Do not rely on state from an earlier test; build what the
test needs in it or in a fixture.

Writing Tests
-------------

Follow pytest conventions and mock the device layer:

.. code-block:: python

   from sandroid.core.adb import Adb


   def test_reads_android_version(monkeypatch):
       monkeypatch.setattr(
           Adb, "send_adb_command", lambda cmd, serial=None: ("35\n", "")
       )
       ...

Textual widgets are tested headlessly with ``App.run_test()`` (see
``tests/tui/``); async tests need no decorator (``asyncio_mode = "auto"``).
Wait for a condition rather than sleeping a fixed time: under parallel load a
fixed sleep is the most common cause of a flaky test.

Testing Standards
-----------------

See the *Testing Requirements* section of ``CODING_GUIDELINES.md`` for
coverage expectations, naming and mocking conventions.
