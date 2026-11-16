Testing
=======

Sandroid uses pytest. The suite (~1100 tests) lives in ``tests/`` and mirrors
the package layout (``tests/core``, ``tests/ai``, ``tests/tui``, ...). CI runs
it on Python 3.12 and 3.13 for every push and pull request against ``main``
and ``dev`` (``.github/workflows/tests.yml``).

Running Tests
-------------

.. code-block:: bash

   pip install -e ".[dev,full]"

   # Run all tests
   pytest

   # One package / one file / one test
   pytest tests/core
   pytest tests/tui/test_chat_panel.py -k toggle

   # With coverage
   pytest --cov=sandroid --cov-report=html

Device Isolation
----------------

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
   SANDROID_TESTS_STRICT_DEVICE=1 pytest

   # Also append blocked calls to a file
   SANDROID_TESTS_BLOCKED_LOG=/tmp/blocked.log pytest

Tests that really need hardware are marked ``@pytest.mark.requires_device``;
they are skipped unless pytest runs with ``--allow-device`` (and only those
tests then run without the guard).

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

Testing Standards
-----------------

See the *Testing Requirements* section of ``CODING_GUIDELINES.md`` for
coverage expectations, naming and mocking conventions.
