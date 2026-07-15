"""Persistent MCP client manager.

Owns one daemon thread running its own asyncio event loop for the process's
lifetime -- similar in spirit to :class:`sandroid.core.adb_device_monitor.AdbDeviceMonitor`'s
one-thread-owns-a-long-lived-connection shape, though the asyncio-loop-in-thread
plus ``run_coroutine_threadsafe`` mechanics here are a new pattern for this
codebase (``AdbDeviceMonitor`` itself is a plain blocking-socket thread with no
event loop of its own).

:meth:`MCPClientManager.start` connects to every ``enabled`` server in
``config.mcp.servers`` via ``mcp.client.stdio.stdio_client`` +
``mcp.ClientSession`` and caches each server's ``list_tools()`` result. A
single unreachable/broken server does not break the others -- each server is
served by its own asyncio Task, independent of the others.

Each connected server gets one long-lived ``asyncio.Task`` (:meth:`_serve_one`)
that opens the ``stdio_client``/``ClientSession`` async context managers,
publishes the session + tool list, then waits on a per-server shutdown
``asyncio.Event`` before exiting those context managers. This is deliberate,
not incidental: ``anyio`` (which the ``mcp`` package's stdio transport is
built on) requires a cancel scope to be entered and exited in the *same*
asyncio Task. Opening the context managers in one coroutine/Task (e.g. inside
a "connect all" helper) and later closing them from a *different* Task (e.g.
a later "shutdown" call scheduled via a fresh ``run_coroutine_threadsafe``)
raises ``RuntimeError: Attempted to exit cancel scope in a different task
than it was entered in``. Keeping one task alive end-to-end per server (open
-> wait for shutdown signal -> close, all within that one task) sidesteps
this entirely.

:meth:`MCPClientManager.call_tool` is the thread-safe synchronous entry point
everything else uses to actually invoke a tool on a connected server -- this
is safe to call from a different task/thread than the one serving the
session, since it only sends a request through the already-open session and
awaits the matching response (no cancel-scope entry/exit involved).

Shutdown (:meth:`MCPClientManager.stop`) is deliberately NOT just "stop the
loop": stopping the event loop out from under a live per-server serve task
can leak the server subprocess as a zombie, so shutdown first signals every
serve task to exit cleanly and waits for them to finish, and only then stops
the loop and joins the thread.
"""

import asyncio
import logging
import threading
from typing import Any

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

from sandroid.ai.errors import AIClientError, ToolExecutionError

logger = logging.getLogger(__name__)

#: How long start() waits for the background loop to come up before giving up.
_LOOP_STARTUP_TIMEOUT = 5.0
#: How long start() waits for every server to report ready (or failed) before
#: returning -- a slow/unreachable server just won't have its tools cached
#: yet by the time start() returns, it does not block the others.
_CONNECT_ALL_TIMEOUT = 30.0
#: How long stop() waits for every serve task to exit cleanly before forcing
#: the loop to stop anyway.
_SHUTDOWN_TIMEOUT = 5.0
#: How long stop() waits for the background thread to actually exit.
_THREAD_JOIN_TIMEOUT = 5.0


class MCPClientManager:
    """Connects to configured MCP servers and bridges sync calls into them.

    Thread safety: all MCP protocol work (connect, list_tools, call_tool,
    shutdown) runs on the manager's own event-loop thread. Public methods are
    plain, synchronous, and safe to call from any other thread (e.g. a
    Textual worker thread running the tool-calling loop).
    """

    def __init__(self) -> None:
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._loop_ready = threading.Event()
        self._sessions: dict[str, ClientSession] = {}
        self._tools_cache: dict[str, list] = {}
        self._serve_tasks: dict[str, asyncio.Task] = {}
        self._shutdown_events: dict[str, asyncio.Event] = {}

    def start(self) -> None:
        """Start the background loop thread and connect every enabled server.

        Idempotent against a double-start (a second call is a no-op if the
        thread is already alive).
        """
        if self._thread is not None and self._thread.is_alive():
            return
        self._loop_ready.clear()
        self._thread = threading.Thread(
            target=self._run_loop, name="mcp-client-loop", daemon=True
        )
        self._thread.start()
        if not self._loop_ready.wait(timeout=_LOOP_STARTUP_TIMEOUT):
            raise AIClientError("MCP client loop failed to start in time")

        future = asyncio.run_coroutine_threadsafe(self._connect_all(), self._loop)
        future.result(timeout=_CONNECT_ALL_TIMEOUT)

    def _run_loop(self) -> None:
        """Thread entry point: own an event loop for the rest of the process."""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop
        self._loop_ready.set()
        loop.run_forever()

    async def _connect_all(self) -> None:
        """Spawn one long-lived serve task per enabled server and wait for readiness."""
        from sandroid.config import get_config

        servers = get_config().mcp.servers
        ready_futures: list[asyncio.Future] = []
        for server in servers:
            if not server.enabled:
                continue
            ready = asyncio.get_running_loop().create_future()
            shutdown_event = asyncio.Event()
            task = asyncio.create_task(
                self._serve_one(server, ready, shutdown_event),
                name=f"mcp-serve-{server.name}",
            )
            self._serve_tasks[server.name] = task
            self._shutdown_events[server.name] = shutdown_event
            ready_futures.append(ready)

        if ready_futures:
            await asyncio.wait(ready_futures, timeout=_CONNECT_ALL_TIMEOUT)

    async def _serve_one(
        self,
        server: Any,
        ready: asyncio.Future,
        shutdown_event: asyncio.Event,
    ) -> None:
        """Own one server's session for its entire lifetime, in one Task.

        Opens the stdio transport + client session, publishes the session and
        its tool list, then blocks until ``shutdown_event`` is set -- at which
        point this same coroutine (same Task) exits the ``async with`` blocks,
        satisfying anyio's same-task cancel-scope requirement. Any failure
        (connect, initialize, list_tools) resolves ``ready`` with ``False``
        and returns -- this server is simply absent from ``list_all_tools()``,
        it does not affect any other server's task.
        """
        try:
            if server.transport != "stdio":
                # Only stdio is actually implemented -- fail loudly and
                # specifically rather than silently building a
                # StdioServerParameters(command=None, ...) that would fail
                # deep inside stdio_client with a confusing, generic error.
                raise NotImplementedError(
                    f"MCP server {server.name!r} requests transport "
                    f"{server.transport!r}, but only 'stdio' is implemented"
                )
            params = StdioServerParameters(command=server.command, args=server.args)
            async with (
                stdio_client(params) as (read, write),
                ClientSession(read, write) as session,
            ):
                await session.initialize()
                tools_result = await session.list_tools()
                self._sessions[server.name] = session
                self._tools_cache[server.name] = list(tools_result.tools)
                logger.debug(
                    "Connected MCP server %r (%d tools)",
                    server.name,
                    len(self._tools_cache[server.name]),
                )
                if not ready.done():
                    ready.set_result(True)
                await shutdown_event.wait()
        except Exception:
            logger.exception(
                "MCP server %r connection/session failed; skipping", server.name
            )
            if not ready.done():
                ready.set_result(False)
        finally:
            self._sessions.pop(server.name, None)
            self._tools_cache.pop(server.name, None)

    def call_tool(
        self, server: str, tool: str, arguments: dict, timeout: float = 5.0
    ) -> Any:
        """Call a tool on a connected server, synchronously, with a hard timeout.

        Args:
            server: Configured server name.
            tool: Tool name as reported by that server's ``list_tools()``.
            arguments: Arguments passed to the tool.
            timeout: Seconds to wait for the call to complete. Keep this
                short -- a blocked call cannot be interrupted mid-flight by a
                caller's own cancellation (the ``cancel_event`` used elsewhere
                in this package is only checked between calls, never inside
                one), so bounding it here is the mitigation: a hung external
                server surfaces as a tool error within a bounded window
                instead of appearing to hang the whole turn indefinitely.

        Returns:
            The raw ``mcp.types.CallToolResult`` from the session call.

        Raises:
            AIClientError: If the manager hasn't been started.
            ToolExecutionError: If ``server`` isn't a connected session.
        """
        if self._loop is None:
            raise AIClientError("MCP client manager not started")
        future = asyncio.run_coroutine_threadsafe(
            self._call(server, tool, arguments), self._loop
        )
        return future.result(timeout=timeout)

    async def _call(self, server: str, tool: str, arguments: dict) -> Any:
        session = self._sessions.get(server)
        if session is None:
            raise ToolExecutionError(f"MCP server not connected: {server!r}")
        return await session.call_tool(tool, arguments)

    def list_all_tools(self) -> dict[str, list]:
        """Return cached ``list_tools()`` results per connected server.

        Returns:
            Mapping of server name to a list of ``mcp.types.Tool`` objects.
        """
        return dict(self._tools_cache)

    def stop(self) -> None:
        """Tear down every connected server cleanly, then stop the loop/thread.

        Explicit sequence (NOT just "stop the loop"): stopping the asyncio
        loop out from under a live per-server serve task can leak the server
        subprocess as a zombie, so every serve task is signalled and awaited
        first.
        """
        if self._loop is None:
            return

        future = asyncio.run_coroutine_threadsafe(self._shutdown_all(), self._loop)
        try:
            future.result(timeout=_SHUTDOWN_TIMEOUT)
        except Exception:
            logger.exception("MCP shutdown coroutine failed or timed out")

        self._loop.call_soon_threadsafe(self._loop.stop)
        if self._thread is not None:
            self._thread.join(timeout=_THREAD_JOIN_TIMEOUT)

        self._loop = None
        self._thread = None
        self._sessions.clear()
        self._tools_cache.clear()
        self._serve_tasks.clear()
        self._shutdown_events.clear()

    async def _shutdown_all(self) -> None:
        """Signal every serve task to exit, then wait for them to finish."""
        for event in self._shutdown_events.values():
            event.set()
        tasks = [t for t in self._serve_tasks.values() if not t.done()]
        if tasks:
            await asyncio.wait(tasks, timeout=_SHUTDOWN_TIMEOUT)


_mcp_client_manager: MCPClientManager | None = None


def get_mcp_client_manager() -> MCPClientManager:
    """Get or create the MCPClientManager singleton.

    Returns:
        MCPClientManager instance shared across the process.
    """
    global _mcp_client_manager
    if _mcp_client_manager is None:
        _mcp_client_manager = MCPClientManager()
    return _mcp_client_manager
