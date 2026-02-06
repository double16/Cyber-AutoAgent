"""
MCP tool integration.
"""
import asyncio
import json
import os
import re
import threading
import atexit
import signal
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, cast

from mcp.client.session import ClientSession
from mcp import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.client.sse import sse_client

from strands.types.exceptions import MCPClientInitializationError
from strands.types.tools import AgentTool, ToolGenerator, ToolSpec, ToolUse
from strands.tools.mcp.mcp_client import MCPClient

from modules.config import AgentConfig
from modules.config.system.logger import get_logger
from modules.handlers.utils import print_status

logger = get_logger("Agents.CyberAutoAgent")

MCP_HEARTBEAT_INTERVAL = max(0, int(os.getenv("CYBER_MCP_HEARTBEAT_INTERVAL", "45")))
MCP_HEARTBEAT_TIMEOUT = max(1, int(os.getenv("CYBER_MCP_HEARTBEAT_TIMEOUT", "10")))
MCP_MAX_RETRIES = max(1, int(os.getenv("CYBER_MCP_MAX_SESSION_RETRIES", "2")))
MCP_RESTART_BACKOFF = max(0.1, float(os.getenv("CYBER_MCP_RESTART_BACKOFF", "2.0")))


def _start_keepalive(client: MCPClient) -> Optional[tuple[threading.Event, threading.Thread]]:
    if MCP_HEARTBEAT_INTERVAL <= 0:
        return None

    handle = getattr(client, "_cyber_keepalive_handle", None)
    if handle:
        return handle

    stop_event = threading.Event()

    def _loop() -> None:
        while not stop_event.wait(MCP_HEARTBEAT_INTERVAL):
            try:
                _send_ping(client)
            except Exception as exc:  # pragma: no cover - defensive
                logger.warning("MCP keepalive ping failed: %s", exc)
                _restart_client(client)

    thread = threading.Thread(target=_loop, name="mcp-heartbeat", daemon=True)
    thread.start()
    handle = (stop_event, thread)
    setattr(client, "_cyber_keepalive_handle", handle)
    return handle


def _stop_keepalive(client: MCPClient) -> None:
    handle = getattr(client, "_cyber_keepalive_handle", None)
    if not handle:
        return
    stop_event, thread = handle
    stop_event.set()
    if thread.is_alive() and threading.current_thread() != thread:
        thread.join(timeout=5)
    setattr(client, "_cyber_keepalive_handle", None)


def _send_ping(client: MCPClient) -> None:
    if not client._is_session_active():  # noqa: SLF001 - best-effort keepalive
        raise MCPClientInitializationError("MCP session inactive during keepalive")

    async def _ping() -> None:
        if client._background_thread_session is None:  # noqa: SLF001
            raise MCPClientInitializationError("No MCP session available")
        await cast(ClientSession, client._background_thread_session).send_ping()  # noqa: SLF001

    future = client._invoke_on_background_thread(_ping())  # noqa: SLF001
    future.result(timeout=MCP_HEARTBEAT_TIMEOUT)


_RESTART_LOCK = threading.Lock()


def _restart_client(client: MCPClient) -> None:
    with _RESTART_LOCK:
        try:
            _stop_keepalive(client)
            client.stop(None, None, None)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("MCP stop during restart raised: %s", exc)
        client.start()
        _start_keepalive(client)
        logger.info("MCP session restarted")


def start_managed_mcp_client(client: MCPClient) -> Callable[[], None]:
    """
    Start an MCP client and enable heartbeat keepalive. Returns a cleanup hook.
    """
    client.start()
    _start_keepalive(client)

    def _cleanup() -> None:
        _stop_keepalive(client)
        client.stop(None, None, None)

    return _cleanup


class ResilientMCPToolAdapter(AgentTool):
    """Wraps an MCP tool with retry/restart behavior and heartbeat keepalive.

    Note: Timeout is handled by SDK's MCPAgentTool (via read_timeout_seconds).
    This wrapper adds retry logic, session restart, and heartbeat keepalive.
    """

    def __init__(self, inner: AgentTool, client: MCPClient) -> None:
        super().__init__()
        self._inner = inner
        self._client = client
        self._max_retries = MCP_MAX_RETRIES
        self._backoff = MCP_RESTART_BACKOFF

    @property
    def tool_name(self) -> str:
        return self._inner.tool_name

    @property
    def tool_spec(self) -> ToolSpec:
        return self._inner.tool_spec

    @property
    def tool_type(self) -> str:
        return getattr(self._inner, "tool_type", "python")

    def __getattr__(self, name: str) -> Any:
        return getattr(self._inner, name)

    async def stream(
        self,
        tool_use: ToolUse,
        invocation_state: dict[str, Any],
        **kwargs: Any,
    ) -> ToolGenerator:
        """Stream with retry/restart on recoverable errors.

        Note: Timeout is handled by inner SDK tool (MCPAgentTool.timeout).
        This method adds retry logic and session restart capability.
        """
        last_error: Optional[Exception] = None
        for attempt in range(1, self._max_retries + 1):
            try:
                # SDK's MCPAgentTool handles timeout via read_timeout_seconds
                async for event in self._inner.stream(tool_use, invocation_state, **kwargs):
                    yield event
                return
            except Exception as exc:
                if not self._is_recoverable(exc):
                    raise
                last_error = exc
                logger.warning(
                    "MCP tool '%s' failed (attempt %s/%s): %s",
                    self.tool_name,
                    attempt,
                    self._max_retries,
                    exc,
                )
                _restart_client(self._client)
                if attempt < self._max_retries and self._backoff > 0:
                    await asyncio.sleep(self._backoff)
        if last_error:
            raise last_error

    @staticmethod
    def _is_recoverable(exc: Exception) -> bool:
        if isinstance(exc, MCPClientInitializationError):
            return True
        if isinstance(exc, RuntimeError) and "MCP server was closed" in str(exc):
            return True
        return False


_VAR_PATTERN = re.compile(r"\$\{([^}]+)}")


def resolve_env_vars_in_dict(input_dict: Dict[str, str], env: Dict[str, str]) -> Dict[str, str]:
    """
    Replace ${VAR} references in values with env['VAR'] where available.
    Unrecognized variables are left as-is.
    """
    if input_dict is None:
        return {}

    resolved: Dict[str, str] = {}

    for key, value in input_dict.items():
        def _sub(match: re.Match) -> str:
            var_name = match.group(1)
            return env.get(var_name, match.group(0))  # leave ${VAR} if not found

        resolved[key] = _VAR_PATTERN.sub(_sub, value)

    return resolved


def resolve_env_vars_in_list(input_array: List[str], env: Dict[str, str]) -> List[str]:
    """
    Replace ${VAR} references in values with env['VAR'] where available.
    Unrecognized variables are left as-is.
    """
    if input_array is None:
        return []

    resolved: List[str] = []

    for value in input_array:
        def _sub(match: re.Match) -> str:
            var_name = match.group(1)
            return env.get(var_name, match.group(0))  # leave ${VAR} if not found

        resolved.append(_VAR_PATTERN.sub(_sub, value))

    return resolved


def shorten_description(text: str, max_len: int) -> str:
    """
    Shorten a string of English sentences to at most max_len characters.
    Prefer to keep whole sentences; fall back to word boundary, then hard cut.
    """
    text = text.strip()
    if len(text) <= max_len:
        return text

    # 1. Try to cut at a sentence boundary (., !, ?) before max_len
    cut_pos = -1
    for i, ch in enumerate(text):
        if i >= max_len:
            break
        if ch in ".!?":
            cut_pos = i

    if cut_pos != -1:
        return text[: cut_pos + 1].rstrip()

    # 2. No sentence end: try to cut at the last space before max_len
    last_space = text.rfind(" ", 0, max_len)
    if last_space != -1:
        return text[:last_space].rstrip()

    # 3. No space either (single long word etc.): hard cut
    return text[:max_len].rstrip()


def discover_mcp_tools(config: AgentConfig) -> List[AgentTool]:
    """Discover and register MCP tools from configured connections."""
    tool_discovery_event = {
        "type": "tool_discovery_start",
        "timestamp": datetime.now().isoformat(),
        "message": "Starting MCP tool discovery",
    }
    print(f"__CYBER_EVENT__{json.dumps(tool_discovery_event)}__CYBER_EVENT_END__")

    mcp_tools = []
    environ = os.environ.copy()
    for mcp_conn in (config.mcp_connections or []):
        if '*' in mcp_conn.plugins or config.module in mcp_conn.plugins:
            logger.debug("Discover MCP tools from: %s", mcp_conn)
            try:
                headers = resolve_env_vars_in_dict(mcp_conn.headers, environ)
                match mcp_conn.transport:
                    case "stdio":
                        if not mcp_conn.command:
                            raise ValueError(f"{mcp_conn.transport} requires command")
                        command_list: List[str] = resolve_env_vars_in_list(mcp_conn.command, environ)
                        transport = lambda: stdio_client(StdioServerParameters(
                            command=command_list[0], args=command_list[1:],
                            env=environ,
                        ))
                        tool_path = mcp_conn.command
                    case "streamable-http":
                        transport = lambda: streamablehttp_client(
                            url=mcp_conn.server_url,
                            headers=headers,
                            timeout=mcp_conn.timeoutSeconds if mcp_conn.timeoutSeconds else 30,
                        )
                        tool_path = mcp_conn.server_url
                    case "sse":
                        transport = lambda: sse_client(
                            url=mcp_conn.server_url,
                            headers=headers,
                            timeout=mcp_conn.timeoutSeconds if mcp_conn.timeoutSeconds else 30,
                        )
                        tool_path = mcp_conn.server_url
                    case _:
                        raise ValueError(f"Unsupported MCP transport {mcp_conn.transport}")
                client = MCPClient(transport, prefix=mcp_conn.id)
                prefix_idx = len(mcp_conn.id) + 1
                cleanup_fn: Callable[[], None] | None = None
                cleanup_fn = start_managed_mcp_client(client)
                client_used = False
                page_token = None
                missing_tools = mcp_conn.allowed_tools.copy()
                if "*" in missing_tools:
                    missing_tools.remove("*")
                while len(tools := client.list_tools_sync(page_token)) > 0:
                    page_token = tools.pagination_token
                    for tool in tools:
                        logger.debug(f"Considering tool: {tool.tool_name}")
                        tool_name_base = tool.tool_name[prefix_idx:]
                        if '*' in mcp_conn.allowed_tools or tool_name_base in mcp_conn.allowed_tools:
                            logger.debug(f"Allowed tool: {tool.tool_name}")
                            try:
                                missing_tools.remove(tool_name_base)
                            except ValueError:
                                pass

                            tool = ResilientMCPToolAdapter(tool, client)
                            mcp_tools.append(tool)
                            client_used = True

                            tool_desc = shorten_description(tool.tool_spec.get('description'), 256)
                            print_status(f"✓ {tool.tool_name:<12} - {tool_path}", "SUCCESS")
                            tool_event = {
                                "type": "tool_available",
                                "timestamp": datetime.now().isoformat(),
                                "tool_name": tool.tool_name,
                                "description": tool_desc,
                                "status": "available",
                                "binary": None,
                                "path": tool_path,
                            }
                            print(f"__CYBER_EVENT__{json.dumps(tool_event)}__CYBER_EVENT_END__")
                    if not page_token:
                        break

                def client_stop(*_):
                    if cleanup_fn:
                        cleanup_fn()
                    else:
                        client.stop(exc_type=None, exc_val=None, exc_tb=None)

                if client_used:
                    atexit.register(client_stop)
                    signal.signal(signal.SIGINT, client_stop)
                    signal.signal(signal.SIGTSTP, client_stop)
                    signal.signal(signal.SIGTERM, client_stop)
                else:
                    client_stop()

                for missing_tool in missing_tools:
                    tool_name = mcp_conn.id + "_" + missing_tool
                    print_status(f"○ {tool_name:<12} - {tool_path} (not available)", "WARNING")
                    tool_event = {
                        "type": "tool_unavailable",
                        "timestamp": datetime.now().isoformat(),
                        "tool_name": tool_name,
                        "description": None,
                        "status": "unavailable",
                        "binary": None,
                        "path": None,
                    }
                    print(f"__CYBER_EVENT__{json.dumps(tool_event)}__CYBER_EVENT_END__")

            except Exception as e:
                logger.error(f"Communicating with MCP: {repr(mcp_conn)}", exc_info=e)
                raise e

    env_ready_event = {
        "type": "environment_ready",
        "timestamp": datetime.now().isoformat(),
        "available_tools": list(map(lambda t: t.tool_name, mcp_tools)),
        "tool_count": len(mcp_tools),
        "message": f"Environment ready with {len(mcp_tools)} MCP tools",
    }
    print(f"__CYBER_EVENT__{json.dumps(env_ready_event)}__CYBER_EVENT_END__")

    return mcp_tools
