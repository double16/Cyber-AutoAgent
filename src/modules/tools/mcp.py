"""
Lists the full catalog of MCP tools.
"""
import asyncio
import json
import os
import re
import threading
import time
from datetime import timedelta
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Tuple, TypedDict, cast

from mcp.client.session import ClientSession
from strands import tool
from strands.types.exceptions import MCPClientInitializationError
from strands.types.tools import AgentTool, ToolGenerator, ToolResult, ToolSpec, ToolUse
from strands.tools.mcp.mcp_client import MCPClient

from modules.config.system.logger import get_logger
from modules.handlers.core import sanitize_target_name

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

def list_mcp_tools_wrapper(mcp_tools: List[AgentTool]):
    mcp_full_catalog = f"""
## MCP FULL TOOL CATALOG

"""
    for mcp_tool in mcp_tools:
        mcp_full_catalog += f"""
----
name: {mcp_tool.tool_name}

input schema:
{json.dumps(mcp_tool.tool_spec.get("inputSchema"))}
"""
        output_schema = mcp_tool.tool_spec.get("outputSchema", None)
        if output_schema:
            mcp_full_catalog += f"""

output schema:
{json.dumps(output_schema)}

"""

        mcp_full_catalog += f"""
{mcp_tool.tool_spec.get("description")}
----
"""

    @tool
    def list_mcp_tools() -> str:
        """
        List the full catalog of MCP tools.
        """
        return mcp_full_catalog

    return list_mcp_tools


def _snake_case(name: str) -> str:
    """Convert a string to a Pythonic snake_case identifier."""
    s = re.sub(r"[\s\-\.]+", "_", name)
    s = re.sub(r"[^\w_]", "", s)
    s = re.sub(r"__+", "_", s)
    s = s.strip("_").lower()
    if not s:
        return "func"
    if not re.match(r"^[a-zA-Z_]", s):
        s = f"f_{s}"
    return s


def _type_hint_for(prop: Dict[str, Any]) -> str:
    """Infer a Python type hint from the JSON schema property."""
    def _map_simple(t: str) -> str:
        return {
            "string": "str",
            "integer": "int",
            "number": "float",
            "boolean": "bool",
            "object": "dict",
            "array": "list",
            "null": "None",
        }.get(t, "Any")

    # Handle "anyOf" or "oneOf"
    if "anyOf" in prop or "oneOf" in prop:
        options = prop.get("anyOf") or prop.get("oneOf")
        types = []
        for opt in options:
            if not isinstance(opt, dict):
                continue
            if opt.get("type") == "array":
                item_type = "Any"
                if "items" in opt and isinstance(opt["items"], dict):
                    item_type = _map_simple(opt["items"].get("type", "Any"))
                types.append(f"list[{item_type}]")
            else:
                t = _map_simple(opt.get("type", "Any"))
                types.append(t)
        types = [t for t in types if t != "None"]
        # If null is allowed, wrap in Optional
        if any(o.get("type") == "null" for o in options if isinstance(o, dict)):
            if len(types) == 1:
                return f"Optional[{types[0]}]"
            return f"Optional[Union[{', '.join(types)}]]"
        elif len(types) > 1:
            return f"Union[{', '.join(types)}]"
        return types[0] if types else "Any"

    # Handle direct type
    t = prop.get("type")
    if t == "array":
        item_type = "Any"
        if "items" in prop and isinstance(prop["items"], dict):
            item_type = _map_simple(prop["items"].get("type", "Any"))
        return f"list[{item_type}]"
    return _map_simple(t or "Any")


def _default_value_for(prop: Dict[str, Any]) -> str:
    """Infer the Python default literal for the property."""
    if "default" in prop:
        val = prop["default"]
    else:
        val = None
        if prop.get("type") == "boolean":
            val = False
        elif "anyOf" in prop or "oneOf" in prop:
            options = prop.get("anyOf") or prop.get("oneOf")
            if any(o.get("type") == "null" for o in options if isinstance(o, dict)):
                val = None
    return repr(val)


def mcp_tools_input_schema_to_function_call(schema: Dict[str, Any], func_name: str | None = None) -> str:
    """
    Convert a JSON Schema object into a Python-style function signature and call example.
    """
    # Unwrap {"json": {...}} wrapper if present
    if "properties" not in schema and "json" in schema:
        schema = schema["json"]

    if func_name is None:
        func_name = _snake_case(schema.get("title", "func"))

    props = schema.get("properties", {})
    params = []
    call_args = []
    for key, prop in props.items():
        t = _type_hint_for(prop)
        d = _default_value_for(prop)
        params.append(f"{key}: {t} = {d}")
        call_args.append(f"{key}={d}")

    signature = f"{func_name}({', '.join(params)})"
    return signature
    # call_example = f"{func_name}({', '.join(call_args)})"
    # return signature + "\n\n# Example call:\n" + call_example


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


class FileWritingAgentToolAdapter(AgentTool):
    """
    Adapter that wraps an AgentTool and sends its streamed events through
    FileWritingToolGenerator to persist ToolResultEvent results to files.
    """

    def __init__(self, inner: AgentTool, output_base_path: Path) -> None:
        super().__init__()
        self._inner = inner
        self._output_base_path = output_base_path

    @property
    def tool_name(self) -> str:
        return self._inner.tool_name

    @property
    def tool_spec(self) -> ToolSpec:
        return self._inner.tool_spec

    @property
    def tool_type(self) -> str:
        # Delegate if present; fall back to the inner's type or "python"
        return getattr(self._inner, "tool_type", "python")

    @property
    def supports_hot_reload(self) -> bool:
        return False

    @property
    def is_dynamic(self) -> bool:
        return False

    def stream(
            self,
            tool_use: ToolUse,
            invocation_state: dict[str, Any],
            **kwargs: Any,
    ) -> ToolGenerator:
        inner_gen = self._inner.stream(tool_use, invocation_state, **kwargs)

        async def _wrapped() -> ToolGenerator:
            async for event in inner_gen:
                if self._is_tool_result_event(event):
                    # offload sync file IO to a thread so we don't block the event loop
                    try:
                        tool_result = getattr(event, "tool_result", None)
                        output_paths, output_size = await asyncio.to_thread(self._write_result, tool_result)

                        # Use same threshold as ToolRouter (10KB) for consistency
                        # Only replace content for large outputs (>10KB)
                        ARTIFACT_THRESHOLD = int(os.getenv("CYBER_TOOL_RESULT_ARTIFACT_THRESHOLD", "10000"))

                        if output_size > ARTIFACT_THRESHOLD:
                            # Large output: externalize and provide preview + path
                            summary = {"artifact_paths": output_paths, "has_more": True}
                            preview_text = ""
                            # Extract preview from original content
                            if "content" in tool_result and isinstance(tool_result["content"], list):
                                for block in tool_result["content"]:
                                    if isinstance(block, dict) and "text" in block:
                                        preview_text = str(block["text"])[:4000]  # 4KB preview
                                        break

                            preview_msg = f"[Tool output: {output_size:,} chars | Full output saved to artifact]\n\n{preview_text}\n\n... [truncated, full output in artifact]"
                            tool_result["content"] = [
                                {"text": preview_msg},
                                {"text": json.dumps(summary), "json": summary}
                            ]
                            tool_result["structuredContent"] = summary
                        else:
                            # Small output: keep in conversation, just add artifact reference
                            tool_result["structuredContent"]["artifact_paths"] = output_paths
                            if "content" in tool_result and isinstance(tool_result["content"], list):
                                summary = {"artifact_paths": output_paths}
                                tool_result["content"].append({"text": json.dumps(summary), "json": summary})

                    except Exception:
                        logger.debug(
                            "Failed to write ToolResultEvent result",
                            exc_info=True,
                        )
                yield event

        return _wrapped()

    def __getattr__(self, name: str):
        # Only called if the attribute isn't found on self
        return getattr(self._inner, name)

    def _write_result(self, result: ToolResult) -> Tuple[List[str], int]:
        output_paths = []
        size = 0
        try:
            output_basename = f"output_{time.time_ns()}"
            self._output_base_path.mkdir(parents=True, exist_ok=True)
            for idx, content in enumerate(result.get("content", [])):
                # ToolResultContent

                if "json" in content:
                    output_path = Path(os.path.join(self._output_base_path, f"{output_basename}_{idx}.json"))
                    with output_path.open("a", encoding="utf-8") as f:
                        f.write(json.dumps(content.get("json", "")))
                    output_paths.append(output_path)
                    size += output_path.stat().st_size

                if "text" in content:
                    output_path = Path(os.path.join(self._output_base_path, f"{output_basename}_{idx}.txt"))
                    with output_path.open("a", encoding="utf-8") as f:
                        f.write(content.get("text", ""))
                    output_paths.append(output_path)
                    size += output_path.stat().st_size

                for file_type in ["document", "image"]:
                    if file_type in content:
                        document: TypedDict = content.get(file_type)
                        ext = sanitize_target_name(document.get("format", "bin"))
                        output_path = Path(os.path.join(self._output_base_path, f"{output_basename}_{idx}.{ext}"))
                        with output_path.open("ab") as f:
                            f.write(document.get("source", {}).get("bytes", b''))
                        output_paths.append(output_path)
                        size += output_path.stat().st_size

            return list(map(str, output_paths)), size
        except Exception:
            logger.debug(
                "Failed to write ToolResultEvent result to %s",
                str(self._output_base_path),
                exc_info=True,
            )
            return [], 0

    @staticmethod
    def _is_tool_result_event(event: Any) -> bool:
        try:
            name = event.__class__.__name__
            if name == "ToolResultEvent":
                return True
            # Heuristic fallback for environments where the class cannot be imported
            return hasattr(event, "tool_result") and not hasattr(event, "delta")
        except Exception:
            return False


def with_result_file(tool: AgentTool, output_base_path: Path) -> AgentTool:
    """
    Convenience helper to wrap an AgentTool so its streamed results
    are persisted via FileWritingToolGenerator.
    """
    return FileWritingAgentToolAdapter(tool, output_base_path)
