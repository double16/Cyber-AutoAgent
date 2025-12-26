import uuid
import asyncio
import base64
import logging
import time
from typing import Dict, Optional, List, Literal
from dataclasses import dataclass, field

from pydantic import BaseModel, Field

from modules.utils.pick_nic import pick_local_addr
from modules.handlers.utils import b64

from strands import tool

logger = logging.getLogger(__name__)


class PollEvent(BaseModel):
    ts: float = Field(description="Unix epoch seconds.")
    stream: Literal["output", "status"] = Field(
        ..., description="'output' has bytes (data_b64). 'status' has a human-readable note."
    )
    data_b64: Optional[str] = Field(
        None, description="Base64 bytes for 'output' events."
    )
    note: Optional[str] = Field(
        None,
        description=(
            "Status message (e.g., 'process_started_pid_<pid>', 'listening', 'client_connected', "
            "'output_eof', 'client_disconnected', 'channel_closed')."
        ),
    )


@dataclass
class Channel:
    id: str
    kind: Literal["forward", "reverse"]
    created_at: float = field(default_factory=time.time)
    closed: bool = False

    events: "asyncio.Queue[PollEvent]" = field(default_factory=asyncio.Queue)

    # forward
    proc: Optional[asyncio.subprocess.Process] = None
    _output_task: Optional[asyncio.Task] = None

    # reverse (single duplex connection)
    host: Optional[str] = None
    server: Optional[asyncio.AbstractServer] = None
    _client_reader: Optional[asyncio.StreamReader] = None
    _client_writer: Optional[asyncio.StreamWriter] = None
    _client_read_task: Optional[asyncio.Task] = None

    async def put_event(self, ev: PollEvent):
        # simple cap to avoid unbounded growth
        if self.events.qsize() > 50_000:
            try:
                _ = self.events.get_nowait()
            except asyncio.QueueEmpty:
                pass
        await self.events.put(ev)

    async def mark_status(self, note: str):
        await self.put_event(PollEvent(ts=time.time(), stream="status", note=note))

    async def close(self):
        if self.closed:
            return
        self.closed = True

        # cancel tasks
        for t in [self._output_task, self._client_read_task]:
            if t and not t.done():
                t.cancel()

        # close server and client
        if self.server:
            self.server.close()
            try:
                await self.server.wait_closed()
            except Exception:
                pass
        if self._client_writer:
            try:
                self._client_writer.close()
                await self._client_writer.wait_closed()
            except Exception:
                pass

        # kill process
        if self.proc and self.proc.returncode is None:
            try:
                self.proc.terminate()
                try:
                    await asyncio.wait_for(self.proc.wait(), timeout=2)
                except asyncio.TimeoutError:
                    self.proc.kill()
            except ProcessLookupError:
                pass

        await self.mark_status("channel_closed")


class ChannelManager:
    def __init__(self):
        self._channels: Dict[str, Channel] = {}

    def new_id(self) -> str:
        return str(uuid.uuid4())

    def add(self, ch: Channel) -> Channel:
        self._channels[ch.id] = ch
        return ch

    def get(self, cid: str) -> Channel:
        ch = self._channels.get(cid)
        if not ch:
            raise KeyError(f"unknown channel_id {cid}")
        return ch

    async def close(self, cid: str) -> bool:
        ch = self._channels.pop(cid, None)
        if not ch:
            return False
        await ch.close()
        return True

    async def cleanup(self):
        ids = list(self._channels.keys())
        for cid in ids:
            await self.close(cid)


class CreateForwardResult(BaseModel):
    channel_id: str = Field(description="New channel id; persist this for later calls.")
    kind: Literal["forward", "reverse"] = Field(description="Channel type.")
    created_at: float = Field(description="Unix epoch seconds.")
    pid: int = Field(description="Process ID holding the forward channel.")


class CreateReverseResult(BaseModel):
    channel_id: str = Field(description="New channel id; persist this for later calls.")
    kind: Literal["forward", "reverse"] = Field(description="Channel type.")
    created_at: float = Field(description="Unix epoch seconds.")
    listen_address: str = Field(description="Address on which the reverse channel is listening")
    listen_port: int = Field(description="Port on which the reverse channel is listening")


class PollResult(BaseModel):
    channel_id: str = Field(description="Echo channel id.")
    closed: bool = Field(description="True if channel has been closed.")
    events: List[PollEvent] = Field(description="Events since last poll (consumed on delivery).")


class SendResult(BaseModel):
    channel_id: str = Field(description="Echo channel id.")
    bytes_sent: int = Field(description="Bytes written to stdin.")


class CloseResult(BaseModel):
    channel_id: str = Field(description="Echo channel id.")
    success: bool = Field(description="True if the channel existed and is now closed.")


class StatusResult(BaseModel):
    channel_id: str = Field(description="Echo channel id.")
    kind: Literal["forward", "reverse"] = Field(description="Channel type.")
    connected: bool = Field(
        description=(
            "Forward: True if process started and not closed. "
            "Reverse: True if a client is currently connected."
        )
    )
    ready_for_send: bool = Field(
        description=(
            "True if writing to stdin should succeed now. "
            "Forward: stdin pipe open; Reverse: client connected."
        )
    )
    details: Dict[str, str] = Field(
        description=(
            "Additional state hints. Forward includes {'pid': '<pid>', 'proc_alive': 'true/false'}. "
            "Reverse includes {'listening': 'true/false', 'client_connected': 'true/false', 'port': '<port>'} when known."
        )
    )


async def _read_output(reader: asyncio.StreamReader, ch: Channel, chunk: int = 65536):
    try:
        while True:
            data = await reader.read(chunk)
            if not data:
                break
            await ch.put_event(PollEvent(ts=time.time(), stream="output", data_b64=b64(data)))
    except asyncio.CancelledError:
        raise
    except Exception as e:
        await ch.mark_status(f"output_reader_error: {e!r}")
    finally:
        await ch.mark_status("output_eof")
        await ch.close()


_CHANNEL_MANAGER: ChannelManager = ChannelManager()


def _mgr() -> ChannelManager:
    return _CHANNEL_MANAGER


@tool
async def channel_create_forward(
        command: str,
        env: Dict[str, str] = None,
) -> CreateForwardResult:
    """
Forward Channel Instructions

To create and use a forward channel backed by a local subprocess (stdout and stderr merged), follow this sequence of tool calls:

  1. **Create forward channel**
     - Tool: `channel_create_forward`
     - Args: `cmd=['nc','target.local','8080']`
     - Response: use the returned `channel_id`.

  2. **Check status (optional)**
     - Tool: `channel_status`
     - Args: `channel_id`
     - Use to confirm readiness if needed.

  3. **Receive output**
     - Tool: `channel_poll`
     - Args: `channel_id`, `timeout=5`, `min_events=1`

  4. **Send data**
     - Tool: `channel_send`
     - Args: `channel_id`, `mode='text'`, `data='help'`, `append_newline=True`

  5. **Close channel**
     - Tool: `channel_close`
     - Args: `channel_id`

Args:
    command: Command to execute in a bash shell, shell expansion is supported.
      Example: 'sshpass -p passw0rd ssh user@host'.
      Usage: channel_create_forward → save channel_id → loop channel_poll for output →
      channel_send to write stdin → channel_close when done.
    env: Dict of environment variables

Returns:
    Dict of the channel ID information:
        {
            "channel_id": "channel_2374823764",
            "kind": "forward",
            "created_at": 473847387.0,
            "pid", "123"
        }

Important:
  - Commands are run on the local machine, not the target. Only use commands that will connect to the target such as ssh, nc, etc.
"""

    mgr = _mgr()
    cid = mgr.new_id()

    logger.info("Creating a forward channel with command: %s", command)

    proc = await asyncio.create_subprocess_exec(
        "/bin/bash", "-c", command,
        env=env,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,  # merge
    )

    ch = Channel(id=cid, kind="forward", proc=proc)
    await ch.mark_status(f"process_started_pid_{proc.pid}")

    if proc.stdout:
        ch._output_task = asyncio.create_task(_read_output(proc.stdout, ch))

    mgr.add(ch)
    return CreateForwardResult(
        channel_id=cid,
        kind="forward",
        created_at=ch.created_at,
        pid=proc.pid,
    )


@tool
async def channel_create_reverse(
        listener_host: str = "0.0.0.0",
        listener_port: int = 0,
        target: Optional[str] = None,
) -> CreateReverseResult:
    """
Channel Management Instructions

To create and use a reverse channel for one duplex client, follow this sequence of tool calls:

  1. **Create reverse channel**
     - Tool: `channel_create_reverse`
     - Args: `listener_host='0.0.0.0'`, `listener_port=0`
     - Response: use `listen_port` from the result.

  2. **Check status**
     - Tool: `channel_status`
     - Args: `channel_id`
     - Use this to confirm if the channel is listening or connected.

  3. **Wait for client**
     - The remote connects to `listener_host:listen_port`.
     - Keep polling status until it equals `"client_connected"`.

  4. **Send data**
     - Tool: `channel_send`
     - Args: `channel_id`, `mode='text'`, `data='ping'`, `append_newline=True`

  5. **Receive data**
     - Tool: `channel_poll`
     - Args: `channel_id`, `timeout=5`, `min_events=1`
     - Look for `"output"` events in the response.

  6. **Close channel**
     - Tool: `channel_close`
     - Args: `channel_id`

Args:
    listener_host: the IP address to listen on, defaults to "0.0.0.0" for all interfaces
    listener_port: the port to listen on, defaults to 0 to choose an available port
    target: the name or IP address of the target, used to select a reachable network address

Returns:
    Dict of the channel ID information:
        {
            "channel_id": "channel_2374823764",
            "kind": "reverse",
            "created_at": 473847387.0,
        }

Important:
  - It is best to leave the port set to 0 so the tool can choose a free port. The target may have networking filtering,
    in which case specifying the port of a common service like 443 may be helpful.
  - The target argument is helpful for determining which network interface to bind.
"""
    if target and listener_host == "0.0.0.0":
        listener_host, *_ = pick_local_addr(target)
        logger.info("Listening on %s to be reachable by target %s", listener_host, target)

    mgr = _mgr()
    cid = mgr.new_id()
    ch = Channel(id=cid, kind="reverse", host=listener_host)

    async def on_client(reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        # Only allow a single active client; drop additional connections.
        if ch._client_writer is not None:
            try:
                writer.close()
                await writer.wait_closed()
            finally:
                return
        ch._client_reader = reader
        ch._client_writer = writer
        await ch.mark_status("client_connected")

        # Start reading output from the client
        ch._client_read_task = asyncio.create_task(_read_output(reader, ch))
        try:
            await ch._client_read_task
        finally:
            await ch.mark_status("client_disconnected")
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass
            ch._client_reader = None
            ch._client_writer = None
            ch._client_read_task = None

    ch.server = await asyncio.start_server(on_client, listener_host, listener_port)
    port = ch.server.sockets[0].getsockname()[1]
    await ch.mark_status("listening")

    mgr.add(ch)
    logger.info(f"channel_create_reverse result: channel_id={cid}, listener_host={listener_host}, listener_port={port}")
    return CreateReverseResult(
        channel_id=cid,
        kind="reverse",
        created_at=ch.created_at,
        listen_address=listener_host,
        listen_port=port,
    )


@tool
async def channel_poll(
        channel_id: str,
        timeout: float = 5.0,
        max_events: int = 1024,
        min_events: int = 0
) -> PollResult:
    """
Long-poll for events from a channel; events are consumed on delivery.

Usage:
    loop:
      r = channel_poll(channel_id, timeout=5, min_events=1)
      for e in r.events: if e.stream=='output': decode e.data_b64

Args:
    timeout: Long-poll timeout (seconds). 0 = return immediately.
    max_events: Upper bound on events returned this call. 1 - 10000
    min_events: Early-return threshold. Set to 1 to wait on first event. 0 - 10000

Returns:
    Dict of events:
    {
        "channel_id": "echoed channel id",
        "closed": bool,
        "events": [
          {
            "ts": float,  # timestamp
            "stream": "output|status",  # 'output' has bytes (data_b64). 'status' has a human-readable note.
            "data_b64": "",  # "Base64 bytes for 'output' events."
            "note": ""
          }
        ]
    """

    ch = _mgr().get(channel_id)

    events: List[PollEvent] = []
    deadline = time.time() + timeout

    def drain_now():
        while len(events) < max_events:
            try:
                ev = ch.events.get_nowait()
                events.append(ev)
            except asyncio.QueueEmpty:
                break

    drain_now()
    if min_events and len(events) >= min_events:
        return PollResult(channel_id=ch.id, closed=ch.closed, events=events)

    while (timeout > 0) and (time.time() < deadline) and (len(events) < max(min_events, 1)):
        remaining = max(0.0, deadline - time.time())
        try:
            ev = await asyncio.wait_for(ch.events.get(), timeout=min(0.25, remaining))
            events.append(ev)
            drain_now()
        except asyncio.TimeoutError:
            pass

    return PollResult(channel_id=ch.id, closed=ch.closed, events=events)


@tool
async def channel_send(
        channel_id: str,
        data: str,
        mode: Literal["text", "base64"] = "text",
        append_newline: bool = False,
) -> SendResult:
    """
Write bytes to a channel's stdin (forward → subprocess, reverse → connected client).

Usage:
    channel_send(channel_id, mode='text', data='ls -la', append_newline=True)
    channel_send(channel_id, mode='base64', data='<b64>')

Args:
    channel_id: channel ID
    mode: 'text' = UTF-8 (optionally add newline). 'base64' = raw bytes from base64.
    data: Payload for stdin. Base64 when mode='base64'.
    append_newline: If true and mode='text', append '\n' before sending.

Returns:
    Dict of results
    {
        "channel_id": "echoed channel id",
        "bytes_sent": int  # Bytes written to stdin.
    }
    """
    ch = _mgr().get(channel_id)
    payload = base64.b64decode(data) if mode == "base64" else (
        (data + ("\n" if append_newline else "")).encode("utf-8")
    )

    total = 0
    if ch.kind == "forward":
        if not ch.proc or not ch.proc.stdin:
            raise RuntimeError("forward channel has no stdin")
        try:
            ch.proc.stdin.write(payload)
            await ch.proc.stdin.drain()
            total = len(payload)
        except (BrokenPipeError, ConnectionResetError):
            await ch.mark_status("stdin_closed")
    else:
        if not ch._client_writer:
            await ch.mark_status("client_not_connected")
            return SendResult(channel_id=ch.id, bytes_sent=0)
        try:
            ch._client_writer.write(payload)
            await ch._client_writer.drain()
            total = len(payload)
        except (BrokenPipeError, ConnectionResetError) as e:
            await ch.mark_status(f"send_error: {e!r}")

    return SendResult(channel_id=ch.id, bytes_sent=total)


@tool
async def channel_status(
        channel_id: str
) -> StatusResult:
    """
Check whether a channel is established and ready for send/receive.
Usage:
    s = channel_status(channel_id)
    if s.connected and s.ready_for_send:
    channel_send(channel_id, mode='text', data='ping', append_newline=True)
Args:
    channel_id: channel ID
Returns:
    Dict of channel status
    {
        "channel_id": str = Field(description="Echo channel id.")
        "kind": "forward|reverse"],
        "connected": bool, # Forward: True if process started and not closed., Reverse: True if a client is currently connected.
        "ready_for_send": bool,  # True if writing to stdin should succeed now., Forward: stdin pipe open; Reverse: client connected.
        "details": {}
    }
    """
    ch = _mgr().get(channel_id)

    if ch.kind == "forward":
        proc_alive = bool(ch.proc and ch.proc.returncode is None and not ch.closed)
        stdin_open = bool(proc_alive and ch.proc.stdin and not ch.proc.stdin.is_closing())
        return StatusResult(
            channel_id=ch.id,
            kind=ch.kind,
            connected=proc_alive,
            ready_for_send=stdin_open,
            details={
                "pid": str(ch.proc.pid) if ch.proc else "",
                "proc_alive": "true" if proc_alive else "false",
            },
        )
    else:
        listening = bool(ch.server is not None and not ch.closed)
        client_connected = bool(ch._client_writer is not None and not ch._client_writer.is_closing())
        port = ""
        if ch.server and ch.server.sockets:
            try:
                port = str(ch.server.sockets[0].getsockname()[1])
            except Exception:
                port = ""
        return StatusResult(
            channel_id=ch.id,
            kind=ch.kind,
            connected=client_connected,
            ready_for_send=client_connected,
            details={
                "listening": "true" if listening else "false",
                "client_connected": "true" if client_connected else "false",
                "port": port,
            },
        )


@tool
async def channel_close(
        channel_id: str
) -> CloseResult:
    """
Close a specific channel; safe to call multiple times.
Usage: channel_close(channel_id)
Args:
    channel_id: channel ID
    """
    ok = await _mgr().close(channel_id)
    return CloseResult(channel_id=channel_id, success=ok)


async def channel_close_all() -> Dict[str, int]:
    """
Close all channels.
Usage: channel_close_all()
    """
    mgr = _mgr()
    count = len(getattr(mgr, "_channels", {}))
    await mgr.cleanup()
    return {"closed": count}
