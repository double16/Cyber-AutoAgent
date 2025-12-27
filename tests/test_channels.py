import asyncio
import base64
import sys
import time
import pytest

MODULE_UNDER_TEST = "modules.tools.channels"

mod = __import__(MODULE_UNDER_TEST, fromlist=["*"])


# Common helpers

def b64_to_bytes(ev):
    return base64.b64decode(ev.data_b64) if getattr(ev, "data_b64", None) else b""


async def poll_until(channel_id, pred, timeout=3.0):
    """Poll repeatedly until pred(events) is True or timeout; returns accumulated events."""
    start = time.time()
    collected = []
    while time.time() - start < timeout:
        res = await mod.channel_poll(
            channel_id=channel_id,
            timeout=0.25,
            max_events=1024,
            min_events=1,
        )
        collected.extend(res.events)
        if pred(collected):
            return collected
    return collected


# Forward channel tests (Docker-free by mocking create_subprocess_exec)

ECHO_CODE = (
    "import sys\n"
    "print('ready', flush=True)\n"
    "for line in sys.stdin:\n"
    "    sys.stdout.write(line)\n"
    "    sys.stdout.flush()\n"
)


@pytest.fixture
def mock_subprocess(monkeypatch):
    orig = asyncio.create_subprocess_exec

    async def fake_create_subprocess_exec(*args, **kwargs):
        # Ignore the 'docker ... image ... cmd...' invocation and run a simple echo script instead
        return await orig(
            sys.executable, "-u", "-c", ECHO_CODE,
            stdin=kwargs.get("stdin"),
            stdout=kwargs.get("stdout"),
            stderr=kwargs.get("stderr"),
            limit=kwargs.get("limit", 2 ** 16),
            env=kwargs.get("env"),
            cwd=kwargs.get("cwd"),
        )

    monkeypatch.setattr(mod.asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    yield
    # restore implicitly when fixture exits


@pytest.mark.asyncio
async def test_forward_create_status_send_poll_close(mock_subprocess):
    # Create forward channel
    res = await mod.channel_create_forward(command="/bin/bash -lc 'echo ready; while true; do read L; echo $L; done'")
    cid = res.channel_id
    assert res.kind == "forward"
    assert isinstance(res.pid, int) and res.pid > 0

    # Status should be connected and ready
    s = await mod.channel_status(channel_id=cid)
    assert s.kind == "forward"
    assert s.connected is True
    assert s.ready_for_send is True
    assert "pid" in s.details

    # Poll for the "ready" line from the echo script
    evs = await poll_until(cid, lambda es: any(b"ready" in b64_to_bytes(e) for e in es if e.stream == "output"))
    assert any(b"ready" in b64_to_bytes(e) for e in evs if e.stream == "output")

    # Send a line; expect it echoed back
    await mod.channel_send(channel_id=cid, mode="text", data="ping", append_newline=True)
    evs = await poll_until(cid, lambda es: any(b"ping" in b64_to_bytes(e) for e in es if e.stream == "output"))
    assert any(b"ping" in b64_to_bytes(e) for e in evs if e.stream == "output")

    # Close channel
    closed = await mod.channel_close(channel_id=cid)
    assert closed.success is True

    # After close, channel_status should raise (channel removed)
    with pytest.raises(KeyError):
        await mod.channel_status(channel_id=cid)


@pytest.mark.asyncio
async def test_poll_timeout_returns_quickly(mock_subprocess):
    # Create forward channel and poll with short timeout; ensure it doesn't hang
    res = await mod.channel_create_forward(command="bash -lc true")
    cid = res.channel_id
    out = await mod.channel_poll(channel_id=cid, timeout=0.010, max_events=10, min_events=1)
    assert isinstance(out.events, list)
    await mod.channel_close(channel_id=cid)


# Reverse channel tests

@pytest.mark.asyncio
async def test_reverse_connect_duplex_send_both_ways_and_close():
    r = await mod.channel_create_reverse(target=None, listener_host="127.0.0.1", listener_port=0)
    cid = r.channel_id
    assert r.listen_port > 0
    assert r.listen_address == "127.0.0.1"

    # Before client connect
    s0 = await mod.channel_status(channel_id=cid)
    assert s0.connected is False
    assert s0.details.get("listening") == "true"
    assert s0.details.get("port") == str(r.listen_port)

    # Connect a client
    reader, writer = await asyncio.open_connection(r.listen_address, r.listen_port)

    # Wait for server to report 'client_connected'
    evs = await poll_until(cid,
                           lambda es: any((e.stream == "status" and (e.note or "") == "client_connected") for e in es))
    assert any((e.stream == "status" and (e.note or "") == "client_connected") for e in evs)

    # Server → client
    await mod.channel_send(channel_id=cid, mode="text", data="srv2cli", append_newline=True)
    line = await asyncio.wait_for(reader.readline(), timeout=1.0)
    assert line.strip() == b"srv2cli"

    # Client → server
    writer.write(b"cli2srv\n")
    await writer.drain()
    evs = await poll_until(cid, lambda es: any(b"cli2srv" in b64_to_bytes(e) for e in es if e.stream == "output"))
    assert any(b"cli2srv" in b64_to_bytes(e) for e in evs if e.stream == "output")

    # Close server side and then client
    closed = await mod.channel_close(channel_id=cid)
    assert closed.success is True
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass


@pytest.mark.asyncio
async def test_reverse_send_when_not_connected_returns_zero():
    r = await mod.channel_create_reverse(target=None, listener_host="127.0.0.1", listener_port=0)
    cid = r.channel_id
    out = await mod.channel_send(channel_id=cid, mode="text", data="hello", append_newline=False)
    assert out.bytes_sent == 0
    await mod.channel_close(channel_id=cid)


# Close-all & cleanup

@pytest.mark.asyncio
async def test_close_all(mock_subprocess):
    r1 = await mod.channel_create_forward(command="bash -lc 'echo a'")
    r2 = await mod.channel_create_forward(command="bash -lc 'echo b'")
    res = await mod.channel_close_all()
    assert res["closed"] >= 2

    # Any subsequent status on the old channels should fail
    for cid in (r1.channel_id, r2.channel_id):
        with pytest.raises(KeyError):
            await mod.channel_status(channel_id=cid)
