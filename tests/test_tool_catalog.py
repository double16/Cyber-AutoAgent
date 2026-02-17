from pathlib import Path
from types import SimpleNamespace

import pytest
import yaml

import modules.tools.tool_catalog as tc


@pytest.fixture(autouse=True)
def _clear_caches():
    # Ensure lru_cache does not leak state between tests
    tc._get_cyber_tools.cache_clear()
    tc._get_shell_command_help.cache_clear()
    yield
    tc._get_cyber_tools.cache_clear()
    tc._get_shell_command_help.cache_clear()


def _write_env(tmp_path: Path, cyber_tools: dict):
    env_path = tmp_path / "environment.yaml"
    env_path.write_text(yaml.safe_dump({"cyber_tools": cyber_tools}), encoding="utf-8")
    return env_path


def _patch_environment_file(monkeypatch, tmp_path: Path):
    # tool_catalog._get_cyber_tools does: Path(environment.__file__).with_name("environment.yaml")
    # So set environment.__file__ to something inside tmp_path.
    fake_env_py = tmp_path / "environment.py"
    fake_env_py.write_text("# fake", encoding="utf-8")
    monkeypatch.setattr(tc, "environment", SimpleNamespace(__file__=str(fake_env_py)))


def _patch_strands_tool_decorator(monkeypatch):
    # Replace `from strands import tool` decorator with a no-op decorator that returns the function.
    def tool_decorator(*, name: str):
        def deco(fn):
            fn.__tool_name__ = name
            return fn
        return deco

    monkeypatch.setattr(tc, "tool", tool_decorator)


class _FakeToolRegistry:
    def __init__(self, tools_config):
        self._tools_config = tools_config

    def get_all_tools_config(self):
        return self._tools_config


class _FakeAgent:
    def __init__(self, tools_config):
        self.tool_registry = _FakeToolRegistry(tools_config)


def test_get_cyber_tools_loads_environment_yaml(monkeypatch, tmp_path):
    cyber_tools = {
        "httpx": {"description": "HTTP probing", "caps": ["web_recon"], "preference": "preferred"},
    }
    _write_env(tmp_path, cyber_tools)
    _patch_environment_file(monkeypatch, tmp_path)

    loaded = tc._get_cyber_tools()
    assert loaded["httpx"]["description"] == "HTTP probing"


def test_get_cyber_tools_by_caps_filters_by_available_and_groups_by_cap_and_preference(monkeypatch, tmp_path):
    cyber_tools = {
        "httpx": {"description": "HTTP probing", "caps": ["web_recon"], "preference": "preferred"},
        "katana": {"description": "Crawler", "caps": ["web_crawling"], "preference": "fallback"},
        "missingtool": {"description": "Nope", "caps": ["web_recon"], "preference": "preferred"},
    }
    _write_env(tmp_path, cyber_tools)
    _patch_environment_file(monkeypatch, tmp_path)

    res = tc.get_cyber_tools_by_caps(available=["httpx", "katana"])
    assert res["web_recon"]["preferred"] == ["httpx"]
    # fallback-only bucket should be normalized to preferred
    assert res["web_crawling"]["preferred"] == ["katana"]


def test_get_cyber_tools_by_caps_coerces_caps_string_and_normalizes_preference(monkeypatch, tmp_path):
    cyber_tools = {
        "t1": {"caps": "web_recon", "preference": " Preferred "},
        "t2": {"caps": ["web_recon"], "preference": "fallback"},
        "t3": {"caps": ["web_recon"], "preference": ""},  # should not crash; becomes fallback
    }
    _write_env(tmp_path, cyber_tools)
    _patch_environment_file(monkeypatch, tmp_path)

    res = tc.get_cyber_tools_by_caps(available=["t1", "t2", "t3"])
    assert "web_recon" in res
    assert "preferred" in res["web_recon"]
    assert "fallback" in res["web_recon"]
    assert "t1" in res["web_recon"]["preferred"]
    assert "t2" in res["web_recon"]["fallback"]
    assert "t3" in res["web_recon"]["fallback"]


def test_get_cyber_tools_by_caps_uses_command_override(monkeypatch, tmp_path):
    cyber_tools = {
        "theharvester": {"command": "theHarvester", "caps": ["osint"], "preference": "preferred"},
    }
    _write_env(tmp_path, cyber_tools)
    _patch_environment_file(monkeypatch, tmp_path)

    res = tc.get_cyber_tools_by_caps(available=["theharvester"])
    assert res["osint"]["preferred"] == ["theHarvester"]


def test_get_shell_command_help_tries_help_flags_and_returns_long_output(monkeypatch):
    calls = []

    def fake_run(cmd, capture_output, text, timeout):
        calls.append(cmd)
        # First attempt: --help returns short -> should continue
        if cmd == ["foo", "--help"]:
            return SimpleNamespace(stdout="x", stderr="")
        # Second attempt: -h returns long -> should return it
        if cmd == ["foo", "-h"]:
            return SimpleNamespace(stdout="A" * 40, stderr="")
        return SimpleNamespace(stdout="", stderr="")

    monkeypatch.setattr(tc.subprocess, "run", fake_run)

    out = tc._get_shell_command_help("foo")
    assert len(out) >= 40
    assert calls[0] == ["foo", "--help"]
    assert calls[1] == ["foo", "-h"]


def test_tool_catalog_wrapper_lists_agent_tools_and_schemas(monkeypatch, tmp_path):
    _patch_strands_tool_decorator(monkeypatch)
    _patch_environment_file(monkeypatch, tmp_path)
    _write_env(tmp_path, cyber_tools={})  # no cyber tools needed for this test

    tools_config = {
        "validation_specialist": {
            "description": "Validates findings",
            "inputSchema": {"type": "object", "properties": {"x": {"type": "string"}}, "required": ["x"]},
            "outputSchema": {"type": "object", "properties": {"ok": {"type": "boolean"}}},
        }
    }
    agent = _FakeAgent(tools_config)
    tool_catalog = tc.tool_catalog_wrapper(agent, shell_commands=[])

    text = tool_catalog()
    assert "# TOOL CATALOG" in text
    assert "name: validation_specialist" in text
    assert "input schema:" in text
    # Pretty JSON should be present (indent=2 => newline + two spaces)
    assert "\n  \"type\": \"object\"" in text
    assert "output schema:" in text


def test_tool_catalog_wrapper_filters_by_keywords_for_agent_tool(monkeypatch, tmp_path):
    _patch_strands_tool_decorator(monkeypatch)
    _patch_environment_file(monkeypatch, tmp_path)
    _write_env(tmp_path, cyber_tools={})

    tools_config = {
        "t1": {"description": "alpha", "inputSchema": {"type": "object"}, "outputSchema": None},
        "t2": {"description": "beta", "inputSchema": {"type": "object"}, "outputSchema": None},
    }
    agent = _FakeAgent(tools_config)
    tool_catalog = tc.tool_catalog_wrapper(agent, shell_commands=[])

    text = tool_catalog("t2")
    assert "name: t2" in text
    assert "name: t1" not in text
    assert "**Tools found**:" not in text
    assert "**Command line tools found**:" not in text

    text = tool_catalog("t1 t2")
    assert "name: t2" in text
    assert "name: t1" in text
    assert "**Tools found**: t1,t2" in text
    assert "**Command line tools found**:" not in text

    text = tool_catalog("nothing_to_see_here")
    assert "name: t2" not in text
    assert "name: t1" not in text
    assert "**Tools found**:" not in text
    assert "**Command line tools found**:" not in text
    assert "**NO RESULTS**\nkeywords: nothing_to_see_here" in text


def test_tool_catalog_wrapper_includes_shell_commands_and_handles_missing_cyber_tool_entry(monkeypatch, tmp_path):
    _patch_strands_tool_decorator(monkeypatch)

    cyber_tools = {
        "httpx": {
            "description": "HTTP probing",
            "caps": ["web_recon", "http_client"],
            "preference": "preferred",
        }
    }
    _write_env(tmp_path, cyber_tools)
    _patch_environment_file(monkeypatch, tmp_path)

    # Avoid calling real subprocess help
    monkeypatch.setattr(tc, "_get_shell_command_help", lambda cmd: f"HELP({cmd})")

    tools_config = {}
    agent = _FakeAgent(tools_config)

    # Include a command not present in cyber_tools to ensure no crash (e.g., grep/cat)
    tool_catalog = tc.tool_catalog_wrapper(agent, shell_commands=["httpx", "grep"])

    text = tool_catalog()
    assert "# COMMAND LINE PROGRAMS" in text

    # httpx entry includes configured fields
    assert "command: httpx" in text
    assert "capabilities: web_recon, http_client" in text
    assert "preference: preferred" in text
    assert "HELP(httpx)" in text

    # grep entry does not exist in cyber_tools but should still render without crashing
    assert "command: grep" in text


def test_tool_catalog_wrapper_filters_by_keywords_for_shell_command(monkeypatch, tmp_path):
    _patch_strands_tool_decorator(monkeypatch)
    _write_env(tmp_path, cyber_tools={"httpx": {"description": "HTTP probing", "caps": ["web_recon"], "preference": "preferred"}})
    _patch_environment_file(monkeypatch, tmp_path)

    monkeypatch.setattr(tc, "_get_shell_command_help", lambda cmd: "")

    agent = _FakeAgent({})
    tool_catalog = tc.tool_catalog_wrapper(agent, shell_commands=["httpx", "nmap"])

    text = tool_catalog("httpx")
    assert "command: httpx" in text
    assert "command: nmap" not in text
    assert "**Tools found**:" not in text
    assert "**Command line tools found**:" not in text

    text = tool_catalog("httpx nmap")
    assert "command: httpx" in text
    assert "command: nmap" in text
    assert "**Tools found**:" not in text
    assert "**Command line tools found**: httpx,nmap" in text

    text = tool_catalog("nothing_to_see_here")
    assert "command: httpx" not in text
    assert "command: nmap" not in text
    assert "**Tools found**:" not in text
    assert "**Command line tools found**:" not in text
    assert "**NO RESULTS**\nkeywords: nothing_to_see_here" in text
