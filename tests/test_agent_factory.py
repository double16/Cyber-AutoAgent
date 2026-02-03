import sys
import types
from dataclasses import dataclass
import pytest

from modules.agents import factory
import strands

from modules.agents.factory import AgentFactoryConfig


# -------------------------
# Test helpers / fakes
# -------------------------

@dataclass
class FakeCaps:
    supports_reasoning: bool


@dataclass
class FakeLLMConfig:
    model_id: str


class FakeAgent:
    """
    Stand-in for strands.Agent that just records init args.
    Also supports setattr for private attrs set after construction.
    """

    def __init__(self, **kwargs):
        self._init_kwargs = kwargs


class FakeConfigManager:
    def __init__(
            self,
            provider="bedrock",
            swarm_model_id="swarm-model",
            main_model_id="main-model",
    ):
        self._provider = provider
        self._swarm_model_id = swarm_model_id
        self._main_model_id = main_model_id

    def get_provider(self):
        return self._provider

    def get_swarm_model_id(self, provider):
        # in real code this may vary by provider; keep deterministic
        return f"{provider}:{self._swarm_model_id}"

    def get_llm_config(self, provider):
        return FakeLLMConfig(model_id=f"{provider}:{self._main_model_id}")


class DummyHook:
    pass


def install_fake_tooluseidhook(monkeypatch):
    """Install a ToolUseIdHook for tests without polluting other tests.

    `agent_factory()` does a runtime import:
        from modules.agents.patches import ToolUseIdHook

    If `modules.agents.patches` already exists (real module), we patch only the
    `ToolUseIdHook` attribute and let `monkeypatch` restore it.

    If it does not exist, we create a temporary module and register it in
    `sys.modules` via `monkeypatch.setitem`, so it is automatically removed.
    """
    import importlib

    module_name = "modules.agents.patches"

    try:
        patches_mod = importlib.import_module(module_name)
    except ModuleNotFoundError:
        patches_mod = types.ModuleType(module_name)
        monkeypatch.setitem(sys.modules, module_name, patches_mod)

    class ToolUseIdHook:
        pass

    # Patch only the attribute; do not replace the whole module.
    monkeypatch.setattr(patches_mod, "ToolUseIdHook", ToolUseIdHook, raising=False)
    return ToolUseIdHook


def install_fake_toolregistry(monkeypatch):
    """Provide a minimal strands.tools.registry.ToolRegistry for patch tests."""
    import importlib

    # Ensure parent module `strands.tools` exists in sys.modules
    try:
        import strands.tools  # type: ignore
    except Exception:
        # If strands.tools isn't importable for some reason, create a placeholder.
        tools_mod = types.ModuleType("strands.tools")
        monkeypatch.setitem(sys.modules, "strands.tools", tools_mod)

    registry_mod = types.ModuleType("strands.tools.registry")

    class ToolRegistry:
        def __init__(self):
            self.registered = []

        def register_tool(self, tool, *args, **kwargs):
            # Minimal behavior: remember and return
            self.registered.append((tool, args, kwargs))
            return tool

    registry_mod.ToolRegistry = ToolRegistry

    # Install/override module import path
    monkeypatch.setitem(sys.modules, "strands.tools.registry", registry_mod)

    # Also attach to strands.tools so attribute resolution works in some environments
    try:
        tools_pkg = importlib.import_module("strands.tools")
        monkeypatch.setattr(tools_pkg, "registry", registry_mod, raising=False)
    except Exception:
        pass

    return ToolRegistry


# Prevent ToolRegistry.register_tool monkey patch from leaking across tests.
@pytest.fixture(autouse=True)
def _isolate_toolregistry_register_tool_patch(monkeypatch):
    """Prevent ToolRegistry.register_tool monkey patch from leaking across tests.

    factory.patch_toolregistry_register_tool() uses a module-level guard flag.
    Reset it per test and ensure we always patch a fake ToolRegistry rather than the
    real strands implementation (if installed).
    """
    # Reset the module-level patch guard so each test can re-apply against its own fake module.
    monkeypatch.setattr(factory, "_TOOLREGISTRY_REGISTER_TOOL_PATCHED", False, raising=False)

    # Ensure init_agent_factory() (and explicit patch calls) operate on an ephemeral ToolRegistry.
    install_fake_toolregistry(monkeypatch)

    yield

    # Best-effort reset in case a test mutated the global directly.
    try:
        factory._TOOLREGISTRY_REGISTER_TOOL_PATCHED = False
    except Exception:
        pass


# -------------------------
# init_agent_factory() tests
# -------------------------

def test_agent_factory_sets_load_tools_from_directory_default(monkeypatch):
    ToolUseIdHook = install_fake_tooluseidhook(monkeypatch)

    fake_cm = FakeConfigManager(provider="bedrock")

    monkeypatch.setattr(factory, "get_config_manager", lambda: fake_cm)
    monkeypatch.setattr(factory, "Agent", FakeAgent)
    monkeypatch.setattr(factory, "create_strands_model", lambda provider, model_id, _: ("MODEL", provider, model_id))
    monkeypatch.setattr(factory, "get_shared_conversation_manager", lambda: object())
    monkeypatch.setattr(factory, "get_capabilities", lambda provider, model_id: FakeCaps(supports_reasoning=False))
    monkeypatch.setattr(factory, "_resolve_prompt_token_limit", lambda provider, model_id: 123)
    monkeypatch.setattr(factory, "get_tool_name", lambda t: "tool-x")

    cfg = factory.AgentFactoryConfig(hooks=[DummyHook()], base_trace_attributes={"k": "v"})
    make_agent = factory.init_agent_factory(cfg)

    agent = make_agent("sub", tools=[])

    assert agent._init_kwargs["load_tools_from_directory"] is True
    # ToolUseIdHook should have been appended if not present
    assert any(isinstance(h, ToolUseIdHook) for h in agent._init_kwargs["hooks"])


def test_agent_factory_respects_existing_load_tools_from_directory(monkeypatch):
    install_fake_tooluseidhook(monkeypatch)
    fake_cm = FakeConfigManager(provider="bedrock")

    monkeypatch.setattr(factory, "get_config_manager", lambda: fake_cm)
    monkeypatch.setattr(factory, "Agent", FakeAgent)
    monkeypatch.setattr(factory, "create_strands_model", lambda provider, model_id, _: ("MODEL", provider, model_id))
    monkeypatch.setattr(factory, "get_shared_conversation_manager", lambda: object())
    monkeypatch.setattr(factory, "get_capabilities", lambda provider, model_id: FakeCaps(supports_reasoning=False))
    monkeypatch.setattr(factory, "_resolve_prompt_token_limit", lambda provider, model_id: 123)

    cfg = factory.AgentFactoryConfig()
    make_agent = factory.init_agent_factory(cfg)

    agent = make_agent("sub", load_tools_from_directory=False)
    assert agent._init_kwargs["load_tools_from_directory"] is False


def test_agent_factory_provider_override_to_ollama(monkeypatch):
    install_fake_tooluseidhook(monkeypatch)
    fake_cm = FakeConfigManager(provider="bedrock")

    monkeypatch.setattr(factory, "get_config_manager", lambda: fake_cm)
    monkeypatch.setattr(factory, "Agent", FakeAgent)

    seen = {}

    def fake_create(provider, model_id, purpose):
        seen["provider"] = provider
        seen["model_id"] = model_id
        return ("MODEL", provider, model_id)

    monkeypatch.setattr(factory, "create_strands_model", fake_create)
    monkeypatch.setattr(factory, "get_shared_conversation_manager", lambda: object())
    monkeypatch.setattr(factory, "get_capabilities", lambda provider, model_id: FakeCaps(supports_reasoning=False))
    monkeypatch.setattr(factory, "_resolve_prompt_token_limit", lambda provider, model_id: 1)

    cfg = factory.AgentFactoryConfig()
    make_agent = factory.init_agent_factory(cfg)

    make_agent("sub", model_spec={"provider": "ollama", "model_settings": {"model_id": "llama3"}})

    assert seen["provider"] == "ollama"
    assert seen["model_id"] == "llama3"


def test_agent_factory_swarm_model_fallback_when_create_strands_model_fails(monkeypatch):
    install_fake_tooluseidhook(monkeypatch)
    fake_cm = FakeConfigManager(provider="bedrock", swarm_model_id="swarm-bad", main_model_id="main-good")

    monkeypatch.setattr(factory, "get_config_manager", lambda: fake_cm)
    monkeypatch.setattr(factory, "Agent", FakeAgent)
    monkeypatch.setattr(factory, "get_shared_conversation_manager", lambda: object())
    monkeypatch.setattr(factory, "get_capabilities", lambda provider, model_id: FakeCaps(supports_reasoning=False))
    monkeypatch.setattr(factory, "_resolve_prompt_token_limit", lambda provider, model_id: 1)

    calls = []

    def fake_create(provider, model_id, purpose):
        calls.append((provider, model_id, purpose))
        # fail first attempt, succeed second
        if len(calls) == 1:
            raise RuntimeError("boom")
        return ("MODEL", provider, model_id)

    monkeypatch.setattr(factory, "create_strands_model", fake_create)

    cfg = factory.AgentFactoryConfig()
    make_agent = factory.init_agent_factory(cfg)

    agent = make_agent("sub")

    assert calls[0][0] == "bedrock"
    assert calls[1][0] == "bedrock"  # fallback uses config_manager.get_provider() again
    assert calls[1][1].endswith("main-good")  # provider:main-model-id
    assert agent._init_kwargs["model"][0] == "MODEL"


def test_agent_factory_allow_reasoning_content_true(monkeypatch):
    install_fake_tooluseidhook(monkeypatch)
    fake_cm = FakeConfigManager(provider="bedrock")

    monkeypatch.setattr(factory, "get_config_manager", lambda: fake_cm)
    monkeypatch.setattr(factory, "Agent", FakeAgent)
    monkeypatch.setattr(factory, "create_strands_model", lambda provider, model_id, _: ("MODEL", provider, model_id))
    monkeypatch.setattr(factory, "get_shared_conversation_manager", lambda: object())
    monkeypatch.setattr(factory, "get_capabilities", lambda provider, model_id: FakeCaps(supports_reasoning=True))
    monkeypatch.setattr(factory, "_resolve_prompt_token_limit", lambda provider, model_id: 1)

    cfg = factory.AgentFactoryConfig()
    make_agent = factory.init_agent_factory(cfg)

    agent = make_agent("sub")
    assert getattr(agent, "_allow_reasoning_content") is True


def test_agent_factory_allow_reasoning_content_false_on_exception(monkeypatch):
    install_fake_tooluseidhook(monkeypatch)
    fake_cm = FakeConfigManager(provider="bedrock")

    monkeypatch.setattr(factory, "get_config_manager", lambda: fake_cm)
    monkeypatch.setattr(factory, "Agent", FakeAgent)
    monkeypatch.setattr(factory, "create_strands_model", lambda provider, model_id, _: ("MODEL", provider, model_id))
    monkeypatch.setattr(factory, "get_shared_conversation_manager", lambda: object())

    def boom(*args, **kwargs):
        raise RuntimeError("nope")

    monkeypatch.setattr(factory, "get_capabilities", boom)
    monkeypatch.setattr(factory, "_resolve_prompt_token_limit", lambda provider, model_id: 1)

    cfg = factory.AgentFactoryConfig()
    make_agent = factory.init_agent_factory(cfg)

    agent = make_agent("sub")
    assert getattr(agent, "_allow_reasoning_content") is False


def test_agent_factory_trace_attributes_include_tools_and_names(monkeypatch):
    install_fake_tooluseidhook(monkeypatch)
    fake_cm = FakeConfigManager(provider="bedrock")

    monkeypatch.setattr(factory, "get_config_manager", lambda: fake_cm)
    monkeypatch.setattr(factory, "Agent", FakeAgent)
    monkeypatch.setattr(factory, "create_strands_model", lambda provider, model_id, _: ("MODEL", provider, model_id))
    monkeypatch.setattr(factory, "get_shared_conversation_manager", lambda: object())
    monkeypatch.setattr(factory, "get_capabilities", lambda provider, model_id: FakeCaps(supports_reasoning=False))
    monkeypatch.setattr(factory, "_resolve_prompt_token_limit", lambda provider, model_id: 1)

    monkeypatch.setattr(factory, "get_tool_name", lambda t: f"name:{t}")

    cfg = factory.AgentFactoryConfig(base_trace_attributes={"base": 1})
    make_agent = factory.init_agent_factory(cfg)

    agent = make_agent("sub", agent_type="TypeA", tools=["t1", "t2", "t3"])
    ta = agent._init_kwargs["trace_attributes"]

    assert ta["base"] == 1
    assert ta["langfuse.agent.type"] == "TypeA"
    assert ta["tools.available"] == 3
    assert ta["tools.names"] == ["name:t1", "name:t2", "name:t3"]


def test_agent_factory_sets_prompt_token_limit_only_when_truthy(monkeypatch):
    """
    Documents current behavior in factory.py:
        if prompt_token_limit: setattr(...)
    So a 0 limit will NOT be set.
    """
    install_fake_tooluseidhook(monkeypatch)
    fake_cm = FakeConfigManager(provider="bedrock")

    monkeypatch.setattr(factory, "get_config_manager", lambda: fake_cm)
    monkeypatch.setattr(factory, "Agent", FakeAgent)
    monkeypatch.setattr(factory, "create_strands_model", lambda provider, model_id, _: ("MODEL", provider, model_id))
    monkeypatch.setattr(factory, "get_shared_conversation_manager", lambda: object())
    monkeypatch.setattr(factory, "get_capabilities", lambda provider, model_id: FakeCaps(supports_reasoning=False))
    monkeypatch.setattr(factory, "_resolve_prompt_token_limit", lambda provider, model_id: 0)

    cfg = factory.AgentFactoryConfig()
    make_agent = factory.init_agent_factory(cfg)

    agent = make_agent("sub")
    assert not hasattr(agent, "_prompt_token_limit")


# -------------------------
# ToolRegistry.register_tool monkey-patch tests
# -------------------------


class SimpleCallableTool:
    def __call__(self, *args, **kwargs):
        return "ok"


def test_toolregistry_register_tool_calls_agent_factory_wrapper(monkeypatch):
    ToolRegistry = install_fake_toolregistry(monkeypatch)

    called = {"count": 0, "tool": None}

    def spy_wrapper(tool_obj, *a, **k):
        called["count"] += 1
        called["tool"] = tool_obj
        return tool_obj

    monkeypatch.setattr(factory, "agent_factory_wrapper", spy_wrapper)

    # Apply patch and register
    factory.patch_toolregistry_register_tool()
    reg = ToolRegistry()

    t = object()
    out = reg.register_tool(t)

    assert out is t
    assert called["count"] == 1
    assert called["tool"] is t


def test_toolregistry_register_tool_noop_when_not_callable(monkeypatch):
    ToolRegistry = install_fake_toolregistry(monkeypatch)

    # Use real wrapper behavior, but force an agent_factory via a delegating spy
    original = factory.agent_factory_wrapper

    def delegated(tool_obj, *a, **k):
        return original(tool_obj)

    monkeypatch.setattr(factory, "agent_factory_wrapper", delegated)

    factory.patch_toolregistry_register_tool()
    reg = ToolRegistry()

    tool = object()
    out = reg.register_tool(tool)
    assert out is tool


def test_toolregistry_register_tool_noop_when_no__tool_func(monkeypatch):
    ToolRegistry = install_fake_toolregistry(monkeypatch)

    original = factory.agent_factory_wrapper

    def delegated(tool_obj, *a, **k):
        return original(tool_obj)

    monkeypatch.setattr(factory, "agent_factory_wrapper", delegated)

    factory.patch_toolregistry_register_tool()
    reg = ToolRegistry()

    tool = SimpleCallableTool()
    out = reg.register_tool(tool)
    assert out is tool


def test_toolregistry_register_tool_noop_when_signature_lacks_agent_factory(monkeypatch):
    ToolRegistry = install_fake_toolregistry(monkeypatch)

    original = factory.agent_factory_wrapper

    def delegated(tool_obj, *a, **k):
        return original(tool_obj)

    monkeypatch.setattr(factory, "agent_factory_wrapper", delegated)

    def f(x, y):
        return (x, y)

    tool = strands.tool(f)

    factory.patch_toolregistry_register_tool()
    reg = ToolRegistry()

    out = reg.register_tool(tool)
    assert out is tool
    assert tool._tool_func is f


def test_toolregistry_register_tool_wraps_and_removes_schema_agent_factory(monkeypatch):
    ToolRegistry = install_fake_toolregistry(monkeypatch)
    factory.init_agent_factory(AgentFactoryConfig())

    def f(x):
        agent_factory = getattr(f, "agent_factory", None)
        assert agent_factory is not None
        return (x, agent_factory)

    tool = strands.tool(f)

    reg = ToolRegistry()

    out = reg.register_tool(tool)
    assert out is tool

    # _tool_func should now be partially applied with agent_factory
    res = tool("hello")
    assert res[0] == "hello"
    assert callable(res[1])
