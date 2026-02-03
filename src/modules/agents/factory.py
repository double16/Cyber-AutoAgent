"""
Provides a factory for creating agents that applies hooks, conversation_manager, and settings that are necessary
for managing context, tool calls, observability, etc.
"""
import functools
import threading
from dataclasses import dataclass
from typing import Callable, List, Any, Dict, Optional

from strands import Agent
from strands.hooks import HookProvider
from strands.agent.conversation_manager import ConversationManager

from modules.config import get_config_manager
from modules.config.models import create_strands_model, get_capabilities
from modules.config.system import get_logger
from modules.handlers.conversation_budget import get_shared_conversation_manager
from modules.config.models.factory import _resolve_prompt_token_limit
from modules.handlers.utils import get_tool_name

logger = get_logger("Agents.CyberAutoAgent")

_SHARED_AGENT_FACTORY: Optional[Callable[..., "Agent"]] = None
_SHARED_AGENT_FACTORY_LOCK = threading.RLock()

# Guard to ensure we only patch ToolRegistry once
_TOOLREGISTRY_REGISTER_TOOL_PATCHED = False


def patch_toolregistry_register_tool() -> None:
    """Monkey-patch strands ToolRegistry.register_tool to inject agent_factory automatically.

    This ensures any tool registered that accepts an `agent_factory` parameter is wrapped via
    `agent_factory_wrapper()` before being registered.
    """
    global _TOOLREGISTRY_REGISTER_TOOL_PATCHED
    if _TOOLREGISTRY_REGISTER_TOOL_PATCHED:
        return

    try:
        from strands.tools.registry import ToolRegistry  # type: ignore
    except Exception as exc:
        logger.debug("Unable to import ToolRegistry for monkey patch: %s", exc)
        return

    original_register_tool = getattr(ToolRegistry, "register_tool", None)
    if not callable(original_register_tool):
        logger.debug("ToolRegistry.register_tool not found or not callable; skipping patch")
        return

    # Avoid double-patching if something else already wrapped it.
    if getattr(original_register_tool, "__cyber_agent_factory_wrapper_patched__", False):
        _TOOLREGISTRY_REGISTER_TOOL_PATCHED = True
        return

    @functools.wraps(original_register_tool)
    def patched_register_tool(self, *args, **kwargs):
        # Common signature: register_tool(self, tool, *...)
        if args:
            tool_obj = args[0]
            tool_obj = agent_factory_wrapper(tool_obj)
            args = (tool_obj,) + args[1:]
        elif "tool" in kwargs:
            kwargs["tool"] = agent_factory_wrapper(kwargs["tool"])
        return original_register_tool(self, *args, **kwargs)

    setattr(patched_register_tool, "__cyber_agent_factory_wrapper_patched__", True)
    setattr(ToolRegistry, "register_tool", patched_register_tool)
    _TOOLREGISTRY_REGISTER_TOOL_PATCHED = True
    logger.debug("Patched ToolRegistry.register_tool to call agent_factory_wrapper")


@dataclass
class AgentFactoryConfig:
    hooks: Optional[List[HookProvider]] = None
    callback_handler: Optional[Callable[..., Any]] = None
    conversation_manager: Optional[ConversationManager] = None
    base_trace_attributes: Optional[Dict[str, Any]] = None


def init_agent_factory(config: AgentFactoryConfig) -> Callable[..., "Agent"]:
    """
    Initialize the agent factory passed to tools for creating new Agent instances. The agent factory is stored as
    a shared instance so that calls to strands.tools.ToolRegistry.register_tool(...) can modify tools with an
    `agent_factory` parameter to include the factory.
    :config: factory configuration, which may be changed after this function returns.
    """
    global _SHARED_AGENT_FACTORY_LOCK, _SHARED_AGENT_FACTORY

    config_manager = get_config_manager()

    # Ensure all tools registered after startup get agent_factory injected automatically
    patch_toolregistry_register_tool()

    def agent_factory(
            name: str,
            model_spec: Optional[Dict[str, Any]] = None,
            agent_type: Optional[str] = None,
            **kwargs,
    ) -> "Agent":
        """
        Create a new Agent.
        name: Name of the agent
        model_spec: Model specification. The same shape as the swarm tool model specs.
            "provider" or "model_provider": "bedrock", "litellm", "ollama", "gemini"
            "model_settings":
                "model_id": model ID
                "params": {"temperature": 0.8, ...}
        agent_type: agent type for observability, defaults to agent name
        kwargs: passed to the strands Agent constructor
        :return: shiny new Agent
        """

        assert name

        # prevent circular imports
        from modules.agents.patches import ToolUseIdHook

        model_spec = model_spec or {}
        agent_type = agent_type or name

        kwargs = kwargs.copy()
        if not "load_tools_from_directory" in kwargs:
            kwargs["load_tools_from_directory"] = True

        # Configure model provider
        provider = config_manager.get_provider()
        # only allow agent provider to change to local/ollama model
        # TODO: allow any correctly configured provider (API keys, etc.)
        if model_spec.get("model_provider", model_spec.get("provider", "")) == "ollama":
            provider = "ollama"

        # Configure model settings
        # We default to the swarm model ID for sub-agents
        swarm_model_id = config_manager.get_swarm_model_id(provider)
        model_settings = model_spec.get("model_settings")
        if model_settings and "model_id" in model_settings:
            request_model_id = model_settings["model_id"]
            if request_model_id and "purpose-built-model" not in request_model_id:
                swarm_model_id = request_model_id
        # TODO: accept model parameters such as temperature

        try:
            strands_model = create_strands_model(provider, swarm_model_id, "swarm")
        except Exception as exc:  # fall back to main LLM if swarm override is misconfigured
            provider_from_spec = provider
            model_from_spec = swarm_model_id
            provider = config_manager.get_provider()
            swarm_model_id = config_manager.get_llm_config(provider).model_id
            logger.warning(
                "Swarm model '%s' unavailable for provider '%s' (%s). Falling back to main model '%s'.",
                model_from_spec,
                provider_from_spec,
                exc,
                swarm_model_id,
            )
            strands_model = create_strands_model(provider, swarm_model_id, "swarm")

        try:
            caps = get_capabilities(provider, swarm_model_id)
            allow_reasoning_content = bool(caps.supports_reasoning)
        except Exception:
            allow_reasoning_content = False

        prompt_token_limit = _resolve_prompt_token_limit(
            provider, swarm_model_id
        )

        if config.base_trace_attributes is not None:
            trace_attributes_tool_names = []
            for tool in kwargs.get("tools", []):
                trace_attributes_tool_names.append(get_tool_name(tool))

            trace_attributes = config.base_trace_attributes | {
                "langfuse.agent.type": agent_type,
                "langfuse.capabilities.swarm": False,
                # Model configuration
                "model.provider": provider,
                "model.id": swarm_model_id,
                "gen_ai.request.model": swarm_model_id,
                # Agent identification
                "agent.name": f"Cyber-{name}",
                "gen_ai.agent.name": f"Cyber-{name}",
                # Tool configuration
                "tools.available": len(trace_attributes_tool_names),
                "tools.names": trace_attributes_tool_names,
            }
        else:
            trace_attributes = None

        agent_hooks = config.hooks.copy() if config.hooks else []
        if "hooks" in kwargs:
            # ToolUseIdHook must be last, so prepend agent specific hooks
            agent_hooks = list(kwargs["hooks"]) + agent_hooks
            kwargs.pop("hooks")
        if not any([isinstance(h, ToolUseIdHook) for h in agent_hooks]):
            # we must have this for providers whose toolUseId is broken
            agent_hooks.append(ToolUseIdHook())

        agent = Agent(
            model=strands_model,
            name=name,
            conversation_manager=config.conversation_manager or get_shared_conversation_manager(),
            callback_handler=config.callback_handler,
            trace_attributes=trace_attributes,
            hooks=agent_hooks,
            **kwargs,
        )

        if prompt_token_limit:
            setattr(agent, "_prompt_token_limit", prompt_token_limit)
        setattr(agent, "_allow_reasoning_content", allow_reasoning_content)

        logger.debug(f"Created agent '{name}'")

        return agent

    with _SHARED_AGENT_FACTORY_LOCK:
        _SHARED_AGENT_FACTORY = agent_factory

    return agent_factory


def agent_factory_wrapper(agent_tool: Callable) -> Callable:
    """
    Optionally wraps a callable if there is a parameter named "agent_factory".
    """
    global _SHARED_AGENT_FACTORY_LOCK, _SHARED_AGENT_FACTORY

    if not callable(agent_tool):
        return agent_tool
    target_func = agent_tool
    if hasattr(agent_tool, "_tool_func"):
        target_func = getattr(agent_tool, "_tool_func")

    with _SHARED_AGENT_FACTORY_LOCK:
        agent_factory = _SHARED_AGENT_FACTORY
    assert agent_factory is not None

    setattr(agent_tool, "agent_factory", agent_factory)
    setattr(target_func, "agent_factory", agent_factory)

    return agent_tool
