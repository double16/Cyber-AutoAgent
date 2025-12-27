#!/usr/bin/env python3
"""
Model creation factory for all providers.

This module contains all model instantiation logic for Bedrock, Ollama, and LiteLLM.
Model creation is a configuration concern because it involves reading configuration,
applying provider-specific settings, and managing credentials.
"""
import logging
import os
from typing import Any, Dict, List, Optional, Tuple

import ollama

from strands.models import BedrockModel, Model
from strands.models.litellm import LiteLLMModel
from strands.models.ollama import OllamaModel
from strands.models.gemini import GeminiModel

from langchain_aws import ChatBedrock
from langchain_ollama import ChatOllama
from langchain_litellm import ChatLiteLLM
from langchain_google_genai import ChatGoogleGenerativeAI

from modules.config.providers import get_ollama_host
from modules.config.providers.ollama_config import get_ollama_timeout
from modules.config.system import EnvironmentReader
from modules.config.system.logger import get_logger
from modules.config.models.capabilities import (
    get_model_input_limit,
    get_provider_default_limit,
)
from modules.handlers.utils import print_status

from google.genai import types

logger = get_logger("Config.ModelFactory")

PROMPT_TOKEN_FALLBACK_LIMIT = 0
try:
    PROMPT_TOKEN_FALLBACK_LIMIT = int(os.getenv("CYBER_CONTEXT_LIMIT", "0"))
except ValueError:
    pass

def _get_config_manager():
    """Lazy import to avoid circular dependency."""
    from modules.config.manager import get_config_manager
    return get_config_manager()


# === Helper Functions ===


def _split_model_prefix(model_id: str) -> Tuple[str, str]:
    """Split model ID into provider prefix and remainder.

    Args:
        model_id: Full model ID (e.g., "bedrock/claude-3", "openai/gpt-4")

    Returns:
        Tuple of (prefix, remainder). Returns ("", model_id) if no prefix found.
    """
    if not isinstance(model_id, str):
        return "", ""
    if "/" in model_id:
        prefix, remainder = model_id.split("/", 1)
        return prefix.lower(), remainder
    return "", model_id


def _get_prompt_limit_from_model(model_id: Optional[str]) -> Optional[int]:
    """Get INPUT token limit (context window) from LiteLLM registry.

    Tries multiple forms of the model ID to find the limit in LiteLLM's database.

    Args:
        model_id: Model identifier

    Returns:
        INPUT token limit or None if not found
    """
    if not model_id:
        return None
    try:
        import litellm

        prefix, remainder = _split_model_prefix(model_id)
        candidates: List[str] = []
        # Common forms to try with LiteLLM's registry
        if remainder:
            candidates.append(remainder)  # e.g. openrouter/polaris-alpha
            # Also try last segment, e.g. polaris-alpha
            if "/" in remainder:
                candidates.append(remainder.split("/", 1)[-1])
        # Always include the full id as a last resort (e.g. openrouter/openrouter/polaris-alpha)
        candidates.append(model_id)

        for cand in candidates:
            limit: Optional[int] = None
            try:
                # Try get_context_window first (most accurate if available)
                get_cw = getattr(litellm, "get_context_window", None)
                if callable(get_cw):
                    cw = get_cw(cand)
                    if isinstance(cw, (int, float)) and int(cw) > 0:
                        limit = int(cw)
                # Check model_cost registry for max_input_tokens (INPUT limit, not output)
                # This must come BEFORE get_max_tokens because get_max_tokens returns OUTPUT limits
                if not limit:
                    model_cost = getattr(litellm, "model_cost", None)
                    if isinstance(model_cost, dict) and cand in model_cost:
                        info = model_cost.get(cand) or {}
                        # Prioritize max_input_tokens (correct input limit)
                        input_limit = info.get("max_input_tokens")
                        if (
                            isinstance(input_limit, (int, float))
                            and int(input_limit) > 0
                        ):
                            limit = int(input_limit)
                            logger.debug(
                                "Using max_input_tokens=%d for '%s' (not max_tokens which is output limit)",
                                limit,
                                cand,
                            )
                        # Fallback to context_window or max_tokens if max_input_tokens unavailable
                        elif not limit:
                            for key in ("context_window", "max_tokens"):
                                v = info.get(key)
                                if isinstance(v, (int, float)) and int(v) > 0:
                                    limit = int(v)
                                    break
                # Last resort: get_max_tokens (often returns OUTPUT limit, less reliable)
                if not limit:
                    get_mt = getattr(litellm, "get_max_tokens", None)
                    if callable(get_mt):
                        mt = get_mt(cand)
                        if isinstance(mt, (int, float)) and int(mt) > 0:
                            limit = int(mt)
                            logger.debug(
                                "Using get_max_tokens=%d for '%s' (may be output limit, verify with CYBER_CONTEXT_LIMIT)",
                                limit,
                                cand,
                            )
                if isinstance(limit, int) and limit > 0:
                    logger.info(
                        "Resolved prompt limit %d via LiteLLM for model '%s' (candidate '%s')",
                        limit,
                        model_id,
                        cand,
                    )
                    return limit
            except Exception:
                # Try next candidate
                continue
    except Exception:
        logger.debug(
            "Unable to resolve prompt token limit for %s", model_id, exc_info=True
        )
    return None


def _resolve_prompt_token_limit(
    provider: str, server_config: Any, model_id: Optional[str]
) -> Optional[int]:
    """
    Resolve INPUT token limit (context window capacity) for the model.

    Priority order:
    1. CYBER_PROMPT_LIMIT_FORCE - Explicit override
    2. Static model registry - Known models with verified limits
    3. LiteLLM max_input_tokens - Auto-detection from registry
    4. CYBER_CONTEXT_LIMIT - Explicit context limit (fallback)
    5. Provider defaults - Conservative last resort

    Args:
        provider: Provider name ("bedrock", "ollama", "litellm", "gemini")
        server_config: Server configuration object
        model_id: Model identifier

    Returns:
        INPUT limit (for conversation history), NOT output limit (for generation)
    """
    # Priority 1: Explicit override
    try:
        forced = os.getenv("CYBER_PROMPT_LIMIT_FORCE")
        if forced is not None:
            fv = int(forced)
            if fv > 0:
                logger.info(
                    "Using CYBER_PROMPT_LIMIT_FORCE=%d for model %s", fv, model_id
                )
                return fv
    except Exception:
        pass

    # Priority 2: Static model registry (known models with verified limits)
    limit = get_model_input_limit(model_id) if model_id else None
    if limit:
        logger.info(
            "Using static registry input limit=%d for model %s", limit, model_id
        )
        return limit

    # Priority 3: Ollama metadata
    if provider == "ollama" and model_id:
        env_reader = EnvironmentReader()
        ollama_client = ollama.Client(host=get_ollama_host(env_reader), timeout=get_ollama_timeout(env_reader))

        try:
            show_response = ollama_client.show(model=model_id)
            if show_response.parameters:
                ollama_parameters = dict()
                for line in show_response.parameters.splitlines(keepends=False):
                    k, v = line.split(sep=None, maxsplit=1)
                    ollama_parameters[k] = v
                if "num_ctx" in ollama_parameters:
                    return int(ollama_parameters["num_ctx"])

        except Exception as e:
            logger.warning(
                f"OllamaError: Error getting model info for {model_id}."
            )

    # Priority 4: LiteLLM automatic detection (check max_input_tokens)
    if provider == "litellm" and model_id:
        limit = _get_prompt_limit_from_model(model_id)
        if limit:
            logger.info(
                "Using LiteLLM detected input limit=%d for model %s", limit, model_id
            )
            return limit

    # Priority 5: CYBER_CONTEXT_LIMIT (explicit context limit config)
    if PROMPT_TOKEN_FALLBACK_LIMIT > 0:
        logger.info(
            "Using CYBER_CONTEXT_LIMIT=%d as fallback for model %s",
            PROMPT_TOKEN_FALLBACK_LIMIT,
            model_id,
        )
        return PROMPT_TOKEN_FALLBACK_LIMIT

    # Priority 6: Provider-specific conservative defaults
    provider_default = get_provider_default_limit(provider)
    if provider_default:
        logger.warning(
            "Using conservative provider default limit=%d for %s (model %s). "
            "Consider setting CYBER_CONTEXT_LIMIT for accurate limit.",
            provider_default,
            provider,
            model_id,
        )
        return provider_default

    # No limit could be determined - warn and return None
    logger.warning(
        "Could not resolve input token limit for provider=%s model=%s. "
        "Set CYBER_CONTEXT_LIMIT or CYBER_PROMPT_LIMIT_FORCE to specify limit.",
        provider,
        model_id,
    )
    return None


def _parse_context_window_fallbacks() -> Optional[List[Dict[str, List[str]]]]:
    """Parse context window fallbacks from environment or configuration.

    Returns:
        List of fallback mappings or None if not configured
    """

    def _parse_spec(spec: str) -> Optional[List[Dict[str, List[str]]]]:
        fallbacks: List[Dict[str, List[str]]] = []
        for clause in spec.split(";"):
            clause = clause.strip()
            if not clause or ":" not in clause:
                continue
            model, targets = clause.split(":", 1)
            target_list = [
                target.strip() for target in targets.split(",") if target.strip()
            ]
            model_name = model.strip()
            if not model_name or not target_list:
                continue
            fallbacks.append({model_name: target_list})
        return fallbacks or None

    env_spec = os.getenv("CYBER_CONTEXT_WINDOW_FALLBACKS", "").strip()
    if env_spec:
        parsed = _parse_spec(env_spec)
        if parsed:
            return parsed
    try:
        config_manager = _get_config_manager()
        config_fallbacks = (
            config_manager.get_context_window_fallbacks("litellm") or []
        )
        if config_fallbacks:
            copied: List[Dict[str, List[str]]] = []
            for mapping in config_fallbacks:
                for model_name, targets in mapping.items():
                    copied.append({model_name: list(targets)})
            return copied or None
    except Exception:
        logger.debug("No configured context_window_fallbacks available", exc_info=True)
    return None


def _apply_context_window_fallbacks(client_args: Dict[str, Any]) -> None:
    """Attach context window fallbacks to LiteLLM if configured.

    Args:
        client_args: Client arguments dictionary (modified in-place)
    """
    fallbacks = _parse_context_window_fallbacks()
    if not fallbacks:
        return
    client_args.setdefault("context_window_fallbacks", fallbacks)
    try:
        import litellm

        litellm.context_window_fallbacks = fallbacks
    except Exception:
        logger.debug(
            "Unable to apply context_window_fallbacks to LiteLLM", exc_info=True
        )


def _handle_model_creation_error(provider: str, error: Exception) -> None:
    """Provide helpful error messages based on provider type.

    Args:
        provider: Provider name ("bedrock", "ollama", "litellm")
        error: Exception that occurred
    """
    error_messages = {
        "ollama": [
            "Ensure Ollama is installed: https://ollama.ai",
            "Start Ollama: ollama serve",
            "Pull required models (see config.py file)",
            "Set OLLAMA_HOST=http://<IP>:11434",
        ],
        "bedrock": [
            "Check AWS credentials and region settings",
            "Verify AWS_ACCESS_KEY_ID or AWS_BEARER_TOKEN_BEDROCK",
            "Ensure Bedrock access is enabled in your AWS account",
        ],
        "gemini": [
            "Verify GEMINI_API_KEY or GOOGLE_API_KEY",
        ],
        "litellm": [
            "Check environment variables for your model provider",
            "For Bedrock: AWS_ACCESS_KEY_ID (bearer tokens not supported)",
            "For OpenAI: OPENAI_API_KEY",
            "For Anthropic: ANTHROPIC_API_KEY",
            "For OpenRouter: OPENROUTER_API_KEY",
        ],
    }

    print_status(f"{provider.title()} model creation failed: {error}", "ERROR")
    if provider in error_messages:
        print_status("Troubleshooting steps:", "WARNING")
        for i, step in enumerate(error_messages[provider], 1):
            print_status(f"    {i}. {step}", "INFO")


# === Model Creation Functions ===


def create_bedrock_model(
    model_id: str,
    region_name: str,
    provider: str = "bedrock",
    **kwargs,
) -> BedrockModel:
    """Create AWS Bedrock model instance using centralized configuration.

    Args:
        model_id: Bedrock model identifier
        region_name: AWS region
        provider: Provider name (default: "bedrock")
        **kwargs: Additional arguments (e.g., effort, additional_request_fields)

    Returns:
        Configured BedrockModel instance

    Raises:
        Exception: If model creation fails
    """
    from botocore.config import Config as BotocoreConfig

    # Get centralized configuration
    config_manager = _get_config_manager()

    # Configure boto3 client with robust retry and timeout settings
    # This prevents ReadTimeoutError during long-running operations
    boto_config = BotocoreConfig(
        region_name=region_name,
        retries={"max_attempts": 10, "mode": "adaptive"},
        read_timeout=1200,  # 20 minutes
        connect_timeout=1200,  # 20 minutes
        max_pool_connections=100,
    )

    # Handle beta features (effort, etc.) passed via kwargs
    additional_fields = kwargs.get("additional_request_fields", {})
    effort = kwargs.get("effort")

    if effort:
        additional_fields.setdefault("anthropic_beta", [])
        if "effort-2025-11-24" not in additional_fields["anthropic_beta"]:
            additional_fields["anthropic_beta"].append("effort-2025-11-24")
        additional_fields.setdefault("output_config", {})
        additional_fields["output_config"]["effort"] = effort

    if config_manager.is_thinking_model(model_id):
        # Use thinking model configuration
        config = config_manager.get_thinking_model_config(model_id, region_name)

        # Merge with config's additional_request_fields if present
        if "additional_request_fields" in config:
            for k, v in config["additional_request_fields"].items():
                if k == "anthropic_beta" and "anthropic_beta" in additional_fields:
                    additional_fields[k] = list(set(additional_fields[k] + v))
                elif k not in additional_fields:
                    additional_fields[k] = v

        model = BedrockModel(
            model_id=config["model_id"],
            region_name=config["region_name"],
            temperature=config["temperature"],
            max_tokens=config["max_tokens"],
            additional_request_fields=additional_fields if additional_fields else None,
            boto_client_config=boto_config,
        )

        return model
    
    # Standard model configuration
    config = config_manager.get_standard_model_config(model_id, region_name, provider)

    # Merge with config's additional_request_fields if present
    if "additional_request_fields" in config:
        for k, v in config["additional_request_fields"].items():
            if k == "anthropic_beta" and "anthropic_beta" in additional_fields:
                additional_fields[k] = list(set(additional_fields[k] + v))
            elif k not in additional_fields:
                additional_fields[k] = v
    
    # Select parameter source by model role (primary vs swarm)
    try:
        server_config = config_manager.get_server_config(provider)
        llm_temp = server_config.llm.temperature
        llm_max = server_config.llm.max_tokens
        role = "primary"
        swarm_env = config_manager.getenv("CYBER_AGENT_SWARM_MODEL")
        is_swarm = False
        if swarm_env and model_id and swarm_env == model_id:
            is_swarm = True
        elif (
            server_config.swarm
            and server_config.swarm.llm
            and server_config.swarm.llm.model_id == model_id
            and server_config.swarm.llm.model_id != server_config.llm.model_id
        ):
            is_swarm = True
        if is_swarm:
            llm_temp = server_config.swarm.llm.temperature
            # Use swarm model's max_tokens (calculated by ConfigManager from models.dev)
            # This respects per-model limits - different models have different constraints
            llm_max = server_config.swarm.llm.max_tokens

            # Defensive: Ensure valid max_tokens
            if not isinstance(llm_max, int) or llm_max <= 0:
                logger.warning(
                    "Invalid swarm max_tokens=%s for model %s, falling back to 4096",
                    llm_max,
                    config.get("model_id"),
                )
                llm_max = 4096

            role = "swarm"
    except Exception:
        # Fallback to standard config if any issue arises
        llm_temp = config.get("temperature", 0.95)
        llm_max = config.get("max_tokens", 4096)
        role = "unknown"

    # Observability: one-liner
    try:
        logger.info(
            "Model build: role=%s provider=%s model=%s max_tokens=%s effort=%s",
            role,
            provider,
            config.get("model_id"),
            llm_max,
            effort or "none",
        )
    except Exception:
        pass

    # If top_p is in config, add it to additional_fields
    if config.get("top_p") is not None:
        # BedrockModel doesn't support top_p in init directly in all versions, 
        # but usually it's passed via model_kwargs if using LangChain, 
        # or we might need to check Strands BedrockModel signature.
        # Assuming Strands BedrockModel handles it via kwargs or we ignore it for now as per previous code.
        pass


    model = BedrockModel(
        model_id=config["model_id"],
        region_name=config["region_name"],
        temperature=llm_temp,
        max_tokens=llm_max,
        additional_request_fields=additional_fields if additional_fields else None,
        boto_client_config=boto_config,
    )
    
    return model




def create_ollama_model(
    model_id: str,
    provider: str = "ollama",
) -> OllamaModel:
    """Create Ollama model instance using centralized configuration.

    Args:
        model_id: Ollama model identifier
        provider: Provider name (default: "ollama")

    Returns:
        Configured OllamaModel instance

    Raises:
        Exception: If model creation fails
    """
    # Get centralized configuration
    config_manager = _get_config_manager()
    config = config_manager.get_local_model_config(model_id, provider)

    # Select parameter source by model role (primary vs swarm)
    try:
        server_config = config_manager.get_server_config(provider)
        llm_temp = server_config.llm.temperature
        llm_max = server_config.llm.max_tokens
        role = "primary"
        swarm_env = config_manager.getenv("CYBER_AGENT_SWARM_MODEL")
        is_swarm = False
        if swarm_env and model_id and swarm_env == model_id:
            is_swarm = True
        elif (
            server_config.swarm
            and server_config.swarm.llm
            and server_config.swarm.llm.model_id == model_id
            and server_config.swarm.llm.model_id != server_config.llm.model_id
        ):
            is_swarm = True
        if is_swarm:
            llm_temp = server_config.swarm.llm.temperature
            # Use swarm model's max_tokens (calculated by ConfigManager from models.dev)
            # This respects per-model limits - different models have different constraints
            llm_max = server_config.swarm.llm.max_tokens

            # Defensive: Ensure valid max_tokens
            if not isinstance(llm_max, int) or llm_max <= 0:
                logger.warning(
                    "Invalid swarm max_tokens=%s for model %s, falling back to 4096",
                    llm_max,
                    config.get("model_id"),
                )
                llm_max = 4096

            role = "swarm"
    except Exception:
        llm_temp = config.get("temperature", 0.95)
        llm_max = config.get("max_tokens", 4096)
        role = "unknown"

    # Observability: one-liner
    try:
        logger.info(
            "Model build: role=%s provider=ollama model=%s max_tokens=%s",
            role,
            config.get("model_id"),
            llm_max,
        )
    except Exception:
        pass

    return OllamaModel(
        host=config["host"],
        model_id=config["model_id"],
        temperature=llm_temp,
        max_tokens=llm_max,
        ollama_client_args={
            "timeout": config["timeout"],
        },
    )


def create_litellm_model(
    model_id: str,
    region_name: str,
    provider: str = "litellm",
) -> LiteLLMModel:
    """Create LiteLLM model instance for universal provider access.

    Args:
        model_id: LiteLLM model identifier (e.g., "bedrock/...", "openai/...")
        region_name: AWS region (for Bedrock/SageMaker models)
        provider: Provider name (default: "litellm")

    Returns:
        Configured LiteLLMModel instance

    Raises:
        Exception: If model creation fails
    """
    # Get centralized configuration
    config_manager = _get_config_manager()

    # Get standard configuration (LiteLLM doesn't have special thinking mode handling)
    config = config_manager.get_standard_model_config(model_id, region_name, provider)

    # Prepare client args based on model prefix
    client_args: Dict[str, Any] = {}

    # Configure AWS Bedrock models via LiteLLM
    if model_id.startswith(("bedrock/", "sagemaker/")):
        client_args["aws_region_name"] = region_name
        aws_profile = config_manager.getenv("AWS_PROFILE") or config_manager.getenv(
            "AWS_DEFAULT_PROFILE"
        )
        if aws_profile:
            client_args["aws_profile_name"] = aws_profile
        role_arn = config_manager.getenv("AWS_ROLE_ARN")
        if role_arn:
            client_args["aws_role_name"] = role_arn
        session_name = config_manager.getenv("AWS_ROLE_SESSION_NAME")
        if session_name:
            client_args["aws_session_name"] = session_name
        sts_endpoint = config_manager.getenv("AWS_STS_ENDPOINT")
        if sts_endpoint:
            client_args["aws_sts_endpoint"] = sts_endpoint
        external_id = config_manager.getenv("AWS_EXTERNAL_ID")
        if external_id:
            client_args["aws_external_id"] = external_id

    if model_id.startswith("sagemaker/"):
        sagemaker_base_url = config_manager.getenv("SAGEMAKER_BASE_URL")
        if sagemaker_base_url:
            client_args["sagemaker_base_url"] = sagemaker_base_url

    # Build params dict with optional reasoning parameters
    # Select parameter source by model role (primary vs swarm)
    try:
        server_config = config_manager.get_server_config(provider)
        llm_temp = server_config.llm.temperature
        llm_max = server_config.llm.max_tokens
        role = "primary"
        swarm_env = config_manager.getenv("CYBER_AGENT_SWARM_MODEL")
        is_swarm = False
        if swarm_env and model_id and swarm_env == model_id:
            is_swarm = True
        elif (
            server_config.swarm
            and server_config.swarm.llm
            and server_config.swarm.llm.model_id == model_id
            and server_config.swarm.llm.model_id != server_config.llm.model_id
        ):
            is_swarm = True
        if is_swarm:
            llm_temp = server_config.swarm.llm.temperature
            # Use swarm model's max_tokens (calculated by ConfigManager from models.dev)
            # This respects per-model limits - different models have different constraints
            llm_max = server_config.swarm.llm.max_tokens

            # Defensive: Ensure valid max_tokens
            if not isinstance(llm_max, int) or llm_max <= 0:
                logger.warning(
                    "Invalid swarm max_tokens=%s for model %s, falling back to 4096",
                    llm_max,
                    config.get("model_id"),
                )
                llm_max = 4096

            role = "swarm"
    except Exception:
        llm_temp = config.get("temperature", 0.95)
        llm_max = config.get("max_tokens", 4096)
        role = "unknown"

    # LiteLLM best-effort output clamp (no new envs, best-effort only)
    try:
        import litellm  # type: ignore

        base = config.get("model_id") or model_id
        if isinstance(base, str) and "/" in base:
            base = base.split("/", 1)[1]
        model_cap = litellm.get_max_tokens(base)  # may return None for unknown models
        if (
            isinstance(model_cap, (int, float))
            and int(model_cap) > 0
            and llm_max > int(model_cap)
        ):
            logger.info(
                "LiteLLM cap: reducing max_tokens from %s to %s for model=%s",
                llm_max,
                int(model_cap),
                config.get("model_id"),
            )
            llm_max = int(model_cap)
    except Exception:
        pass

    # Observability: one-liner
    try:
        logger.info(
            "Model build: role=%s provider=litellm model=%s max_tokens=%s",
            role,
            config.get("model_id"),
            llm_max,
        )
    except Exception:
        pass

    params: Dict[str, Any] = {
        "temperature": llm_temp,
        "max_tokens": llm_max,
    }

    # Only include top_p if present in config (avoid provider conflicts)
    if "top_p" in config:
        params["top_p"] = config["top_p"]

    # Add request timeout and retries for robustness (env-overridable)
    timeout_secs = config_manager.getenv_int("LITELLM_TIMEOUT", 600)
    num_retries = config_manager.getenv_int("LITELLM_NUM_RETRIES", 3)
    if timeout_secs > 0:
        client_args["timeout"] = timeout_secs
    if num_retries >= 0:
        client_args["num_retries"] = num_retries
        client_args["max_retries"] = num_retries

    # Reasoning parameters for reasoning-capable models (o1, o3, o4, gpt-5)
    reasoning_effort = config_manager.getenv("REASONING_EFFORT")
    try:
        from modules.config.models.capabilities import get_capabilities

        caps = get_capabilities(provider, config.get("model_id", ""))
        if reasoning_effort and caps.pass_reasoning_effort:
            params["reasoning_effort"] = reasoning_effort
    except Exception:
        # If capability resolution fails, do not attach the param
        pass

    # Reasoning text verbosity for Azure Responses API models (default: medium)
    reasoning_verbosity = config_manager.getenv("REASONING_VERBOSITY", "medium")
    if reasoning_verbosity and "azure/responses/" in config["model_id"]:
        params["text"] = {
            "format": {"type": "text"},
            "verbosity": reasoning_verbosity,
        }
        logger.info(
            "Set reasoning text verbosity=%s for model %s",
            reasoning_verbosity,
            config["model_id"],
        )

    max_completion_tokens = config_manager.getenv_int("MAX_COMPLETION_TOKENS", 0)
    if max_completion_tokens > 0:
        params["max_completion_tokens"] = max_completion_tokens

    _apply_context_window_fallbacks(client_args)

    return LiteLLMModel(
        client_args=client_args,
        model_id=config["model_id"],
        params=params,
    )


def create_gemini_model(
    model_id: str,
    region_name: str,
    provider: str = "gemini",
) -> GeminiModel:
    """Create native Gemini model instance using Google's genai SDK.

    This avoids LiteLLM's transformation layer and uses Google's native SDK directly,
    which better handles tool calling and turn ordering for agentic workflows.

    Args:
        model_id: Gemini model identifier (e.g., "gemini/gemini-3-pro-preview")
        region_name: Unused for Gemini (kept for interface compatibility)
        provider: Provider name (should be "gemini")

    Returns:
        Configured GeminiModel instance

    Raises:
        Exception: If model creation fails or GEMINI_API_KEY not set
    """
    config_manager = _get_config_manager()

    # Get standard configuration
    config = config_manager.get_standard_model_config(model_id, region_name, provider)

    # Strip gemini/ prefix if present
    clean_model_id = model_id.replace("gemini/", "")

    # Get API key from environment
    api_key = config_manager.getenv("GEMINI_API_KEY") or config_manager.getenv("GOOGLE_API_KEY")
    if not api_key:
        raise ValueError(
            "GEMINI_API_KEY environment variable must be set for native Gemini provider. "
            "Get your API key from https://ai.google.dev/"
        )

    # Prepare client args
    client_args: dict[str, Any] = {
        "api_key": api_key,
    }

    # Build params dict
    params: Dict[str, Any] = {}

    # Temperature from config
    try:
        server_config = config_manager.get_server_config(provider)
        llm_temp = server_config.llm.temperature
        llm_max = server_config.llm.max_tokens
    except Exception:
        llm_temp = config.get("temperature", 0.95)
        llm_max = config.get("max_tokens", 4096)

    params["temperature"] = llm_temp
    params["max_output_tokens"] = llm_max

    logger.info(
        "Creating native GeminiModel: model=%s, temperature=%s, max_tokens=%s",
        clean_model_id,
        llm_temp,
        llm_max,
    )

    client_args["http_options"] = types.HttpOptions(
        retry_options=types.HttpRetryOptions(
            attempts=10,
            exp_base=4.0,
        )
    )

    return GeminiModel(
        client_args=client_args,
        model_id=clean_model_id,
        params=params,
    )


def create_strands_model(provider: Optional[str] = None, model_id: Optional[str] = None) -> Model:
    """ Create model based on provider type """
    agent_logger = logging.getLogger("CyberAutoAgent")

    config_manager = _get_config_manager()
    if not provider:
        provider = config_manager.get_provider()
    if not model_id:
        model_id = config_manager.get_llm_config(provider).model_id

    try:
        if provider == "ollama":
            agent_logger.debug("Configuring OllamaModel")
            model = create_ollama_model(model_id, provider)
            print_status(f"Ollama model initialized: {model_id}", "SUCCESS")
        elif provider == "bedrock":
            agent_logger.debug("Configuring BedrockModel")
            # Check for effort configuration (Opus 4.5 feature)
            effort = os.getenv("BEDROCK_EFFORT")
            model = create_bedrock_model(
                model_id, config_manager.get_default_region(), provider, effort=effort
            )
            print_status(f"Bedrock model initialized: {model_id}", "SUCCESS")
        elif provider == "litellm":
            agent_logger.debug("Configuring LiteLLMModel")
            model = create_litellm_model(
                model_id, config_manager.get_default_region(), provider
            )
            print_status(f"LiteLLM model initialized: {model_id}", "SUCCESS")
        elif provider == "gemini":
            agent_logger.debug("Configuring native GeminiModel")
            model = create_gemini_model(
                model_id, config_manager.get_default_region(), provider
            )
            print_status(f"Native Gemini model initialized: {model_id}", "SUCCESS")
        else:
            raise ValueError(f"Unsupported provider: {provider}")

        return model

    except Exception as e:
        _handle_model_creation_error(provider, e)
        # Re-raise to satisfy tests expecting exception propagation after logging
        raise


def get_model_timeout(model: Optional[Model] = None, default_timeout: Optional[int] = None) -> Optional[int]:
    if model is None:
        return default_timeout

    model_timeout = default_timeout
    if isinstance(model, OllamaModel):
        ollama_model = model
        if "timeout" in ollama_model.client_args:
            model_timeout = float(ollama_model.client_args["timeout"])

    return model_timeout if model_timeout else default_timeout


def configure_model_rate_limits(provider: Optional[str] = None):
    config_manager = _get_config_manager()
    if not provider:
        provider = config_manager.get_provider()

    rate_limit_config = config_manager.get_rate_limit_config(provider)
    if rate_limit_config is None:
        return

    # limiter must be per-provider
    from modules.rate_limit.rate_limit import (
        ThreadSafeRateLimiter,
        patch_model_provider_class,
        patch_langchain_chat_class_generate
    )

    if provider == "ollama":
        limiter = ThreadSafeRateLimiter(rate_limit_config)
        patch_model_provider_class(OllamaModel, limiter)
        patch_langchain_chat_class_generate(ChatOllama, limiter)
    elif provider == "bedrock":
        limiter = ThreadSafeRateLimiter(rate_limit_config)
        patch_model_provider_class(BedrockModel, limiter)
        patch_langchain_chat_class_generate(ChatBedrock, limiter)
    elif provider == "litellm":
        limiter = ThreadSafeRateLimiter(rate_limit_config)
        patch_model_provider_class(LiteLLMModel, limiter)
        patch_langchain_chat_class_generate(ChatLiteLLM, limiter)
    elif provider == "gemini":
        limiter = ThreadSafeRateLimiter(rate_limit_config)
        patch_model_provider_class(GeminiModel, limiter)
        patch_langchain_chat_class_generate(ChatGoogleGenerativeAI, limiter)
    else:
        raise ValueError(f"Unsupported provider: {provider}")
