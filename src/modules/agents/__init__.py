"""Agents module for Cyber-AutoAgent."""

from modules.agents.cyber_autoagent import check_existing_memories, create_agent
from modules.agents.report_agent import ReportAgent, ReportGenerator
from modules.agents.patches import patch_model_class_tool_use_id

from strands.models import BedrockModel
from strands.models.litellm import LiteLLMModel
from strands.models.ollama import OllamaModel
from strands.models.gemini import GeminiModel

__all__ = ["create_agent", "check_existing_memories", "ReportAgent", "ReportGenerator"]

patch_model_class_tool_use_id(BedrockModel)
patch_model_class_tool_use_id(LiteLLMModel)
patch_model_class_tool_use_id(OllamaModel)
patch_model_class_tool_use_id(GeminiModel)
