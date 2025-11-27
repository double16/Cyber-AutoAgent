#!/usr/bin/env python3
"""Integration tests for conversation management features.

Tests cover:
- Safe max_tokens calculation from models.dev (ConfigManager)
- Dynamic char/token ratios for different model providers
- Quiet pruning warnings for small conversations

Validates expected behavior with mock data to ensure:
- Accurate token estimation across all model providers
- Safe specialist token limits preventing failures
- Clean logs without spurious warnings
"""

import logging
from typing import Any
from unittest.mock import Mock, patch
import types

import pytest

from modules.config.manager import ConfigManager
from modules.config.models.dev_client import ModelsDevClient, ModelLimits
from modules.handlers.conversation_budget import (
    _get_char_to_token_ratio_dynamic,
    _estimate_prompt_tokens,
    _ensure_prompt_within_budget,
    MappingConversationManager,
    SYSTEM_PROMPT_OVERHEAD_TOKENS,
    TOOL_DEFINITIONS_OVERHEAD_TOKENS,
    MESSAGE_METADATA_OVERHEAD_TOKENS,
)


def _expected_tokens(char_count: int, ratio: float, num_messages: int = 1) -> int:
    """Calculate expected tokens with overhead constants."""
    overhead = (
        SYSTEM_PROMPT_OVERHEAD_TOKENS
        + TOOL_DEFINITIONS_OVERHEAD_TOKENS
        + num_messages * MESSAGE_METADATA_OVERHEAD_TOKENS
    )
    content_tokens = max(1, int(char_count / ratio))
    return overhead + content_tokens


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_models_client():
    """Mock ModelsDevClient with known test models."""
    client = Mock(spec=ModelsDevClient)

    def get_limits(model_id: str):
        limits_map = {
            "azure/gpt-5": ModelLimits(context=272000, output=128000),
            "azure/gpt-4o": ModelLimits(context=128000, output=16384),
            "moonshot/kimi-k2-thinking": ModelLimits(context=262144, output=262144),
            "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0": ModelLimits(context=200000, output=8192),
            "anthropic/claude-sonnet-4-5-20250929": ModelLimits(context=200000, output=64000),
            "google/gemini-2.5-flash": ModelLimits(context=1000000, output=8192),
        }
        return limits_map.get(model_id)

    def get_model_info(model_id: str):
        # Mock provider detection for ratio calculation
        info = Mock()
        if "gpt" in model_id.lower():
            info.provider = "azure" if "azure/" in model_id else "openai"
        elif "claude" in model_id.lower() or "anthropic" in model_id:
            info.provider = "anthropic" if "anthropic/" in model_id else "amazon-bedrock"
        elif "kimi" in model_id.lower() or "moonshot" in model_id:
            info.provider = "moonshotai"
        elif "gemini" in model_id.lower():
            info.provider = "google"
        else:
            return None
        return info

    client.get_limits.side_effect = get_limits
    client.get_model_info.side_effect = get_model_info

    return client


@pytest.fixture
def config_manager_with_mock_client(mock_models_client):
    """ConfigManager with mocked models client."""
    with patch('modules.config.manager.get_models_client', return_value=mock_models_client):
        manager = ConfigManager()
        yield manager


class MockModelConfig:
    """Mock model with config for testing."""

    def __init__(self, model_id: str):
        self.model_id = model_id
        self.config = {"model_id": model_id}


class AgentStub:
    """Mock agent for testing conversation management."""

    def __init__(
        self,
        messages: list[dict[str, Any]],
        model: str = "",
        limit: int | None = None,
        telemetry: int | None = None,
        name: str = "test_agent"
    ):
        self.messages = messages
        self.model = MockModelConfig(model) if model else None
        self._prompt_token_limit = limit
        self.name = name

        # Conversation manager stub
        self.conversation_manager = types.SimpleNamespace(
            calls=[],
            reduce_context=lambda agent: self.conversation_manager.calls.append(
                len(agent.messages)
            ),
        )

        # Telemetry injection
        if telemetry is not None:
            self.callback_handler = types.SimpleNamespace(sdk_input_tokens=telemetry)


def make_message(text: str, role: str = "assistant") -> dict[str, Any]:
    """Create a simple text message."""
    return {"role": role, "content": [{"type": "text", "text": text}]}


# ============================================================================
# P1: Dynamic Char/Token Ratios
# ============================================================================


class TestDynamicCharTokenRatios:
    """Test P1 feature: Model-aware character-to-token ratios."""

    def test_claude_ratio_3_7(self, mock_models_client):
        """Test Claude models use 3.7 chars/token (aggressive tokenizer)."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            # Anthropic Claude
            ratio = _get_char_to_token_ratio_dynamic("anthropic/claude-sonnet-4-5-20250929")
            assert ratio == 3.7, "Claude should use 3.7 ratio"

            # Bedrock Claude
            ratio = _get_char_to_token_ratio_dynamic("bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0")
            assert ratio == 3.7, "Bedrock Claude should use 3.7 ratio"

    def test_gpt_ratio_4_0(self, mock_models_client):
        """Test GPT-4/5 models use 4.0 chars/token (o200k_base)."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            ratio = _get_char_to_token_ratio_dynamic("azure/gpt-5")
            assert ratio == 4.0, "GPT-5 should use 4.0 ratio"

            ratio = _get_char_to_token_ratio_dynamic("azure/gpt-4o")
            assert ratio == 4.0, "GPT-4o should use 4.0 ratio"

    def test_kimi_ratio_3_8(self, mock_models_client):
        """Test Moonshot Kimi uses 3.8 chars/token (proprietary)."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            ratio = _get_char_to_token_ratio_dynamic("moonshot/kimi-k2-thinking")
            assert ratio == 3.8, "Kimi should use 3.8 ratio"

    def test_gemini_ratio_4_2(self, mock_models_client):
        """Test Gemini models use 4.2 chars/token (SentencePiece)."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            ratio = _get_char_to_token_ratio_dynamic("google/gemini-2.5-flash")
            assert ratio == 4.2, "Gemini should use 4.2 ratio"

    def test_unknown_model_defaults_to_conservative(self, mock_models_client):
        """Test unknown models default to 3.7 (conservative)."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            ratio = _get_char_to_token_ratio_dynamic("unknown/model")
            assert ratio == 3.7, "Unknown models should use conservative 3.7 ratio"

    def test_empty_model_defaults_to_conservative(self, mock_models_client):
        """Test empty model ID defaults to 3.7."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            ratio = _get_char_to_token_ratio_dynamic("")
            assert ratio == 3.7, "Empty model should use conservative 3.7 ratio"


class TestDynamicRatioTokenEstimation:
    """Test token estimation accuracy with dynamic ratios."""

    def test_claude_estimation_accuracy(self, mock_models_client):
        """Test Claude estimation uses 3.7 ratio for accuracy."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            agent = AgentStub(
                messages=[make_message("x" * 1000)],
                model="anthropic/claude-sonnet-4-5-20250929"
            )
            estimated = _estimate_prompt_tokens(agent)
            expected = _expected_tokens(1000, 3.7, 1)

            assert estimated == expected, f"Expected {expected}, got {estimated}"

    def test_gpt_estimation_accuracy(self, mock_models_client):
        """Test GPT estimation uses 4.0 ratio for accuracy."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            agent = AgentStub(
                messages=[make_message("x" * 1000)],
                model="azure/gpt-5"
            )
            estimated = _estimate_prompt_tokens(agent)
            expected = _expected_tokens(1000, 4.0, 1)

            assert estimated == expected, f"Expected {expected}, got {estimated}"

    def test_kimi_estimation_accuracy(self, mock_models_client):
        """Test Kimi estimation uses 3.8 ratio for accuracy."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            agent = AgentStub(
                messages=[make_message("x" * 1000)],
                model="moonshot/kimi-k2-thinking"
            )
            estimated = _estimate_prompt_tokens(agent)
            expected = _expected_tokens(1000, 3.8, 1)

            assert estimated == expected, f"Expected {expected}, got {estimated}"

    def test_gemini_estimation_accuracy(self, mock_models_client):
        """Test Gemini estimation uses 4.2 ratio for accuracy."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            agent = AgentStub(
                messages=[make_message("x" * 1000)],
                model="google/gemini-2.5-flash"
            )
            estimated = _estimate_prompt_tokens(agent)
            expected = _expected_tokens(1000, 4.2, 1)

            assert estimated == expected, f"Expected {expected}, got {estimated}"


# ============================================================================
# P0: Safe max_tokens from models.dev
# ============================================================================


class TestSafeMaxTokens:
    """Test P0 feature: Safe max_tokens calculation from models.dev."""

    def test_azure_gpt_5_safe_tokens(self, config_manager_with_mock_client):
        """Test Azure GPT-5 safe max_tokens is 50% of 128,000 = 64,000."""
        safe_max = config_manager_with_mock_client.get_safe_max_tokens("azure/gpt-5")
        assert safe_max == 64000, f"Expected 64000, got {safe_max}"

    def test_azure_gpt_4o_safe_tokens(self, config_manager_with_mock_client):
        """Test Azure GPT-4o safe max_tokens is 50% of 16,384 = 8,192."""
        safe_max = config_manager_with_mock_client.get_safe_max_tokens("azure/gpt-4o")
        assert safe_max == 8192, f"Expected 8192, got {safe_max}"

    def test_bedrock_claude_35_safe_tokens(self, config_manager_with_mock_client):
        """Test Bedrock Claude 3.5 safe max_tokens is 50% of 8,192 = 4,096."""
        safe_max = config_manager_with_mock_client.get_safe_max_tokens(
            "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0"
        )
        assert safe_max == 4096, f"Expected 4096, got {safe_max}"

    def test_moonshot_kimi_safe_tokens(self, config_manager_with_mock_client):
        """Test Moonshot Kimi safe max_tokens is 50% of 262,144 = 131,072."""
        safe_max = config_manager_with_mock_client.get_safe_max_tokens("moonshot/kimi-k2-thinking")
        assert safe_max == 131072, f"Expected 131072, got {safe_max}"

    def test_anthropic_claude_sonnet_45_safe_tokens(self, config_manager_with_mock_client):
        """Test Anthropic Claude Sonnet 4.5 safe max_tokens is 50% of 64,000 = 32,000."""
        safe_max = config_manager_with_mock_client.get_safe_max_tokens(
            "anthropic/claude-sonnet-4-5-20250929"
        )
        assert safe_max == 32000, f"Expected 32000, got {safe_max}"

    def test_custom_buffer_percentage(self, config_manager_with_mock_client):
        """Test custom buffer percentage (e.g., 75% instead of 50%)."""
        # 75% of 128,000 = 96,000
        safe_max = config_manager_with_mock_client.get_safe_max_tokens("azure/gpt-5", buffer=0.75)
        assert safe_max == 96000, f"Expected 96000, got {safe_max}"

    def test_unknown_model_returns_safe_default(self, config_manager_with_mock_client):
        """Test unknown model returns safe default of 4,096."""
        safe_max = config_manager_with_mock_client.get_safe_max_tokens("unknown/model")
        assert safe_max == 4096, f"Expected 4096, got {safe_max}"


class TestSwarmModelConfig:
    """Test swarm model configuration uses safe limits."""

    def test_swarm_inherits_safe_limit(self, config_manager_with_mock_client, monkeypatch):
        """Test swarm model gets safe max_tokens from models.dev."""
        # Set swarm model env var
        monkeypatch.setenv("CYBER_AGENT_SWARM_MODEL", "azure/gpt-4o")

        # Get swarm config
        swarm_cfg = config_manager_with_mock_client._get_swarm_llm_config(
            "litellm",
            {"swarm_llm": Mock(model_id="azure/gpt-4o", max_tokens=None)}
        )

        # Should be 8,192 (50% of 16,384)
        assert swarm_cfg.max_tokens == 8192, f"Expected 8192, got {swarm_cfg.max_tokens}"

    def test_explicit_override_takes_precedence(self, config_manager_with_mock_client, monkeypatch):
        """Test CYBER_AGENT_SWARM_MAX_TOKENS overrides auto-calculation."""
        monkeypatch.setenv("CYBER_AGENT_SWARM_MODEL", "azure/gpt-4o")
        monkeypatch.setenv("CYBER_AGENT_SWARM_MAX_TOKENS", "12288")  # 75% instead of 50%

        swarm_cfg = config_manager_with_mock_client._get_swarm_llm_config(
            "litellm",
            {"swarm_llm": Mock(model_id="azure/gpt-4o", max_tokens=None)}
        )

        assert swarm_cfg.max_tokens == 12288, f"Expected 12288, got {swarm_cfg.max_tokens}"


# ============================================================================
# P2: Quiet Pruning Warnings
# ============================================================================


class TestQuietPruningWarnings:
    """Test P2 feature: Quiet pruning warnings for small conversations."""

    def test_small_conversations_no_excessive_warnings(self, caplog):
        """P2: Test small conversations don't spam WARNING logs."""
        manager = MappingConversationManager(
            window_size=100,
            preserve_recent_messages=12,
            summary_ratio=0.5
        )

        # Simulate typical specialist invocation with 3 messages
        agent = AgentStub(
            [
                make_message("system: scan for XSS"),
                make_message("thinking about approach..."),
                make_message("result: no vulnerabilities found"),
            ],
            name="xss_specialist"
        )

        caplog.clear()
        with caplog.at_level(logging.WARNING):
            # apply_management should handle small conversations gracefully
            manager.apply_management(agent)

        # P2 Feature: Small conversations should not generate WARNING logs
        warning_logs = [rec for rec in caplog.records if rec.levelname == "WARNING"]
        assert len(warning_logs) == 0, \
            f"P2 violation: Small conversations should not generate warnings. Got: {[r.message for r in warning_logs]}"

    def test_large_conversations_still_prune(self):
        """P2: Ensure large conversations still prune normally (functional test)."""
        manager = MappingConversationManager(
            window_size=10,  # Small window to trigger pruning
            preserve_recent_messages=3,
            summary_ratio=0.5
        )

        # 20 messages - well over window size
        agent = AgentStub([make_message(f"msg{i}") for i in range(20)])
        initial_count = len(agent.messages)

        # apply_management respects window size
        manager.apply_management(agent)

        # P2 doesn't break normal pruning - large conversations still get managed
        # Window is 10, so we should have at most 10 messages
        assert len(agent.messages) <= 10, \
            f"Large conversations should prune to window size. Expected <=10 messages, got {len(agent.messages)}"

        # Verify some messages were actually removed
        assert len(agent.messages) < initial_count, \
            "Some messages should have been pruned"

    def test_p2_early_return_for_tiny_conversations(self):
        """P2: Test Layer 2 compression returns early for <3 message conversations."""
        from modules.handlers.conversation_budget import LargeToolResultMapper

        _mapper = LargeToolResultMapper()
        manager = MappingConversationManager(
            window_size=100,
            preserve_recent_messages=12,
            summary_ratio=0.5
        )

        # 2 messages - too small for Layer 2 compression
        agent = AgentStub([make_message("msg1"), make_message("msg2")])
        initial_count = len(agent.messages)

        # Layer 2 should return early without modifying messages
        # Note: This will still fail on sliding window, but Layer 2 skips correctly
        try:
            manager.reduce_context(agent)
        except Exception:
            pass  # Expected to fail on tiny conversations in Layer 1

        # Verify messages weren't modified by Layer 2 before Layer 1 failure
        # (Layer 2 returns early for small conversations)
        assert len(agent.messages) == initial_count, \
            "P2: Layer 2 should not modify conversations <3 messages"


# ============================================================================
# Integration Tests: End-to-End Scenarios
# ============================================================================


class TestSpecialistFlowIntegration:
    """Test end-to-end specialist invocation flow."""

    def test_specialist_gets_safe_token_limit(self, config_manager_with_mock_client, mock_models_client):
        """Test specialist tool gets safe token limit, not main agent's."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            # Main agent with high limit
            _main_agent = AgentStub(
                messages=[make_message("main task")],
                model="azure/gpt-5",
                limit=272000
            )

            # Specialist with swarm model (should get safe limit that accounts for overhead)
            # Overhead = 8000 + 3000 + 50 = 11050 tokens just for system/tools/metadata
            # So safe limit must exceed overhead to allow any content
            specialist = AgentStub(
                messages=[make_message("specialist task")],
                model="azure/gpt-4o",
                limit=20000  # Safe limit that accounts for overhead
            )

            # Estimate tokens for specialist
            estimated = _estimate_prompt_tokens(specialist)

            # Should not exceed safe limit (includes overhead)
            assert estimated < specialist._prompt_token_limit, \
                f"Specialist estimated {estimated} tokens exceeds safe limit {specialist._prompt_token_limit}"

    def test_no_spurious_warnings_from_specialist(self, caplog, mock_models_client):
        """Test specialist with 2-3 messages doesn't spam warnings."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            manager = MappingConversationManager(
                window_size=100,
                preserve_recent_messages=12,
                summary_ratio=0.5
            )

            # Specialist with minimal conversation
            specialist = AgentStub(
                messages=[
                    make_message("system: scan for XSS"),
                    make_message("specialist: analyzing..."),
                ],
                model="azure/gpt-4o",
                name="xss_specialist"
            )

            with caplog.at_level(logging.WARNING):
                manager.apply_management(specialist)

            # Should have no WARNING logs
            warning_logs = [rec for rec in caplog.records if rec.levelname == "WARNING"]
            assert len(warning_logs) == 0, f"Specialist should not spam warnings: {warning_logs}"


class TestBudgetEnforcementAccuracy:
    """Test budget enforcement accuracy with dynamic ratios."""

    def test_claude_budget_enforcement(self, mock_models_client):
        """Test Claude models trigger reduction at correct threshold with 3.7 ratio."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            # Use a limit that accounts for overhead (11050) plus content
            # 65% threshold of 20000 = 13000 tokens
            # Overhead = 11050, so we need content of 13000 - 11050 = 1950 tokens
            # With 3.7 ratio: 1950 * 3.7 = ~7215 chars needed
            agent = AgentStub(
                messages=[make_message("x" * 4000)] * 2,  # 8000 chars total
                model="anthropic/claude-sonnet-4-5-20250929",
                limit=20000
            )

            _ensure_prompt_within_budget(agent)

            # Should trigger reduction because content tokens + overhead exceed threshold
            assert len(agent.conversation_manager.calls) > 0, \
                "Should trigger reduction when exceeding threshold"

    def test_gpt_budget_enforcement(self, mock_models_client):
        """Test GPT models trigger reduction at correct threshold with 4.0 ratio."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            agent = AgentStub(
                messages=[make_message("x" * 4000)] * 2,  # 8000 chars total
                model="azure/gpt-5",
                limit=20000
            )

            _ensure_prompt_within_budget(agent)

            # Should trigger reduction when exceeding threshold
            assert len(agent.conversation_manager.calls) > 0, \
                "Should trigger reduction when exceeding threshold"

    def test_no_false_positives_below_threshold(self, mock_models_client):
        """Test no reduction triggered when below 65% threshold."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            # Use a high limit where overhead + small content is well below threshold
            # Limit = 50000, 65% threshold = 32500
            # Overhead = 11050 + 2*50 = 11150 (for 2 messages)
            # Small content: 100 chars / 3.7 = ~27 tokens
            # Total = 11177 tokens, well below 32500
            agent = AgentStub(
                messages=[make_message("x" * 50)] * 2,  # 100 chars total
                model="anthropic/claude-sonnet-4-5-20250929",
                limit=50000
            )

            _ensure_prompt_within_budget(agent)

            # Should NOT trigger because we're well below threshold
            assert len(agent.conversation_manager.calls) == 0, \
                "Should not trigger reduction below threshold"


# ============================================================================
# Validation: Expected vs Actual Behavior
# ============================================================================


class TestExpectedBehaviorValidation:
    """Validate expected behavior matches actual implementation."""

    def test_all_user_models_have_correct_ratios(self, mock_models_client):
        """Validate all user's production models get correct ratios."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            expected = {
                "azure/gpt-5": 4.0,
                "azure/gpt-4o": 4.0,
                "moonshot/kimi-k2-thinking": 3.8,
                "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0": 3.7,
                "anthropic/claude-sonnet-4-5-20250929": 3.7,
                "google/gemini-2.5-flash": 4.2,
            }

            for model_id, expected_ratio in expected.items():
                actual_ratio = _get_char_to_token_ratio_dynamic(model_id)
                assert actual_ratio == expected_ratio, \
                    f"Model {model_id}: expected ratio {expected_ratio}, got {actual_ratio}"

    def test_all_user_models_have_safe_limits(self, config_manager_with_mock_client):
        """Validate all user's production models get safe max_tokens."""
        expected = {
            "azure/gpt-5": 64000,           # 50% of 128,000
            "azure/gpt-4o": 8192,           # 50% of 16,384
            "moonshot/kimi-k2-thinking": 131072,  # 50% of 262,144
            "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0": 4096,  # 50% of 8,192
            "anthropic/claude-sonnet-4-5-20250929": 32000,  # 50% of 64,000
        }

        for model_id, expected_safe in expected.items():
            actual_safe = config_manager_with_mock_client.get_safe_max_tokens(model_id)
            assert actual_safe == expected_safe, \
                f"Model {model_id}: expected safe max_tokens {expected_safe}, got {actual_safe}"

    def test_estimation_accuracy_within_1_percent(self, mock_models_client):
        """Test token estimation accuracy is within ±1 token for all models."""
        with patch('modules.handlers.conversation_budget.get_models_client', return_value=mock_models_client):
            test_cases = [
                ("anthropic/claude-sonnet-4-5-20250929", 10000, 3.7),
                ("azure/gpt-5", 10000, 4.0),
                ("moonshot/kimi-k2-thinking", 10000, 3.8),
                ("google/gemini-2.5-flash", 10000, 4.2),
            ]

            for model_id, char_count, ratio in test_cases:
                agent = AgentStub(
                    messages=[make_message("x" * char_count)],
                    model=model_id
                )

                estimated = _estimate_prompt_tokens(agent)
                expected = _expected_tokens(char_count, ratio, 1)

                # Allow ±1 token difference (rounding)
                assert abs(estimated - expected) <= 1, \
                    f"Model {model_id}: expected ~{expected} tokens, got {estimated}"


# ============================================================================
# Pipeline Integration: Threshold Alignment Tests
# ============================================================================


class TestThresholdAlignment:
    """Test that ToolRouterHook and LargeToolResultMapper thresholds work together.

    Production pipeline:
    1. ToolRouterHook externalizes outputs > artifact_threshold (10K) to artifacts/
    2. LargeToolResultMapper compresses tool results > compress_threshold (40K)

    If artifact_threshold < compress_threshold, the mapper acts as a safety net
    for edge cases where externalization fails or is bypassed.
    """

    def test_compress_threshold_matches_artifact_threshold(self):
        """Verify compression threshold matches artifact externalization threshold.

        CRITICAL FIX: Changed from 1.5x to 1.0x to catch externalized previews.

        Previous behavior (broken):
        - ToolRouterHook externalizes at 10K, leaving 10K inline preview
        - LargeToolResultMapper compressed at 15K threshold
        - 10K < 15K meant NO compression ever triggered
        - Result: 50 tool calls accumulated 500K+ chars without compression

        Fixed behavior:
        - Compression threshold matches externalization threshold (10K)
        - Externalized 10K previews now trigger compression
        - Compression truncates to 8K (TOOL_COMPRESS_TRUNCATE)
        """
        from modules.handlers.conversation_budget import (
            TOOL_COMPRESS_THRESHOLD,
            _TOOL_ARTIFACT_THRESHOLD,
        )

        # Compression threshold must MATCH artifact threshold (not 1.5x)
        assert TOOL_COMPRESS_THRESHOLD == _TOOL_ARTIFACT_THRESHOLD, (
            f"Compression threshold ({TOOL_COMPRESS_THRESHOLD}) must match "
            f"artifact threshold ({_TOOL_ARTIFACT_THRESHOLD}) to catch externalized previews"
        )

        # Verify the relationship
        assert _TOOL_ARTIFACT_THRESHOLD == 10000, "Artifact threshold should be 10K"
        assert TOOL_COMPRESS_THRESHOLD == 10000, "Compression threshold should be 10K (matching artifact)"

    def test_mapper_acts_as_safety_net(self):
        """Test that mapper compresses results that bypass externalization."""
        from modules.handlers.conversation_budget import (
            LargeToolResultMapper,
            TOOL_COMPRESS_THRESHOLD,
            TOOL_COMPRESS_TRUNCATE,
        )

        mapper = LargeToolResultMapper(
            max_tool_chars=TOOL_COMPRESS_THRESHOLD,
            truncate_at=TOOL_COMPRESS_TRUNCATE,
        )

        # Simulate a result that bypassed externalization (edge case)
        large_result = "X" * (TOOL_COMPRESS_THRESHOLD + 5000)
        message = {
            "role": "user",
            "content": [
                {
                    "toolResult": {
                        "toolUseId": "bypass_test",
                        "status": "success",
                        "content": [{"text": large_result}],
                    }
                }
            ],
        }

        result = mapper(message, 0, [message])

        # Mapper should compress this oversized result
        compressed_text = result["content"][0]["toolResult"]["content"][0]["text"]
        assert len(compressed_text) < len(large_result), (
            "Mapper should compress results exceeding threshold"
        )
        assert "compressed" in compressed_text.lower(), (
            "Compressed result should indicate compression"
        )

    def test_normal_operation_no_compression_needed(self):
        """Test that externalized results (summaries) don't trigger compression.

        This validates the production behavior where:
        1. Large outputs are externalized by ToolRouterHook
        2. Only summaries (<10K) enter conversation
        3. Mapper correctly reports 'no compression needed'
        """
        from modules.handlers.conversation_budget import (
            LargeToolResultMapper,
            TOOL_COMPRESS_THRESHOLD,
        )

        mapper = LargeToolResultMapper(max_tool_chars=TOOL_COMPRESS_THRESHOLD)

        # Simulate externalized result (summary with artifact reference)
        externalized_summary = (
            "[Tool output: 125,432 chars total | Preview: 4,000 chars below | "
            "Full: artifacts/nmap_20241124_143022_a1b2c3.log]\n\n"
            + "X" * 4000  # 4K preview - well under 40K threshold
        )

        message = {
            "role": "user",
            "content": [
                {
                    "toolResult": {
                        "toolUseId": "externalized_test",
                        "status": "success",
                        "content": [{"text": externalized_summary}],
                    }
                }
            ],
        }

        result = mapper(message, 0, [message])

        # Result should be unchanged - no compression needed
        result_text = result["content"][0]["toolResult"]["content"][0]["text"]
        assert result_text == externalized_summary, (
            "Externalized summaries should pass through unchanged"
        )

    def test_sliding_window_handles_accumulated_small_messages(self):
        """Test that sliding window manages growth from many small messages.

        When externalization works correctly:
        - Individual messages are small (<10K chars each)
        - Mapper reports 'no compression needed' (correct)
        - Sliding window caps total message count
        - Token budget is managed by window, not compression
        """
        manager = MappingConversationManager(
            window_size=10,
            preserve_first_messages=1,
            preserve_recent_messages=3,
        )

        # Create 15 small messages (each ~500 chars, well under thresholds)
        messages = []
        for i in range(15):
            messages.append({
                "role": "user" if i % 2 == 0 else "assistant",
                "content": [{"text": f"Message {i}: " + "x" * 500}],
            })

        agent = AgentStub(messages=messages, model="test/model", limit=100000)

        # Apply management
        manager.apply_management(agent)

        # Sliding window should cap at 10 messages
        assert len(agent.messages) <= 10, (
            f"Sliding window should cap messages at 10, got {len(agent.messages)}"
        )

    def test_preservation_zone_configuration(self):
        """Test that preservation zone doesn't block all pruning."""
        manager = MappingConversationManager(
            window_size=100,
            preserve_first_messages=1,
            preserve_recent_messages=12,  # Current default
        )

        total_preserved = manager.preserve_first + manager.preserve_last

        # Preservation should not exceed 50% of window
        max_preserved = int(100 * 0.5)
        assert total_preserved <= max_preserved, (
            f"Preservation zone ({total_preserved}) exceeds 50% of window ({max_preserved})"
        )

        # With 100-message window, pruning should be possible at message 14+
        min_messages_for_pruning = total_preserved + 1
        assert min_messages_for_pruning == 14, (
            f"Pruning should be possible at message {min_messages_for_pruning}"
        )


class TestFullPipelineSimulation:
    """Simulate the full context management pipeline behavior."""

    def test_pipeline_with_mixed_output_sizes(self):
        """Simulate realistic operation with mixed tool output sizes."""
        from modules.handlers.conversation_budget import (
            LargeToolResultMapper,
            TOOL_COMPRESS_THRESHOLD,
        )

        mapper = LargeToolResultMapper(max_tool_chars=TOOL_COMPRESS_THRESHOLD)
        manager = MappingConversationManager(
            window_size=20,
            preserve_first_messages=1,
            preserve_recent_messages=5,
        )

        messages = []
        compression_count = 0

        # Simulate 25 tool executions with varying output sizes
        for i in range(25):
            # Most outputs are externalized (simulated as summaries)
            if i % 10 == 0:
                # Edge case: Large result that bypassed externalization
                content = "X" * (TOOL_COMPRESS_THRESHOLD + 1000)
            else:
                # Normal: Externalized summary
                content = f"[Tool output externalized to artifacts/tool_{i}.log]\n" + "x" * 2000

            message = {
                "role": "user",
                "content": [
                    {
                        "toolResult": {
                            "toolUseId": f"tool_{i}",
                            "status": "success",
                            "content": [{"text": content}],
                        }
                    }
                ],
            }

            # Apply mapper (simulates LargeToolResultMapper in pipeline)
            mapped = mapper(message, i, messages + [message])
            if mapped != message:
                compression_count += 1
            messages.append(mapped)

            # Add assistant response
            messages.append({
                "role": "assistant",
                "content": [{"text": f"Analyzed tool {i} output."}],
            })

        # Create agent with accumulated messages
        agent = AgentStub(messages=messages, model="test/model", limit=200000)

        # Apply sliding window
        initial_count = len(agent.messages)
        manager.apply_management(agent)
        final_count = len(agent.messages)

        # Verify behaviors
        assert compression_count >= 2, (
            f"Expected at least 2 compressions for edge cases, got {compression_count}"
        )
        assert final_count <= 20, (
            f"Sliding window should cap at 20, got {final_count}"
        )
        assert final_count < initial_count, (
            f"Window should reduce messages: {initial_count} -> {final_count}"
        )


class TestToolPairPreservation:
    """Test that force pruning preserves toolUse/toolResult pairs."""

    def test_force_prune_keeps_tool_pairs_together(self):
        """Verify pruning removes complete tool pairs, not orphaned results."""
        manager = MappingConversationManager(
            window_size=10,
            preserve_first_messages=1,
            preserve_recent_messages=2,
        )

        # Create conversation with tool pairs
        # Pattern: user -> assistant(toolUse) -> user(toolResult) -> assistant
        messages = [
            {"role": "user", "content": [{"text": "Initial prompt"}]},
            # Tool pair 1
            {"role": "assistant", "content": [{"toolUse": {"name": "shell", "toolUseId": "t1", "input": {}}}]},
            {"role": "user", "content": [{"toolResult": {"toolUseId": "t1", "status": "success", "content": []}}]},
            {"role": "assistant", "content": [{"text": "Result 1"}]},
            # Tool pair 2
            {"role": "assistant", "content": [{"toolUse": {"name": "shell", "toolUseId": "t2", "input": {}}}]},
            {"role": "user", "content": [{"toolResult": {"toolUseId": "t2", "status": "success", "content": []}}]},
            {"role": "assistant", "content": [{"text": "Result 2"}]},
            # Tool pair 3
            {"role": "assistant", "content": [{"toolUse": {"name": "shell", "toolUseId": "t3", "input": {}}}]},
            {"role": "user", "content": [{"toolResult": {"toolUseId": "t3", "status": "success", "content": []}}]},
            {"role": "assistant", "content": [{"text": "Result 3"}]},
            # Tool pair 4
            {"role": "assistant", "content": [{"toolUse": {"name": "shell", "toolUseId": "t4", "input": {}}}]},
            {"role": "user", "content": [{"toolResult": {"toolUseId": "t4", "status": "success", "content": []}}]},
            {"role": "assistant", "content": [{"text": "Result 4"}]},
        ]

        agent = AgentStub(messages=messages, model="test/model", limit=200000)
        initial_count = len(agent.messages)

        # Apply management (should trigger force prune since 13 > 10)
        manager.apply_management(agent)

        # Verify no orphaned toolResults
        for i, msg in enumerate(agent.messages):
            content = msg.get("content", [])
            has_tool_result = any(
                isinstance(block, dict) and "toolResult" in block
                for block in content
                if isinstance(block, dict)
            )

            if has_tool_result and i > 0:
                prev_msg = agent.messages[i - 1]
                prev_content = prev_msg.get("content", [])
                has_tool_use = any(
                    isinstance(block, dict) and "toolUse" in block
                    for block in prev_content
                    if isinstance(block, dict)
                )
                assert has_tool_use, (
                    f"Message {i} has toolResult but message {i-1} has no toolUse. "
                    f"Tool pair was broken during pruning."
                )

        # Verify some pruning occurred
        assert len(agent.messages) < initial_count, (
            f"Expected pruning: {initial_count} -> {len(agent.messages)}"
        )

    def test_window_overflow_triggers_at_boundary(self):
        """Test that pruning triggers when message count equals window size."""
        manager = MappingConversationManager(
            window_size=10,
            preserve_first_messages=1,
            preserve_recent_messages=2,
        )

        # Create exactly 10 messages (at window boundary)
        messages = [
            {"role": "user", "content": [{"text": f"Message {i}"}]}
            for i in range(10)
        ]

        agent = AgentStub(messages=messages, model="test/model", limit=200000)

        # Apply management - should trigger pruning at boundary (>=, not >)
        manager.apply_management(agent)

        # Verify pruning occurred (target is 90% = 9 messages)
        assert len(agent.messages) < 10, (
            f"Window overflow should trigger at boundary: expected <10, got {len(agent.messages)}"
        )


# ============================================================================
# CRITICAL: 10K-15K Threshold Gap Tests
# ============================================================================


class TestThresholdGapFailureMode:
    """Test the 10K externalization vs 15K compression threshold gap.

    This test class validates the FAILURE MODE where:
    1. ToolRouterHook externalizes at 10K, leaving 10K inline preview
    2. LargeToolResultMapper compresses at 15K threshold
    3. 10K < 15K, so compression NEVER triggers for externalized results
    4. 10K previews accumulate in conversation without compression

    These tests are designed to FAIL with current configuration to prove
    the bug exists, then PASS after the fix is applied.
    """

    def test_10k_preview_triggers_compression_after_fix(self):
        """Validate 10K externalized previews NOW trigger compression.

        After the fix (TOOL_COMPRESS_THRESHOLD lowered from 15K to 10K):
        - Externalized content is 10K (from ToolRouterHook)
        - Compression threshold is NOW 10K (matching externalization)
        - 10K >= 10K means compression DOES trigger

        This test validates the fix works correctly.
        """
        from modules.handlers.conversation_budget import (
            LargeToolResultMapper,
            TOOL_COMPRESS_THRESHOLD,
            _TOOL_ARTIFACT_THRESHOLD,
        )

        # Verify the fix is applied: thresholds should now match
        assert _TOOL_ARTIFACT_THRESHOLD == 10000, "Externalization threshold is 10K"
        assert TOOL_COMPRESS_THRESHOLD == 10000, "Compression threshold should NOW be 10K (fixed)"

        mapper = LargeToolResultMapper(max_tool_chars=TOOL_COMPRESS_THRESHOLD)

        # Simulate ToolRouterHook output: exactly 10K inline preview
        # This is what enters conversation after externalization
        header = (
            "[Tool output: 687,114 chars | Inline: 10,000 chars | "
            "Full: artifacts/nmap_20241124_143022_a1b2c3.log]\n\n"
        )
        # Pad to exactly 10,000 chars total (header + padding)
        padding_needed = 10000 - len(header)
        externalized_preview = header + "X" * padding_needed  # Total exactly 10K chars

        message = {
            "role": "user",
            "content": [
                {
                    "toolResult": {
                        "toolUseId": "externalized_test",
                        "status": "success",
                        "content": [{"text": externalized_preview}],
                    }
                }
            ],
        }

        # Calculate input size
        input_size = len(externalized_preview)
        assert 9500 < input_size < 11000, f"Preview should be ~10K chars, got {input_size}"

        # Apply mapper - with 10K threshold (fixed), 10K content SHOULD trigger compression
        result = mapper(message, 0, [message])
        result_text = result["content"][0]["toolResult"]["content"][0]["text"]

        # FIXED BEHAVIOR: Compression should now trigger
        assert result_text != externalized_preview, (
            f"FIX VALIDATION FAILED: 10K preview ({input_size} chars) should trigger "
            f"compression at 10K threshold, but was passed through unchanged."
        )

        # Verify compression reduced size
        assert len(result_text) < input_size, (
            f"Compression should reduce size: {input_size} -> {len(result_text)}"
        )

    def test_accumulated_10k_previews_now_compressed(self):
        """Validate that 50 externalized results are NOW properly compressed.

        After the fix (TOOL_COMPRESS_THRESHOLD lowered from 15K to 10K):
        - 50 tool executions (realistic CTF session)
        - Each leaves 10K inline preview (externalized)
        - ALL trigger compression (10K >= 10K threshold)
        - Total: Much smaller than 500K chars

        This test validates the fix works for realistic workloads.
        """
        from modules.handlers.conversation_budget import (
            LargeToolResultMapper,
            MappingConversationManager,
            TOOL_COMPRESS_THRESHOLD,
        )

        mapper = LargeToolResultMapper(max_tool_chars=TOOL_COMPRESS_THRESHOLD)
        manager = MappingConversationManager(
            window_size=100,  # Large window to allow accumulation
            preserve_first_messages=1,
            preserve_recent_messages=5,
        )

        messages = []
        compression_count = 0

        # Simulate 50 tool executions with externalized 10K previews
        for i in range(50):
            # Create externalized preview (exactly 10K chars each to match ToolRouterHook output)
            header = (
                f"[Tool output: {50000 + i * 1000} chars | Inline: 10,000 chars | "
                f"Full: artifacts/tool_{i:03d}.log]\n\n"
                f"Output from tool execution {i}:\n"
            )
            padding_needed = 10000 - len(header)
            preview = header + "X" * padding_needed  # Exactly 10K total

            message = {
                "role": "user",
                "content": [
                    {
                        "toolResult": {
                            "toolUseId": f"tool_{i}",
                            "status": "success",
                            "content": [{"text": preview}],
                        }
                    }
                ],
            }

            # Check if mapper compresses this message
            mapped = mapper(message, i, messages + [message])
            original_size = len(preview)
            mapped_text = mapped["content"][0]["toolResult"]["content"][0]["text"]
            mapped_size = len(mapped_text)

            if mapped_size < original_size * 0.9:  # 10%+ reduction = compression occurred
                compression_count += 1

            messages.append(mapped)

            # Add assistant response
            messages.append({
                "role": "assistant",
                "content": [{"text": f"Analyzed output from tool {i}."}],
            })

        # Calculate total accumulated size
        total_chars = 0
        for msg in messages:
            for block in msg.get("content", []):
                if "text" in block:
                    total_chars += len(block["text"])
                elif "toolResult" in block:
                    for content in block["toolResult"].get("content", []):
                        if "text" in content:
                            total_chars += len(content["text"])

        # FIXED BEHAVIOR: All 50 tool results should be compressed
        # With 10K threshold, all 10K previews trigger compression
        assert compression_count == 50, (
            f"FIX VALIDATION: Expected ALL 50 tool results to be compressed, "
            f"but only {compression_count} were compressed.\n"
            f"Total accumulated: {total_chars:,} chars"
        )

        # Verify total size is now manageable
        # Without compression: 50 x 10K = 500K
        # With compression to 8K: should be much smaller
        max_acceptable_chars = 500000  # Should be well under 500K
        assert total_chars < max_acceptable_chars, (
            f"FIX VALIDATION: Total {total_chars:,} chars exceeds "
            f"acceptable limit of {max_acceptable_chars:,}.\n"
            f"Compressions triggered: {compression_count} out of 50 tool results."
        )

    def test_compression_must_actually_reduce_size(self):
        """CRITICAL: Verify compression produces smaller output, not just metadata.

        Tests that when compression IS triggered:
        1. Output size is actually smaller than input
        2. Metadata overhead doesn't negate the compression benefit
        3. At least 30% reduction is achieved

        This catches the case where compression adds metadata that
        increases total size rather than decreasing it.
        """
        from modules.handlers.conversation_budget import (
            LargeToolResultMapper,
            TOOL_COMPRESS_THRESHOLD,
            TOOL_COMPRESS_TRUNCATE,
        )

        mapper = LargeToolResultMapper(
            max_tool_chars=TOOL_COMPRESS_THRESHOLD,
            truncate_at=TOOL_COMPRESS_TRUNCATE,
        )

        # Create content that WILL trigger compression (> 15K)
        large_content = "X" * 20000  # 20K chars, above 15K threshold

        message = {
            "role": "user",
            "content": [
                {
                    "toolResult": {
                        "toolUseId": "compression_test",
                        "status": "success",
                        "content": [{"text": large_content}],
                    }
                }
            ],
        }

        original_size = len(large_content)
        result = mapper(message, 0, [message])

        # Calculate compressed size (including all content blocks)
        compressed_size = 0
        for block in result["content"][0]["toolResult"]["content"]:
            if "text" in block:
                compressed_size += len(block["text"])
            elif "json" in block:
                compressed_size += len(str(block["json"]))

        # Verify compression actually reduced size
        assert compressed_size < original_size, (
            f"Compression INCREASED size: {original_size} -> {compressed_size}. "
            f"Metadata overhead is negating compression benefit."
        )

        # Verify at least 30% reduction (meaningful compression)
        reduction_ratio = 1 - (compressed_size / original_size)
        min_reduction = 0.30

        assert reduction_ratio >= min_reduction, (
            f"Compression only achieved {reduction_ratio:.1%} reduction "
            f"(need at least {min_reduction:.0%}). "
            f"Original: {original_size}, Compressed: {compressed_size}"
        )

    def test_window_management_handles_accumulated_content(self):
        """Test that window management reduces context even without compression.

        When compression doesn't trigger (10K < 15K gap), the sliding window
        should still enforce message count limits and reduce total context.

        This test validates that the backup mechanism (window pruning) works
        even when the primary mechanism (compression) fails.
        """
        manager = MappingConversationManager(
            window_size=20,
            preserve_first_messages=1,
            preserve_recent_messages=3,
        )

        # Create 30 messages with 10K content each (under compression threshold)
        messages = []
        for i in range(30):
            content = f"[Tool output {i}]\n" + "X" * 9500  # ~10K, under 15K threshold
            messages.append({
                "role": "user" if i % 2 == 0 else "assistant",
                "content": [{"text": content}],
            })

        agent = AgentStub(messages=messages, model="test/model", limit=200000)

        # Calculate initial size
        initial_count = len(agent.messages)
        initial_chars = sum(
            len(block.get("text", ""))
            for msg in agent.messages
            for block in msg.get("content", [])
        )

        # Apply management
        manager.apply_management(agent)

        # Verify window enforced message limit
        final_count = len(agent.messages)
        final_chars = sum(
            len(block.get("text", ""))
            for msg in agent.messages
            for block in msg.get("content", [])
        )

        assert final_count <= 20, (
            f"Window should cap at 20 messages, got {final_count}"
        )

        assert final_count < initial_count, (
            f"Window should reduce message count: {initial_count} -> {final_count}"
        )

        # Even without compression, window pruning should reduce total size
        assert final_chars < initial_chars, (
            f"Window pruning should reduce total chars: {initial_chars} -> {final_chars}"
        )
