#!/usr/bin/env python3
"""Comprehensive conversation manager tests with mock data generators.

Mock data patterns derived from real production operations:
- XBEN-029: Claude Sonnet 4.5 on Bedrock, window_size=100
- XBEN-066: GPT-5.1 on Azure, window_size=60
"""

import copy
import uuid
from dataclasses import dataclass, field
from typing import Any, Optional

import pytest

from modules.handlers.conversation_budget import (
    DEFAULT_CHAR_TO_TOKEN_RATIO,
    LargeToolResultMapper,
    MappingConversationManager,
    MESSAGE_METADATA_OVERHEAD_TOKENS,
    PROACTIVE_COMPRESSION_THRESHOLD,
    SYSTEM_PROMPT_OVERHEAD_TOKENS,
    TOOL_COMPRESS_THRESHOLD,
    TOOL_COMPRESS_TRUNCATE,
    TOOL_DEFINITIONS_OVERHEAD_TOKENS,
    _estimate_prompt_tokens,
    _safe_estimate_tokens,
)


@dataclass
class ModelConfig:
    """Model configuration for mock data generation."""

    model_id: str
    provider: str
    char_to_token_ratio: float
    window_size: int
    preserve_first: int = 1
    preserve_last: Optional[int] = None
    context_limit_tokens: int = 200000


CLAUDE_SONNET_CONFIG = ModelConfig(
    model_id="bedrock/us.anthropic.claude-sonnet-4-5-20250929-v1:0",
    provider="bedrock",
    char_to_token_ratio=3.7,
    window_size=100,
    preserve_first=1,
    context_limit_tokens=200000,
)

GPT_5_CONFIG = ModelConfig(
    model_id="azure/gpt-5",
    provider="azure",
    char_to_token_ratio=4.0,
    window_size=60,
    preserve_first=1,
    context_limit_tokens=128000,
)

KIMI_K2_CONFIG = ModelConfig(
    model_id="openai/kimi-k2-0711-preview",
    provider="moonshot",
    char_to_token_ratio=3.8,
    window_size=80,
    preserve_first=1,
    context_limit_tokens=131072,
)

GEMINI_CONFIG = ModelConfig(
    model_id="vertex/gemini-2.5-pro",
    provider="google",
    char_to_token_ratio=4.2,
    window_size=100,
    preserve_first=1,
    context_limit_tokens=1000000,
)


@dataclass
class MockDataGenerator:
    """Generate realistic mock conversation data based on production patterns."""

    config: ModelConfig
    _message_counter: int = field(default=0, init=False)

    def create_user_message(self, content: str) -> dict[str, Any]:
        """Create a user message."""
        return {"role": "user", "content": [{"text": content}]}

    def create_assistant_message(self, content: str) -> dict[str, Any]:
        """Create an assistant message."""
        return {"role": "assistant", "content": [{"text": content}]}

    def create_tool_use_message(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        tool_use_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Create an assistant message with tool use."""
        return {
            "role": "assistant",
            "content": [
                {
                    "toolUse": {
                        "name": tool_name,
                        "toolUseId": tool_use_id or str(uuid.uuid4())[:8],
                        "input": tool_input,
                    }
                }
            ],
        }

    def create_tool_result_message(
        self,
        tool_use_id: str,
        result_text: str,
        status: str = "success",
    ) -> dict[str, Any]:
        """Create a user message with tool result."""
        return {
            "role": "user",
            "content": [
                {
                    "toolResult": {
                        "toolUseId": tool_use_id,
                        "status": status,
                        "content": [{"text": result_text}],
                    }
                }
            ],
        }

    def create_large_tool_result(
        self,
        tool_use_id: str,
        size_chars: int,
        status: str = "success",
    ) -> dict[str, Any]:
        """Create a tool result with specified size."""
        result_text = "X" * size_chars
        return self.create_tool_result_message(tool_use_id, result_text, status)

    def create_reasoning_message(
        self,
        reasoning_text: str,
        response_text: str,
    ) -> dict[str, Any]:
        """Create an assistant message with reasoning content."""
        return {
            "role": "assistant",
            "content": [
                {
                    "reasoningContent": {
                        "reasoningText": {"text": reasoning_text},
                    }
                },
                {"text": response_text},
            ],
        }

    def create_conversation(
        self,
        num_exchanges: int,
        include_tool_calls: bool = True,
        tool_result_size: int = 5000,
    ) -> list[dict[str, Any]]:
        """Create a realistic conversation with the specified number of exchanges."""
        messages: list[dict[str, Any]] = []

        for i in range(num_exchanges):
            messages.append(self.create_user_message(f"User query {i + 1}"))

            if include_tool_calls and i % 2 == 0:
                tool_id = f"tool_{i}"
                messages.append(
                    self.create_tool_use_message(
                        "shell",
                        {"command": f"nmap -sV target_{i}"},
                        tool_id,
                    )
                )
                messages.append(
                    self.create_large_tool_result(tool_id, tool_result_size)
                )

            messages.append(
                self.create_assistant_message(f"Analysis response for query {i + 1}")
            )

        return messages

    def create_window_boundary_conversation(self) -> list[dict[str, Any]]:
        """Create a conversation that exceeds the window size."""
        target_messages = int(self.config.window_size * 1.3)
        return self.create_conversation(
            num_exchanges=target_messages // 2,
            include_tool_calls=True,
            tool_result_size=3000,
        )

    def create_compression_threshold_conversation(
        self,
        num_large_results: int = 3,
    ) -> list[dict[str, Any]]:
        """Create a conversation with tool results exceeding compression threshold."""
        messages: list[dict[str, Any]] = []

        for i in range(num_large_results):
            tool_id = f"large_tool_{i}"
            messages.append(self.create_user_message(f"Execute scan {i + 1}"))
            messages.append(
                self.create_tool_use_message(
                    "shell",
                    {"command": f"nikto -h target_{i}"},
                    tool_id,
                )
            )
            result_size = TOOL_COMPRESS_THRESHOLD + 10000
            messages.append(
                self.create_large_tool_result(tool_id, result_size)
            )
            messages.append(
                self.create_assistant_message(f"Analyzed scan results for target {i}")
            )

        return messages


class MockAgent:
    """Mock agent for testing conversation manager."""

    def __init__(
        self,
        messages: list[dict[str, Any]],
        config: Optional[ModelConfig] = None,
    ) -> None:
        self.messages = messages
        self.system_prompt = "You are a security assessment agent."
        self.tool_registry = None
        self.name = "test_agent"
        self._context_reduction_events: list[dict[str, Any]] = []

        if config:
            self.model = MockModel(config)
            self._prompt_token_limit = config.context_limit_tokens

    def get_message_count(self) -> int:
        return len(self.messages)


class MockModel:
    """Mock model for testing."""

    def __init__(self, config: ModelConfig) -> None:
        self.config = {"model_id": config.model_id}
        self.model_id = config.model_id


class TestMockDataGenerator:
    """Test the mock data generator itself."""

    def test_create_user_message(self):
        generator = MockDataGenerator(CLAUDE_SONNET_CONFIG)
        msg = generator.create_user_message("test content")

        assert msg["role"] == "user"
        assert msg["content"][0]["text"] == "test content"

    def test_create_tool_use_message(self):
        generator = MockDataGenerator(CLAUDE_SONNET_CONFIG)
        msg = generator.create_tool_use_message(
            "shell", {"command": "ls -la"}, "test_id"
        )

        assert msg["role"] == "assistant"
        assert msg["content"][0]["toolUse"]["name"] == "shell"
        assert msg["content"][0]["toolUse"]["toolUseId"] == "test_id"

    def test_create_large_tool_result(self):
        generator = MockDataGenerator(CLAUDE_SONNET_CONFIG)
        msg = generator.create_large_tool_result("tool_id", 50000)

        result_text = msg["content"][0]["toolResult"]["content"][0]["text"]
        assert len(result_text) == 50000

    def test_create_conversation(self):
        generator = MockDataGenerator(CLAUDE_SONNET_CONFIG)
        messages = generator.create_conversation(10)

        assert len(messages) > 10
        roles = [m["role"] for m in messages]
        assert "user" in roles
        assert "assistant" in roles


class TestTokenEstimation:
    """Test token estimation accuracy with different model configurations."""

    @pytest.mark.parametrize(
        "config,expected_ratio",
        [
            (CLAUDE_SONNET_CONFIG, 3.7),
            (GPT_5_CONFIG, 4.0),
            (KIMI_K2_CONFIG, 3.8),
            (GEMINI_CONFIG, 4.2),
        ],
    )
    def test_char_to_token_ratios(self, config: ModelConfig, expected_ratio: float):
        """Verify model-specific character-to-token ratios."""
        generator = MockDataGenerator(config)
        messages = generator.create_conversation(5, include_tool_calls=False)
        agent = MockAgent(messages, config)

        total_chars = sum(
            len(block.get("text", ""))
            for msg in messages
            for block in msg.get("content", [])
            if isinstance(block, dict)
        )

        estimated = _estimate_prompt_tokens(agent)
        overhead = (
            SYSTEM_PROMPT_OVERHEAD_TOKENS
            + TOOL_DEFINITIONS_OVERHEAD_TOKENS
            + len(messages) * MESSAGE_METADATA_OVERHEAD_TOKENS
        )
        content_tokens = estimated - overhead

        actual_ratio = total_chars / content_tokens if content_tokens > 0 else 0
        assert abs(actual_ratio - expected_ratio) < 1.0

    def test_token_estimation_includes_overhead(self):
        """Verify overhead constants are included in estimation."""
        generator = MockDataGenerator(CLAUDE_SONNET_CONFIG)
        messages = generator.create_conversation(1, include_tool_calls=False)
        agent = MockAgent(messages, CLAUDE_SONNET_CONFIG)

        estimated = _estimate_prompt_tokens(agent)
        min_overhead = SYSTEM_PROMPT_OVERHEAD_TOKENS + TOOL_DEFINITIONS_OVERHEAD_TOKENS

        assert estimated > min_overhead

    def test_token_estimation_empty_messages(self):
        """Verify estimation handles empty message list."""
        agent = MockAgent([], CLAUDE_SONNET_CONFIG)
        estimated = _safe_estimate_tokens(agent)

        assert estimated == 0

    def test_token_estimation_with_tool_results(self):
        """Verify tool result content is counted in estimation."""
        generator = MockDataGenerator(CLAUDE_SONNET_CONFIG)
        messages_without_tools = generator.create_conversation(
            5, include_tool_calls=False
        )
        messages_with_tools = generator.create_conversation(
            5, include_tool_calls=True, tool_result_size=10000
        )

        agent_without = MockAgent(messages_without_tools, CLAUDE_SONNET_CONFIG)
        agent_with = MockAgent(messages_with_tools, CLAUDE_SONNET_CONFIG)

        tokens_without = _estimate_prompt_tokens(agent_without)
        tokens_with = _estimate_prompt_tokens(agent_with)

        assert tokens_with > tokens_without

    def test_token_estimation_with_reasoning(self):
        """Verify reasoning content is counted in estimation."""
        generator = MockDataGenerator(CLAUDE_SONNET_CONFIG)

        messages_without = [
            generator.create_user_message("Query"),
            generator.create_assistant_message("Response"),
        ]

        messages_with = [
            generator.create_user_message("Query"),
            generator.create_reasoning_message(
                "This is my reasoning process..." * 100,
                "Response",
            ),
        ]

        agent_without = MockAgent(messages_without, CLAUDE_SONNET_CONFIG)
        agent_with = MockAgent(messages_with, CLAUDE_SONNET_CONFIG)

        tokens_without = _estimate_prompt_tokens(agent_without)
        tokens_with = _estimate_prompt_tokens(agent_with)

        assert tokens_with > tokens_without


class TestSlidingWindowBehavior:
    """Test sliding window pruning behavior."""

    @pytest.mark.parametrize("window_size", [30, 60, 100])
    def test_window_enforces_limit(self, window_size: int):
        """Verify sliding window enforces message limit."""
        config = ModelConfig(
            model_id="test/model",
            provider="test",
            char_to_token_ratio=4.0,
            window_size=window_size,
        )
        generator = MockDataGenerator(config)

        initial_count = int(window_size * 1.5)
        messages = generator.create_conversation(
            initial_count // 2, include_tool_calls=False
        )
        agent = MockAgent(messages, config)

        manager = MappingConversationManager(
            window_size=window_size,
            preserve_first_messages=1,
        )
        manager.apply_management(agent)

        assert len(agent.messages) <= window_size

    def test_newest_messages_preserved(self):
        """Verify newest messages are preserved during pruning."""
        config = ModelConfig(
            model_id="test/model",
            provider="test",
            char_to_token_ratio=4.0,
            window_size=10,
        )
        generator = MockDataGenerator(config)

        messages = []
        for i in range(20):
            messages.append(generator.create_assistant_message(f"Message_{i}"))

        agent = MockAgent(messages, config)
        manager = MappingConversationManager(
            window_size=10,
            preserve_first_messages=1,
            preserve_recent_messages=5,
        )
        manager.apply_management(agent)

        remaining_texts = [
            block["text"]
            for msg in agent.messages
            for block in msg.get("content", [])
            if "text" in block
        ]

        assert any("19" in text for text in remaining_texts)
        assert any("18" in text for text in remaining_texts)

    def test_preserve_first_in_compression_zone(self):
        """Verify first messages are excluded from compression zone."""
        config = ModelConfig(
            model_id="test/model",
            provider="test",
            char_to_token_ratio=4.0,
            window_size=20,
        )
        generator = MockDataGenerator(config)

        tool_id = "first_tool"
        messages = [
            generator.create_user_message("Initial query"),
            generator.create_tool_use_message("shell", {"command": "nmap"}, tool_id),
            generator.create_large_tool_result(tool_id, TOOL_COMPRESS_THRESHOLD + 5000),
        ]
        for i in range(10):
            messages.append(generator.create_assistant_message(f"Message_{i}"))

        agent = MockAgent(messages, config)
        manager = MappingConversationManager(
            window_size=20,
            preserve_first_messages=3,
            preserve_recent_messages=5,
        )

        first_tool_result = messages[2]["content"][0]["toolResult"]["content"][0]["text"]
        original_length = len(first_tool_result)

        manager._apply_mapper(agent)

        preserved_result = agent.messages[2]["content"][0]["toolResult"]["content"][0]["text"]
        assert len(preserved_result) == original_length

    def test_dynamic_preserve_last_scaling(self):
        """Verify preserve_last scales with window size."""
        manager_60 = MappingConversationManager(window_size=60)
        manager_100 = MappingConversationManager(window_size=100)

        assert manager_60.preserve_last >= 8
        assert manager_60.preserve_last <= 60 * 0.5

        assert manager_100.preserve_last >= 8
        assert manager_100.preserve_last <= 100 * 0.5
        assert manager_100.preserve_last > manager_60.preserve_last


class TestToolResultCompression:
    """Test Layer 2 tool result compression."""

    def test_large_result_compression(self):
        """Verify large tool results are compressed."""
        mapper = LargeToolResultMapper(
            max_tool_chars=TOOL_COMPRESS_THRESHOLD,
            truncate_at=TOOL_COMPRESS_TRUNCATE,
        )

        generator = MockDataGenerator(CLAUDE_SONNET_CONFIG)
        tool_id = "test_tool"
        message = generator.create_large_tool_result(
            tool_id, TOOL_COMPRESS_THRESHOLD + 10000
        )

        result = mapper(message, 1, [message])

        assert result is not None
        compressed_content = result["content"][0]["toolResult"]["content"]
        compressed_text = " ".join(
            block.get("text", "") for block in compressed_content
        )
        assert "compressed" in compressed_text.lower()

    def test_small_result_preserved(self):
        """Verify small tool results are not compressed."""
        mapper = LargeToolResultMapper(
            max_tool_chars=TOOL_COMPRESS_THRESHOLD,
            truncate_at=TOOL_COMPRESS_TRUNCATE,
        )

        generator = MockDataGenerator(CLAUDE_SONNET_CONFIG)
        message = generator.create_large_tool_result("tool", 1000)

        result = mapper(message, 1, [message])

        result_content = result["content"][0]["toolResult"]["content"][0]["text"]
        assert "compressed" not in result_content.lower()
        assert len(result_content) == 1000

    def test_compression_produces_valid_structure(self):
        """Verify compressed results maintain valid message structure."""
        mapper = LargeToolResultMapper(
            max_tool_chars=1000,
            truncate_at=100,
        )

        generator = MockDataGenerator(CLAUDE_SONNET_CONFIG)
        message = generator.create_large_tool_result("tool", 5000)

        result = mapper(message, 1, [message])

        assert "content" in result
        assert len(result["content"]) > 0
        tool_result = result["content"][0].get("toolResult")
        assert tool_result is not None
        assert "content" in tool_result
        assert "status" in tool_result

    def test_json_compression_metadata(self):
        """Verify JSON compression includes structured metadata."""
        mapper = LargeToolResultMapper(max_tool_chars=100, truncate_at=50)

        message = {
            "role": "user",
            "content": [
                {
                    "toolResult": {
                        "toolUseId": "json_test",
                        "status": "success",
                        "content": [
                            {"json": {"key_" + str(i): "value" * 50 for i in range(10)}}
                        ],
                    }
                }
            ],
        }

        result = mapper(message, 1, [message])

        compressed_content = result["content"][0]["toolResult"]["content"]
        json_blocks = [b for b in compressed_content if "json" in b]

        assert len(json_blocks) > 0
        json_data = json_blocks[0]["json"]
        assert "_compressed" in json_data
        assert json_data["_compressed"] is True


class TestPreservationZones:
    """Test preservation zone behavior."""

    def test_preservation_overlap_small_conversation(self):
        """Verify small conversations skip pruning gracefully."""
        config = ModelConfig(
            model_id="test/model",
            provider="test",
            char_to_token_ratio=4.0,
            window_size=100,
        )
        generator = MockDataGenerator(config)

        messages = generator.create_conversation(2, include_tool_calls=False)
        agent = MockAgent(messages, config)

        manager = MappingConversationManager(
            window_size=100,
            preserve_first_messages=1,
            preserve_recent_messages=10,
        )
        manager._apply_mapper(agent)

        assert len(agent.messages) == len(messages)

    def test_preservation_does_not_exceed_fifty_percent(self):
        """Verify total preservation does not exceed 50% of window."""
        manager = MappingConversationManager(
            window_size=20,
            preserve_first_messages=5,
            preserve_recent_messages=15,
        )

        total_preserved = manager.preserve_first + manager.preserve_last
        max_allowed = int(20 * 0.5)

        assert total_preserved <= max_allowed


class TestProactiveCompression:
    """Test proactive compression behavior."""

    def test_proactive_threshold(self):
        """Verify proactive compression triggers at threshold."""
        config = ModelConfig(
            model_id="test/model",
            provider="test",
            char_to_token_ratio=4.0,
            window_size=100,
        )

        threshold_message_count = int(100 * PROACTIVE_COMPRESSION_THRESHOLD) + 5
        generator = MockDataGenerator(config)
        messages = []
        for i in range(threshold_message_count):
            messages.append(generator.create_assistant_message(f"Message {i}"))

        agent = MockAgent(messages, config)

        manager = MappingConversationManager(window_size=100)
        manager.apply_management(agent)

        assert len(agent.messages) <= 100


class TestMultiModelConfiguration:
    """Test conversation management with different model configurations."""

    @pytest.mark.parametrize(
        "config",
        [CLAUDE_SONNET_CONFIG, GPT_5_CONFIG, KIMI_K2_CONFIG, GEMINI_CONFIG],
    )
    def test_window_management_per_model(self, config: ModelConfig):
        """Verify window management works correctly for each model config."""
        generator = MockDataGenerator(config)
        messages = generator.create_window_boundary_conversation()
        agent = MockAgent(messages, config)

        manager = MappingConversationManager(
            window_size=config.window_size,
            preserve_first_messages=config.preserve_first,
        )
        manager.apply_management(agent)

        assert len(agent.messages) <= config.window_size

    @pytest.mark.parametrize(
        "config",
        [CLAUDE_SONNET_CONFIG, GPT_5_CONFIG, KIMI_K2_CONFIG, GEMINI_CONFIG],
    )
    def test_compression_per_model(self, config: ModelConfig):
        """Verify compression works correctly for each model config."""
        generator = MockDataGenerator(config)
        messages = generator.create_compression_threshold_conversation(2)
        agent = MockAgent(messages, config)

        manager = MappingConversationManager(
            window_size=config.window_size,
            preserve_first_messages=config.preserve_first,
        )

        initial_tokens = _estimate_prompt_tokens(agent)
        manager.apply_management(agent)
        final_tokens = _estimate_prompt_tokens(agent)

        assert final_tokens <= initial_tokens


class TestReductionEventTracking:
    """Test context reduction event tracking."""

    def test_reduction_event_recorded(self):
        """Verify reduction events are recorded on agent."""
        config = ModelConfig(
            model_id="test/model",
            provider="test",
            char_to_token_ratio=4.0,
            window_size=5,
        )
        generator = MockDataGenerator(config)
        messages = generator.create_conversation(10, include_tool_calls=False)
        agent = MockAgent(messages, config)
        agent._pending_reduction_reason = "test reduction"

        manager = MappingConversationManager(window_size=5)
        manager.reduce_context(agent)

        events = getattr(agent, "_context_reduction_events", [])
        assert len(events) > 0
        assert events[-1]["reason"] == "test reduction"

    def test_reduction_history_capped(self):
        """Verify reduction history does not grow unbounded."""
        config = ModelConfig(
            model_id="test/model",
            provider="test",
            char_to_token_ratio=4.0,
            window_size=5,
        )
        generator = MockDataGenerator(config)
        agent = MockAgent([], config)
        manager = MappingConversationManager(window_size=5)

        for i in range(20):
            agent.messages = generator.create_conversation(8, include_tool_calls=False)
            agent._pending_reduction_reason = f"reduction {i}"
            manager.reduce_context(agent)

        events = getattr(agent, "_context_reduction_events", [])
        assert len(events) <= 5


class TestInPlaceModification:
    """Test SDK contract for in-place message modification."""

    def test_messages_modified_in_place(self):
        """Verify messages are modified in-place per SDK contract."""
        config = ModelConfig(
            model_id="test/model",
            provider="test",
            char_to_token_ratio=4.0,
            window_size=5,
        )
        generator = MockDataGenerator(config)
        messages = generator.create_conversation(10, include_tool_calls=False)
        agent = MockAgent(messages, config)

        original_list_id = id(agent.messages)

        manager = MappingConversationManager(window_size=5)
        manager.apply_management(agent)

        assert id(agent.messages) == original_list_id
        assert len(agent.messages) <= 5

    def test_deep_copy_prevents_aliasing(self):
        """Verify compressed messages are deep copied to prevent aliasing."""
        mapper = LargeToolResultMapper(max_tool_chars=100, truncate_at=50)

        original_message = {
            "role": "user",
            "content": [
                {
                    "toolResult": {
                        "toolUseId": "test",
                        "status": "success",
                        "content": [{"text": "X" * 500}],
                    }
                }
            ],
        }

        original_copy = copy.deepcopy(original_message)
        result = mapper(original_message, 1, [original_message])

        assert original_message == original_copy


class TestStatelessBehavior:
    """Test stateless behavior per SDK MessageMapper protocol."""

    def test_mapper_stateless(self):
        """Verify mapper produces consistent results without state."""
        mapper = LargeToolResultMapper(max_tool_chars=100, truncate_at=50)

        message = {
            "role": "user",
            "content": [
                {
                    "toolResult": {
                        "toolUseId": "test",
                        "status": "success",
                        "content": [{"text": "X" * 500}],
                    }
                }
            ],
        }

        result1 = mapper(copy.deepcopy(message), 1, [message])
        result2 = mapper(copy.deepcopy(message), 1, [message])

        compressed1 = result1["content"][0]["toolResult"]["content"]
        compressed2 = result2["content"][0]["toolResult"]["content"]

        texts1 = [b.get("text", "") for b in compressed1]
        texts2 = [b.get("text", "") for b in compressed2]

        for t1, t2 in zip(texts1, texts2):
            if "X" in t1 or "truncated" in t1:
                assert t1 == t2


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_content_blocks(self):
        """Verify empty content blocks are handled."""
        mapper = LargeToolResultMapper()
        message = {"role": "assistant", "content": []}

        result = mapper(message, 0, [message])
        assert result is not None

    def test_none_message_content(self):
        """Verify None content is handled."""
        mapper = LargeToolResultMapper()
        message = {"role": "assistant", "content": None}

        result = mapper(message, 0, [message])
        assert result is not None

    def test_window_size_one(self):
        """Verify minimum window size works."""
        generator = MockDataGenerator(CLAUDE_SONNET_CONFIG)
        messages = generator.create_conversation(5, include_tool_calls=False)
        agent = MockAgent(messages, CLAUDE_SONNET_CONFIG)

        manager = MappingConversationManager(
            window_size=1,
            preserve_first_messages=0,
            preserve_recent_messages=1,
        )
        manager.apply_management(agent)

        assert len(agent.messages) <= 1

    def test_negative_window_size_corrected(self):
        """Verify negative window size is corrected to minimum."""
        manager = MappingConversationManager(window_size=-5)
        assert manager._window_size >= 1

    def test_very_large_tool_result(self):
        """Verify very large tool results are handled."""
        mapper = LargeToolResultMapper(
            max_tool_chars=TOOL_COMPRESS_THRESHOLD,
            truncate_at=TOOL_COMPRESS_TRUNCATE,
        )

        generator = MockDataGenerator(CLAUDE_SONNET_CONFIG)
        message = generator.create_large_tool_result("huge_tool", 1_000_000)

        result = mapper(message, 1, [message])

        assert result is not None
        compressed_content = result["content"][0]["toolResult"]["content"]
        total_compressed_size = sum(
            len(str(block)) for block in compressed_content
        )
        assert total_compressed_size < 1_000_000
