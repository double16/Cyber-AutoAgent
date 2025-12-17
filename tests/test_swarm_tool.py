import unittest
from types import SimpleNamespace
from unittest.mock import patch

import modules.tools.swarm as swarm_mod
from strands.models.ollama import OllamaModel


class FakeSwarm:
    """Captures constructor args and returns a predefined result on call."""
    last_init_kwargs = None
    last_task = None
    result_to_return = None

    def __init__(self, **kwargs):
        FakeSwarm.last_init_kwargs = kwargs

    def __call__(self, task: str):
        FakeSwarm.last_task = task
        return FakeSwarm.result_to_return


def _mk_result():
    # Shape matches what swarm() expects.
    content_a1 = [SimpleNamespace(text="A1 says hello.")]
    content_a2 = [SimpleNamespace(text="A2 final answer.")]
    node_result_a1 = SimpleNamespace(result=SimpleNamespace(content=content_a1))
    node_result_a2 = SimpleNamespace(result=SimpleNamespace(content=content_a2))

    return SimpleNamespace(
        status="success",
        execution_time=1234,
        execution_count=7,
        node_history=[SimpleNamespace(node_id="agent1"), SimpleNamespace(node_id="agent2")],
        results={"agent1": node_result_a1, "agent2": node_result_a2},
        accumulated_usage={"inputTokens": 10, "outputTokens": 20, "totalTokens": 30},
    )


class SwarmToolTests(unittest.TestCase):
    def test_swarm_returns_error_when_agents_missing(self):
        out = swarm_mod.swarm(task="x", agents=[])
        self.assertEqual("error", out["status"])
        self.assertIn("At least one agent specification is required", out["content"][0]["text"])

    @patch.object(swarm_mod, "create_rich_status_panel", autospec=True)
    @patch.object(swarm_mod.console_util, "create", autospec=True)
    def test_swarm_enforces_minimums_and_adjusts_timeouts_for_ollama(self, _console_create, _rich_panel):
        FakeSwarm.result_to_return = _mk_result()

        # Make first agent appear to have an Ollama model timeout > 300.
        ollama_model = OllamaModel(
            host="http://127.0.0.1:11434",
            model_id="llama3.2",
            ollama_client_args={"timeout": "400"}
        )
        dummy_first = SimpleNamespace(model=ollama_model)
        dummy_second = SimpleNamespace(model=object())

        with patch.object(swarm_mod, "_create_custom_agents", autospec=True, return_value=[dummy_first, dummy_second]), \
                patch.object(swarm_mod, "Swarm", autospec=True, side_effect=lambda **kw: FakeSwarm(**kw)):

            out = swarm_mod.swarm(
                task="do the thing",
                agents=[{"name": "agent1"}, {"name": "agent2"}],
                max_handoffs=1,
                max_iterations=2,
                execution_timeout=1.0,
                node_timeout=1.0,
                repetitive_handoff_detection_window=1,
                repetitive_handoff_min_unique_agents=1,
                agent=None,
            )

        self.assertEqual("success", out["status"])
        self.assertEqual("do the thing", FakeSwarm.last_task)

        # Minimum enforcement
        init = FakeSwarm.last_init_kwargs
        self.assertEqual(20, init["max_handoffs"])
        self.assertEqual(20, init["max_iterations"])
        self.assertEqual(8, init["repetitive_handoff_detection_window"])
        self.assertEqual(3, init["repetitive_handoff_min_unique_agents"])

        # Timeout adjustments based on model_timeout=400
        self.assertEqual(1200.0, init["execution_timeout"])  # 400 * 3
        self.assertEqual(400.0, init["node_timeout"])

        # Response includes final team result content
        txt = out["content"][0]["text"]
        self.assertIn("**Custom Agent Team Execution Complete**", txt)
        self.assertIn("** Final Team Result:**", txt)
        self.assertIn("A2 final answer.", txt)
        self.assertIn(" Team Resource Usage:", txt)

    @patch.object(swarm_mod, "create_rich_status_panel", autospec=True)
    @patch.object(swarm_mod.console_util, "create", autospec=True)
    def test_swarm_returns_error_on_exception(self, _console_create, _rich_panel):
        # Force sdk swarm execution to raise
        class BoomSwarm:
            def __init__(self, **_kwargs):
                pass

            def __call__(self, _task: str):
                raise RuntimeError("kaboom")

        with patch.object(swarm_mod, "_create_custom_agents", autospec=True, return_value=[SimpleNamespace(model=object())]), \
                patch.object(swarm_mod, "Swarm", autospec=True, side_effect=lambda **kw: BoomSwarm(**kw)):
            out = swarm_mod.swarm(task="x", agents=[{"name": "a"}])

        self.assertEqual("error", out["status"])
        self.assertIn("Custom swarm execution failed: kaboom", out["content"][0]["text"])
