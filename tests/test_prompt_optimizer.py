import json
from pathlib import Path

import pytest

from modules.tools.prompt_optimizer import (
    PromptOptimizerError,
    prompt_optimizer,
    _extract_protected_blocks,
    _llm_rewrite_execution_prompt,
)


def _setup_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "outputs" / "target" / "OP_TEST"
    root.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("CYBER_OPERATION_ROOT", str(root))
    monkeypatch.setenv("CYBER_OPERATION_ID", "OP_TEST")
    monkeypatch.setenv("CYBER_TARGET_NAME", "target")
    return root


def _install_llm_rewrite_stubs(monkeypatch: pytest.MonkeyPatch, *, response_text: str, call_counter: dict) -> None:
    """Patch config manager + strands Agent/model classes so _llm_rewrite_execution_prompt is deterministic."""
    import types

    class _DummyServerConfig:
        llm = types.SimpleNamespace(model_id="dummy-model")

    class _DummyConfigManager:
        def get_provider(self) -> str:
            return "ollama"

        def get_server_config(self, provider: str):
            return _DummyServerConfig()

        def get_default_region(self) -> str:
            return "us-east-1"

        def get_local_model_config(self, model_id: str, provider: str):
            return {
                "host": "http://127.0.0.1:11434",
                "model_id": "dummy-model",
                "temperature": 0.0,
                "timeout": 1,
            }

    class _DummyModel:
        def __init__(self, *args, **kwargs):
            self.args = args
            self.kwargs = kwargs

    class _FakeAgent:
        def __init__(self, model=None, system_prompt: str = ""):
            self.model = model
            self.system_prompt = system_prompt

        def __call__(self, request: str):
            call_counter["count"] = call_counter.get("count", 0) + 1
            return response_text

    # Patch config manager factory
    import modules.config.manager as config_manager_mod

    monkeypatch.setattr(config_manager_mod, "get_config_manager", lambda: _DummyConfigManager())

    # Patch strands Agent + Ollama model class
    import strands
    import strands.models.ollama as ollama_mod

    monkeypatch.setattr(strands, "Agent", _FakeAgent)
    monkeypatch.setattr(ollama_mod, "OllamaModel", _DummyModel)


def test_prompt_optimizer_apply_and_reset(tmp_path, monkeypatch):
    root = _setup_env(tmp_path, monkeypatch)

    result = prompt_optimizer(
        action="apply",
        overlay={
            "directives": ["Focus on consolidation"],
            "trajectory": {"mode": "consolidate"},
        },
        trigger="agent_reflection",
        current_step=12,
        expires_after_steps=10,
    )

    assert result["status"] == "success"
    assert result["action"] == "apply"

    overlay_path = root / "adaptive_prompt.json"
    assert overlay_path.exists()
    data = json.loads(overlay_path.read_text(encoding="utf-8"))
    assert data["payload"]["directives"] == ["Focus on consolidation"]
    assert data["origin"] == "agent_reflection"
    assert data["expires_after_steps"] == 10

    # Cooldown should be persisted and scoped to OP_TEST
    assert data["cooldown"]["operation_id"] == "OP_TEST"
    assert data["cooldown"]["last_step"] == 12
    assert data["cooldown"]["cooldown_steps"] == 8

    reset_result = prompt_optimizer(action="reset")
    assert reset_result["status"] == "success"
    assert reset_result["overlay"] is None
    assert not overlay_path.exists()


def test_prompt_optimizer_cooldown_enforced(tmp_path, monkeypatch):
    _setup_env(tmp_path, monkeypatch)

    prompt_optimizer(
        action="apply", overlay={"directives": ["initial"]}, current_step=5
    )

    # Cooldown state should exist and be scoped to OP_TEST
    overlay_path = Path(__import__("os").environ["CYBER_OPERATION_ROOT"]) / "adaptive_prompt.json"
    data = json.loads(overlay_path.read_text(encoding="utf-8"))
    assert data["cooldown"]["operation_id"] == "OP_TEST"
    assert data["cooldown"]["last_step"] == 5

    with pytest.raises(PromptOptimizerError):
        prompt_optimizer(
            action="apply", overlay={"directives": ["too_soon"]}, current_step=10
        )

    # After reset, cooldown clears
    prompt_optimizer(action="reset")
    prompt_optimizer(
        action="apply", overlay={"directives": ["after_reset"]}, current_step=25
    )


def test_prompt_optimizer_view_and_update(tmp_path, monkeypatch):
    root = _setup_env(tmp_path, monkeypatch)

    view_result = prompt_optimizer(action="view")
    assert view_result["status"] == "success"
    assert view_result["overlay"] is None
    assert view_result.get("overlayActive") is False

    update_result = prompt_optimizer(
        action="update",
        prompt="Directive alpha\nDirective beta",
        current_step=9,
        trigger="reflection",
        note="initial rewrite",
    )
    assert update_result["action"] == "update"
    overlay_path = root / "adaptive_prompt.json"
    data = json.loads(overlay_path.read_text(encoding="utf-8"))
    assert data["payload"]["directives"] == ["Directive alpha", "Directive beta"]
    assert data["origin"] == "reflection"
    assert data["note"] == "initial rewrite"


def test_prompt_optimizer_add_context(tmp_path, monkeypatch):
    overlay_dir = _setup_env(tmp_path, monkeypatch)
    prompt_optimizer(action="apply", overlay={"directives": ["seed"]}, current_step=1)
    prompt_optimizer(
        action="add_context",
        context="expand attack surface focus",
        current_step=20,
        reviewer="operator",
    )

    overlay_path = overlay_dir / "adaptive_prompt.json"
    data = json.loads(overlay_path.read_text(encoding="utf-8"))
    assert data["payload"]["directives"] == ["seed", "expand attack surface focus"]
    assert data["reviewer"] == "operator"
    assert "history" in data


def test_prompt_optimizer_update_requires_prompt(tmp_path, monkeypatch):
    _setup_env(tmp_path, monkeypatch)
    with pytest.raises(PromptOptimizerError):
        prompt_optimizer(action="update", current_step=3)


def test_prompt_optimizer_optimize_execution_handles_missing_file(
    tmp_path, monkeypatch
):
    """Test optimize_execution handles missing execution_prompt_optimized.txt"""
    _setup_env(tmp_path, monkeypatch)

    # Don't create execution_prompt_optimized.txt

    result = prompt_optimizer(
        action="optimize_execution",
        learned_patterns="Some patterns",
        remove_dead_ends=["tactic_a"],
        focus_areas=["tactic_b"],
    )

    assert result["status"] == "error"
    assert "content" in result
    error_text = result["content"][0]["text"].lower()
    assert "not found" in error_text


def test_prompt_optimizer_optimize_execution_with_empty_lists(tmp_path, monkeypatch):
    """Test optimize_execution with empty remove_dead_ends and focus_areas"""
    import sys
    from unittest.mock import patch

    root = _setup_env(tmp_path, monkeypatch)

    optimized_path = root / "execution_prompt_optimized.txt"
    optimized_path.write_text("Current prompt")

    # Get the actual module object from sys.modules
    prompt_opt_module = sys.modules["modules.tools.prompt_optimizer"]

    with patch.object(
        prompt_opt_module, "_llm_rewrite_execution_prompt"
    ) as mock_rewrite:
        mock_rewrite.return_value = "Optimized prompt"

        result = prompt_optimizer(
            action="optimize_execution",
            learned_patterns="General learning without specific tactics",
            remove_dead_ends=[],
            focus_areas=[],
        )

    assert result["status"] == "success"
    mock_rewrite.assert_called_once()
    call_kwargs = mock_rewrite.call_args[1]
    assert call_kwargs["remove_tactics"] == []
    assert call_kwargs["focus_tactics"] == []
    assert optimized_path.exists()


def test_prompt_optimizer_optimize_execution_with_empty_lists_dev_backup(tmp_path, monkeypatch):
    """Test optimize_execution keeps previous prompts for comparison"""
    import sys
    from unittest.mock import patch

    root = _setup_env(tmp_path, monkeypatch)

    optimized_path = root / "execution_prompt_optimized.txt"
    optimized_path.write_text("Current prompt")

    # Get the actual module object from sys.modules
    prompt_opt_module = sys.modules["modules.tools.prompt_optimizer"]

    with patch.object(
            prompt_opt_module, "_llm_rewrite_execution_prompt"
    ) as mock_rewrite:
        mock_rewrite.return_value = "Optimized prompt"

        for idx in range(3):
            result = prompt_optimizer(
                action="optimize_execution",
                learned_patterns="General learning without specific tactics",
                remove_dead_ends=[],
                focus_areas=[],
            )

    assert result["status"] == "success"
    mock_rewrite.assert_called()
    assert optimized_path.exists()
    assert (root / "execution_prompt_optimized.txt.1").exists()
    assert (root / "execution_prompt_optimized.txt.2").exists()
    assert (root / "execution_prompt_optimized.txt.3").exists()
    assert not (root / "execution_prompt_optimized.txt.4").exists()


def test_prompt_optimizer_quarantines_invalid_overlay_json(tmp_path, monkeypatch):
    root = _setup_env(tmp_path, monkeypatch)

    overlay_path = root / "adaptive_prompt.json"
    overlay_path.write_text("{not valid json", encoding="utf-8")

    view_result = prompt_optimizer(action="view")
    assert view_result["status"] == "success"
    assert view_result["overlay"] is None

    # Corrupted overlay should be quarantined (moved aside)
    assert not overlay_path.exists()
    quarantined = sorted(root.glob("adaptive_prompt.json.corrupt.*"))
    assert quarantined, "Expected corrupt overlay to be quarantined"


def test_prompt_optimizer_quarantines_non_dict_overlay(tmp_path, monkeypatch):
    root = _setup_env(tmp_path, monkeypatch)

    overlay_path = root / "adaptive_prompt.json"
    overlay_path.write_text(json.dumps(["not", "a", "dict"]), encoding="utf-8")

    view_result = prompt_optimizer(action="view")
    assert view_result["status"] == "success"
    assert view_result["overlay"] is None

    assert not overlay_path.exists()
    quarantined = sorted(root.glob("adaptive_prompt.json.corrupt.*"))
    assert quarantined, "Expected non-dict overlay to be quarantined"


def test_prompt_optimizer_cooldown_scoped_by_operation_id(tmp_path, monkeypatch):
    _setup_env(tmp_path, monkeypatch)

    prompt_optimizer(action="apply", overlay={"directives": ["initial"]}, current_step=5)

    # Different operation_id should not be subject to the previous cooldown
    monkeypatch.setenv("CYBER_OPERATION_ID", "OP_OTHER")
    result = prompt_optimizer(
        action="apply", overlay={"directives": ["new_op"]}, current_step=10
    )
    assert result["status"] == "success"


def test_prompt_optimizer_cooldown_step_rollback_treated_as_reset(tmp_path, monkeypatch):
    _setup_env(tmp_path, monkeypatch)

    prompt_optimizer(action="apply", overlay={"directives": ["initial"]}, current_step=50)

    # If steps go backwards, cooldown should be treated as reset/new timeline
    result = prompt_optimizer(
        action="apply", overlay={"directives": ["rollback_ok"]}, current_step=10
    )
    assert result["status"] == "success"


def test_extract_protected_blocks_round_trip():
    text = "a\n<!-- PROTECTED -->\nKEEP\n<!-- /PROTECTED -->\nb\n"
    blocks = _extract_protected_blocks(text)
    assert blocks == ["<!-- PROTECTED -->\nKEEP\n<!-- /PROTECTED -->"]


def test_llm_rewrite_rejects_line_growth(tmp_path, monkeypatch):
    _setup_env(tmp_path, monkeypatch)
    monkeypatch.setenv("CYBER_OPERATION_ID", "OP_LINE")

    # Reset per-operation failure cache between tests
    if hasattr(_llm_rewrite_execution_prompt, "_failure_counts"):
        _llm_rewrite_execution_prompt._failure_counts.clear()

    current_prompt = (
            "L1 " + ("x" * 60) + "\n" +
            "L2 " + ("y" * 60) + "\n" +
            "L3 " + ("z" * 60)
    )
    # 4 lines -> should be rejected even if within ±15% chars
    rewritten = current_prompt + "\nL4 extra"

    calls = {"count": 0}
    _install_llm_rewrite_stubs(monkeypatch, response_text=rewritten, call_counter=calls)

    out = _llm_rewrite_execution_prompt(
        current_prompt=current_prompt,
        learned_patterns="evidence",
        remove_tactics=[],
        focus_tactics=[],
    )
    assert calls["count"] == 1
    assert out == current_prompt


def test_llm_rewrite_rejects_protected_block_modification(tmp_path, monkeypatch):
    _setup_env(tmp_path, monkeypatch)
    monkeypatch.setenv("CYBER_OPERATION_ID", "OP_PROT")

    if hasattr(_llm_rewrite_execution_prompt, "_failure_counts"):
        _llm_rewrite_execution_prompt._failure_counts.clear()

    current_prompt = (
            "Intro " + ("a" * 40) + "\n"
            "<!-- PROTECTED -->\n"
            "KEEP_THIS\n"
            "<!-- /PROTECTED -->\n"
            "Outro " + ("b" * 40)
    )

    # Same number of lines, within bounds, but changes protected content
    rewritten = current_prompt.replace("KEEP_THIS", "CHANGED")

    calls = {"count": 0}
    _install_llm_rewrite_stubs(monkeypatch, response_text=rewritten, call_counter=calls)

    out = _llm_rewrite_execution_prompt(
        current_prompt=current_prompt,
        learned_patterns="evidence",
        remove_tactics=[],
        focus_tactics=[],
    )
    assert calls["count"] == 1
    assert out == current_prompt


def test_llm_rewrite_failure_count_scoped_per_operation(tmp_path, monkeypatch):
    _setup_env(tmp_path, monkeypatch)

    if hasattr(_llm_rewrite_execution_prompt, "_failure_counts"):
        _llm_rewrite_execution_prompt._failure_counts.clear()

    current_prompt = (
            "L1 " + ("x" * 60) + "\n" +
            "L2 " + ("y" * 60) + "\n" +
            "L3 " + ("z" * 60)
    )

    # Force repeated failures by returning a line-growing rewrite
    bad_rewrite = current_prompt + "\nL4"

    calls = {"count": 0}
    _install_llm_rewrite_stubs(monkeypatch, response_text=bad_rewrite, call_counter=calls)

    monkeypatch.setenv("CYBER_OPERATION_ID", "OP_FAIL")
    for _ in range(4):
        out = _llm_rewrite_execution_prompt(
            current_prompt=current_prompt,
            learned_patterns="evidence",
            remove_tactics=[],
            focus_tactics=[],
        )
        assert out == current_prompt

    # The 4th call should have short-circuited (no Agent call) due to 3 prior failures
    assert calls["count"] == 3

    # Different operation id should get its own failure budget
    monkeypatch.setenv("CYBER_OPERATION_ID", "OP_FAIL_OTHER")
    out2 = _llm_rewrite_execution_prompt(
        current_prompt=current_prompt,
        learned_patterns="evidence",
        remove_tactics=[],
        focus_tactics=[],
    )
    assert out2 == current_prompt
    assert calls["count"] == 4
