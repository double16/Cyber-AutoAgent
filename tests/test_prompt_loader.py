#!/usr/bin/env python3
import os
from pathlib import Path
from unittest.mock import patch

from modules.prompts.factory import ModulePromptLoader


@patch.dict(os.environ, {"CYBER_PLUGIN_PATH": "/a:/b:/c"})
def test_module_prompt_loader_parses_plugin_path(tmp_path, monkeypatch):
    loader = ModulePromptLoader()
    assert loader.plugin_dirs == [
        Path("/a"),
        Path("/b"),
        Path("/c"),
        Path("~/.cyber-autoagent/modules/").expanduser(),
        (Path(__file__).parent.parent / "src" / "modules" / "operation_plugins").resolve()
    ]


def test_module_prompt_loader_discovers_tools(tmp_path, monkeypatch):
    # Create fake operation_plugins structure with a tool
    plugins_dir = tmp_path / "operation_plugins" / "web" / "tools"
    plugins_dir.mkdir(parents=True)
    (plugins_dir.parent / "module.yaml").write_text("name: web\n")
    (plugins_dir / "__init__.py").write_text("\n")
    (plugins_dir / "quick_recon.py").write_text("# tool\n")

    loader = ModulePromptLoader()
    # Point the loader at our temp plugins dir
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "does_not_exist", tmp_path / "operation_plugins"])

    tools, tools_remaining = loader.discover_module_tools("web")
    names = [Path(p).name for p in tools]
    assert "quick_recon.py" in names
    assert "__init__.py" not in names
    assert tools_remaining is None


def test_module_prompt_loader_discovers_tools_allowlist(tmp_path, monkeypatch):
    # Create fake operation_plugins structure with a tool
    plugins_dir = tmp_path / "operation_plugins" / "web" / "tools"
    plugins_dir.mkdir(parents=True)
    (plugins_dir.parent / "module.yaml").write_text("name: web\n")
    (plugins_dir / "__init__.py").write_text("\n")
    (plugins_dir / "quick_recon.py").write_text("# tool\n")
    (plugins_dir / ".." / "module.yaml").write_text("tools:\n  - quick_recon\n  - http_request\n  - browser_*\n")

    loader = ModulePromptLoader()
    # Point the loader at our temp plugins dir
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    tools, tools_remaining = loader.discover_module_tools("web")
    names = [Path(p).name for p in tools]
    assert "quick_recon.py" in names
    assert "__init__.py" not in names
    assert tools_remaining == ['http_request', 'browser_*']


def test_module_prompt_loader_discovers_tools_inheritance_union_and_precedence(tmp_path, monkeypatch):
    """Tool discovery should union tools across inheritance with correct precedence."""
    # app extends web, ctf
    app_dir = tmp_path / "operation_plugins" / "app"
    app_tools = app_dir / "tools"
    app_tools.mkdir(parents=True)
    (app_dir / "module.yaml").write_text("extend:\n  - web\n  - ctf\n")
    (app_tools / "__init__.py").write_text("\n")
    (app_tools / "recon.py").write_text("# app tool\n")
    (app_tools / "shared.py").write_text("# app shared\n")

    web_dir = tmp_path / "operation_plugins" / "web"
    web_tools = web_dir / "tools"
    web_tools.mkdir(parents=True)
    (web_dir / "module.yaml").write_text("name: web\n")
    (web_tools / "__init__.py").write_text("\n")
    (web_tools / "web_only.py").write_text("# web only\n")
    (web_tools / "shared.py").write_text("# web shared\n")

    ctf_dir = tmp_path / "operation_plugins" / "ctf"
    ctf_tools = ctf_dir / "tools"
    ctf_tools.mkdir(parents=True)
    (ctf_dir / "module.yaml").write_text("name: ctf\n")
    (ctf_tools / "__init__.py").write_text("\n")
    (ctf_tools / "ctf_only.py").write_text("# ctf only\n")
    (ctf_tools / "shared.py").write_text("# ctf shared\n")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    tools, tools_remaining = loader.discover_module_tools("app")
    names = [Path(p).name for p in tools]

    # union
    assert "recon.py" in names
    assert "shared.py" in names
    assert "web_only.py" in names
    assert "ctf_only.py" in names

    # precedence: shared.py should come from app (module overrides parents)
    shared_path = next(Path(p) for p in tools if Path(p).name == "shared.py")
    assert str(shared_path).endswith("/app/tools/shared.py")

    assert tools_remaining is None


def test_module_prompt_loader_discovers_tools_parent_precedence_order(tmp_path, monkeypatch):
    """If module lacks a tool but multiple parents provide it, extend order determines precedence."""
    # app extends web, ctf; app has no shared.py
    app_dir = tmp_path / "operation_plugins" / "app"
    app_tools = app_dir / "tools"
    app_tools.mkdir(parents=True)
    (app_dir / "module.yaml").write_text("extend:\n  - web\n  - ctf\n")
    (app_tools / "__init__.py").write_text("\n")

    web_dir = tmp_path / "operation_plugins" / "web"
    web_tools = web_dir / "tools"
    web_tools.mkdir(parents=True)
    (web_dir / "module.yaml").write_text("name: web\n")
    (web_tools / "__init__.py").write_text("\n")
    (web_tools / "shared.py").write_text("# web shared\n")

    ctf_dir = tmp_path / "operation_plugins" / "ctf"
    ctf_tools = ctf_dir / "tools"
    ctf_tools.mkdir(parents=True)
    (ctf_dir / "module.yaml").write_text("name: ctf\n")
    (ctf_tools / "__init__.py").write_text("\n")
    (ctf_tools / "shared.py").write_text("# ctf shared\n")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    tools, _ = loader.discover_module_tools("app")
    shared_path = next(Path(p) for p in tools if Path(p).name == "shared.py")
    assert str(shared_path).endswith("/web/tools/shared.py")


def test_module_prompt_loader_tools_allowlist_not_inherited(tmp_path, monkeypatch):
    """Base module tools allowlist should not filter inherited module tools."""
    # app extends web; app allowlists only recon
    app_dir = tmp_path / "operation_plugins" / "app"
    app_tools = app_dir / "tools"
    app_tools.mkdir(parents=True)
    (app_dir / "module.yaml").write_text(
        "extend:\n  - web\n\ntools:\n  - recon\n  - missing_tool\n"
    )
    (app_tools / "__init__.py").write_text("\n")
    (app_tools / "recon.py").write_text("# app recon\n")
    (app_tools / "app_extra.py").write_text("# should be filtered by app allowlist\n")

    web_dir = tmp_path / "operation_plugins" / "web"
    web_tools = web_dir / "tools"
    web_tools.mkdir(parents=True)
    (web_dir / "module.yaml").write_text("name: web\n")
    (web_dir / "module.yaml").write_text(
        "tools:\n  - web_only\n"
    )
    (web_tools / "__init__.py").write_text("\n")
    (web_tools / "web_only.py").write_text("# inherited tool should remain\n")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    tools, tools_remaining = loader.discover_module_tools("app")
    names = [Path(p).name for p in tools]

    # app allowlist applies to app only
    assert "recon.py" in names
    assert "app_extra.py" not in names

    # inherited tools still included
    assert "web_only.py" not in names

    # missing allowlisted tools returned only for base module
    assert tools_remaining == ["missing_tool"]


def test_module_prompt_loader_load_module_report_prompt(tmp_path, monkeypatch):
    # Create a report_prompt.md for module
    module_dir = tmp_path / "operation_plugins" / "web"
    module_dir.mkdir(parents=True)
    (module_dir / "module.yaml").write_text("name: web\n")
    (module_dir / "report_prompt.md").write_text("Report Guidance\n")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    content = loader.load_module_report_prompt("web")
    assert "Report Guidance" in content


def test_module_prompt_loader_load_module_report_prompt_path_order(tmp_path, monkeypatch):
    module_dir1 = tmp_path / "operation_plugins1" / "web"
    module_dir1.mkdir(parents=True)
    (module_dir1 / "module.yaml").write_text("name: web\n")
    (module_dir1 / "report_prompt.md").write_text("Report Guidance\n")

    module_dir2 = tmp_path / "operation_plugins2" / "web"
    module_dir2.mkdir(parents=True)
    (module_dir2 / "module.yaml").write_text("name: web\n")
    (module_dir2 / "report_prompt.md").write_text("Wrong File!\n")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins1", tmp_path / "operation_plugins2"])

    content = loader.load_module_report_prompt("web")
    assert "Report Guidance" in content


def test_module_prompt_loader_report_prompt_inheritance_order(tmp_path, monkeypatch):
    """If prompt is missing in module, it should be resolved from parents in extend order."""
    # app extends web, ctf (web has priority)
    app_dir = tmp_path / "operation_plugins" / "app"
    app_dir.mkdir(parents=True)
    (app_dir / "module.yaml").write_text("extend:\n  - web\n  - ctf\n")

    web_dir = tmp_path / "operation_plugins" / "web"
    web_dir.mkdir(parents=True)
    (web_dir / "module.yaml").write_text("name: web\n")
    (web_dir / "report_prompt.md").write_text("WEB REPORT\n")

    ctf_dir = tmp_path / "operation_plugins" / "ctf"
    ctf_dir.mkdir(parents=True)
    (ctf_dir / "module.yaml").write_text("name: ctf\n")
    (ctf_dir / "report_prompt.md").write_text("CTF REPORT\n")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    content = loader.load_module_report_prompt("app")
    assert content.strip() == "WEB REPORT"


def test_module_prompt_loader_report_prompt_inheritance_transitive(tmp_path, monkeypatch):
    """Inheritance should be transitive (depth-first) while preserving declared order."""
    # app extends web; web extends ctf; only ctf has report_prompt
    app_dir = tmp_path / "operation_plugins" / "app"
    app_dir.mkdir(parents=True)
    (app_dir / "module.yaml").write_text("extend:\n  - web\n")

    web_dir = tmp_path / "operation_plugins" / "web"
    web_dir.mkdir(parents=True)
    (web_dir / "module.yaml").write_text("extend:\n  - ctf\n")

    ctf_dir = tmp_path / "operation_plugins" / "ctf"
    ctf_dir.mkdir(parents=True)
    (ctf_dir / "module.yaml").write_text("name: ctf\n")
    (ctf_dir / "report_prompt.md").write_text("CTF ONLY\n")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    content = loader.load_module_report_prompt("app")
    assert content.strip() == "CTF ONLY"


def test_module_prompt_loader_report_prompt_inheritance_cycle_safe(tmp_path, monkeypatch):
    """Cycles should not hang resolution; traversal should be truncated safely."""
    # a extends b; b extends a; only b has report_prompt
    a_dir = tmp_path / "operation_plugins" / "a"
    a_dir.mkdir(parents=True)
    (a_dir / "module.yaml").write_text("extend:\n  - b\n")

    b_dir = tmp_path / "operation_plugins" / "b"
    b_dir.mkdir(parents=True)
    (b_dir / "module.yaml").write_text("extend:\n  - a\n")
    (b_dir / "report_prompt.md").write_text("B REPORT\n")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    content = loader.load_module_report_prompt("a")
    assert content.strip() == "B REPORT"


def test_module_prompt_loader_prioritizes_operation_optimized_prompt(
    tmp_path, monkeypatch
):
    """Test that operation-specific optimized prompt takes priority."""
    # Create operation folder with optimized prompt
    operation_root = tmp_path / "outputs" / "target" / "OP_TEST"
    operation_root.mkdir(parents=True)
    optimized_path = operation_root / "execution_prompt_optimized.txt"
    optimized_path.write_text("Optimized execution prompt for this operation")

    # Create master prompt
    plugins_dir = tmp_path / "operation_plugins" / "web"
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "module.yaml").write_text("name: web\n")
    master_path = plugins_dir / "execution_prompt.md"
    master_path.write_text("Master execution prompt")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    # Load with operation_root - should get optimized version
    content = loader.load_module_execution_prompt(
        "web", operation_root=str(operation_root)
    )
    assert content == "Optimized execution prompt for this operation"
    assert loader.last_loaded_execution_prompt_source == f"optimized:{optimized_path}"


def test_module_prompt_loader_falls_back_to_master_when_no_optimized(
    tmp_path, monkeypatch
):
    """Test fallback to master when optimized prompt doesn't exist."""
    # Create operation folder WITHOUT optimized prompt
    operation_root = tmp_path / "outputs" / "target" / "OP_TEST"
    operation_root.mkdir(parents=True)

    # Create master prompt
    plugins_dir = tmp_path / "operation_plugins" / "web"
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "module.yaml").write_text("name: web\n")
    master_path = plugins_dir / "execution_prompt.md"
    master_path.write_text("Master execution prompt")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    # Load with operation_root - should fall back to master
    content = loader.load_module_execution_prompt(
        "web", operation_root=str(operation_root)
    )
    assert content == "Master execution prompt"
    assert loader.last_loaded_execution_prompt_source == f"web:{master_path}"


def test_module_prompt_loader_handles_invalid_operation_root(tmp_path, monkeypatch):
    """Test handling of invalid operation_root path."""
    # Create master prompt
    plugins_dir = tmp_path / "operation_plugins" / "web"
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "module.yaml").write_text("name: web\n")
    master_path = plugins_dir / "execution_prompt.md"
    master_path.write_text("Master execution prompt")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    # Load with non-existent operation_root - should fall back to master
    content = loader.load_module_execution_prompt(
        "web", operation_root="/nonexistent/path"
    )
    assert content == "Master execution prompt"
    assert loader.last_loaded_execution_prompt_source == f"web:{master_path}"


def test_module_prompt_loader_handles_empty_optimized_file(tmp_path, monkeypatch):
    """Test handling of empty optimized prompt file."""
    # Create operation folder with EMPTY optimized prompt
    operation_root = tmp_path / "outputs" / "target" / "OP_TEST"
    operation_root.mkdir(parents=True)
    optimized_path = operation_root / "execution_prompt_optimized.txt"
    optimized_path.write_text("")  # Empty file

    # Create master prompt
    plugins_dir = tmp_path / "operation_plugins" / "web"
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "module.yaml").write_text("name: web\n")
    master_path = plugins_dir / "execution_prompt.md"
    master_path.write_text("Master execution prompt")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    # Load with operation_root - should fall back to master since optimized is empty
    content = loader.load_module_execution_prompt(
        "web", operation_root=str(operation_root)
    )
    assert content == "Master execution prompt"
    assert loader.last_loaded_execution_prompt_source == f"web:{master_path}"


def test_module_prompt_loader_operation_root_none(tmp_path, monkeypatch):
    """Test that operation_root=None works correctly."""
    # Create master prompt
    plugins_dir = tmp_path / "operation_plugins" / "web"
    plugins_dir.mkdir(parents=True)
    (plugins_dir / "module.yaml").write_text("name: web\n")
    master_path = plugins_dir / "execution_prompt.md"
    master_path.write_text("Master execution prompt")

    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])

    # Load with operation_root=None - should use master
    content = loader.load_module_execution_prompt("web", operation_root=None)
    assert content == "Master execution prompt"
    assert loader.last_loaded_execution_prompt_source == f"web:{master_path}"


def test_module_prompt_loader_find_module_dir_deep_search(tmp_path, monkeypatch):
    """Test that modules are discovered via deep search when they have a module.yaml."""
    # Create module in a subdirectory with module.yaml
    collection_dir = tmp_path / "operation_plugins" / "my_collection"
    module_dir = collection_dir / "web"
    module_dir.mkdir(parents=True)
    (module_dir / "module.yaml").write_text("name: web\n")
    
    (module_dir / "module.yaml").write_text("name: web\n")
    
    loader = ModulePromptLoader()
    monkeypatch.setattr(loader, "plugin_dirs", [tmp_path / "operation_plugins"])
    
    found_dir = loader._find_module_dir("web")
    assert found_dir == module_dir
