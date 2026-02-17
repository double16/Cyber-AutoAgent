import json
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import List, Any, Dict, Optional

import yaml
from strands import tool, Agent

from modules.config.system import environment, get_logger

logger = get_logger("Tools.Catalog")


@lru_cache()
def _get_cyber_tools() -> Dict[str, Any]:
    env_path = Path(environment.__file__).with_name("environment.yaml")
    with env_path.open("r", encoding="utf-8") as f:
        env_config = yaml.safe_load(f) or {}

    return env_config.get("cyber_tools", {})


def get_cyber_tools_by_caps(available: List[str]) -> Dict[str, Dict[str, Any]]:
    """
    Returns command line tools:
        capability -> preferred|fallback -> tools (list[str])
    """
    result = {}
    cyber_tools = _get_cyber_tools()
    for tool in cyber_tools:
        if tool not in available:
            continue
        tool_cfg = cyber_tools.get(tool) or {}
        real_command = tool_cfg.get("command", tool)

        pref_raw = tool_cfg.get("preference") or "fallback"
        pref_raw = str(pref_raw).strip().lower()
        pref = "preferred" if pref_raw.startswith("p") else "fallback"

        caps = tool_cfg.get("caps") or []
        if isinstance(caps, str):
            caps = [caps]
        for cap in caps:
            if not cap in result:
                result[cap] = {}
            cap_dict = result.get(cap)
            if not pref in cap_dict:
                cap_dict[pref] = []
            pref_list = cap_dict.get(pref)
            pref_list.append(real_command)
    # if only fallback is specified, make it preferred
    for cap, cap_dict in result.items():
        if len(cap_dict) == 1 and "preferred" not in cap_dict:
            old_pref = next(iter(cap_dict.keys()))
            cap_dict["preferred"] = cap_dict[old_pref]
            cap_dict.pop(old_pref)
    return result


@lru_cache(maxsize=200)
def _get_shell_command_help(command: str) -> str:
    try:
        for option in ["--help", "-h", ""]:
            cmd = [command]
            if option:
                cmd.append(option)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            if result.stdout is None and result.stderr is None:
                continue
            result_str = str(result.stdout) + str(result.stderr)
            if len(result_str) > 30:
                return result_str
    except Exception as e:
        logger.warning(f"Getting help text for {command}", exc_info=e)
    return ""


def tool_catalog_wrapper(agent: Agent, shell_commands: List[str]):
    """
    Create a full catalog of all available tools.
    :param agent: agent from which tools will be gathered
    :param shell_commands: available shell commands
    :return: tool
    """

    @tool(name="tool_catalog")
    def tool_catalog(keywords: Optional[str] = None) -> str:
        """
        List the catalog of available tools with descriptions and calling guidance. Invoke this tool when a
        capability is needed. Use the results to understand the purpose of each tool, how it is invoked and
        understand the available options you should use.

        Args:
            keywords: space separated keywords for filtering the tools returned (Optional)
        """
        separator = "=" * 80
        keywords = list(filter(bool, [w.strip().lower() for w in (keywords or "").split()]))
        found_tools = []
        catalog = ""
        all_tools = agent.tool_registry.get_all_tools_config()
        specific_tool = len(keywords) == 1 and (keywords[0] in all_tools or keywords[0] in shell_commands)
        for tool_name, tool_spec in all_tools.items():
            if specific_tool and tool_name != keywords[0]:
                continue
            if keywords:
                if not any([w in tool_name.lower() or w in tool_spec.get("description", "").lower() for w in keywords]):
                    continue
            found_tools.append(tool_name)

            catalog += f"""
{separator}
name: {tool_name}

{tool_spec.get("description")}

input schema:
{json.dumps(tool_spec.get("inputSchema"), indent=2, sort_keys=True, ensure_ascii=False)}
"""
            output_schema = tool_spec.get("outputSchema", None)
            if output_schema:
                catalog += f"""

output schema:
{json.dumps(output_schema, indent=2, sort_keys=True, ensure_ascii=False)}

{separator}
"""

        found_cyber_tools = []
        if shell_commands and (not specific_tool or keywords[0] in shell_commands):
            catalog += f"""
# COMMAND LINE PROGRAMS

Use the **shell** tool to invoke the following command line programs in a bash shell.

**Example**:
{{"tool":"shell","args":{{"command":"nmap -sV ...","timeout":600}}}}
{{"tool":"shell","args":{{"command":"nuclei ...","timeout":300}}}}

Always use options that reduce progress but not supress meaningful output. If possible, use options that save output to
a file in the ARTIFACTS DIRECTORY and silence program output.
"""
            cyber_tools = _get_cyber_tools()
            for shell_command in shell_commands:
                if specific_tool and shell_command != keywords[0]:
                    continue
                tool_cfg = (cyber_tools.get(shell_command) or {})
                real_command = tool_cfg.get("command", shell_command)
                description = tool_cfg.get("description", "")
                preference = tool_cfg.get("preference", "")
                caps = tool_cfg.get("caps") or []
                if isinstance(caps, str):
                    caps = [caps]
                if keywords:
                    desc_l = str(description).lower()
                    if not any(
                            [w in shell_command.lower() or w in real_command.lower() or w in desc_l for w in keywords]):
                        continue
                found_cyber_tools.append(real_command)

                catalog += f"""
{separator}
command: {real_command}
capabilities: {", ".join(caps)}
preference: {preference}

{description}

{_get_shell_command_help(real_command)}

{separator}
"""
        if len(found_tools) + len(found_cyber_tools) == 0:
            return f"**NO RESULTS**\nkeywords: {' '.join(keywords)}"

        prologue = """
# TOOL CATALOG

"""
        if len(found_tools) + len(found_cyber_tools) > 1:
            if len(found_tools) > 0:
                prologue += f"""**Tools found**: {','.join(found_tools)}\n"""
            if len(found_cyber_tools) > 0:
                prologue += f"""**Command line tools found**: {','.join(found_cyber_tools)}\n"""

        return prologue + catalog

    return tool_catalog
