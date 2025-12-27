"""Tools module for Cyber-AutoAgent."""

from modules.tools.memory import (
    Mem0ServiceClient,
    get_memory_client,
    initialize_memory_system,
    mem0_memory,
)
from modules.tools.browser import (
    initialize_browser,
    browser_goto_url,
    browser_observe_page,
    browser_get_page_html,
    browser_set_headers,
    browser_perform_action,
    browser_evaluate_js,
    browser_get_cookies,
)
from modules.tools.mcp import (
    mcp_tool_catalog,
    discover_mcp_tools,
)
from modules.tools.channels import (
    channel_create_forward,
    channel_create_reverse,
    channel_send,
    channel_poll,
    channel_status,
    channel_close,
    channel_close_all,
)
from modules.tools.prompt_optimizer import prompt_optimizer
from modules.tools.oast import (
    oast_health,
    oast_endpoints,
    oast_poll,
    oast_register_http_response,
    oast_clear_http_responses,
    close_oast_providers,
)

__all__ = [
    "mem0_memory",
    "initialize_memory_system",
    "get_memory_client",
    "Mem0ServiceClient",
    "initialize_browser",
    "browser_set_headers",
    "browser_goto_url",
    "browser_observe_page",
    "browser_get_page_html",
    "browser_perform_action",
    "browser_get_cookies",
    "browser_evaluate_js",
    "prompt_optimizer",
    "mcp_tool_catalog",
    "discover_mcp_tools",
    "channel_create_forward",
    "channel_create_reverse",
    "channel_send",
    "channel_poll",
    "channel_status",
    "channel_close",
    "channel_close_all",
    "oast_health",
    "oast_endpoints",
    "oast_poll",
    "oast_register_http_response",
    "oast_clear_http_responses",
    "close_oast_providers",
]
