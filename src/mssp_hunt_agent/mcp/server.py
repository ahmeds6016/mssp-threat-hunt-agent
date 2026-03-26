"""MCP Server definition — registers all tools, resources, and prompts.

Start with::

    mcp dev src/mssp_hunt_agent/mcp/server.py
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

try:
    from mcp.server import Server
    from mcp.types import Tool, TextContent

    _MCP_AVAILABLE = True
except ImportError:
    _MCP_AVAILABLE = False

from mssp_hunt_agent.mcp.tools import TOOL_REGISTRY, execute_tool
from mssp_hunt_agent.mcp.resources import RESOURCE_REGISTRY, read_resource
from mssp_hunt_agent.mcp.prompts import PROMPT_REGISTRY, render_prompt


def create_server() -> "Server":
    """Create and configure the MCP server with all tools, resources, and prompts."""
    if not _MCP_AVAILABLE:
        raise ImportError(
            "MCP SDK not installed. Install with: pip install 'mssp-hunt-agent[mcp]'"
        )

    server = Server("mssp-hunt-agent")

    @server.list_tools()
    async def list_tools() -> list[Tool]:
        return [
            Tool(
                name=name,
                description=meta["description"],
                inputSchema=meta["input_schema"],
            )
            for name, meta in TOOL_REGISTRY.items()
        ]

    @server.call_tool()
    async def call_tool(name: str, arguments: dict) -> list[TextContent]:
        result = execute_tool(name, arguments)
        return [TextContent(type="text", text=result)]

    @server.list_resources()
    async def list_resources():
        from mcp.types import Resource
        return [
            Resource(uri=uri, name=meta["name"], description=meta["description"])
            for uri, meta in RESOURCE_REGISTRY.items()
        ]

    @server.read_resource()
    async def handle_read_resource(uri: str) -> str:
        return read_resource(uri)

    @server.list_prompts()
    async def list_prompts():
        from mcp.types import Prompt
        return [
            Prompt(name=name, description=meta["description"])
            for name, meta in PROMPT_REGISTRY.items()
        ]

    @server.get_prompt()
    async def handle_get_prompt(name: str, arguments: dict | None = None):
        from mcp.types import PromptMessage, TextContent as TC
        text = render_prompt(name, arguments or {})
        return [PromptMessage(role="user", content=TC(type="text", text=text))]

    return server


# Entry point for `mcp dev` / `mcp run`
if _MCP_AVAILABLE:
    app = create_server()
