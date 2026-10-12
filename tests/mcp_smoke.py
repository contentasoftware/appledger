"""Smoke test: start the AppLedger MCP server over stdio and call each tool like an agent would.

    python tests/mcp_smoke.py <app-folder>

In hosted mode this sends the folder's files to appledger.net (the script plays the user saying
yes to the upload), so only point it at a sample app.
"""

import asyncio
import json
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client


async def main(app_dir):
    params = StdioServerParameters(command=sys.executable, args=["-m", "appledger.server"],
                                   env=dict(os.environ))
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            print("server:", init.serverInfo.name, init.serverInfo.version)
            tools = await session.list_tools()
            for t in tools.tools:
                print(f"tool: {t.name:16} read-only={t.annotations.readOnlyHint} title={t.annotations.title!r}")

            status = await session.call_tool("scanner_status", {})
            print("scanner_status:", status.content[0].text[:300])

            preview = json.loads((await session.call_tool("preview_upload", {"path": app_dir})).content[0].text)
            assert preview["ok"], preview
            print(f"preview_upload: {preview['files']} files ({preview['size']}), "
                  f"{preview['excluded_total']} left out, selected by {preview['selected_by']}")

            args = {"path": app_dir, "app_name": "Sales quote calculator"}
            data = json.loads((await session.call_tool("check_app", args)).content[0].text)
            if data.get("needs_confirmation"):
                print("check_app asked first:", data["upload_preview"])
                assert data["upload_preview"]["files"] == preview["files"]
                data = json.loads((await session.call_tool("check_app", {**args, "confirm_upload": True})).content[0].text)
            assert data["ok"], data
            print(f"check_app: grade {data['grade']}, score {data['score']}, counts {data['counts']}")
            print("first finding:", data["findings"][0]["title"])
            print("dashboard:", data["dashboard"])

            prompt = await session.call_tool("get_fix_prompt", {"path": app_dir})
            text = prompt.content[0].text
            assert text.startswith("# Fix request"), text[:100]
            print("get_fix_prompt:", text.splitlines()[0], f"({len(text)} chars)")

            cost = json.loads((await session.call_tool("ai_cost", {"path": app_dir})).content[0].text)
            print("ai_cost:", f"{cost.get('tokens_total', 0):,} tokens, ${cost.get('cost_usd', 0)}"
                  if cost.get("found") else cost.get("message"))
            print("OK")


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1]))
