#!/usr/bin/env python3
"""
Job Analytics MCP Server

A secure wrapper that exposes only 4 specific Redash queries for job analytics.
This prevents arbitrary SQL execution and limits data access to job-specific queries.

Tools:
- get_job_details: Get basic job information
- get_agent_trajectory: Get agent execution steps
- get_hitl_interactions: Get human-in-the-loop messages
- get_deployment_details: Get deployment information for a job
"""

import asyncio
import json
import re
import os
import time
import httpx
from typing import Any
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

# Configuration
REDASH_URL = os.environ.get("REDASH_URL", "http://redash.internal-apps.emergentagent.com")
REDASH_API_KEY = os.environ.get("REDASH_API_KEY", "XIXbS7SnqARem4jxMsXTi8OMouxTcMda1Pugi3hM")
DATA_SOURCE_ID = 3  # agent-service-dev-replica (Postgres)

# SQL Query Templates (only JOB_ID is substitutable)
QUERY_JOB_DETAILS = """
SELECT
  id AS job_id,
  created_by AS user_id,
  LEFT(payload->>'task', 2000) AS original_task,
  payload->>'prompt_name' AS prompt_name,
  status,
  created_at,
  payload->>'dynamic_preview_subdomain' AS dynamic_preview_subdomain
FROM jobs
WHERE id = '{job_id}'
ORDER BY created_at
"""

QUERY_AGENT_TRAJECTORY = """
SELECT
  step_num,
  agent_name,
  traj_payload->>'function_name' AS function_name,
  LEFT(traj_payload->>'thought', 500) AS agent_thought,
  LEFT(traj_payload->>'action', 500) AS agent_action,
  LEFT(traj_payload->>'user_messages_string', 500) AS user_message
FROM trajectories
WHERE job_id = '{job_id}'
ORDER BY created_at
LIMIT 25
"""

QUERY_HITL_INTERACTIONS = """
SELECT
  step_num,
  LEFT(traj_payload->>'user_messages_string', 800) AS user_message,
  LEFT(traj_payload->>'human_message', 800) AS human_message
FROM trajectories
WHERE job_id = '{job_id}'
  AND (LENGTH(traj_payload->>'user_messages_string') > 3 OR traj_payload->>'human_message' IS NOT NULL)
ORDER BY created_at
"""

QUERY_DEPLOYMENT_DETAILS = """
SELECT
  job_id,
  domain_name,
  created_at,
  type,
  app_name
FROM analytics.deployer_db_data
WHERE job_id = '{job_id}'
"""

# Job ID validation pattern (UUID format: alphanumeric with hyphens)
JOB_ID_PATTERN = re.compile(r'^[a-zA-Z0-9\-_]{1,64}$')


def validate_job_id(job_id: str) -> bool:
    """Validate job_id to prevent SQL injection."""
    if not job_id or not isinstance(job_id, str):
        return False
    return bool(JOB_ID_PATTERN.match(job_id))


async def _submit_query(client: httpx.AsyncClient, query: str, data_source_id: int = DATA_SOURCE_ID) -> dict:
    """Submit a query to Redash and return parsed results."""
    import logging
    log = logging.getLogger("redash_mcp")
    response = await client.post(
        f"{REDASH_URL}/api/query_results",
        headers={
            "Authorization": f"Key {REDASH_API_KEY}",
            "Content-Type": "application/json"
        },
        json={
            "query": query,
            "data_source_id": data_source_id,
            "max_age": 0
        }
    )
    log.warning(f"Redash POST status={response.status_code}")

    if response.status_code == 200:
        result = response.json()
        if "query_result" in result:
            return {
                "columns": [col["name"] for col in result["query_result"]["data"].get("columns", [])],
                "rows": result["query_result"]["data"].get("rows", [])
            }
        elif "job" in result:
            job_id = result["job"]["id"]
            initial_status = result["job"].get("status")
            log.warning(f"Redash job={job_id} initial_status={initial_status}")
            return await poll_query_job(client, job_id)
    return {"error": f"Redash API error: {response.status_code}", "details": response.text[:500]}


async def execute_redash_query(query: str, max_retries: int = 3, data_source_id: int = DATA_SOURCE_ID) -> dict:
    """Execute a query against Redash and return results. Retries on cancellation with unique query."""
    if not REDASH_API_KEY:
        return {"error": "REDASH_API_KEY not configured"}

    async with httpx.AsyncClient(timeout=360.0) as client:
        for attempt in range(max_retries):
            try:
                # Always append unique comment to avoid Redash job deduplication issues
                q = f"{query}\n-- q{int(time.time() * 1000)}"
                result = await _submit_query(client, q, data_source_id=data_source_id)
                if result.get("error") == "Query was cancelled" and attempt < max_retries - 1:
                    await asyncio.sleep(2)
                    continue
                return result
            except httpx.TimeoutException:
                return {"error": "Query timed out"}
            except Exception as e:
                return {"error": f"Query execution failed: {str(e)}"}
    return {"error": "Query failed after retries"}


async def poll_query_job(client: httpx.AsyncClient, job_id: str, max_attempts: int = 150) -> dict:
    """Poll for query job completion."""
    import logging
    log = logging.getLogger("redash_mcp")
    for attempt in range(max_attempts):
        await asyncio.sleep(2)

        response = await client.get(
            f"{REDASH_URL}/api/jobs/{job_id}",
            headers={"Authorization": f"Key {REDASH_API_KEY}"}
        )

        if response.status_code != 200:
            return {"error": f"Job status check failed: {response.status_code}"}

        job_data = response.json()["job"]
        status = job_data.get("status")
        log.warning(f"Poll {attempt}: job={job_id} status={status} error={job_data.get('error','')}")

        if status == 3:  # Success
            query_result_id = job_data.get("query_result_id")
            if query_result_id:
                result_response = await client.get(
                    f"{REDASH_URL}/api/query_results/{query_result_id}",
                    headers={"Authorization": f"Key {REDASH_API_KEY}"}
                )
                if result_response.status_code == 200:
                    result = result_response.json()
                    return {
                        "columns": [col["name"] for col in result["query_result"]["data"].get("columns", [])],
                        "rows": result["query_result"]["data"].get("rows", [])
                    }
            return {"error": "Query completed but no results found"}
        elif status == 4:  # Failed
            return {"error": f"Query failed: {job_data.get('error', 'Unknown error')}"}
        elif status == 2:  # Cancelled (but BigQuery may show transient status=2, so keep polling)
            continue

    return {"error": "Query timed out waiting for results"}


def format_results(result: dict) -> str:
    """Format query results for display."""
    if "error" in result:
        return f"Error: {result['error']}"

    rows = result.get("rows", [])
    columns = result.get("columns", [])

    if not rows:
        return "No results found."

    output = []
    output.append(f"Found {len(rows)} result(s):\n")

    for i, row in enumerate(rows, 1):
        output.append(f"--- Result {i} ---")
        for col in columns:
            value = row.get(col, "N/A")
            if isinstance(value, str) and len(value) > 500:
                value = value[:500] + "..."
            output.append(f"  {col}: {value}")
        output.append("")

    return "\n".join(output)


# Initialize MCP Server
server = Server("job-analytics-mcp")


@server.list_tools()
async def list_tools() -> list[Tool]:
    """List available tools."""
    return [
        Tool(
            name="get_job_details",
            description="Get basic information about a job including task, status, and creation time. Use this to understand what a job was trying to accomplish.",
            inputSchema={
                "type": "object",
                "properties": {
                    "job_id": {
                        "type": "string",
                        "description": "The job ID to look up (UUID format)"
                    }
                },
                "required": ["job_id"]
            }
        ),
        Tool(
            name="get_agent_trajectory",
            description="Get the agent's execution trajectory for a job - shows the steps taken, thoughts, actions, and function calls. Limited to last 25 steps within 90 days.",
            inputSchema={
                "type": "object",
                "properties": {
                    "job_id": {
                        "type": "string",
                        "description": "The job ID to look up (UUID format)"
                    }
                },
                "required": ["job_id"]
            }
        ),
        Tool(
            name="get_hitl_interactions",
            description="Get human-in-the-loop (HITL) interactions for a job - shows user messages and human responses during the job execution.",
            inputSchema={
                "type": "object",
                "properties": {
                    "job_id": {
                        "type": "string",
                        "description": "The job ID to look up (UUID format)"
                    }
                },
                "required": ["job_id"]
            }
        ),
        Tool(
            name="get_deployment_details",
            description="Get deployment information for a job including domain name, app name, deployment type, and creation time.",
            inputSchema={
                "type": "object",
                "properties": {
                    "job_id": {
                        "type": "string",
                        "description": "The job ID to look up (UUID format)"
                    }
                },
                "required": ["job_id"]
            }
        )
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict[str, Any]) -> list[TextContent]:
    """Execute a tool."""
    job_id = arguments.get("job_id", "")

    if not validate_job_id(job_id):
        return [TextContent(
            type="text",
            text="Error: Invalid job_id format. Must be alphanumeric with hyphens/underscores, max 64 characters."
        )]

    if name == "get_job_details":
        query = QUERY_JOB_DETAILS.format(job_id=job_id)
    elif name == "get_agent_trajectory":
        query = QUERY_AGENT_TRAJECTORY.format(job_id=job_id)
    elif name == "get_hitl_interactions":
        query = QUERY_HITL_INTERACTIONS.format(job_id=job_id)
    elif name == "get_deployment_details":
        query = QUERY_DEPLOYMENT_DETAILS.format(job_id=job_id)
    else:
        return [TextContent(type="text", text=f"Error: Unknown tool '{name}'")]

    ds_id = 7 if name == "get_deployment_details" else DATA_SOURCE_ID
    result = await execute_redash_query(query, data_source_id=ds_id)
    formatted = format_results(result)

    return [TextContent(type="text", text=formatted)]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            server.create_initialization_options()
        )


if __name__ == "__main__":
    asyncio.run(main())
