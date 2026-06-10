"""
Phishing Agent — Anthropic SDK Autonomous Classifier

Takes a job_id, runs a Claude Opus 4.6 (1M context) agent loop with tool_use
to query Redash for job evidence + user profile, then classifies using the
Cloudflare Deployment Risk Classifier prompt.

No CLI dependency — talks directly to the Anthropic API.

Usage:
    ANTHROPIC_API_KEY=sk-ant-... python agent_runner.py <job_id>
"""

import asyncio
import json
import os
import sys
import time
import re
from pathlib import Path

import anthropic
import httpx

# ---- Configuration ----

AGENT_DIR = Path(__file__).parent
CLASSIFIER_PROMPT_PATH = AGENT_DIR / "classifier_prompt.md"

REDASH_URL = os.environ.get("REDASH_URL", "http://redash.internal-apps.emergentagent.com")
REDASH_API_KEY = os.environ.get("REDASH_API_KEY", "XIXbS7SnqARem4jxMsXTi8OMouxTcMda1Pugi3hM")

MODEL = "claude-opus-4-20250514"
MAX_TURNS = 15

# ---- Redash Query Templates ----

QUERIES = {
    "get_job_details": {
        "sql": """
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
""",
        "data_source_id": 3,
        "param": "job_id",
    },
    "get_agent_trajectory": {
        "sql": """
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
""",
        "data_source_id": 3,
        "param": "job_id",
    },
    "get_hitl_interactions": {
        "sql": """
SELECT
  step_num,
  LEFT(traj_payload->>'user_messages_string', 800) AS user_message,
  LEFT(traj_payload->>'human_message', 800) AS human_message
FROM trajectories
WHERE job_id = '{job_id}'
  AND (LENGTH(traj_payload->>'user_messages_string') > 3 OR traj_payload->>'human_message' IS NOT NULL)
ORDER BY created_at
""",
        "data_source_id": 3,
        "param": "job_id",
    },
    "get_deployment_details": {
        "sql": """
SELECT
  job_id,
  domain_name,
  created_at,
  type,
  app_name
FROM analytics.deployer_db_data
WHERE job_id = '{job_id}'
""",
        "data_source_id": 7,
        "param": "job_id",
    },
    "get_user_jobs": {
        "sql": """
SELECT DISTINCT
  id AS job_id,
  LEFT(payload->>'task', 2000) AS original_task,
  created_at
FROM jobs
WHERE created_by = '{user_id}'
ORDER BY created_at DESC
LIMIT 10
""",
        "data_source_id": 3,
        "param": "user_id",
    },
}

# ---- Tool Definitions (Anthropic format) ----

TOOLS = [
    {
        "name": "get_job_details",
        "description": "Get basic information about a job including task description, status, user ID, and creation time.",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "The job ID (UUID format)"}
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "get_agent_trajectory",
        "description": "Get the agent's execution trajectory — steps taken, thoughts, actions, function calls. Shows what was actually built.",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "The job ID (UUID format)"}
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "get_hitl_interactions",
        "description": "Get human-in-the-loop interactions — user messages and human responses during job execution. Shows builder intent.",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "The job ID (UUID format)"}
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "get_deployment_details",
        "description": "Get deployment information — domain name, app name, deployment type. Shows if app is live.",
        "input_schema": {
            "type": "object",
            "properties": {
                "job_id": {"type": "string", "description": "The job ID (UUID format)"}
            },
            "required": ["job_id"],
        },
    },
    {
        "name": "get_user_jobs",
        "description": "Get the 10 most recent jobs created by a user. Returns job_id, task description, and creation time. Use this AFTER get_job_details to build a user profile — see what else this user has been building to detect fraud toolkit patterns (e.g. same user building BIN generators, card checkers, bypass tools, license crackers).",
        "input_schema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "The user ID (UUID format)"}
            },
            "required": ["user_id"],
        },
    },
]

# ---- Redash Execution ----

SAFE_ID_PATTERN = re.compile(r'^[a-zA-Z0-9\-_]{1,64}$')


def validate_id(val: str) -> bool:
    if not val or not isinstance(val, str):
        return False
    return bool(SAFE_ID_PATTERN.match(val))


async def execute_redash_query(query_sql: str, data_source_id: int, max_retries: int = 3) -> str:
    """Execute a query against Redash with retries. Polls for async results."""
    async with httpx.AsyncClient(timeout=360.0) as client:
        for attempt in range(max_retries):
            try:
                q = f"{query_sql}\n-- q{int(time.time() * 1000)}_{attempt}"
                resp = await client.post(
                    f"{REDASH_URL}/api/query_results",
                    headers={
                        "Authorization": f"Key {REDASH_API_KEY}",
                        "Content-Type": "application/json",
                    },
                    json={"query": q, "data_source_id": data_source_id, "max_age": 0},
                )
                if resp.status_code != 200:
                    print(f"[WARN] Redash returned {resp.status_code} (attempt {attempt+1}/{max_retries})")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(3 * (attempt + 1))
                        continue
                    return f"Error: Redash API returned {resp.status_code} after {max_retries} retries"

                result = resp.json()
                if "query_result" in result:
                    return _format_rows(result["query_result"]["data"])
                if "job" in result:
                    poll_result = await _poll_job(client, result["job"]["id"])
                    if poll_result.startswith("Error: Query was cancelled") and attempt < max_retries - 1:
                        print(f"[WARN] Redash query cancelled (attempt {attempt+1}), retrying...")
                        await asyncio.sleep(3)
                        continue
                    return poll_result
                return "Error: Unexpected Redash response"

            except httpx.TimeoutException:
                print(f"[WARN] Redash timeout (attempt {attempt+1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(5)
                    continue
                return "Error: Redash query timed out after retries"
            except Exception as e:
                print(f"[WARN] Redash error (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(3)
                    continue
                return f"Error: Redash query failed: {str(e)}"

    return "Error: Redash query failed after all retries"


async def _poll_job(client: httpx.AsyncClient, job_id: str) -> str:
    """Poll a Redash job until completion."""
    for _ in range(150):
        await asyncio.sleep(2)
        resp = await client.get(
            f"{REDASH_URL}/api/jobs/{job_id}",
            headers={"Authorization": f"Key {REDASH_API_KEY}"},
        )
        if resp.status_code != 200:
            return f"Error: Job poll failed ({resp.status_code})"

        job = resp.json()["job"]
        status = job.get("status")

        if status == 3:  # Success
            qr_id = job.get("query_result_id")
            if qr_id:
                rr = await client.get(
                    f"{REDASH_URL}/api/query_results/{qr_id}",
                    headers={"Authorization": f"Key {REDASH_API_KEY}"},
                )
                if rr.status_code == 200:
                    return _format_rows(rr.json()["query_result"]["data"])
            return "Error: Query completed but no results"
        elif status == 4:  # Failed
            return f"Error: Query failed: {job.get('error', 'unknown')}"
        elif status == 2:  # Cancelled / transient
            continue

    return "Error: Query timed out"


def _format_rows(data: dict) -> str:
    """Format Redash query result data into readable text."""
    columns = [c["name"] for c in data.get("columns", [])]
    rows = data.get("rows", [])

    if not rows:
        return "No results found."

    output = [f"Found {len(rows)} result(s):\n"]
    for i, row in enumerate(rows, 1):
        output.append(f"--- Result {i} ---")
        for col in columns:
            val = row.get(col, "N/A")
            if isinstance(val, str) and len(val) > 800:
                val = val[:800] + "..."
            output.append(f"  {col}: {val}")
        output.append("")

    return "\n".join(output)


# ---- Tool Execution ----

async def execute_tool(tool_name: str, tool_input: dict) -> str:
    """Execute a tool call and return the result as text."""
    query_def = QUERIES.get(tool_name)
    if not query_def:
        return f"Error: Unknown tool '{tool_name}'"

    param_name = query_def["param"]
    param_value = tool_input.get(param_name, "")

    if not validate_id(param_value):
        return f"Error: Invalid {param_name} format."

    sql = query_def["sql"].format(**{param_name: param_value})
    return await execute_redash_query(sql, query_def["data_source_id"])


# ---- Agent Loop ----

async def run_classifier(job_id: str) -> dict:
    """
    Run the classifier agent for a single job.
    Returns parsed verdict dict.
    """
    client = anthropic.AsyncAnthropic(timeout=600.0)

    system_prompt = CLASSIFIER_PROMPT_PATH.read_text()

    user_prompt = f"""Investigate job `{job_id}` for Cloudflare deployment risk.

Run ALL 5 tools to gather evidence:
1. get_job_details(job_id="{job_id}")
2. get_agent_trajectory(job_id="{job_id}")
3. get_hitl_interactions(job_id="{job_id}")
4. get_deployment_details(job_id="{job_id}")
5. AFTER get_job_details returns, extract the user_id and call get_user_jobs(user_id="<user_id>") to see what else this user has been building. This is critical for detecting fraud toolkit patterns — a user building BIN generators, card checkers, bypass tools, and license crackers within a short window is strong evidence of malicious intent even if any single job looks borderline.

Factor the user's job history into your classification. If the user has a pattern of building fraud/attack tools, that context should make you MORE likely to classify ambiguous jobs as CONFIRMED_MALICIOUS.

Then classify using the framework in your system prompt and output a JSON verdict block."""

    messages = [{"role": "user", "content": user_prompt}]
    tool_calls_made = []

    print(f"\n{'='*60}")
    print(f"Investigating job: {job_id}")
    print(f"{'='*60}\n")

    for turn in range(MAX_TURNS):
        response = await client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=system_prompt,
            tools=TOOLS,
            messages=messages,

        )

        print(f"[Turn {turn+1}] stop_reason={response.stop_reason}")

        # Process response content
        has_tool_use = False

        for block in response.content:
            if block.type == "text":
                print(f"[AGENT] {block.text[:300]}")
            elif block.type == "thinking":
                print(f"[THINKING] {block.thinking[:200]}...")
            elif block.type == "tool_use":
                has_tool_use = True
                tool_calls_made.append(block.name)
                print(f"[TOOL] {block.name}({json.dumps(block.input)[:100]})")

        # Add assistant message
        messages.append({"role": "assistant", "content": response.content})

        # If no tool use, we're done
        if response.stop_reason == "end_turn" or not has_tool_use:
            break

        # Execute tool calls and build tool_result messages
        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                result_text = await execute_tool(block.name, block.input)
                print(f"[TOOL_RESULT] {block.name}: {result_text[:150]}...")
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result_text,
                })

        messages.append({"role": "user", "content": tool_results})

    # Extract verdict from final response
    full_text = ""
    for block in response.content:
        if hasattr(block, "text"):
            full_text += block.text

    verdict = _extract_json_verdict(full_text)

    print(f"\n{'='*60}")
    print(f"Tools called: {tool_calls_made}")
    print(f"Turns used: {turn + 1}")
    print(f"{'='*60}")

    if verdict:
        print(f"\nVERDICT: {verdict.get('label', 'UNKNOWN')}")
        print(f"Confidence: {verdict.get('confidence', 'UNKNOWN')}")
        print(f"Severity: {verdict.get('severity', 'N/A')}")
        print(f"Summary: {verdict.get('verdict_summary', 'N/A')}")
        print(f"Policy violated: {verdict.get('cloudflare_policy_violated', 'None')}")
        print(f"Recommended action: {verdict.get('recommended_action', 'N/A')}")
        if verdict.get("key_evidence"):
            print("Key evidence:")
            for ev in verdict["key_evidence"]:
                print(f"  - {ev}")
    else:
        print("\nCould not parse structured verdict. Raw output:")
        print(full_text[:2000])

    return verdict or {"raw_output": full_text, "tools_called": tool_calls_made}


def _extract_json_verdict(text: str) -> dict | None:
    """Extract a JSON verdict block from agent output text."""
    # Try markdown code fence first
    patterns = [
        re.compile(r'```json\s*\n(.*?)\n```', re.DOTALL),
        re.compile(r'```\s*\n(\{.*?\})\n```', re.DOTALL),
    ]

    for pattern in patterns:
        matches = pattern.findall(text)
        for match in reversed(matches):
            try:
                parsed = json.loads(match)
                if "label" in parsed:
                    return parsed
            except json.JSONDecodeError:
                continue

    # Fallback: find JSON object with "label" key
    brace_depth = 0
    start = None
    for i, ch in enumerate(text):
        if ch == '{':
            if brace_depth == 0:
                start = i
            brace_depth += 1
        elif ch == '}':
            brace_depth -= 1
            if brace_depth == 0 and start is not None:
                candidate = text[start:i+1]
                if '"label"' in candidate:
                    try:
                        return json.loads(candidate)
                    except json.JSONDecodeError:
                        pass
                start = None

    return None


async def main():
    if len(sys.argv) < 2:
        print("Usage: ANTHROPIC_API_KEY=sk-ant-... python agent_runner.py <job_id>")
        sys.exit(1)

    job_id = sys.argv[1]

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY not set")
        sys.exit(1)

    verdict = await run_classifier(job_id)

    print(f"\n{'='*60}")
    print("FINAL JSON VERDICT:")
    print(json.dumps(verdict, indent=2))


if __name__ == "__main__":
    asyncio.run(main())
