"""
Opus Agent — Cloudflare Deployment Risk Classifier

Wraps the Claude Opus 4 agent loop for use by the backend.
Queries Redash for job evidence + user history, classifies using
the Cloudflare Deployment Risk Classifier prompt.

Called by opus_poller.py to verify Tier 1/2/3 jobs before enforcement.
"""

import asyncio
import json
import os
import time
import re
import logging
from pathlib import Path

import anthropic
import httpx

logger = logging.getLogger(__name__)

# ---- Configuration ----

CLASSIFIER_PROMPT_PATH = Path(__file__).parent.parent / "phishing-agent" / "classifier_prompt.md"
REDASH_URL = os.environ.get("REDASH_URL")
REDASH_API_KEY = os.environ.get("REDASH_API_KEY")

MODEL = "claude-opus-4-6"
MAX_TURNS = 15

# Structured output schema — enforced via output_config on the final response
VERDICT_SCHEMA = {
    "type": "object",
    "properties": {
        "job_id": {"type": "string"},
        "user_id": {"type": "string"},
        "label": {"type": "string", "enum": ["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW", "LEGITIMATE"]},
        "confidence": {"type": "string", "enum": ["HIGH", "MEDIUM", "LOW"]},
        "severity": {"type": "string", "enum": ["CRITICAL", "HIGH", "MODERATE", "LOW", "N/A"]},
        "cloudflare_policy_violated": {"type": ["string", "null"]},
        "flagged_policies": {
            "type": "array",
            "items": {
                "type": "string",
                "enum": [
                    "CSAM",
                    "FOSTA_VIOLATIONS",
                    "SANCTIONS_EVASION",
                    "PHISHING_CREDENTIAL_HARVESTING",
                    "MALWARE_DISTRIBUTION",
                    "BRAND_IMPERSONATION",
                    "FINANCIAL_FRAUD_INFRASTRUCTURE",
                    "CONTROLLED_SUBSTANCES_MARKETPLACE",
                    "HUMAN_TRAFFICKING_FACILITATION",
                    "REPEAT_COPYRIGHT_INFRINGEMENT",
                    "VIOLENT_THREATS_INCITEMENT",
                    "DOXXING_TARGETED_HARASSMENT",
                    "PII_HARVESTING",
                    "DEFAMATORY_CONTENT",
                    "NONE",
                ]
            },
            "description": "Cloudflare AUP policy categories violated. Tier A: CSAM, FOSTA_VIOLATIONS, SANCTIONS_EVASION. Tier B: PHISHING_CREDENTIAL_HARVESTING, MALWARE_DISTRIBUTION, BRAND_IMPERSONATION, FINANCIAL_FRAUD_INFRASTRUCTURE, CONTROLLED_SUBSTANCES_MARKETPLACE, HUMAN_TRAFFICKING_FACILITATION. Tier C: REPEAT_COPYRIGHT_INFRINGEMENT, VIOLENT_THREATS_INCITEMENT, DOXXING_TARGETED_HARASSMENT, PII_HARVESTING, DEFAMATORY_CONTENT. Use NONE for legitimate jobs."
        },
        "verdict_summary": {"type": "string"},
        "key_evidence": {"type": "array", "items": {"type": "string"}},
        "false_positive_checks_passed": {"type": "boolean"},
        "recommended_action": {"type": "string", "enum": ["takedown", "schedule_takedown", "human_review", "no_action"]},
    },
    "required": ["job_id", "label", "confidence", "severity", "flagged_policies", "verdict_summary", "key_evidence", "false_positive_checks_passed", "recommended_action"],
    "additionalProperties": False,
}

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
    "get_user_ltv": {
        "sql": """
SELECT DISTINCT
  user_id,
  SUM(amount) AS ltv
FROM analytics.user_revenue_events
WHERE user_id = '{user_id}'
GROUP BY 1
""",
        "data_source_id": 7,
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
        "description": "Get the 10 most recent jobs created by a user. Returns job_id, task description, and creation time. Use this AFTER get_job_details to build a user profile — see what else this user has been building to detect fraud toolkit patterns.",
        "input_schema": {
            "type": "object",
            "properties": {
                "user_id": {"type": "string", "description": "The user ID (UUID format)"}
            },
            "required": ["user_id"],
        },
    },
    {
        "name": "get_user_ltv",
        "description": "Get the user's lifetime revenue (LTV) in USD. Use this AFTER get_job_details to check if this is a paying/power user. LTV > $1000 = high-value power user (exercise extreme caution before takedown). LTV > $299 = power user. LTV > $100 = potential power user. LTV = 0 = free user. Higher LTV means higher false-positive cost — route to NEEDS_HUMAN_REVIEW instead of CONFIRMED_MALICIOUS for borderline cases with paying users.",
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


def _validate_id(val: str) -> bool:
    if not val or not isinstance(val, str):
        return False
    return bool(SAFE_ID_PATTERN.match(val))


async def _execute_redash_query(query_sql: str, data_source_id: int, max_retries: int = 3) -> str:
    """Execute a query against Redash with retries. Polls for async results."""
    async with httpx.AsyncClient(timeout=360.0) as client:
        for attempt in range(max_retries):
            try:
                # Unique comment avoids Redash job deduplication
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
                    logger.warning(f"Redash returned {resp.status_code} (attempt {attempt+1}/{max_retries})")
                    if attempt < max_retries - 1:
                        await asyncio.sleep(3 * (attempt + 1))
                        continue
                    return f"Error: Redash API returned {resp.status_code} after {max_retries} retries"

                result = resp.json()
                if "query_result" in result:
                    return _format_rows(result["query_result"]["data"])
                if "job" in result:
                    poll_result = await _poll_redash_job(client, result["job"]["id"])
                    # Retry on cancellation (transient Redash issue)
                    if poll_result.startswith("Error: Query was cancelled") and attempt < max_retries - 1:
                        logger.warning(f"Redash query cancelled (attempt {attempt+1}/{max_retries}), retrying...")
                        await asyncio.sleep(3)
                        continue
                    return poll_result
                return "Error: Unexpected Redash response"

            except httpx.TimeoutException:
                logger.warning(f"Redash timeout (attempt {attempt+1}/{max_retries})")
                if attempt < max_retries - 1:
                    await asyncio.sleep(5)
                    continue
                return "Error: Redash query timed out after retries"
            except Exception as e:
                logger.warning(f"Redash error (attempt {attempt+1}/{max_retries}): {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(3)
                    continue
                return f"Error: Redash query failed: {str(e)}"

    return "Error: Redash query failed after all retries"


async def _poll_redash_job(client: httpx.AsyncClient, job_id: str) -> str:
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
        if status == 3:
            qr_id = job.get("query_result_id")
            if qr_id:
                rr = await client.get(
                    f"{REDASH_URL}/api/query_results/{qr_id}",
                    headers={"Authorization": f"Key {REDASH_API_KEY}"},
                )
                if rr.status_code == 200:
                    return _format_rows(rr.json()["query_result"]["data"])
            return "Error: Query completed but no results"
        elif status == 4:
            return f"Error: Query failed: {job.get('error', 'unknown')}"
        elif status == 5:
            return "Error: Query was cancelled"
        elif status == 2:
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


async def _execute_tool(tool_name: str, tool_input: dict) -> str:
    """Execute a tool call and return the result as text."""
    query_def = QUERIES.get(tool_name)
    if not query_def:
        return f"Error: Unknown tool '{tool_name}'"
    param_name = query_def["param"]
    param_value = tool_input.get(param_name, "")
    if not _validate_id(param_value):
        return f"Error: Invalid {param_name} format."
    sql = query_def["sql"].format(**{param_name: param_value})
    return await _execute_redash_query(sql, query_def["data_source_id"])


# ---- Agent Loop ----

async def run_classifier(job_id: str) -> dict:
    """
    Run the Opus classifier agent for a single job.
    Returns dict with verdict fields + metadata.
    """
    start_time = time.time()
    client = anthropic.AsyncAnthropic(timeout=600.0)

    try:
        system_prompt = CLASSIFIER_PROMPT_PATH.read_text()
    except FileNotFoundError:
        logger.error(f"Classifier prompt not found at {CLASSIFIER_PROMPT_PATH}")
        return {"label": "NEEDS_HUMAN_REVIEW", "error": "classifier prompt not found", "fallback": True}

    user_prompt = f"""Investigate job `{job_id}` for Cloudflare deployment risk.

Run ALL 6 tools to gather evidence:
1. get_job_details(job_id="{job_id}")
2. get_agent_trajectory(job_id="{job_id}")
3. get_hitl_interactions(job_id="{job_id}")
4. get_deployment_details(job_id="{job_id}")
5. AFTER get_job_details returns, extract the user_id and call get_user_jobs(user_id="<user_id>") to see what else this user has been building. This is critical for detecting fraud toolkit patterns.
6. ALSO call get_user_ltv(user_id="<user_id>") to check the user's lifetime revenue. This is critical for calibrating takedown risk — taking down a power user's legitimate job has severe business impact.

Factor BOTH the user's job history AND their LTV into your classification:
- HARD RULE: If LTV >= $299, ALWAYS classify as NEEDS_HUMAN_REVIEW. Never CONFIRMED_MALICIOUS for a power user — let a human decide. The ONLY exception is Tier A violations (CSAM, FOSTA, sanctions).
- If LTV $100-$298: Exercise caution for borderline cases, lean toward NEEDS_HUMAN_REVIEW.
- If LTV = 0 (free user): Standard threshold applies — classify based on evidence.

If the user has a pattern of building fraud/attack tools, that context should make you MORE likely to flag the job — but for LTV >= $299 users, still route to NEEDS_HUMAN_REVIEW with the pattern documented in key_evidence.

Then classify using the framework in your system prompt and output a JSON verdict block."""

    messages = [{"role": "user", "content": user_prompt}]
    tool_calls_made = []
    turns_used = 0

    logger.info(f"Opus agent starting for job {job_id}")

    for turn in range(MAX_TURNS):
        turns_used = turn + 1
        response = await client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=system_prompt,
            tools=TOOLS,
            messages=messages,
        )

        has_tool_use = False
        for block in response.content:
            if block.type == "tool_use":
                has_tool_use = True
                tool_calls_made.append(block.name)
                logger.info(f"Opus [{job_id}] turn {turns_used}: {block.name}({json.dumps(block.input)[:80]})")

        messages.append({"role": "assistant", "content": response.content})

        if response.stop_reason == "end_turn" or not has_tool_use:
            break

        tool_results = []
        for block in response.content:
            if block.type == "tool_use":
                result_text = await _execute_tool(block.name, block.input)
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result_text,
                })
        messages.append({"role": "user", "content": tool_results})

    # Final structured output call — enforce JSON schema on the verdict
    # Add instruction to produce the verdict now
    messages.append({"role": "user", "content": "Now produce your final JSON verdict based on all the evidence gathered."})
    try:
        final_response = await client.messages.create(
            model=MODEL,
            max_tokens=4096,
            system=system_prompt,
            messages=messages,
            output_config={
                "format": {
                    "type": "json_schema",
                    "schema": VERDICT_SCHEMA,
                }
            },
        )
        turns_used += 1
        full_text = ""
        for block in final_response.content:
            if hasattr(block, "text"):
                full_text += block.text
        logger.info(f"Opus [{job_id}] structured output received ({len(full_text)} chars)")
    except Exception as e:
        logger.warning(f"Opus [{job_id}] structured output call failed, falling back to last response: {e}")
        full_text = ""
        for block in response.content:
            if hasattr(block, "text"):
                full_text += block.text

    # Parse the JSON verdict (should be clean JSON from structured output)
    verdict = None
    try:
        verdict = json.loads(full_text)
    except json.JSONDecodeError:
        verdict = _extract_json_verdict(full_text)
    elapsed = round(time.time() - start_time, 2)

    # Check tool completeness — all 5 tools should have been called
    required_tools = {"get_job_details", "get_agent_trajectory", "get_hitl_interactions",
                      "get_deployment_details", "get_user_jobs", "get_user_ltv"}
    unique_tools_called = set(tool_calls_made)
    missing_tools = required_tools - unique_tools_called
    tools_complete = len(missing_tools) == 0

    if missing_tools:
        logger.warning(f"Opus [{job_id}] incomplete investigation — missing tools: {missing_tools}")

    if verdict:
        verdict["tools_called"] = tool_calls_made
        verdict["turns_used"] = turns_used
        verdict["duration_s"] = elapsed
        verdict["tools_complete"] = tools_complete
        verdict["missing_tools"] = list(missing_tools) if missing_tools else None
        # If tools are incomplete and verdict is LEGITIMATE, downgrade confidence
        if not tools_complete and verdict.get("label") == "LEGITIMATE":
            verdict["confidence"] = "LOW"
            verdict["tools_incomplete_warning"] = f"Missing tools: {', '.join(missing_tools)}"
            logger.warning(f"Opus [{job_id}] LEGITIMATE verdict with incomplete tools — confidence downgraded to LOW")
        logger.info(f"Opus [{job_id}] verdict: {verdict.get('label')} ({verdict.get('confidence')}) in {elapsed}s, {turns_used} turns, tools={'complete' if tools_complete else 'INCOMPLETE'}")
    else:
        logger.warning(f"Opus [{job_id}] failed to parse verdict after {elapsed}s, {turns_used} turns")
        verdict = {
            "label": "NEEDS_HUMAN_REVIEW",
            "error": "verdict_parse_failure",
            "fallback": True,
            "raw_output": full_text[:5000],
            "tools_called": tool_calls_made,
            "turns_used": turns_used,
            "duration_s": elapsed,
            "tools_complete": tools_complete,
            "missing_tools": list(missing_tools) if missing_tools else None,
        }

    return verdict


def _extract_json_verdict(text: str) -> dict | None:
    """Extract a JSON verdict block from agent output text."""
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
