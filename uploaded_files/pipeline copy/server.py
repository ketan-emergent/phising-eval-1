#!/usr/bin/env python3
"""
Phishing Pipeline Server — Eval Playground + Consolidated Trace

All pipeline output appears here. Run this in one terminal,
run classifier.py in another. Watch everything here.
Open http://localhost:3000 in a browser for the eval UI.

Pipeline Endpoints:
    POST /api/pipeline-event     - Receive pipeline lifecycle events
    POST /api/classifier-result  - Receive Stage 1 classifier output
    POST /api/whitecircle-result - Receive WhiteCircle comparison result
    POST /api/webhook            - Receive Stage 2 agent escalation result

Eval Endpoints:
    GET  /api/eval/jobs          - All jobs with eval metadata
    POST /api/eval/verdict/{id}  - Save human verdict + notes
    POST /api/eval/config        - Save prompt version config

Trace Endpoints:
    GET  /api/trace/{job_id}     - Retrieve full pipeline trace as JSON
    GET  /api/traces             - List all traced job_ids

Usage:
    python server.py
"""

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, APIRouter, Request, Query
from fastapi.responses import HTMLResponse
from starlette.middleware.cors import CORSMiddleware
from google.cloud import bigquery
from google.oauth2 import service_account
import os
import logging
import uvicorn

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(title="Phishing Pipeline Server")
api_router = APIRouter(prefix="/api")

# ─── Persistence ────────────────────────────────────────────────────
EVAL_FILE = Path(__file__).parent / "eval_results.json"


def load_eval_data() -> dict:
    """Load eval data from disk. Returns default structure if missing."""
    if EVAL_FILE.exists():
        try:
            return json.loads(EVAL_FILE.read_text())
        except (json.JSONDecodeError, IOError):
            pass
    return {
        "config": {
            "llm_classifier_prompt_version": "v1.0",
            "escalation_agent_prompt_version": "v1.0",
            "user_message_prompt_version": "v1.0",
        },
        "jobs": {},
    }


def save_eval_data():
    """Persist eval_store to disk."""
    try:
        EVAL_FILE.write_text(json.dumps(eval_store, indent=2, default=str))
    except IOError as e:
        logger.error(f"Failed to save eval data: {e}")


eval_store = load_eval_data()

# In-memory trace storage keyed by job_id (volatile, for terminal output)
pipeline_traces: dict[str, dict] = {}

# ─── BigQuery Client (Production Mode) ──────────────────────────────
BQ_SA_PATH = Path(__file__).parent / "emergent-default-9652a48502cc (2).json"
bq_credentials = service_account.Credentials.from_service_account_file(
    str(BQ_SA_PATH),
    scopes=["https://www.googleapis.com/auth/bigquery"],
)
bq_client = bigquery.Client(credentials=bq_credentials, project=bq_credentials.project_id)

W = 60  # card width


# ─── Eval helpers ───────────────────────────────────────────────────

def _current_versions() -> dict:
    """Return the current prompt version config."""
    return {
        "llm_classifier": eval_store["config"].get("llm_classifier_prompt_version", ""),
        "escalation_agent": eval_store["config"].get("escalation_agent_prompt_version", ""),
        "user_message": eval_store["config"].get("user_message_prompt_version", ""),
    }


def _eval_key(job_id: str) -> str:
    """Build composite key: job_id::llm_v::agent_v::msg_v.

    Same job + same versions → same key (update in place).
    Same job + different versions → different key (new row).
    """
    v = _current_versions()
    return f"{job_id}::{v['llm_classifier']}::{v['escalation_agent']}::{v['user_message']}"


def upsert_eval_job(job_id: str, **kwargs):
    """Create or update a job entry in eval_store, keyed by job_id + versions."""
    key = _eval_key(job_id)
    if key not in eval_store["jobs"]:
        eval_store["jobs"][key] = {
            "eval_key": key,
            "job_id": job_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "task_preview": None,
            "user_id": None,
            "image_url": None,
            "stage_1": None,
            "whitecircle": None,
            "stage_2": None,
            "human_verdict_s1": None,
            "human_verdict_wc": None,
            "human_verdict_s2": None,
            "human_notes": None,
            "pipeline_time": None,
            "prompt_versions": _current_versions(),
        }
    job = eval_store["jobs"][key]
    for k, v in kwargs.items():
        if v is not None:
            job[k] = v
    save_eval_data()
    return key


# ─── Terminal display helpers ───────────────────────────────────────

def get_trace(job_id: str) -> dict:
    if job_id not in pipeline_traces:
        pipeline_traces[job_id] = {
            "job_id": job_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "events": [],
            "stage_1_classifier": None,
            "stage_2_escalation": None,
        }
    return pipeline_traces[job_id]


def box_top(title: str = ""):
    if title:
        pad = W - len(title) - 4
        print(f"\n┌─ {title} {'─' * max(pad, 0)}┐")
    else:
        print(f"┌{'─' * W}┐")


def box_row(label: str, value, max_len: int = 0):
    if value is None:
        return
    text = f"  {label}: {value}"
    if max_len and len(text) > max_len:
        text = text[:max_len - 3] + "..."
    print(f"│{text}")


def box_bottom():
    print(f"└{'─' * W}┘")


def box_divider(label: str = ""):
    if label:
        pad = W - len(label) - 4
        print(f"├─ {label} {'─' * max(pad, 0)}┤")
    else:
        print(f"├{'─' * W}┤")


def harm_flags(harm: dict) -> str:
    abbrev = {
        "credential_theft": "CT", "deceptive_exfiltration": "DE",
        "user_deceived": "UD", "tool_for_scale_harm": "SH",
        "service_replication": "SR",
    }
    parts = []
    for key, short in abbrev.items():
        h = harm.get(key, {})
        parts.append(f"{short}:{'YES' if h.get('detected') else 'no'}")
    return "  ".join(parts)


def tools_status(tool_findings: dict) -> str:
    abbrev = {"job_details": "job", "agent_trajectory": "traj", "hitl_interactions": "hitl"}
    parts = []
    for key, short in abbrev.items():
        tf = tool_findings.get(key, {})
        if not tf.get("called", False):
            parts.append(f"{short}:skip")
        elif tf.get("success", False):
            parts.append(f"{short}:ok")
        else:
            parts.append(f"{short}:fail")
    return "  ".join(parts)


def wrap_text(text: str, width: int = 54, prefix: str = "│  "):
    words = text.split()
    line = ""
    for word in words:
        if line and len(line) + len(word) + 1 > width:
            print(f"{prefix}{line}")
            line = word
        else:
            line = f"{line} {word}" if line else word
    if line:
        print(f"{prefix}{line}")


# ─────────────────────────────────────────────────────────────────────
# Serve Eval UI
# ─────────────────────────────────────────────────────────────────────

@app.get("/", response_class=HTMLResponse)
async def serve_eval_ui():
    html_path = Path(__file__).parent / "eval.html"
    return HTMLResponse(html_path.read_text())


# ─────────────────────────────────────────────────────────────────────
# Pipeline Events (lifecycle tracking)
# ─────────────────────────────────────────────────────────────────────

@api_router.post("/pipeline-event")
async def pipeline_event(request: Request):
    body = await request.json()
    job_id = body.get("job_id", "unknown")
    event = body.get("event", "unknown")
    trace = get_trace(job_id)
    trace["events"].append(body)

    if event == "bigquery_fetch":
        data = body.get("data", {})
        existing = data.get("existing_classification", {})
        task = data.get("task_preview", "")

        # Persist to eval
        upsert_eval_job(
            job_id,
            task_preview=task,
            user_id=data.get("user_id"),
            image_url=data.get("image_url"),
        )

        if len(task) > 80:
            task = task[:77] + "..."

        box_top(f"JOB {job_id[:8]}...")
        box_row("Task", task)
        box_row("User", data.get("user_id"))
        if existing:
            bq_phish = existing.get("is_phishing")
            bq_conf = existing.get("confidence_score")
            bq_sev = existing.get("severity")
            box_row("BQ Flag", f"{'PHISHING' if bq_phish else 'LEGIT'}  conf={bq_conf}  sev={bq_sev}")
        box_bottom()

    elif event == "escalation_triggered":
        print(f"  >> Escalating to Stage 2 agent...")

    return {"status": "ok"}


# ─────────────────────────────────────────────────────────────────────
# Stage 1: Classifier Result
# ─────────────────────────────────────────────────────────────────────

@api_router.post("/classifier-result")
async def classifier_result(request: Request):
    body = await request.json()
    job_id = body.get("job_id", "unknown")

    trace = get_trace(job_id)
    s1_data = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "classification": body.get("classification"),
        "raw_output": body.get("raw_output"),
        "elapsed_seconds": body.get("elapsed_seconds"),
        "image_url": body.get("image_url"),
        "user_id": body.get("user_id"),
        "task_preview": body.get("task_preview"),
    }
    trace["stage_1_classifier"] = s1_data

    # Persist to eval
    upsert_eval_job(
        job_id,
        stage_1=s1_data,
        image_url=body.get("image_url"),
        user_id=body.get("user_id"),
        task_preview=body.get("task_preview"),
    )

    cls = body.get("classification", {})
    elapsed = body.get("elapsed_seconds")
    is_phishing = cls.get("result")
    usage = cls.get("_usage", {})
    total_tokens = usage.get("total_tokens", "?") if usage else "?"

    result_str = "PHISHING" if is_phishing else "LEGITIMATE"

    box_top("STAGE 1  LLM Classifier (GPT-5.2)")
    box_row("Result", f"{result_str}  conf={cls.get('confidence')}  sev={cls.get('severity')}")
    if cls.get("category"):
        box_row("Category", ", ".join(cls["category"]))
    box_row("Reason", cls.get("reason"), max_len=90)
    if elapsed:
        box_row("Perf", f"{elapsed:.1f}s  {total_tokens} tokens")
    box_bottom()

    if not is_phishing:
        print("  >> LEGITIMATE — pipeline complete\n")

    return {"status": "ok", "job_id": job_id}


# ─────────────────────────────────────────────────────────────────────
# WhiteCircle Comparison Result
# ─────────────────────────────────────────────────────────────────────

@api_router.post("/whitecircle-result")
async def whitecircle_result(request: Request):
    body = await request.json()
    job_id = body.get("job_id", "unknown")
    wc = body.get("result") or {}
    elapsed = body.get("elapsed_seconds")
    error = body.get("error")

    wc_data = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "flagged": wc.get("flagged"),
        "policies": wc.get("policies", {}),
        "internal_session_id": wc.get("internal_session_id"),
        "elapsed_seconds": elapsed,
        "error": error,
        "raw": wc,
    }

    # Persist to eval
    upsert_eval_job(job_id, whitecircle=wc_data)

    # Terminal output
    if error:
        box_top("WHITECIRCLE  (comparison)")
        box_row("Status", f"ERROR — {error}")
        box_bottom()
    else:
        flagged = wc.get("flagged", False)
        policies = wc.get("policies", {})
        flagged_policies = [p["name"] for p in policies.values() if p.get("flagged")]

        box_top("WHITECIRCLE  (comparison)")
        box_row("Flagged", f"{'YES' if flagged else 'NO'}")
        if flagged_policies:
            box_row("Policies", ", ".join(flagged_policies))
        if elapsed:
            box_row("Latency", f"{elapsed:.1f}s")
        box_bottom()

    return {"status": "ok", "job_id": job_id}


# ─────────────────────────────────────────────────────────────────────
# Stage 2: Agent Escalation Result
# ─────────────────────────────────────────────────────────────────────

@api_router.post("/webhook")
async def agent_webhook(request: Request):
    body = await request.json()
    job_id = body.get("job_id", "unknown")

    trace = get_trace(job_id)
    trace["stage_2_escalation"] = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "result": body,
    }

    classification = body.get("classification", {})
    harm = body.get("harm_assessment", {})
    slack = body.get("slack_summary", {})
    tool_findings = body.get("tool_findings", {})

    label = classification.get("label", "?")
    severity = classification.get("severity", "?")
    confidence = classification.get("confidence", "?")
    reasoning = classification.get("reasoning", "")

    # Compute pipeline time
    s1 = trace.get("stage_1_classifier")
    pipeline_time = None
    if s1 and s1.get("received_at"):
        t1 = datetime.fromisoformat(s1["received_at"])
        t2 = datetime.fromisoformat(trace["stage_2_escalation"]["received_at"])
        pipeline_time = (t2 - t1).total_seconds()

    # Persist to eval — store full S2 body
    upsert_eval_job(
        job_id,
        stage_2=body,
        pipeline_time=pipeline_time,
    )

    # Terminal output
    box_top("STAGE 2  Escalation Agent")
    box_row("Verdict", f"{label}  sev={severity}  conf={confidence}")
    box_divider("Harm Flags")
    print(f"│  {harm_flags(harm)}")
    for key in ["credential_theft", "deceptive_exfiltration", "user_deceived", "tool_for_scale_harm", "service_replication"]:
        h = harm.get(key, {})
        if h.get("detected") and h.get("details"):
            detail = h["details"]
            if len(detail) > 80:
                detail = detail[:77] + "..."
            print(f"│    ^ {key}: {detail}")
    box_divider("Tools")
    print(f"│  {tools_status(tool_findings)}")
    box_divider("Reasoning")
    wrap_text(reasoning, width=56)
    if body.get("what_was_built"):
        box_divider("What Was Built")
        built = body["what_was_built"]
        if len(built) > 200:
            built = built[:197] + "..."
        wrap_text(built, width=56)
    box_bottom()

    # Summary
    s1cls = s1.get("classification", {}) if s1 else {}
    s1_result = "PHISHING" if s1cls.get("result") else "LEGIT" if s1 else "n/a"
    s1_conf = s1cls.get("confidence", "?") if s1 else "?"

    box_top(f"SUMMARY  {job_id[:8]}")
    box_row("S1", f"{s1_result} conf={s1_conf}")
    box_row("S2", f"{label} sev={severity} conf={confidence}")
    if pipeline_time:
        box_row("Time", f"total={pipeline_time:.0f}s")
    if slack:
        box_row("Slack", f"{slack.get('emoji', '')} {slack.get('headline', '')}", max_len=70)
    box_bottom()
    print()

    return {"status": 200}


# ─────────────────────────────────────────────────────────────────────
# Production Mode — BigQuery Endpoints
# ─────────────────────────────────────────────────────────────────────

PROD_QUERY = """
WITH ranked_ph AS (
  SELECT
    ph.job_id, ph.timestamp, ph.user_id, ph.confidence_score,
    ph.is_phishing, ph.image_url, ph.reason, ph.severity,
    jj.task,
    DENSE_RANK() OVER (PARTITION BY ph.job_id ORDER BY ph.timestamp DESC) AS rnk
  FROM `hitl.PhishingClassification` ph
  LEFT JOIN `analytics.jobs_full_view` jj ON ph.job_id = jj.id
  WHERE ph.is_phishing = true
    AND ph.severity IN ('high', 'critical')
),
ph AS (
  SELECT * FROM ranked_ph WHERE rnk = 1
),
ag AS (
  SELECT *
  FROM `phishing_eval.escalation_agent`
  WHERE event_name = 'phishing.escalation.completed'
)
SELECT ph.*, ag.* EXCEPT(job_id)
FROM ph
LEFT JOIN ag ON ph.job_id = ag.job_id
{s2_filter}
ORDER BY ph.timestamp DESC
LIMIT @limit OFFSET @offset
"""

VALID_S2_LABELS = {"CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW", "LEGITIMATE"}


def _safe_str(val, max_len: int = 0) -> Optional[str]:
    """Convert BQ value to string, optionally truncating."""
    if val is None:
        return None
    s = str(val)
    if max_len and len(s) > max_len:
        return s[:max_len]
    return s


def _safe_bool(val) -> Optional[bool]:
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    return str(val).lower() in ("true", "1", "yes")


def transform_bq_to_eval_format(ph_row: dict, ag_row: Optional[dict] = None) -> dict:
    """Map flat BQ rows to the nested eval structure expected by the UI."""
    job_id = ph_row.get("job_id", "")
    eval_key = f"prod::{job_id}"
    timestamp = ph_row.get("timestamp")
    ts_str = timestamp.isoformat() if hasattr(timestamp, "isoformat") else str(timestamp) if timestamp else None
    task_raw = _safe_str(ph_row.get("task"), 300)

    # Stage 1
    stage_1 = {
        "received_at": ts_str,
        "classification": {
            "result": _safe_bool(ph_row.get("is_phishing")),
            "confidence": ph_row.get("confidence_score"),
            "severity": ph_row.get("severity"),
            "reason": ph_row.get("reason"),
            "category": None,
            "_usage": None,
        },
        "raw_output": None,
        "elapsed_seconds": None,
        "image_url": ph_row.get("image_url"),
        "user_id": ph_row.get("user_id"),
        "task_preview": task_raw,
    }

    # Stage 2 (from escalation agent, if available)
    stage_2 = None
    if ag_row:
        stage_2 = {
            "classification": {
                "label": ag_row.get("classification_label"),
                "severity": ag_row.get("classification_severity"),
                "confidence": ag_row.get("classification_confidence"),
                "category": ag_row.get("classification_category"),
                "reasoning": ag_row.get("classification_reasoning"),
            },
            "harm_assessment": {
                "credential_theft": {
                    "detected": _safe_bool(ag_row.get("credential_theft_detected")),
                    "details": ag_row.get("credential_theft_details"),
                },
                "deceptive_exfiltration": {
                    "detected": _safe_bool(ag_row.get("deceptive_exfiltration_detected")),
                    "details": ag_row.get("deceptive_exfiltration_details"),
                },
                "user_deceived": {
                    "detected": _safe_bool(ag_row.get("user_deceived_detected")),
                    "details": ag_row.get("user_deceived_details"),
                },
                "tool_for_scale_harm": {
                    "detected": _safe_bool(ag_row.get("tool_for_scale_harm_detected")),
                    "details": ag_row.get("tool_for_scale_harm_details"),
                },
                "service_replication": {
                    "detected": _safe_bool(ag_row.get("service_replication_detected")),
                    "details": ag_row.get("service_replication_details"),
                },
            },
            "what_was_built": ag_row.get("what_was_built"),
            "slack_summary": {
                "emoji": ag_row.get("slack_emoji"),
                "headline": ag_row.get("slack_headline"),
                "verdict": ag_row.get("slack_verdict"),
            },
            "tool_findings": {
                "job_details": {
                    "called": _safe_bool(ag_row.get("job_details_called")),
                    "success": _safe_bool(ag_row.get("job_details_success")),
                    "key_findings": ag_row.get("job_key_findings"),
                },
                "agent_trajectory": {
                    "called": _safe_bool(ag_row.get("agent_trajectory_called")),
                    "success": _safe_bool(ag_row.get("agent_trajectory_success")),
                    "total_steps": ag_row.get("agent_trajectory_total_steps"),
                    "key_findings": ag_row.get("trajectory_key_findings"),
                    "suspicious_actions": ag_row.get("suspicious_actions"),
                    "external_urls_detected": ag_row.get("external_urls_detected"),
                },
                "hitl_interactions": {
                    "called": _safe_bool(ag_row.get("hitl_interactions_called")),
                    "success": _safe_bool(ag_row.get("hitl_interactions_success")),
                    "total_hitl_interactions": ag_row.get("total_hitl_interactions"),
                    "key_findings": ag_row.get("hitl_key_findings"),
                    "notable_quotes": ag_row.get("hitl_notable_quotes"),
                },
            },
        }

    # Merge existing verdicts from eval_results.json
    existing = eval_store.get("jobs", {}).get(eval_key, {})

    return {
        "eval_key": eval_key,
        "job_id": job_id,
        "created_at": ts_str,
        "task_preview": task_raw,
        "user_id": ph_row.get("user_id"),
        "image_url": ph_row.get("image_url"),
        "stage_1": stage_1,
        "whitecircle": None,
        "stage_2": stage_2,
        "human_verdict_s1": existing.get("human_verdict_s1"),
        "human_verdict_wc": existing.get("human_verdict_wc"),
        "human_verdict_s2": existing.get("human_verdict_s2"),
        "human_notes": existing.get("human_notes"),
        "pipeline_time": None,
        "prompt_versions": {
            "llm_classifier": "prod",
            "escalation_agent": "prod",
            "user_message": "prod",
        },
    }


@api_router.get("/prod/jobs")
async def prod_jobs(
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    s2_labels: Optional[str] = Query(None, description="Comma-separated S2 labels to filter by"),
):
    """Fetch production phishing classifications from BigQuery with pagination.

    s2_labels: comma-separated list like "CONFIRMED_MALICIOUS,NEEDS_HUMAN_REVIEW"
               If omitted or empty, returns all rows (no S2 filter).
    """
    try:
        # Build S2 label filter clause
        s2_filter = ""
        query_params = [
            bigquery.ScalarQueryParameter("limit", "INT64", limit + 1),
            bigquery.ScalarQueryParameter("offset", "INT64", offset),
        ]

        if s2_labels:
            labels = [l.strip() for l in s2_labels.split(",") if l.strip() in VALID_S2_LABELS]
            if labels:
                s2_filter = "WHERE ag.classification_label IN UNNEST(@s2_labels)"
                query_params.append(
                    bigquery.ArrayQueryParameter("s2_labels", "STRING", labels),
                )

        query = PROD_QUERY.format(s2_filter=s2_filter)

        job = bq_client.query(
            query,
            job_config=bigquery.QueryJobConfig(query_parameters=query_params),
        )
        rows = [dict(row) for row in job.result()]

        has_more = len(rows) > limit
        if has_more:
            rows = rows[:limit]

        if not rows:
            return {"jobs": [], "has_more": False, "total_loaded": offset}

        # Transform to eval format (each row has both ph + ag columns)
        result_jobs = []
        for row in rows:
            # Split the combined row into ph_row and ag_row parts
            ph_row = {
                "job_id": row.get("job_id"),
                "timestamp": row.get("timestamp"),
                "user_id": row.get("user_id"),
                "confidence_score": row.get("confidence_score"),
                "is_phishing": row.get("is_phishing"),
                "image_url": row.get("image_url"),
                "reason": row.get("reason"),
                "severity": row.get("severity"),
                "task": row.get("task"),
            }
            # ag columns are everything else — pass the full row as ag_row
            # (transform_bq_to_eval_format uses .get() so extra keys are harmless)
            ag_row = row if row.get("classification_label") is not None else None
            result_jobs.append(transform_bq_to_eval_format(ph_row, ag_row))

        return {
            "jobs": result_jobs,
            "has_more": has_more,
            "total_loaded": offset + len(result_jobs),
        }

    except Exception as e:
        logger.error(f"Production jobs query failed: {e}")
        return {"error": str(e), "jobs": [], "has_more": False, "total_loaded": 0}


@api_router.post("/prod/verdict/{job_id}")
async def prod_verdict(job_id: str, request: Request):
    """Save human verdict for a production job. Uses prod::{job_id} key in eval_results.json."""
    body = await request.json()
    eval_key = f"prod::{job_id}"

    if eval_key not in eval_store["jobs"]:
        eval_store["jobs"][eval_key] = {
            "eval_key": eval_key,
            "job_id": job_id,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "human_verdict_s1": None,
            "human_verdict_wc": None,
            "human_verdict_s2": None,
            "human_notes": None,
            "prompt_versions": {
                "llm_classifier": "prod",
                "escalation_agent": "prod",
                "user_message": "prod",
            },
        }

    job = eval_store["jobs"][eval_key]
    if "verdict_s1" in body:
        job["human_verdict_s1"] = body["verdict_s1"]
    if "verdict_wc" in body:
        job["human_verdict_wc"] = body["verdict_wc"]
    if "verdict_s2" in body:
        job["human_verdict_s2"] = body["verdict_s2"]
    if "notes" in body:
        job["human_notes"] = body["notes"]
    save_eval_data()

    return {"status": "ok", "eval_key": eval_key}


# ─────────────────────────────────────────────────────────────────────
# Eval API
# ─────────────────────────────────────────────────────────────────────

@api_router.get("/eval/jobs")
async def eval_jobs():
    """Return all eval jobs + config for the UI."""
    return {
        "config": eval_store.get("config", {}),
        "jobs": list(eval_store.get("jobs", {}).values()),
    }


@api_router.post("/eval/verdict/{eval_key:path}")
async def eval_verdict(eval_key: str, request: Request):
    """Save human verdict and/or notes for a job. Key is eval_key (job_id::versions)."""
    body = await request.json()
    if eval_key not in eval_store["jobs"]:
        return {"error": f"No eval entry found for key: {eval_key}"}

    job = eval_store["jobs"][eval_key]
    if "verdict_s1" in body:
        job["human_verdict_s1"] = body["verdict_s1"]
    if "verdict_wc" in body:
        job["human_verdict_wc"] = body["verdict_wc"]
    if "verdict_s2" in body:
        job["human_verdict_s2"] = body["verdict_s2"]
    if "notes" in body:
        job["human_notes"] = body["notes"]
    save_eval_data()

    return {"status": "ok", "eval_key": eval_key}


@api_router.post("/eval/config")
async def eval_config(request: Request):
    """Save prompt version config."""
    body = await request.json()
    eval_store["config"].update(body)
    save_eval_data()
    return {"status": "ok"}


# ─────────────────────────────────────────────────────────────────────
# Trace retrieval
# ─────────────────────────────────────────────────────────────────────

@api_router.get("/trace/{job_id}")
async def get_job_trace(job_id: str):
    if job_id not in pipeline_traces:
        return {"error": f"No trace found for job_id: {job_id}"}
    return pipeline_traces[job_id]


@api_router.get("/traces")
async def list_traces():
    summaries = []
    for job_id, trace in pipeline_traces.items():
        s1 = trace.get("stage_1_classifier")
        s2 = trace.get("stage_2_escalation")
        summaries.append({
            "job_id": job_id,
            "created_at": trace.get("created_at"),
            "stage_1_complete": s1 is not None,
            "stage_2_complete": s2 is not None,
            "stage_1_result": s1.get("classification", {}).get("result") if s1 else None,
            "stage_2_label": s2.get("result", {}).get("classification", {}).get("label") if s2 else None,
        })
    return {"traces": summaries, "total": len(summaries)}


@api_router.post("/alert")
async def mongo_alert_webhook(request: Request):
    raw_body = await request.body()
    print(raw_body)
    return {"status": "verified"}


app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)

if __name__ == "__main__":
    # Suppress noisy polling logs from eval UI auto-refresh
    class QuietAccessLog(logging.Filter):
        def filter(self, record):
            msg = record.getMessage()
            return "GET /api/eval/jobs" not in msg and "GET /api/prod/jobs" not in msg and "GET / " not in msg

    logging.getLogger("uvicorn.access").addFilter(QuietAccessLog())

    print(f"\n  Eval UI:  http://localhost:3456\n")
    uvicorn.run(app, host="localhost", port=3456)
