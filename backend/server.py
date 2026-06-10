"""
Phishing Pipeline Server -- Eval Playground + Consolidated Trace
Migrated to Emergent platform with MongoDB, BigQuery, and Supabase Auth.
"""

import json
import asyncio
import httpx
import logging
import os
import re
import uuid as uuid_mod
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from automation import (
    run_automation_tick,
    execute_pending_takedowns,
    ensure_automation_indexes,
    sync_actions_to_bq,
    classify_tier,
    has_mcp_error,
    format_policies,
    log_pipeline_run,
    get_dry_run,
    set_dry_run,
    auto_takedown_job,
    slack_notify_external,
    send_external_takedown_notification,
)
from pipeline_health import pipeline_health_loop, check_pipeline_health
from abuse_responder import extract_domains, lookup_url_via_redash, build_reply, reply_in_thread
from datetime import timedelta
from dotenv import load_dotenv
from fastapi import FastAPI, APIRouter, Request, Query, HTTPException
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
from google.cloud import bigquery
from google.oauth2 import service_account

ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / ".env")

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger(__name__)

# MongoDB
# The platform-injected MONGO_URL may contain timeoutMS=10000 which is too aggressive
# for bulk operations (20K+ upserts). Override with longer socket/server timeouts.
mongo_url = os.environ["MONGO_URL"]
mongo_client = AsyncIOMotorClient(
    mongo_url,
    socketTimeoutMS=120_000,       # 120s per socket operation (bulk_write batches)
    connectTimeoutMS=30_000,       # 30s for initial connection
    serverSelectionTimeoutMS=30_000,  # 30s for server selection
    timeoutMS=None,                # Disable CSOT (Client-Side Operation Timeout) so it
                                   # doesn't override the socket/connect timeouts above
)
db = mongo_client[os.environ["DB_NAME"]]

app = FastAPI(title="Phishing Pipeline Server", redirect_slashes=False)
api_router = APIRouter(prefix="/api")

# BigQuery Client
BQ_SA_PATH = ROOT_DIR / "gcp-service-account.json"
bq_client = None
try:
    bq_credentials = service_account.Credentials.from_service_account_file(
        str(BQ_SA_PATH),
        scopes=["https://www.googleapis.com/auth/bigquery"],
    )
    bq_client = bigquery.Client(credentials=bq_credentials, project=bq_credentials.project_id)
    logger.info("BigQuery client initialized successfully")
except Exception as e:
    logger.error(f"BigQuery client init failed: {e}")

# Pipeline cutoff — only process data from this timestamp onwards
BQ_CUTOFF = "2026-02-21 10:48:21.939779 UTC"



# ---- Supabase Auth ----

SUPABASE_URL = os.environ.get("SUPABASE_URL")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY")

_supabase_user_cache = {}


async def get_current_user(request: Request) -> dict:
    token = None
    # Try Authorization header first
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:]
    # Fallback: cookie
    if not token:
        token = request.cookies.get("sb_token")
    # Fallback: query param (survives proxy 307 redirects that strip headers)
    if not token:
        token = request.query_params.get("_token")
    if not token:
        raise HTTPException(status_code=401, detail="Not authenticated: missing Authorization header")

    # Verify token with Supabase
    try:
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{SUPABASE_URL}/auth/v1/user",
                headers={
                    "Authorization": f"Bearer {token}",
                    "apikey": SUPABASE_ANON_KEY,
                },
            )
        if resp.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid or expired token")

        supabase_user = resp.json()
        email = supabase_user.get("email", "")
        user_id = supabase_user.get("id", "")

        return {
            "user_id": user_id,
            "email": email,
            "name": supabase_user.get("user_metadata", {}).get("name", email.split("@")[0]),
        }
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Supabase token verification failed: {e}")
        raise HTTPException(status_code=401, detail="Authentication failed")


@api_router.get("/auth/me")
async def auth_me(request: Request):
    return await get_current_user(request)


# ---- Health Check ----

@app.get("/health")
async def root_health_check():
    """Root health check for deployment platform (no /api prefix)."""
    return {"status": "ok"}


@app.get("/api/sync-debug")
async def sync_debug():
    """Debug endpoint to check sync status (no auth required)."""
    try:
        bq_count = await db.bq_jobs.count_documents({})
        sync_meta = await db.sync_metadata.find_one({"_id": "bq_sync"})
        if sync_meta:
            sync_meta.pop("_id", None)
        aa_count = await db.automated_actions.count_documents({})
        td_count = await db.takedowns.count_documents({})
        return {
            "bq_jobs_count": bq_count,
            "automated_actions_count": aa_count,
            "takedowns_count": td_count,
            "sync_metadata": sync_meta or "no sync yet",
            "bigquery_connected": bq_client is not None,
        }
    except Exception as e:
        return {"error": str(e)}


@api_router.get("/health")
async def health_check():
    checks = {"status": "ok", "mongo": False, "bigquery": False}
    try:
        await db.command("ping")
        checks["mongo"] = True
    except Exception:
        pass
    if bq_client:
        checks["bigquery"] = True
    return checks


# ---- Eval Config helpers ----

async def get_eval_config() -> dict:
    config = await db.eval_config.find_one({"_id": "global"})
    if config:
        return {
            "llm_classifier_prompt_version": config.get("llm_classifier_prompt_version", "v1.0"),
            "escalation_agent_prompt_version": config.get("escalation_agent_prompt_version", "v1.0"),
            "user_message_prompt_version": config.get("user_message_prompt_version", "v1.0"),
        }
    return {
        "llm_classifier_prompt_version": "v1.0",
        "escalation_agent_prompt_version": "v1.0",
        "user_message_prompt_version": "v1.0",
    }


async def current_versions() -> dict:
    cfg = await get_eval_config()
    return {
        "llm_classifier": cfg.get("llm_classifier_prompt_version", ""),
        "escalation_agent": cfg.get("escalation_agent_prompt_version", ""),
        "user_message": cfg.get("user_message_prompt_version", ""),
    }


def eval_key(job_id: str, versions: dict) -> str:
    return f"{job_id}::{versions['llm_classifier']}::{versions['escalation_agent']}::{versions['user_message']}"


async def upsert_eval_job(job_id: str, **kwargs):
    v = await current_versions()
    key = eval_key(job_id, v)
    existing = await db.eval_jobs.find_one({"eval_key": key}, {"_id": 0})
    if not existing:
        doc = {
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
            "prompt_versions": v,
        }
        for k, val in kwargs.items():
            if val is not None:
                doc[k] = val
        await db.eval_jobs.insert_one(doc)
    else:
        updates = {k: val for k, val in kwargs.items() if val is not None}
        if updates:
            await db.eval_jobs.update_one({"eval_key": key}, {"$set": updates})
    return key


# ---- Pipeline Events ----

@api_router.post("/pipeline-event")
async def pipeline_event(request: Request):
    body = await request.json()
    job_id = body.get("job_id", "unknown")
    event = body.get("event", "unknown")

    await db.pipeline_traces.update_one(
        {"job_id": job_id},
        {"$setOnInsert": {"job_id": job_id, "created_at": datetime.now(timezone.utc).isoformat()},
         "$push": {"events": body}},
        upsert=True,
    )

    if event == "bigquery_fetch":
        data = body.get("data", {})
        await upsert_eval_job(
            job_id,
            task_preview=data.get("task_preview"),
            user_id=data.get("user_id"),
            image_url=data.get("image_url"),
        )

    return {"status": "ok"}


@api_router.post("/classifier-result")
async def classifier_result(request: Request):
    body = await request.json()
    job_id = body.get("job_id", "unknown")

    s1_data = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "classification": body.get("classification"),
        "raw_output": body.get("raw_output"),
        "elapsed_seconds": body.get("elapsed_seconds"),
        "image_url": body.get("image_url"),
        "user_id": body.get("user_id"),
        "task_preview": body.get("task_preview"),
    }

    await db.pipeline_traces.update_one(
        {"job_id": job_id},
        {"$set": {"stage_1_classifier": s1_data}},
        upsert=True,
    )
    await upsert_eval_job(
        job_id,
        stage_1=s1_data,
        image_url=body.get("image_url"),
        user_id=body.get("user_id"),
        task_preview=body.get("task_preview"),
    )

    return {"status": "ok", "job_id": job_id}


@api_router.post("/whitecircle-result")
async def whitecircle_result(request: Request):
    body = await request.json()
    job_id = body.get("job_id", "unknown")
    wc = body.get("result") or {}
    wc_data = {
        "received_at": datetime.now(timezone.utc).isoformat(),
        "flagged": wc.get("flagged"),
        "policies": wc.get("policies", {}),
        "internal_session_id": wc.get("internal_session_id"),
        "elapsed_seconds": body.get("elapsed_seconds"),
        "error": body.get("error"),
        "raw": wc,
    }
    await upsert_eval_job(job_id, whitecircle=wc_data)
    return {"status": "ok", "job_id": job_id}


@api_router.post("/webhook")
async def agent_webhook(request: Request):
    body = await request.json()
    job_id = body.get("job_id", "unknown")

    classification = body.get("classification", {})
    trace = await db.pipeline_traces.find_one({"job_id": job_id})
    pipeline_time = None
    if trace:
        s1 = trace.get("stage_1_classifier")
        if s1 and s1.get("received_at"):
            t1 = datetime.fromisoformat(s1["received_at"])
            t2 = datetime.now(timezone.utc)
            pipeline_time = (t2 - t1).total_seconds()

    await db.pipeline_traces.update_one(
        {"job_id": job_id},
        {"$set": {"stage_2_escalation": {"received_at": datetime.now(timezone.utc).isoformat(), "result": body}}},
        upsert=True,
    )
    await upsert_eval_job(job_id, stage_2=body, pipeline_time=pipeline_time)
    return {"status": 200}


# ---- BigQuery → MongoDB Sync ----

# When live mode is enabled, only process escalation_agent rows emitted after this cutoff.
# This prevents re-processing all historical jobs when switching from dry_run to live.
LIVE_MODE_ESCALATION_CUTOFF = "2026-03-09T18:40:00Z"

SYNC_INTERVAL_SECONDS = 30 * 60  # 30 minutes

SYNC_QUERY = f"""
WITH ranked_ph AS (
  SELECT
    ph.job_id, ph.timestamp, ph.user_id, ph.confidence_score,
    ph.is_phishing, ph.image_url, ph.reason, ph.severity,
    jj.task, jj.model_name,
    DENSE_RANK() OVER (PARTITION BY ph.job_id ORDER BY ph.timestamp DESC) AS rnk
  FROM `hitl.PhishingClassification` ph
  LEFT JOIN `analytics.jobs_full_view` jj ON ph.job_id = jj.id
  WHERE ph.is_phishing = true
    AND ph.severity IN ('high', 'critical')
    AND ph.timestamp >= '{BQ_CUTOFF}'
),
ph AS (SELECT * FROM ranked_ph WHERE rnk = 1),
ranked_ag AS (
  SELECT *,
    ROW_NUMBER() OVER (
      PARTITION BY job_id
      ORDER BY
        CASE classification_label
          WHEN 'CONFIRMED_MALICIOUS' THEN 1
          WHEN 'NEEDS_HUMAN_REVIEW' THEN 2
          WHEN 'LEGITIMATE' THEN 3
          ELSE 4
        END,
        CASE classification_severity
          WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
          WHEN 'MODERATE' THEN 3 ELSE 4
        END,
        emitted_at DESC
    ) AS ag_rnk
  FROM `phishing_eval.escalation_agent`
  WHERE event_name = 'phishing.escalation.completed'
    AND emitted_at >= '{BQ_CUTOFF}'
),
ag AS (SELECT * EXCEPT(ag_rnk) FROM ranked_ag WHERE ag_rnk = 1)
SELECT ph.*, ag.* EXCEPT(job_id)
FROM ph
LEFT JOIN ag ON ph.job_id = ag.job_id
WHERE ph.timestamp >= @last_sync OR ag.emitted_at >= @last_sync
"""

FULL_SYNC_QUERY = f"""
WITH ranked_ph AS (
  SELECT
    ph.job_id, ph.timestamp, ph.user_id, ph.confidence_score,
    ph.is_phishing, ph.image_url, ph.reason, ph.severity,
    jj.task, jj.model_name,
    DENSE_RANK() OVER (PARTITION BY ph.job_id ORDER BY ph.timestamp DESC) AS rnk
  FROM `hitl.PhishingClassification` ph
  LEFT JOIN `analytics.jobs_full_view` jj ON ph.job_id = jj.id
  WHERE ph.is_phishing = true
    AND ph.severity IN ('high', 'critical')
    AND ph.timestamp >= '{BQ_CUTOFF}'
),
ph AS (SELECT * FROM ranked_ph WHERE rnk = 1),
ranked_ag AS (
  SELECT *,
    ROW_NUMBER() OVER (
      PARTITION BY job_id
      ORDER BY
        CASE classification_label
          WHEN 'CONFIRMED_MALICIOUS' THEN 1
          WHEN 'NEEDS_HUMAN_REVIEW' THEN 2
          WHEN 'LEGITIMATE' THEN 3
          ELSE 4
        END,
        CASE classification_severity
          WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
          WHEN 'MODERATE' THEN 3 ELSE 4
        END,
        emitted_at DESC
    ) AS ag_rnk
  FROM `phishing_eval.escalation_agent`
  WHERE event_name = 'phishing.escalation.completed'
    AND emitted_at >= '{BQ_CUTOFF}'
),
ag AS (SELECT * EXCEPT(ag_rnk) FROM ranked_ag WHERE ag_rnk = 1)
SELECT ph.*, ag.* EXCEPT(job_id)
FROM ph
LEFT JOIN ag ON ph.job_id = ag.job_id
"""


def _safe_str(val, max_len=0):
    if val is None:
        return None
    s = str(val)
    if max_len and len(s) > max_len:
        return s[:max_len]
    return s


def _safe_bool(val):
    if val is None:
        return None
    if isinstance(val, bool):
        return val
    return str(val).lower() in ("true", "1", "yes")


def _ts_to_str(val):
    if val is None:
        return None
    if hasattr(val, "isoformat"):
        return val.isoformat()
    return str(val)


BQ_USER_DETAILS_BATCH_SIZE = 50  # Max user_ids per EXTERNAL_QUERY call


def _build_user_details_query(user_ids: list) -> str:
    """Build BQ query to fetch user emails + subscription/LTV data for given user_ids."""
    # Validate all IDs are UUIDs to prevent injection
    for uid in user_ids:
        uuid_mod.UUID(uid)

    pg_array_items = ", ".join(f"\\'{uid}\\'" for uid in user_ids)

    return f"""
    WITH user_emails AS (
      SELECT id AS user_id, email
      FROM EXTERNAL_QUERY(
        'emergent-default.us-central1.agent_service_psql_connection',
        'SELECT id::text, email FROM users WHERE id::text = ANY(ARRAY[{pg_array_items}])'
      )
    ),
    sub_events AS (
      SELECT *, DENSE_RANK() OVER (PARTITION BY user_id ORDER BY created_at DESC) AS rnk
      FROM `analytics.subscription_events`
    )
    SELECT
      ue.user_id,
      ue.email,
      COALESCE(se.plan_type, 'Free User') AS plan_type,
      COALESCE(r.ltv, 0) AS ltv,
      se.payment_gateway,
      COALESCE(se.discount_amount, 0) AS discount_amount
    FROM user_emails ue
    LEFT JOIN (SELECT * FROM sub_events WHERE rnk = 1) se ON ue.user_id = se.user_id
    LEFT JOIN (
      SELECT user_id, SUM(amount) AS ltv
      FROM `analytics.user_revenue_events`
      GROUP BY 1
    ) r ON ue.user_id = r.user_id
    """


def _fetch_user_details_from_bq(user_ids: list) -> dict:
    """Fetch user details from BQ in batches. Returns {user_id: {email, plan_type, ltv, ...}}."""
    if not bq_client or not user_ids:
        return {}

    result = {}
    for i in range(0, len(user_ids), BQ_USER_DETAILS_BATCH_SIZE):
        batch = user_ids[i:i + BQ_USER_DETAILS_BATCH_SIZE]
        try:
            query = _build_user_details_query(batch)
            rows = list(bq_client.query(query).result())
            for r in rows:
                result[r.user_id] = {
                    "user_email": r.email,
                    "plan_type": r.plan_type,
                    "ltv": float(r.ltv) if r.ltv is not None else 0.0,
                    "payment_gateway": r.payment_gateway,
                    "discount_amount": float(r.discount_amount) if r.discount_amount is not None else 0.0,
                }
        except Exception as e:
            logger.error(f"User details BQ fetch failed for batch starting at {i} ({len(batch)} users): {type(e).__name__}: {e}")

    return result


def transform_bq_row_to_doc(row: dict) -> dict:
    """Transform a BQ row into the MongoDB bq_jobs document format."""
    job_id = row.get("job_id", "")
    ts_str = _ts_to_str(row.get("timestamp"))
    task_raw = _safe_str(row.get("task"))
    emitted_at_str = _ts_to_str(row.get("emitted_at"))

    doc = {
        "job_id": job_id,
        "timestamp": ts_str,
        "user_id": row.get("user_id"),
        "confidence_score": row.get("confidence_score"),
        "is_phishing": _safe_bool(row.get("is_phishing")),
        "image_url": row.get("image_url"),
        "reason": row.get("reason"),
        "severity": row.get("severity"),
        "task": task_raw,
        "model_name": _safe_str(row.get("model_name")),
        "classification_label": row.get("classification_label"),
        "classification_severity": row.get("classification_severity"),
        "classification_confidence": row.get("classification_confidence"),
        "classification_category": row.get("classification_category"),
        "classification_reasoning": row.get("classification_reasoning"),
        "credential_theft_detected": _safe_bool(row.get("credential_theft_detected")),
        "credential_theft_details": row.get("credential_theft_details"),
        "deceptive_exfiltration_detected": _safe_bool(row.get("deceptive_exfiltration_detected")),
        "deceptive_exfiltration_details": row.get("deceptive_exfiltration_details"),
        "user_deceived_detected": _safe_bool(row.get("user_deceived_detected")),
        "user_deceived_details": row.get("user_deceived_details"),
        "tool_for_scale_harm_detected": _safe_bool(row.get("tool_for_scale_harm_detected")),
        "tool_for_scale_harm_details": row.get("tool_for_scale_harm_details"),
        "service_replication_detected": _safe_bool(row.get("service_replication_detected")),
        "service_replication_details": row.get("service_replication_details"),
        "violent_harmful_content_detected": _safe_bool(row.get("violent_harmful_content_detected")),
        "violent_harmful_content_details": row.get("violent_harmful_content_details"),
        "illegal_content_detected": _safe_bool(row.get("illegal_content_detected")),
        "illegal_content_details": row.get("illegal_content_details"),
        "malware_delivery_detected": _safe_bool(row.get("malware_delivery_detected")),
        "malware_delivery_details": row.get("malware_delivery_details"),
        "what_was_built": row.get("what_was_built"),
        "image_analysis_note": row.get("image_analysis_note"),
        "recommended_actions": row.get("recommended_actions"),
        "task_description": row.get("task_description"),
        "slack_emoji": row.get("slack_emoji"),
        "slack_headline": row.get("slack_headline"),
        "slack_verdict": row.get("slack_verdict"),
        "job_details_called": _safe_bool(row.get("job_details_called")),
        "job_details_success": _safe_bool(row.get("job_details_success")),
        "job_key_findings": row.get("job_key_findings"),
        "job_task_description": row.get("job_task_description"),
        "agent_trajectory_called": _safe_bool(row.get("agent_trajectory_called")),
        "agent_trajectory_success": _safe_bool(row.get("agent_trajectory_success")),
        "agent_trajectory_total_steps": row.get("agent_trajectory_total_steps"),
        "trajectory_key_findings": row.get("trajectory_key_findings"),
        "suspicious_actions": row.get("suspicious_actions"),
        "external_urls_detected": row.get("external_urls_detected"),
        "hitl_interactions_called": _safe_bool(row.get("hitl_interactions_called")),
        "hitl_interactions_success": _safe_bool(row.get("hitl_interactions_success")),
        "total_hitl_interactions": row.get("total_hitl_interactions"),
        "hitl_key_findings": row.get("hitl_key_findings"),
        "hitl_notable_quotes": row.get("hitl_notable_quotes"),
        "deployment_details_called": _safe_bool(row.get("deployment_details_called")),
        "deployment_details_success": _safe_bool(row.get("deployment_details_success")),
        "has_active_deployment": _safe_bool(row.get("has_active_deployment")),
        "deployment_url": row.get("deployment_url"),
        "deployment_key_findings": row.get("deployment_key_findings"),
        "emitted_at": emitted_at_str,
        "synced_at": datetime.now(timezone.utc).isoformat(),
    }
    # User detail fields (populated by Phase 2 of sync, preserved if already set)
    for uf in ("user_email", "plan_type", "ltv", "payment_gateway", "discount_amount"):
        if uf in row:
            doc[uf] = row[uf]
    return doc


async def run_bq_sync(full: bool = False):
    """Sync BigQuery data into MongoDB bq_jobs collection."""
    if not bq_client:
        logger.warning("BQ sync skipped: BigQuery client not configured")
        return {"status": "skipped", "reason": "no bq_client"}

    try:
        if full:
            query = FULL_SYNC_QUERY
            query_params = []
            logger.info("Starting FULL BQ → MongoDB sync...")
        else:
            sync_meta = await db.sync_metadata.find_one({"_id": "bq_sync"})
            if sync_meta and sync_meta.get("last_sync_at"):
                last_sync = sync_meta["last_sync_at"]
            else:
                last_sync = BQ_CUTOFF
                full = True
                query = FULL_SYNC_QUERY
                query_params = []

            if not full:
                query = SYNC_QUERY
                query_params = [bigquery.ScalarQueryParameter("last_sync", "TIMESTAMP", last_sync)]
                logger.info(f"Starting incremental BQ → MongoDB sync since {last_sync}...")

        # In live mode, restrict ALL data to after the live cutoff
        # Both PhishingClassification (ph.timestamp) and escalation_agent (emitted_at)
        if not get_dry_run():
            query = query.replace(
                f"AND ph.timestamp >= '{BQ_CUTOFF}'",
                f"AND ph.timestamp >= '{LIVE_MODE_ESCALATION_CUTOFF}'",
            )
            query = query.replace(
                f"AND emitted_at >= '{BQ_CUTOFF}'",
                f"AND emitted_at >= '{LIVE_MODE_ESCALATION_CUTOFF}'",
            )
            logger.info(f"LIVE MODE: all data filtered to >= {LIVE_MODE_ESCALATION_CUTOFF}")

        job_config = bigquery.QueryJobConfig(query_parameters=query_params) if query_params else bigquery.QueryJobConfig()
        # Run BQ query in a thread to avoid blocking the event loop (health checks)
        def _run_bq_query():
            bq_job = bq_client.query(query, job_config=job_config)
            return [dict(r) for r in bq_job.result()]
        rows = await asyncio.to_thread(_run_bq_query)
        logger.info(f"BQ sync: fetched {len(rows)} rows")

        import time as _time
        pipeline_stats = {}

        # ---- Phase 1: Upsert BQ rows into bq_jobs (isolated error handling) ----
        p1_start = _time.time()
        upserted = 0
        modified = 0
        phase1_failed_batches = 0
        from pymongo import UpdateOne
        if rows:
            ops = []
            for row in rows:
                doc = transform_bq_row_to_doc(row)
                ops.append(UpdateOne(
                    {"job_id": doc["job_id"]},
                    {"$set": doc},
                    upsert=True,
                ))
            # Write in batches of 200 to stay within Atlas timeoutMS
            BATCH_SIZE = 200
            for i in range(0, len(ops), BATCH_SIZE):
                batch = ops[i:i + BATCH_SIZE]
                try:
                    result = await db.bq_jobs.bulk_write(batch, ordered=False)
                    upserted += result.upserted_count
                    modified += result.modified_count
                except Exception as batch_err:
                    phase1_failed_batches += 1
                    logger.error(f"Phase 1: batch {i//BATCH_SIZE + 1} failed ({len(batch)} ops): {type(batch_err).__name__}: {batch_err}")
                await asyncio.sleep(0)  # yield to event loop for health checks
            if phase1_failed_batches:
                logger.warning(f"BQ sync Phase 1: upserted {upserted}, modified {modified}, {phase1_failed_batches} batches failed")
            else:
                logger.info(f"BQ sync Phase 1: upserted {upserted}, modified {modified}")

        pipeline_stats["phase_1"] = {
            "name": "BQ Sync",
            "status": "error" if phase1_failed_batches else "ok",
            "duration_s": round(_time.time() - p1_start, 2),
            "rows_fetched": len(rows),
            "upserted": upserted,
            "modified": modified,
            "failed_batches": phase1_failed_batches,
            "is_full_sync": full,
        }

        # Always write sync_metadata (even on partial Phase 1 success) to prevent full-sync retry loop
        now = datetime.now(timezone.utc).isoformat()
        update_fields = {"last_sync_at": now, "jobs_synced": len(rows), "upserted": upserted}
        if full:
            update_fields["last_full_sync_at"] = now
        if phase1_failed_batches:
            update_fields["phase1_failed_batches"] = phase1_failed_batches
        try:
            await db.sync_metadata.update_one(
                {"_id": "bq_sync"},
                {"$set": update_fields},
                upsert=True,
            )
        except Exception as meta_err:
            logger.error(f"sync_metadata write failed (non-fatal): {type(meta_err).__name__}: {meta_err}")

        # Ensure indexes
        try:
            # Deduplicate bq_jobs before creating unique index (keeps newest per job_id)
            pipeline = [
                {"$sort": {"synced_at": -1}},
                {"$group": {"_id": "$job_id", "keep_id": {"$first": "$_id"}, "count": {"$sum": 1}}},
                {"$match": {"count": {"$gt": 1}}},
            ]
            dupes = await db.bq_jobs.aggregate(pipeline).to_list(10000)
            if dupes:
                # Collect all _ids to keep, delete the rest for each dup job_id
                for d in dupes:
                    await db.bq_jobs.delete_many({"job_id": d["_id"], "_id": {"$ne": d["keep_id"]}})
                logger.info(f"Deduplicated {len(dupes)} bq_jobs entries before index creation")

            # Drop old index if it exists but is incompatible
            try:
                await db.bq_jobs.drop_index("job_id_1")
            except Exception:
                pass
            await db.bq_jobs.create_index([("job_id", 1)], unique=True)
            await db.bq_jobs.create_index("classification_label")
            await db.bq_jobs.create_index("timestamp")
            await db.bq_jobs.create_index("opus_label")
            await db.bq_jobs.create_index("human_verdict_s2")
            await db.bq_jobs.create_index("external_source")
            await db.automated_actions.create_index([("job_id", 1), ("dry_run", 1)], unique=True)
            await db.automated_actions.create_index("tier")
        except Exception as idx_err:
            logger.error(f"Index creation failed (non-fatal): {type(idx_err).__name__}: {idx_err}")

        # ---- Phase 2: Enrich jobs missing user details ----
        p2_start = _time.time()
        p2_enriched = 0
        p2_missing_after = 0
        p2_status = "ok"
        try:
            # Count before to measure
            p2_missing_before = await db.bq_jobs.count_documents({
                "$or": [{"user_email": {"$exists": False}}, {"user_email": None}],
                "classification_label": {"$in": ["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW"]},
                "user_id": {"$ne": None},
            })
            await _enrich_user_details()
            p2_missing_after = await db.bq_jobs.count_documents({
                "$or": [{"user_email": {"$exists": False}}, {"user_email": None}],
                "classification_label": {"$in": ["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW"]},
                "user_id": {"$ne": None},
            })
            p2_enriched = max(0, p2_missing_before - p2_missing_after)
        except Exception as e:
            p2_status = "error"
            logger.error(f"Phase 2 user enrichment failed (non-fatal): {type(e).__name__}: {e}")

        pipeline_stats["phase_2"] = {
            "name": "User Enrichment",
            "status": p2_status,
            "duration_s": round(_time.time() - p2_start, 2),
            "jobs_enriched": p2_enriched,
            "still_missing": p2_missing_after if p2_status == "ok" else None,
        }

        # ---- Phase 3: Rebuild user_profiles for users that have enriched data ----
        p3_start = _time.time()
        p3_profiles = 0
        p3_status = "ok"
        try:
            affected_user_ids = list({r.get("user_id") for r in rows if r.get("user_id")})
            # Only rebuild profiles for users that have been enriched (have user_email in bq_jobs)
            if affected_user_ids:
                enriched_cursor = db.bq_jobs.find(
                    {"user_id": {"$in": affected_user_ids}, "user_email": {"$exists": True, "$ne": None}},
                    {"user_id": 1, "_id": 0},
                )
                enriched_docs = await enriched_cursor.to_list(len(affected_user_ids))
                enriched_user_ids = list({d["user_id"] for d in enriched_docs})
                if enriched_user_ids:
                    await _rebuild_user_profiles(enriched_user_ids)
                    p3_profiles = len(enriched_user_ids)
                else:
                    logger.info("Phase 3 skipped: no enriched users to rebuild profiles for")
        except Exception as e:
            p3_status = "error"
            logger.error(f"Phase 3 user_profiles rebuild failed (non-fatal): {e}")

        pipeline_stats["phase_3"] = {
            "name": "User Profiles",
            "status": p3_status,
            "duration_s": round(_time.time() - p3_start, 2),
            "profiles_rebuilt": p3_profiles,
        }


        # ---- Verdict backfill: sync eval_verdicts → bq_jobs.human_verdict_s2 ----
        try:
            verdict_docs = await db.eval_verdicts.find(
                {"human_verdict_s2": {"$in": ["correct", "incorrect", "disputed"]}},
                {"_id": 0, "job_id": 1, "human_verdict_s2": 1}
            ).to_list(10000)
            if verdict_docs:
                from pymongo import UpdateOne as _UO
                v_ops = [_UO({"job_id": d["job_id"]}, {"$set": {"human_verdict_s2": d["human_verdict_s2"]}}) for d in verdict_docs]
                if v_ops:
                    v_result = await db.bq_jobs.bulk_write(v_ops, ordered=False)
                    if v_result.modified_count > 0:
                        logger.info(f"Verdict backfill: synced {v_result.modified_count} verdicts to bq_jobs")
        except Exception as e:
            logger.error(f"Verdict backfill failed (non-fatal): {e}")

        # ---- Opus backfill: sync opus_verdicts → bq_jobs.opus_label ----
        try:
            opus_docs = await db.opus_verdicts.find(
                {"opus_label": {"$in": ["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW", "LEGITIMATE"]}},
                {"_id": 0, "job_id": 1, "opus_label": 1, "reviewed_at": 1}
            ).to_list(10000)
            if opus_docs:
                from pymongo import UpdateOne as _UO2
                o_ops = [_UO2({"job_id": d["job_id"]}, {"$set": {"opus_label": d["opus_label"], "opus_reviewed_at": d.get("reviewed_at")}}) for d in opus_docs]
                if o_ops:
                    o_result = await db.bq_jobs.bulk_write(o_ops, ordered=False)
                    if o_result.modified_count > 0:
                        logger.info(f"Opus backfill: synced {o_result.modified_count} opus labels to bq_jobs")
        except Exception as e:
            logger.error(f"Opus backfill failed (non-fatal): {e}")


        # ---- External source backfill: sync automated_actions external_takedowns → bq_jobs.external_source ----
        try:
            ext_docs = await db.automated_actions.find(
                {"action": "external_takedown", "source": {"$in": ["cloudflare", "openai"]}},
                {"_id": 0, "job_id": 1, "source": 1, "executed_at": 1}
            ).to_list(10000)
            if ext_docs:
                from pymongo import UpdateOne as _UO3
                e_ops = [_UO3({"job_id": d["job_id"]}, {"$set": {"external_source": d["source"], "external_takedown_at": d.get("executed_at")}}) for d in ext_docs]
                if e_ops:
                    e_result = await db.bq_jobs.bulk_write(e_ops, ordered=False)
                    if e_result.modified_count > 0:
                        logger.info(f"External source backfill: synced {e_result.modified_count} to bq_jobs")
        except Exception as e:
            logger.error(f"External source backfill failed (non-fatal): {e}")



        # ---- Phase 4: Automated tier classification + actions ----
        p4_start = _time.time()
        p4_status = "ok"
        p4_run_stats = {}
        try:
            await ensure_automation_indexes(db)
            p4_run_stats = await run_automation_tick(db, resolve_fork_chain_fn=resolve_fork_chain) or {}
        except Exception as e:
            p4_status = "error"
            logger.error(f"Phase 4 automation failed (non-fatal): {type(e).__name__}: {e}")

        # Gather Phase 4 cumulative stats from MongoDB (filtered by current dry_run mode)
        _dr = {"dry_run": get_dry_run()}
        p4_tier_counts = {}
        for t in [1, 2, 3, 4, 5]:
            p4_tier_counts[str(t)] = await db.automated_actions.count_documents({"tier": t, **_dr})
        p4_mcp_skipped = await db.automated_actions.count_documents({"action": "skipped_mcp_error", **_dr})
        p4_excluded = await db.automated_actions.count_documents({"action": "skipped_excluded", **_dr})
        p4_sched_pending = await db.scheduled_takedowns.count_documents({"status": "pending", **_dr})
        p4_sched_executed = await db.scheduled_takedowns.count_documents({"status": "executed", **_dr})

        pipeline_stats["phase_4"] = {
            "name": "Automation",
            "status": p4_status,
            "duration_s": round(_time.time() - p4_start, 2),
            "tier_counts": p4_tier_counts,
            "mcp_skipped": p4_mcp_skipped,
            "exclusion_skipped": p4_excluded,
            "scheduled_pending": p4_sched_pending,
            "scheduled_executed": p4_sched_executed,
            # Per-run stats
            "this_run": p4_run_stats,
        }

        # ---- Phase 5: Sync actions to BigQuery ----
        p5_start = _time.time()
        p5_status = "ok"
        p5_result = {}
        try:
            p5_result = await sync_actions_to_bq(db, bq_client) or {}
        except Exception as e:
            p5_status = "error"
            logger.error(f"Phase 5 BQ write-back failed (non-fatal): {type(e).__name__}: {e}")

        pipeline_stats["phase_5"] = {
            "name": "BQ Write-Back",
            "status": p5_status,
            "duration_s": round(_time.time() - p5_start, 2),
            "rows_synced": p5_result.get("rows_synced", 0),
            "bq_job_id": p5_result.get("bq_job_id"),
        }

        # Log the complete pipeline run
        try:
            await log_pipeline_run(db, pipeline_stats)
        except Exception as e:
            logger.error(f"Pipeline run logging failed (non-fatal): {e}")

        return {"status": "ok", "fetched": len(rows), "upserted": upserted, "failed_batches": phase1_failed_batches}
    except Exception as e:
        logger.error(f"BQ sync failed: {e}")
        return {"status": "error", "error": str(e)}


async def _enrich_user_details():
    """Phase 2: Find bq_jobs missing user_email for escalated labels, fetch from BQ, persist."""
    missing_cursor = db.bq_jobs.find(
        {
            "$or": [{"user_email": {"$exists": False}}, {"user_email": None}],
            "classification_label": {"$in": ["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW"]},
            "user_id": {"$ne": None},
        },
        {"user_id": 1, "job_id": 1, "_id": 0},
    )
    missing_docs = await missing_cursor.to_list(5000)
    if not missing_docs:
        return

    distinct_user_ids = list({d["user_id"] for d in missing_docs if d.get("user_id")})
    # Filter to valid UUIDs only
    valid_user_ids = []
    for uid in distinct_user_ids:
        try:
            uuid_mod.UUID(uid)
            valid_user_ids.append(uid)
        except (ValueError, AttributeError):
            pass

    if not valid_user_ids:
        return

    logger.info(f"Phase 2: Enriching user details for {len(valid_user_ids)} users ({len(missing_docs)} jobs)")

    # Run BQ fetch in thread to avoid blocking event loop
    user_details = await asyncio.to_thread(_fetch_user_details_from_bq, valid_user_ids)

    if not user_details:
        logger.warning("Phase 2: No user details returned from BQ")
        return

    # Update bq_jobs docs with user details
    from pymongo import UpdateOne
    ops = []
    for doc in missing_docs:
        uid = doc.get("user_id")
        if uid in user_details:
            ops.append(UpdateOne(
                {"job_id": doc["job_id"]},
                {"$set": user_details[uid]},
            ))

    if ops:
        BATCH_SIZE = 200
        for i in range(0, len(ops), BATCH_SIZE):
            try:
                await db.bq_jobs.bulk_write(ops[i:i + BATCH_SIZE], ordered=False)
            except Exception as batch_err:
                logger.error(f"Phase 2: enrichment batch {i//BATCH_SIZE + 1} failed: {type(batch_err).__name__}: {batch_err}")
            await asyncio.sleep(0)
        logger.info(f"Phase 2: Enriched {len(ops)} bq_jobs docs with user details")


async def _rebuild_user_profiles(user_ids: list):
    """Phase 3: Rebuild user_profiles collection for given user_ids from bq_jobs data."""
    if not user_ids:
        return

    from pymongo import UpdateOne

    pipeline = [
        {"$match": {"user_id": {"$in": user_ids}, "classification_label": {"$ne": None}}},
        {"$group": {
            "_id": "$user_id",
            "email": {"$first": "$user_email"},
            "plan_type": {"$first": "$plan_type"},
            "ltv": {"$first": "$ltv"},
            "payment_gateway": {"$first": "$payment_gateway"},
            "discount_amount": {"$first": "$discount_amount"},
            "jobs": {"$push": {"job_id": "$job_id", "label": "$classification_label"}},
            "first_seen_at": {"$min": "$timestamp"},
            "last_seen_at": {"$max": "$timestamp"},
        }},
    ]
    results = await db.bq_jobs.aggregate(pipeline).to_list(len(user_ids) + 100)

    ops = []
    now = datetime.now(timezone.utc).isoformat()
    for r in results:
        uid = r["_id"]
        job_counts = {}
        job_ids_map = {}
        for j in r.get("jobs", []):
            label = j.get("label")
            if label:
                job_counts[label] = job_counts.get(label, 0) + 1
                job_ids_map.setdefault(label, []).append(j["job_id"])

        total = sum(job_counts.values())
        ops.append(UpdateOne(
            {"user_id": uid},
            {
                "$set": {
                    "email": r.get("email"),
                    "plan_type": r.get("plan_type"),
                    "ltv": r.get("ltv"),
                    "payment_gateway": r.get("payment_gateway"),
                    "discount_amount": r.get("discount_amount"),
                    "job_counts": job_counts,
                    "job_ids": job_ids_map,
                    "total_escalated_jobs": total,
                    "last_seen_at": r.get("last_seen_at"),
                    "updated_at": now,
                },
                "$setOnInsert": {
                    "first_seen_at": r.get("first_seen_at") or now,
                },
            },
            upsert=True,
        ))

    if ops:
        await db.user_profiles.bulk_write(ops, ordered=False)
        await db.user_profiles.create_index("user_id", unique=True)
        logger.info(f"Phase 3: Rebuilt user_profiles for {len(ops)} users")


async def bq_sync_loop():
    """Background loop that syncs BQ → MongoDB every SYNC_INTERVAL_SECONDS."""
    await asyncio.sleep(10)  # Wait for app startup and first health checks
    try:
        count = await db.bq_jobs.count_documents({})
        if count == 0:
            logger.info("No bq_jobs data found — running full sync on first boot")
            await run_bq_sync(full=True)
        else:
            logger.info(f"Found {count} existing bq_jobs — running incremental sync")
            await run_bq_sync(full=False)
    except Exception as e:
        logger.error(f"Initial BQ sync failed: {type(e).__name__}: {e}")
    while True:
        await asyncio.sleep(SYNC_INTERVAL_SECONDS)
        try:
            await run_bq_sync(full=False)
        except Exception as e:
            logger.error(f"BQ sync loop iteration failed: {type(e).__name__}: {e}")


# ---- External Signals Poller ----

EXTERNAL_SIGNALS_TABLE = "emergent-default.phishing_eval.external_signals"
EXTERNAL_SIGNALS_POLL_INTERVAL = 5 * 60  # 5 minutes


async def external_signals_poller():
    """Background loop: poll BQ external_signals for pending rows, execute takedowns."""
    await asyncio.sleep(30)  # Wait for app startup
    logger.info("External signals poller started (every 5 min)")
    while True:
        try:
            await _process_pending_external_signals()
        except Exception as e:
            logger.error(f"External signals poller error: {e}")
        await asyncio.sleep(EXTERNAL_SIGNALS_POLL_INTERVAL)


async def _process_pending_external_signals():
    """Query BQ for pending external signals, resolve fork chains, execute takedowns."""
    if not bq_client:
        return

    is_dry = get_dry_run()
    now = datetime.now(timezone.utc)

    # Read pending signals from BQ
    query = f"""
    SELECT id, source, event_type, resolved_job_ids, reason, resolved_user_id, resolved_domain
    FROM `{EXTERNAL_SIGNALS_TABLE}`
    WHERE status = 'pending'
    ORDER BY received_at ASC
    LIMIT 50
    """
    try:
        rows = list(bq_client.query(query).result())
    except Exception as e:
        logger.error(f"External signals query failed: {e}")
        return

    if not rows:
        return

    # Filter out signals already processed (tracked in MongoDB to avoid BQ streaming buffer issue)
    signal_ids = [r.id for r in rows]
    processed_ids = set()
    async for doc in db.processed_external_signals.find({"signal_id": {"$in": signal_ids}}, {"signal_id": 1}):
        processed_ids.add(doc["signal_id"])
    rows = [r for r in rows if r.id not in processed_ids]

    if not rows:
        return

    logger.info(f"External signals poller: found {len(rows)} pending signal(s)")

    for row in rows:
        signal_id = row.id
        source = row.source
        reason = row.reason or f"External signal from {source}"
        raw_job_ids = []

        try:
            import json as _json
            raw_job_ids = _json.loads(row.resolved_job_ids) if row.resolved_job_ids else []
        except Exception:
            raw_job_ids = []

        if not raw_job_ids:
            # No jobs resolved — mark as failed
            await _mark_signal_processed(signal_id, "failed", error="No job_ids resolved")
            continue

        # Mark as processing
        await _mark_signal_processed(signal_id, "processing")

        # Resolve fork chains for all job_ids, deduplicate
        all_chain_ids = []
        seen = set()
        for jid in raw_job_ids:
            try:
                chain = await asyncio.get_event_loop().run_in_executor(None, resolve_fork_chain, jid)
                for cid in chain:
                    if cid not in seen:
                        seen.add(cid)
                        all_chain_ids.append(cid)
            except Exception as e:
                logger.error(f"Fork chain resolution failed for {jid}: {e}")
                if jid not in seen:
                    seen.add(jid)
                    all_chain_ids.append(jid)

        if len(all_chain_ids) > len(raw_job_ids):
            logger.info(f"Signal {signal_id}: expanded {len(raw_job_ids)} job(s) to {len(all_chain_ids)} via fork chains")

        # Execute takedowns
        ok_count = 0
        fail_count = 0
        for job_id in all_chain_ids:
            try:
                bq_doc = await db.bq_jobs.find_one({"job_id": job_id}, {"_id": 0})
                task_preview = (bq_doc.get("task", "")[:200] if bq_doc and bq_doc.get("task") else "")
                s2_label = (bq_doc.get("classification_label", "") if bq_doc else "")
                user_id = (bq_doc.get("user_id", "") if bq_doc else "")

                # Call disable API (respects dry_run)
                api_result = await auto_takedown_job(job_id, reason, dry_run=is_dry)

                # Write to automated_actions
                action_doc = {
                    "job_id": job_id,
                    "user_id": user_id,
                    "tier": classify_tier(bq_doc) if bq_doc and bq_doc.get("classification_label") else 0,
                    "classification_category": bq_doc.get("classification_category", "") if bq_doc else "",
                    "classification_label": s2_label,
                    "action": "external_takedown",
                    "status": "completed",
                    "executed_at": now.isoformat(),
                    "created_at": now.isoformat(),
                    "dry_run": is_dry,
                    "source": source,
                    "has_mcp_error": False,
                    "metadata": {"api_result": api_result, "external_source": source, "signal_id": signal_id},
                }
                await db.automated_actions.update_one(
                    {"job_id": job_id, "dry_run": is_dry},
                    {"$set": action_doc},
                    upsert=True,
                )

                # Write to takedowns
                takedown_info = {
                    "taken_down_by": f"external:{source}",
                    "taken_down_by_name": f"External — {source.title()}",
                    "taken_down_at": now.isoformat(),
                    "job_id": job_id,
                    "task_preview": task_preview,
                    "s2_label": s2_label,
                    "suspension_reason": reason,
                    "api_result": api_result,
                    "automated": True,
                    "external": True,
                    "source": source,
                    "dry_run": is_dry,
                    "signal_id": signal_id,
                }
                await db.takedowns.insert_one({**takedown_info})

                # Denormalize external_source into bq_jobs for fast filtering
                await db.bq_jobs.update_one(
                    {"job_id": job_id},
                    {"$set": {"external_source": source, "external_takedown_at": now.isoformat()}},
                )

                # Update eval_verdicts only in live mode
                if not is_dry:
                    ek = f"prod::{job_id}"
                    await db.eval_verdicts.update_one(
                        {"eval_key": ek},
                        {"$set": {
                            "taken_down": True,
                            "takedown_info": takedown_info,
                            "takedown_source": source,
                        }},
                        upsert=True,
                    )

                # Log to BQ
                log_takedown_to_bq({
                    "job_id": job_id,
                    "taken_down_by": f"external:{source}",
                    "taken_down_at": now.isoformat(),
                    "suspension_reason": f"[External: {source.title()}] {reason}",
                    "s2_label": s2_label,
                    "task_preview": task_preview,
                    "api_status_code": api_result.get("status_code"),
                    "is_test_mode": is_dry,
                })

                ok_count += 1
                logger.info(f"External poller takedown ({source}) for {job_id}: ok (dry_run={is_dry})")

                # Send RudderStack email notification (LIVE mode only)
                if not is_dry and bq_doc:
                    user_email = bq_doc.get("user_email")
                    plan_type = bq_doc.get("plan_type", "Free User")
                    domain = signal.get("resolved_domain", "")
                    category = bq_doc.get("classification_category", "")
                    if user_email:
                        try:
                            send_external_takedown_notification(
                                user_id, user_email, plan_type, job_id, source, domain, category
                            )
                        except Exception as email_err:
                            logger.error(f"External takedown email failed for {job_id}: {email_err}")

            except Exception as e:
                fail_count += 1
                logger.error(f"External poller takedown ({source}) failed for {job_id}: {e}")

        # Slack: one notification per signal (using first input job_id)
        chain_note = f" (+{len(all_chain_ids) - len(raw_job_ids)} fork chain jobs)" if len(all_chain_ids) > len(raw_job_ids) else ""
        status_str = "completed" if fail_count == 0 else "failed"
        slack_notify_external(
            source, raw_job_ids[0],
            f"{reason}{chain_note} [{ok_count} ok, {fail_count} failed]",
            status=status_str, dry_run=is_dry,
        )

        # Mark signal as done
        final_status = "executed" if fail_count == 0 else ("partial" if ok_count > 0 else "failed")
        error_msg = f"{fail_count} job(s) failed" if fail_count > 0 else None
        await _mark_signal_processed(signal_id, final_status, error=error_msg)
        logger.info(f"Signal {signal_id} ({source}): {final_status} — {ok_count} ok, {fail_count} failed, chain={len(all_chain_ids)}")


async def _mark_signal_processed(signal_id: str, status: str, error: str = None):
    """Track processed signal in MongoDB + update BQ status."""
    now = datetime.now(timezone.utc).isoformat()
    # Write to MongoDB (for dedup on next poll)
    await db.processed_external_signals.update_one(
        {"signal_id": signal_id},
        {"$set": {"signal_id": signal_id, "status": status, "processed_at": now, "error": error}},
        upsert=True,
    )
    # Update BQ row status
    if bq_client:
        error_clause = f', error = "{error}"' if error else ", error = NULL"
        query = f"""
        UPDATE `{EXTERNAL_SIGNALS_TABLE}`
        SET status = "{status}", processed_at = TIMESTAMP("{now}"){error_clause}
        WHERE id = "{signal_id}"
        """
        try:
            bq_client.query(query).result()
        except Exception as e:
            logger.warning(f"BQ status update failed for signal {signal_id}: {e}")


# ---- Production Mode (reads from MongoDB bq_jobs) ----

VALID_S2_LABELS = {"CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW", "LEGITIMATE"}


def mongo_doc_to_eval_format(doc: dict, existing_verdict: dict = None, action: dict = None, scheduled: dict = None, opus_verdict: dict = None) -> dict:
    """Convert a bq_jobs MongoDB doc into the eval format the frontend expects."""
    job_id = doc.get("job_id", "")
    ek = f"prod::{job_id}"
    ts_str = doc.get("timestamp")
    task_raw = doc.get("task")

    stage_1 = {
        "received_at": ts_str,
        "classification": {
            "result": doc.get("is_phishing"),
            "confidence": doc.get("confidence_score"),
            "severity": doc.get("severity"),
            "reason": doc.get("reason"),
            "category": None,
            "_usage": None,
        },
        "raw_output": None,
        "elapsed_seconds": None,
        "image_url": doc.get("image_url"),
        "user_id": doc.get("user_id"),
        "task_preview": task_raw,
    }

    stage_2 = None
    if doc.get("classification_label") is not None:
        stage_2 = {
            "classification": {
                "label": doc.get("classification_label"),
                "severity": doc.get("classification_severity"),
                "confidence": doc.get("classification_confidence"),
                "category": doc.get("classification_category"),
                "reasoning": doc.get("classification_reasoning"),
            },
            "harm_assessment": {
                "credential_theft": {"detected": doc.get("credential_theft_detected"), "details": doc.get("credential_theft_details")},
                "deceptive_exfiltration": {"detected": doc.get("deceptive_exfiltration_detected"), "details": doc.get("deceptive_exfiltration_details")},
                "user_deceived": {"detected": doc.get("user_deceived_detected"), "details": doc.get("user_deceived_details")},
                "tool_for_scale_harm": {"detected": doc.get("tool_for_scale_harm_detected"), "details": doc.get("tool_for_scale_harm_details")},
                "service_replication": {"detected": doc.get("service_replication_detected"), "details": doc.get("service_replication_details")},
                "violent_harmful_content": {"detected": doc.get("violent_harmful_content_detected"), "details": doc.get("violent_harmful_content_details")},
                "illegal_content": {"detected": doc.get("illegal_content_detected"), "details": doc.get("illegal_content_details")},
                "malware_delivery": {"detected": doc.get("malware_delivery_detected"), "details": doc.get("malware_delivery_details")},
            },
            "what_was_built": doc.get("what_was_built"),
            "image_analysis_note": doc.get("image_analysis_note"),
            "recommended_actions": doc.get("recommended_actions"),
            "task_description": doc.get("task_description"),
            "slack_summary": {
                "emoji": doc.get("slack_emoji"),
                "headline": doc.get("slack_headline"),
                "verdict": doc.get("slack_verdict"),
            },
            "tool_findings": {
                "job_details": {"called": doc.get("job_details_called"), "success": doc.get("job_details_success"), "key_findings": doc.get("job_key_findings"), "task_description": doc.get("job_task_description")},
                "agent_trajectory": {"called": doc.get("agent_trajectory_called"), "success": doc.get("agent_trajectory_success"), "total_steps": doc.get("agent_trajectory_total_steps"), "key_findings": doc.get("trajectory_key_findings"), "suspicious_actions": doc.get("suspicious_actions"), "external_urls_detected": doc.get("external_urls_detected")},
                "hitl_interactions": {"called": doc.get("hitl_interactions_called"), "success": doc.get("hitl_interactions_success"), "total_hitl_interactions": doc.get("total_hitl_interactions"), "key_findings": doc.get("hitl_key_findings"), "notable_quotes": doc.get("hitl_notable_quotes")},
                "deployment_details": {"called": doc.get("deployment_details_called"), "success": doc.get("deployment_details_success"), "has_active_deployment": doc.get("has_active_deployment"), "deployment_url": doc.get("deployment_url"), "key_findings": doc.get("deployment_key_findings")},
            },
        }

    ev = existing_verdict or {}
    return {
        "eval_key": ek,
        "job_id": job_id,
        "created_at": ts_str,
        "task_preview": task_raw,
        "user_id": doc.get("user_id"),
        "image_url": doc.get("image_url"),
        "stage_1": stage_1,
        "whitecircle": None,
        "stage_2": stage_2,
        "human_verdict_s1": ev.get("human_verdict_s1"),
        "human_verdict_wc": ev.get("human_verdict_wc"),
        "human_verdict_s2": ev.get("human_verdict_s2"),
        "human_notes": ev.get("human_notes"),
        "pipeline_time": None,
        "prompt_versions": {"llm_classifier": "prod", "escalation_agent": "prod", "user_message": "prod"},
        "taken_down": ev.get("taken_down", False) or (action is not None and action.get("action") == "auto_takedown" and action.get("status") == "completed"),
        "takedown_info": ev.get("takedown_info") or ({"taken_down_by": "automation", "reason": action.get("reason", "Auto takedown (Tier 1)")} if action and action.get("action") == "auto_takedown" and action.get("status") == "completed" else None),
        "user_email": doc.get("user_email"),
        "plan_type": doc.get("plan_type"),
        "ltv": doc.get("ltv"),
        "payment_gateway": doc.get("payment_gateway"),
        "discount_amount": doc.get("discount_amount"),
        "model_name": doc.get("model_name"),
        "task_full": doc.get("task"),
        "automation_tier": classify_tier(doc) if doc.get("classification_label") else None,
        "automation_action": action.get("action") if action else None,
        "automation_status": action.get("status") if action else None,
        "scheduled_takedown": {
            "status": scheduled.get("status"),
            "takedown_at": scheduled.get("takedown_at"),
            "email_sent_at": scheduled.get("email_sent_at"),
        } if scheduled else None,
        "opus_verdict": {
            "label": opus_verdict.get("opus_label"),
            "confidence": opus_verdict.get("opus_confidence"),
            "severity": opus_verdict.get("opus_severity"),
            "recommended_action": opus_verdict.get("opus_recommended_action"),
            "verdict_summary": opus_verdict.get("opus_verdict_summary"),
            "key_evidence": opus_verdict.get("opus_key_evidence"),
            "policy_violated": opus_verdict.get("opus_policy_violated"),
            "flagged_policies": opus_verdict.get("opus_flagged_policies"),
            "tools_called": opus_verdict.get("opus_tools_called"),
            "turns_used": opus_verdict.get("opus_turns_used"),
            "duration_s": opus_verdict.get("opus_duration_s"),
            "reviewed_at": opus_verdict.get("reviewed_at"),
            "is_fallback": opus_verdict.get("opus_fallback", False),
            "overridden": opus_verdict.get("opus_overridden", False) if action else False,
        } if opus_verdict else None,
    }


@api_router.get("/prod/jobs")
async def prod_jobs(
    request: Request,
    offset: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    s2_labels: Optional[str] = Query(None),
    tier: Optional[int] = Query(None, ge=1, le=5),
    opus_label: Optional[str] = Query(None),
    date_from: Optional[str] = Query(None),
    date_to: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    verdict: Optional[str] = Query(None),
    deployment: Optional[str] = Query(None),
):
    await get_current_user(request)

    is_dry = get_dry_run()

    try:
        query_filter = {}
        if s2_labels:
            labels = [lb.strip() for lb in s2_labels.split(",") if lb.strip() in VALID_S2_LABELS]
            if labels:
                query_filter["classification_label"] = {"$in": labels}

        if date_from:
            query_filter.setdefault("timestamp", {})["$gte"] = date_from
        if date_to:
            query_filter.setdefault("timestamp", {})["$lte"] = date_to + "T23:59:59"
        if severity:
            sev_list = [s.strip().upper() for s in severity.split(",") if s.strip()]
            if sev_list:
                query_filter["classification_severity"] = {"$in": sev_list}
        if category:
            query_filter["classification_category"] = {"$regex": category, "$options": "i"}
        if deployment:
            dep_values = [d.strip() for d in deployment.split(",") if d.strip()]
            has_active = "active" in dep_values
            has_inactive = "inactive" in dep_values
            if has_active and not has_inactive:
                query_filter["has_active_deployment"] = True
            elif has_inactive and not has_active:
                query_filter["has_active_deployment"] = {"$ne": True}
            # both selected = all, no filter needed

        # Sort: jobs with S2 (emitted_at) first DESC, then in-flight by timestamp DESC
        # MongoDB sorts null first in DESC, so use aggregation to push nulls to the end
        agg_pipeline = [
            {"$match": query_filter},
        ]

        # Server-side verdict filtering — uses denormalized human_verdict_s2 on bq_jobs (no $lookup needed)
        if verdict:
            verdict_values = [v.strip() for v in verdict.split(",") if v.strip()]
            has_unreviewed = "unreviewed" in verdict_values
            reviewed_values = [v for v in verdict_values if v != "unreviewed"]
            known_verdicts = ["correct", "incorrect", "disputed"]

            if has_unreviewed and reviewed_values:
                query_filter["$or"] = [
                    {"human_verdict_s2": {"$in": reviewed_values}},
                    {"human_verdict_s2": {"$nin": known_verdicts}},
                ]
            elif has_unreviewed:
                query_filter["human_verdict_s2"] = {"$nin": known_verdicts}
            elif reviewed_values:
                query_filter["human_verdict_s2"] = {"$in": reviewed_values}

        # Server-side opus_label filtering — only shows opus-reviewed jobs
        if opus_label and opus_label in VALID_S2_LABELS:
            query_filter["opus_label"] = opus_label

        # Server-side external source filtering
        # Pull job_ids directly from BQ external_signals (complete source of truth)
        external_source = request.query_params.get("external_source")
        if external_source and external_source in ("openai", "cloudflare"):
            try:
                ext_query = f"""
                SELECT DISTINCT job_id
                FROM `phishing_eval.external_signals`,
                UNNEST(JSON_EXTRACT_STRING_ARRAY(resolved_job_ids)) as job_id
                WHERE LOWER(event_type) LIKE '%{external_source}%'
                  AND resolved_job_ids IS NOT NULL AND resolved_job_ids != '[]'
                """
                ext_rows = await asyncio.to_thread(lambda: [r.job_id for r in bq_client.query(ext_query).result()])
                ext_job_ids = list(set(ext_rows))
            except Exception as e:
                logger.error(f"External source BQ query failed: {e}")
                ext_job_ids = []

            if not ext_job_ids:
                return {"jobs": [], "has_more": False, "total_loaded": 0, "total_count": 0}

            # Get bq_jobs data for these job_ids
            bq_docs = await db.bq_jobs.find({"job_id": {"$in": ext_job_ids}}, {"_id": 0}).to_list(5000)
            bq_map = {d["job_id"]: d for d in bq_docs}

            # Get verdicts, actions, opus
            vkeys = [f"prod::{jid}" for jid in ext_job_ids]
            v_docs = await db.eval_verdicts.find({"eval_key": {"$in": vkeys}}, {"_id": 0}).to_list(5000)
            v_map = {d["eval_key"]: d for d in v_docs}
            a_docs = await db.automated_actions.find({"job_id": {"$in": ext_job_ids}, "dry_run": is_dry}, {"_id": 0}).to_list(5000)
            a_map = {d["job_id"]: d for d in a_docs}
            o_docs = await db.opus_verdicts.find({"job_id": {"$in": ext_job_ids}, "dry_run": is_dry}, {"_id": 0}).to_list(5000)
            o_map = {d["job_id"]: d for d in o_docs}

            # Also get takedown records
            td_docs = await db.takedowns.find({"job_id": {"$in": ext_job_ids}}, {"_id": 0}).to_list(5000)
            td_map = {d["job_id"]: d for d in td_docs}

            # Build results
            result_jobs = []
            for jid in ext_job_ids:
                bq_doc = bq_map.get(jid)
                if bq_doc:
                    result_jobs.append(mongo_doc_to_eval_format(bq_doc, v_map.get(f"prod::{jid}", {}), a_map.get(jid), None, o_map.get(jid)))
                else:
                    td = td_map.get(jid, {})
                    act = a_map.get(jid, {})
                    result_jobs.append({
                        "eval_key": f"prod::{jid}",
                        "job_id": jid,
                        "created_at": td.get("taken_down_at") or act.get("executed_at"),
                        "task_preview": td.get("task_preview") or act.get("task_preview"),
                        "user_id": td.get("user_id") or act.get("user_id"),
                        "image_url": None,
                        "stage_1": {"classification": {"result": True, "confidence": None, "severity": None}},
                        "stage_2": {"classification": {"label": td.get("s2_label") or act.get("classification_label")}} if (td.get("s2_label") or act.get("classification_label")) else None,
                        "taken_down": bool(td),
                        "takedown_info": td or None,
                        "human_verdict_s2": v_map.get(f"prod::{jid}", {}).get("human_verdict_s2"),
                        "action_info": act or None,
                        "opus_verdict": o_map.get(jid),
                    })

            # Sort by created_at desc
            result_jobs.sort(key=lambda j: j.get("created_at") or "", reverse=True)
            total_ext = len(result_jobs)
            paged = result_jobs[offset:offset + limit]
            return {"jobs": paged, "has_more": offset + limit < total_ext, "total_loaded": offset + len(paged), "total_count": total_ext}

        # Server-side tier filtering via $lookup on automated_actions (mode-filtered)
        if tier is not None and not opus_label:
            agg_pipeline += [
                {"$lookup": {
                    "from": "automated_actions",
                    "let": {"jid": "$job_id"},
                    "pipeline": [
                        {"$match": {"$expr": {"$and": [
                            {"$eq": ["$job_id", "$$jid"]},
                            {"$eq": ["$dry_run", is_dry]},
                        ]}}},
                    ],
                    "as": "_action",
                }},
                {"$addFields": {"_tier": {"$arrayElemAt": ["$_action.tier", 0]}}},
                {"$match": {"_tier": tier}},
                {"$project": {"_action": 0, "_tier": 0}},
            ]

        agg_pipeline += [
            {"$addFields": {"has_s2": {"$cond": [{"$gt": ["$emitted_at", None]}, 1, 0]}}},
            {"$sort": {"has_s2": -1, "emitted_at": -1, "timestamp": -1}},
        ]

        # Get total count for current filters (run count on same pipeline before skip/limit)
        count_pipeline = agg_pipeline + [{"$count": "total"}]
        count_result = await db.bq_jobs.aggregate(count_pipeline).to_list(1)
        total_count = count_result[0]["total"] if count_result else 0

        agg_pipeline += [
            {"$skip": offset},
            {"$limit": limit + 1},
            {"$project": {"_id": 0, "has_s2": 0}},
        ]
        docs = await db.bq_jobs.aggregate(agg_pipeline).to_list(limit + 1)

        has_more = len(docs) > limit
        if has_more:
            docs = docs[:limit]

        if not docs:
            return {"jobs": [], "has_more": False, "total_loaded": offset, "total_count": total_count}

        # Batch load verdicts + automation actions
        job_ids = [d["job_id"] for d in docs]
        verdict_keys = [f"prod::{jid}" for jid in job_ids]
        verdict_docs = await db.eval_verdicts.find({"eval_key": {"$in": verdict_keys}}, {"_id": 0}).to_list(200)
        verdict_map = {d["eval_key"]: d for d in verdict_docs}

        action_docs = await db.automated_actions.find({"job_id": {"$in": job_ids}, "dry_run": is_dry}, {"_id": 0}).to_list(200)
        action_map = {d["job_id"]: d for d in action_docs}
        sched_docs = await db.scheduled_takedowns.find({"job_id": {"$in": job_ids}, "dry_run": is_dry}, {"_id": 0}).to_list(200)
        sched_map = {d["job_id"]: d for d in sched_docs}
        opus_docs = await db.opus_verdicts.find({"job_id": {"$in": job_ids}, "dry_run": is_dry}, {"_id": 0}).to_list(200)
        opus_map = {d["job_id"]: d for d in opus_docs}

        result_jobs = [mongo_doc_to_eval_format(d, verdict_map.get(f"prod::{d['job_id']}", {}), action_map.get(d["job_id"]), sched_map.get(d["job_id"]), opus_map.get(d["job_id"])) for d in docs]
        return {"jobs": result_jobs, "has_more": has_more, "total_loaded": offset + len(result_jobs), "total_count": total_count}

    except Exception as e:
        logger.error(f"Production jobs query failed: {e}")
        return {"error": str(e), "jobs": [], "has_more": False, "total_loaded": 0, "total_count": 0}


@api_router.get("/prod/job/{job_id}")
async def get_single_job(job_id: str, request: Request):
    """Lookup a single job by job_id from MongoDB."""
    await get_current_user(request)
    doc = await db.bq_jobs.find_one({"job_id": job_id}, {"_id": 0})
    if not doc:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    ev = await db.eval_verdicts.find_one({"eval_key": f"prod::{job_id}"}, {"_id": 0}) or {}
    is_dry = get_dry_run()
    action = await db.automated_actions.find_one({"job_id": job_id, "dry_run": is_dry}, {"_id": 0})
    scheduled = await db.scheduled_takedowns.find_one({"job_id": job_id, "dry_run": is_dry}, {"_id": 0})
    opus = await db.opus_verdicts.find_one({"job_id": job_id, "dry_run": is_dry}, {"_id": 0})
    job = mongo_doc_to_eval_format(doc, ev, action, scheduled, opus)
    return {"job": job}



@api_router.get("/prod/search")
async def search_jobs(request: Request, q: str = Query(..., min_length=1)):
    """Search jobs by job_id, user_id, or user_email. Returns multiple matches."""
    await get_current_user(request)
    is_dry = get_dry_run()
    q = q.strip()

    # Determine search type and build query
    if "@" in q:
        query_filter = {"user_email": {"$regex": re.escape(q), "$options": "i"}}
    elif len(q) > 30:
        # Likely a UUID — search job_id and user_id
        query_filter = {"$or": [{"job_id": q}, {"user_id": q}]}
    else:
        # Short string — search email prefix, user_id prefix, or exact job_id
        query_filter = {"$or": [
            {"job_id": q},
            {"user_id": q},
            {"user_email": {"$regex": re.escape(q), "$options": "i"}},
        ]}

    docs = await db.bq_jobs.find(query_filter, {"_id": 0}).sort("synced_at", -1).to_list(50)

    # Also search takedowns collection (external takedowns may not be in bq_jobs)
    takedown_filter = {"job_id": q} if len(q) > 30 else {"$or": [{"job_id": q}]}
    if "@" in q:
        takedown_filter = {"taken_down_by": {"$regex": re.escape(q), "$options": "i"}}
    takedown_results = await db.takedowns.find(takedown_filter, {"_id": 0}).sort("taken_down_at", -1).to_list(50)

    if not docs and not takedown_results:
        return {"jobs": [], "takedowns": [], "total": 0, "query": q}

    job_ids = [d["job_id"] for d in docs]
    verdict_keys = [f"prod::{jid}" for jid in job_ids]
    verdict_docs = await db.eval_verdicts.find({"eval_key": {"$in": verdict_keys}}, {"_id": 0}).to_list(200)
    verdict_map = {d["eval_key"]: d for d in verdict_docs}
    action_docs = await db.automated_actions.find({"job_id": {"$in": job_ids}, "dry_run": is_dry}, {"_id": 0}).to_list(200)
    action_map = {d["job_id"]: d for d in action_docs}
    sched_docs = await db.scheduled_takedowns.find({"job_id": {"$in": job_ids}, "dry_run": is_dry}, {"_id": 0}).to_list(200)
    sched_map = {d["job_id"]: d for d in sched_docs}
    opus_docs = await db.opus_verdicts.find({"job_id": {"$in": job_ids}, "dry_run": is_dry}, {"_id": 0}).to_list(200)
    opus_map = {d["job_id"]: d for d in opus_docs}

    results = [mongo_doc_to_eval_format(d, verdict_map.get(f"prod::{d['job_id']}", {}), action_map.get(d["job_id"]), sched_map.get(d["job_id"]), opus_map.get(d["job_id"])) for d in docs]
    return {"jobs": results, "takedowns": takedown_results, "total": len(results) + len(takedown_results), "query": q}


@api_router.post("/prod/verdict/{job_id}")
async def prod_verdict(job_id: str, request: Request):
    await get_current_user(request)
    body = await request.json()
    ek = f"prod::{job_id}"

    update = {}
    if "verdict_s1" in body:
        update["human_verdict_s1"] = body["verdict_s1"]
    if "verdict_wc" in body:
        update["human_verdict_wc"] = body["verdict_wc"]
    if "verdict_s2" in body:
        update["human_verdict_s2"] = body["verdict_s2"]
    if "notes" in body:
        update["human_notes"] = body["notes"]

    if update:
        update["eval_key"] = ek
        update["job_id"] = job_id
        await db.eval_verdicts.update_one({"eval_key": ek}, {"$set": update}, upsert=True)

        # Denormalize: write verdict directly into bq_jobs for fast filtering
        bq_update = {}
        if "human_verdict_s2" in update:
            bq_update["human_verdict_s2"] = update["human_verdict_s2"]
        if "human_notes" in update:
            bq_update["human_notes"] = update["human_notes"]
        if bq_update:
            await db.bq_jobs.update_one({"job_id": job_id}, {"$set": bq_update})

    return {"status": "ok", "eval_key": ek}


# ---- BigQuery Takedown Logging ----

BQ_TAKEDOWN_TABLE = "phishing_eval.job_takedowns"


def _bq_insert_takedown_sync(row: dict):
    """Synchronous BQ insert — called via run_in_executor."""
    try:
        errors = bq_client.insert_rows_json(BQ_TAKEDOWN_TABLE, [row])
        if errors:
            logger.error(f"BQ takedown insert errors: {errors}")
        else:
            logger.info(f"BQ takedown logged for job {row.get('job_id')}")
    except Exception as e:
        logger.error(f"BQ takedown insert failed: {e}")


def log_takedown_to_bq(row: dict):
    """Insert a takedown row into BigQuery in the background (fire-and-forget)."""
    if not bq_client:
        logger.warning("BQ takedown log skipped: no bq_client")
        return
    bq_row = {
        "job_id": row.get("job_id", ""),
        "taken_down_by": row.get("taken_down_by", ""),
        "taken_down_at": row.get("taken_down_at", datetime.now(timezone.utc).isoformat()),
        "suspension_reason": row.get("suspension_reason", ""),
        "s2_label": row.get("s2_label"),
        "task_preview": row.get("task_preview"),
        "api_status_code": row.get("api_status_code"),
        "is_test_mode": row.get("is_test_mode", False),
    }
    asyncio.get_event_loop().run_in_executor(None, _bq_insert_takedown_sync, bq_row)


# ---- Fork Chain Resolution ----

FORK_CHAIN_MAX_DEPTH = 50
PSQL_CONNECTION = "emergent-default.us-central1.agent_service_psql_connection"


def resolve_fork_chain(job_id: str) -> list[str]:
    """Resolve full linear fork chain for a job_id.
    Walks UP to root, then DOWN to latest. Returns all job_ids in order.
    If job has no parent (no fork chain), returns [job_id].
    """
    if not bq_client:
        logger.warning("Fork chain resolution skipped: no bq_client")
        return [job_id]

    try:
        import uuid as _uuid
        _uuid.UUID(job_id)  # validate UUID to prevent injection
    except ValueError:
        return [job_id]

    def _ext_query(pg_sql: str) -> list:
        q = 'SELECT * FROM EXTERNAL_QUERY("' + PSQL_CONNECTION + '", "' + pg_sql + '")'
        return list(bq_client.query(q).result())

    # Step 1: Walk UP to root
    current = job_id
    visited = {current}
    root = current
    try:
        for _ in range(FORK_CHAIN_MAX_DEPTH):
            rows = _ext_query(f"SELECT parent_job_id::text FROM jobs WHERE id = '{current}'")
            if not rows:
                break
            parent = rows[0].parent_job_id
            if not parent or parent in visited:
                root = current
                break
            visited.add(parent)
            current = parent
            root = current
    except Exception as e:
        logger.error(f"Fork chain UP traversal failed for {job_id}: {e}")
        return [job_id]

    # Step 2: Walk DOWN from root
    chain = [root]
    current = root
    try:
        for _ in range(FORK_CHAIN_MAX_DEPTH):
            rows = _ext_query(f"SELECT id::text AS job_id FROM jobs WHERE parent_job_id = '{current}'")
            if not rows:
                break
            child = rows[0].job_id
            if child in chain:
                break
            chain.append(child)
            current = child
    except Exception as e:
        logger.error(f"Fork chain DOWN traversal failed for {job_id}: {e}")
        if job_id not in chain:
            chain.append(job_id)
        return chain

    # Ensure the original job_id is always in the chain
    if job_id not in chain:
        chain.append(job_id)

    if len(chain) > 1:
        logger.info(f"Fork chain for {job_id}: {len(chain)} jobs {chain}")

    return chain


# ---- Takedown API ----

@api_router.post("/prod/takedown/{job_id}")
async def takedown_job(job_id: str, request: Request):
    """Mark a job as taken down. Resolves fork chain and disables all jobs in chain."""
    user = await get_current_user(request)
    body = await request.json()

    suspension_reason = body.get("suspension_reason", "").strip()
    if not suspension_reason:
        raise HTTPException(status_code=400, detail="suspension_reason is required")

    # Verdict check on original job only
    ek = f"prod::{job_id}"
    verdict_doc = await db.eval_verdicts.find_one({"eval_key": ek}, {"_id": 0})
    if not verdict_doc or verdict_doc.get("human_verdict_s2") != "correct":
        raise HTTPException(status_code=400, detail="Job must have S2 verdict marked as 'correct' before takedown")

    # Resolve fork chain
    chain = await asyncio.get_event_loop().run_in_executor(None, resolve_fork_chain, job_id)
    logger.info(f"Takedown {job_id}: fork chain resolved to {len(chain)} job(s)")

    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        token = request.query_params.get("_token") or request.cookies.get("sb_token")
        if token:
            auth_header = f"Bearer {token}"

    now = datetime.now(timezone.utc).isoformat()
    results = {}

    for jid in chain:
        try:
            disable_url = f"https://api.emergent.sh/jobs/v0/{jid}/disable"
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    disable_url,
                    headers={"Authorization": auth_header, "Content-Type": "application/json"},
                    json={"is_suspended": True, "suspension_reason": suspension_reason},
                )
                api_result = {"status_code": resp.status_code, "body": resp.text}
                logger.info(f"TAKEDOWN API response for {jid}: {resp.status_code} {resp.text[:200]}")

            takedown_info = {
                "taken_down_by": user.get("email", "unknown"),
                "taken_down_by_name": user.get("name", ""),
                "taken_down_by_user_id": user.get("user_id", ""),
                "taken_down_at": now,
                "job_id": jid,
                "task_preview": body.get("task_preview", ""),
                "s2_label": body.get("s2_label", ""),
                "suspension_reason": suspension_reason,
                "api_result": api_result,
                "fork_chain_root": chain[0] if len(chain) > 1 else None,
            }

            await db.takedowns.insert_one({**takedown_info})
            await db.eval_verdicts.update_one(
                {"eval_key": f"prod::{jid}"},
                {"$set": {"taken_down": True, "takedown_info": takedown_info}},
                upsert=True,
            )

            log_takedown_to_bq({
                "job_id": jid,
                "taken_down_by": user.get("email", "unknown"),
                "taken_down_at": now,
                "suspension_reason": suspension_reason,
                "s2_label": body.get("s2_label", ""),
                "task_preview": body.get("task_preview", ""),
                "api_status_code": api_result.get("status_code"),
                "is_test_mode": False,
            })

            results[jid] = {"status": "ok", "api_status_code": resp.status_code}
        except Exception as e:
            logger.error(f"TAKEDOWN failed for chain job {jid}: {e}")
            results[jid] = {"status": "failed", "error": str(e)}

    return {"status": "ok", "fork_chain": chain, "results": results}


@api_router.post("/prod/enable/{job_id}")
async def enable_job(job_id: str, request: Request):
    """Re-enable a job that was previously taken down. Resolves fork chain and enables all."""
    user = await get_current_user(request)
    body = await request.json()

    reason = (body.get("reason") or "").strip()
    if not reason:
        raise HTTPException(status_code=400, detail="reason is required")

    # Resolve fork chain
    chain = await asyncio.get_event_loop().run_in_executor(None, resolve_fork_chain, job_id)
    logger.info(f"Enable {job_id}: fork chain resolved to {len(chain)} job(s)")

    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        token = request.query_params.get("_token") or request.cookies.get("sb_token")
        if token:
            auth_header = f"Bearer {token}"

    now = datetime.now(timezone.utc).isoformat()
    results = {}

    for jid in chain:
        try:
            enable_url = f"https://api.emergent.sh/jobs/v0/{jid}/enable"
            async with httpx.AsyncClient(timeout=30) as client:
                resp = await client.post(
                    enable_url,
                    headers={"Authorization": auth_header, "Content-Type": "application/json"},
                    json={"is_suspended": False, "suspension_reason": reason},
                )
                api_result = {"status_code": resp.status_code, "body": resp.text}
                logger.info(f"ENABLE API response for {jid}: {resp.status_code} {resp.text[:200]}")

            enable_info = {
                "enabled_by": user.get("email", "unknown"),
                "enabled_by_name": user.get("name", ""),
                "enabled_at": now,
                "job_id": jid,
                "reason": reason,
                "api_result": api_result,
                "fork_chain_root": chain[0] if len(chain) > 1 else None,
            }

            await db.job_enables.insert_one({**enable_info})
            await db.eval_verdicts.update_one(
                {"eval_key": f"prod::{jid}"},
                {"$set": {"taken_down": False, "enabled_info": enable_info}},
            )

            results[jid] = {"status": "ok", "api_status_code": resp.status_code}
        except Exception as e:
            logger.error(f"ENABLE failed for chain job {jid}: {e}")
            results[jid] = {"status": "failed", "error": str(e)}

    return {"status": "ok", "fork_chain": chain, "results": results}


@api_router.get("/prod/enables-history")
async def get_enables_history(request: Request):
    """Return recent job enables for the history table."""
    await get_current_user(request)
    docs = await db.job_enables.find({}, {"_id": 0}).sort("enabled_at", -1).to_list(50)
    return {"enables": docs}


@api_router.post("/prod/schedule-takedown/{job_id}")
async def schedule_takedown_job(job_id: str, request: Request):
    """Manually schedule a takedown (email + 24h). Resolves fork chain and schedules all."""
    user = await get_current_user(request)
    body = await request.json()

    suspension_reason = body.get("suspension_reason", "").strip()
    if not suspension_reason:
        raise HTTPException(status_code=400, detail="suspension_reason is required")

    # Verdict check on original job only
    ek = f"prod::{job_id}"
    verdict_doc = await db.eval_verdicts.find_one({"eval_key": ek}, {"_id": 0})
    if not verdict_doc or verdict_doc.get("human_verdict_s2") != "correct":
        raise HTTPException(status_code=400, detail="Job must have S2 verdict marked as 'correct' before scheduling takedown")

    bq_doc = await db.bq_jobs.find_one({"job_id": job_id}, {"_id": 0})
    if not bq_doc:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")

    # Resolve fork chain
    chain = await asyncio.get_event_loop().run_in_executor(None, resolve_fork_chain, job_id)
    logger.info(f"Schedule-takedown {job_id}: fork chain resolved to {len(chain)} job(s)")

    now = datetime.now(timezone.utc)
    takedown_at = (now + timedelta(hours=24)).isoformat()
    user_id = bq_doc.get("user_id")
    user_email = bq_doc.get("user_email")

    # Send email once per user (not per chain job)
    if user_email and user_id:
        try:
            from automation import send_takedown_warning_email
            send_takedown_warning_email(user_id, user_email, bq_doc.get("plan_type", ""), [bq_doc])
        except Exception as e:
            logger.error(f"Schedule-takedown email failed for {job_id}: {e}")

    _is_dry = get_dry_run()
    results = {}

    for jid in chain:
        try:
            # Skip if already scheduled
            existing = await db.scheduled_takedowns.find_one({"job_id": jid, "status": "pending", "dry_run": _is_dry})
            if existing:
                results[jid] = {"status": "already_scheduled"}
                continue

            chain_bq_doc = await db.bq_jobs.find_one({"job_id": jid}, {"_id": 0}) if jid != job_id else bq_doc

            await db.scheduled_takedowns.update_one(
                {"job_id": jid, "dry_run": _is_dry},
                {"$set": {
                    "job_id": jid,
                    "user_id": user_id,
                    "user_email": user_email,
                    "email_sent_at": now.isoformat(),
                    "takedown_at": takedown_at,
                    "status": "pending",
                    "classification_category": (chain_bq_doc or {}).get("classification_category", ""),
                    "classification_label": (chain_bq_doc or {}).get("classification_label", ""),
                    "scheduled_by": user.get("email", "unknown"),
                    "suspension_reason": suspension_reason,
                    "dry_run": _is_dry,
                    "fork_chain_root": chain[0] if len(chain) > 1 else None,
                }},
                upsert=True,
            )

            await db.automated_actions.update_one(
                {"job_id": jid, "dry_run": _is_dry},
                {"$set": {
                    "job_id": jid,
                    "tier": classify_tier(chain_bq_doc) if chain_bq_doc and chain_bq_doc.get("classification_label") else 0,
                    "action": "email_scheduled",
                    "status": "completed",
                    "executed_at": now.isoformat(),
                    "scheduled_by": user.get("email", "unknown"),
                    "dry_run": _is_dry,
                }},
                upsert=True,
            )

            results[jid] = {"status": "scheduled"}
        except Exception as e:
            logger.error(f"Schedule-takedown failed for chain job {jid}: {e}")
            results[jid] = {"status": "failed", "error": str(e)}

    logger.info(f"Manual schedule-takedown for {job_id} by {user.get('email')}, chain={len(chain)}, deadline {takedown_at}")
    return {"status": "ok", "takedown_at": takedown_at, "fork_chain": chain, "results": results}


@api_router.post("/admin/opus-verdict/{job_id}")
async def trigger_opus_verdict(job_id: str, request: Request):
    """Trigger Opus agent classifier for a single job and return the verdict."""
    await get_current_user(request)
    try:
        from opus_agent import run_classifier
        verdict = await run_classifier(job_id)
        return {"status": "ok", "verdict": verdict}
    except Exception as e:
        logger.error(f"Opus verdict trigger failed for {job_id}: {e}")
        return {"status": "error", "error": str(e)}


@api_router.post("/test/takedown/{job_id}")
async def test_takedown_job(job_id: str, request: Request):
    """QA test takedown — calls the disable API directly without verdict checks."""
    user = await get_current_user(request)
    body = await request.json()

    suspension_reason = body.get("suspension_reason", "").strip()
    if not suspension_reason:
        raise HTTPException(status_code=400, detail="suspension_reason is required")

    disable_url = f"https://api.emergent.sh/jobs/v0/{job_id}/disable"
    auth_header = request.headers.get("Authorization", "")
    if not auth_header:
        token = request.query_params.get("_token") or request.cookies.get("sb_token")
        if token:
            auth_header = f"Bearer {token}"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                disable_url,
                headers={"Authorization": auth_header, "Content-Type": "application/json"},
                json={"is_suspended": True, "suspension_reason": suspension_reason},
            )
            api_result = {"status_code": resp.status_code, "body": resp.text}
            logger.info(f"TEST TAKEDOWN API response for {job_id}: {resp.status_code} {resp.text[:200]}")
            if resp.status_code >= 400:
                raise HTTPException(status_code=502, detail=f"Disable API returned {resp.status_code}: {resp.text[:300]}")
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"TEST TAKEDOWN API call failed for {job_id}: {e}")
        raise HTTPException(status_code=502, detail=f"Disable API call failed: {str(e)}")

    takedown_info = {
        "taken_down_by": user.get("email", "unknown"),
        "taken_down_at": datetime.now(timezone.utc).isoformat(),
        "job_id": job_id,
        "suspension_reason": suspension_reason,
        "api_result": api_result,
        "test_mode": True,
    }

    await db.takedowns.insert_one({**takedown_info})

    # Log to BigQuery in background
    log_takedown_to_bq({
        "job_id": job_id,
        "taken_down_by": user.get("email", "unknown"),
        "taken_down_at": takedown_info["taken_down_at"],
        "suspension_reason": suspension_reason,
        "s2_label": "",
        "task_preview": "",
        "api_status_code": api_result.get("status_code"),
        "is_test_mode": True,
    })

    return {"status": "ok", "takedown_info": takedown_info}


@api_router.get("/prod/takedowns")
async def list_takedowns(request: Request):
    """List all job takedowns."""
    await get_current_user(request)
    takedowns = await db.takedowns.find({}, {"_id": 0}).sort("taken_down_at", -1).to_list(500)
    return {"takedowns": takedowns}


@api_router.get("/prod/external-takedowns")
async def external_takedowns(request: Request, source: str = Query("cloudflare")):
    """List external takedowns from BQ external_signals (complete data)."""
    await get_current_user(request)
    if source not in ("cloudflare", "openai"):
        raise HTTPException(status_code=400, detail="source must be cloudflare or openai")

    try:
        ext_query = f"""
        SELECT
          es.id as signal_id,
          es.status as signal_status,
          es.resolved_domain,
          es.received_at,
          es.reason,
          job_id
        FROM `phishing_eval.external_signals` es,
        UNNEST(JSON_EXTRACT_STRING_ARRAY(es.resolved_job_ids)) as job_id
        WHERE LOWER(es.event_type) LIKE '%{source}%'
          AND es.resolved_job_ids IS NOT NULL AND es.resolved_job_ids != '[]'
        ORDER BY es.received_at DESC
        """
        rows = await asyncio.to_thread(lambda: [dict(r) for r in bq_client.query(ext_query).result()])
    except Exception as e:
        logger.error(f"External takedowns BQ query failed: {e}")
        return {"takedowns": []}

    # Dedupe by job_id (keep latest signal)
    seen = {}
    for r in rows:
        jid = r.get("job_id")
        if jid not in seen:
            seen[jid] = r

    # Enrich with MongoDB data
    job_ids = list(seen.keys())
    bq_docs = await db.bq_jobs.find({"job_id": {"$in": job_ids}}, {"_id": 0, "job_id": 1, "task": 1, "classification_label": 1, "user_email": 1}).to_list(5000)
    bq_map = {d["job_id"]: d for d in bq_docs}
    td_docs = await db.takedowns.find({"job_id": {"$in": job_ids}}, {"_id": 0}).to_list(5000)
    td_map = {d["job_id"]: d for d in td_docs}
    aa_docs = await db.automated_actions.find({"job_id": {"$in": job_ids}, "action": "external_takedown"}, {"_id": 0}).to_list(5000)
    aa_map = {d["job_id"]: d for d in aa_docs}

    result = []
    for jid, signal in seen.items():
        bq_doc = bq_map.get(jid, {})
        td = td_map.get(jid, {})
        aa = aa_map.get(jid, {})
        result.append({
            "job_id": jid,
            "task_preview": bq_doc.get("task", td.get("task_preview", ""))[:200] if bq_doc.get("task") or td.get("task_preview") else "",
            "s2_label": bq_doc.get("classification_label") or td.get("s2_label") or aa.get("classification_label") or "MALICIOUS",
            "source": source,
            "suspension_reason": f"Cloudflare abuse report for {signal.get('resolved_domain', '—')}" if source == "cloudflare" else f"OpenAI report for {signal.get('resolved_domain', '—')}",
            "taken_down_by": td.get("taken_down_by") or f"external:{source}",
            "taken_down_at": td.get("taken_down_at") or aa.get("executed_at") or (signal.get("received_at").isoformat() if signal.get("received_at") else None),
            "signal_status": signal.get("signal_status"),
            "domain": signal.get("resolved_domain"),
        })

    return {"takedowns": result}



@api_router.get("/admin/enrichment-status")
async def enrichment_status(request: Request):
    """Diagnostic: check how many escalated jobs are missing user details."""
    await get_current_user(request)
    total_escalated = await db.bq_jobs.count_documents({
        "classification_label": {"$in": ["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW"]}
    })
    with_email = await db.bq_jobs.count_documents({
        "classification_label": {"$in": ["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW"]},
        "user_email": {"$exists": True, "$ne": None}
    })
    missing_email = await db.bq_jobs.count_documents({
        "classification_label": {"$in": ["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW"]},
        "$or": [{"user_email": {"$exists": False}}, {"user_email": None}]
    })
    return {
        "total_escalated": total_escalated,
        "enriched_with_email": with_email,
        "missing_email": missing_email,
    }




@api_router.post("/admin/test-takedown/{job_id}")
async def test_takedown(job_id: str, request: Request):
    """Test the takedown API flow — authenticates, calls disable API, returns result. Does NOT record in DB."""
    user = await get_current_user(request)
    from automation import get_automation_token

    try:
        token = await get_automation_token()
    except Exception as e:
        return {"status": "error", "step": "auth", "error": str(e)}

    # Call the disable API
    disable_url = f"https://api.emergent.sh/jobs/v0/{job_id}/disable"
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.post(
                disable_url,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json={"is_suspended": True, "suspension_reason": f"Test takedown by {user.get('email', 'unknown')}"},
            )
            return {
                "status": "ok" if resp.status_code < 400 else "error",
                "step": "api_call",
                "status_code": resp.status_code,
                "response": resp.text[:500],
                "job_id": job_id,
                "tested_by": user.get("email", "unknown"),
            }
    except Exception as e:
        return {"status": "error", "step": "api_call", "error": str(e)}


@api_router.get("/admin/tier-audit")
async def tier_audit(request: Request):
    """Audit misclassified jobs — find automated_actions where stored tier != current classify_tier()."""
    await get_current_user(request)
    from automation import classify_tier

    # Load all actions and bq_jobs in bulk (2 queries instead of N+1)
    _dr = {"dry_run": get_dry_run()}
    all_actions = await db.automated_actions.find(_dr, {"job_id": 1, "tier": 1, "_id": 0}).to_list(50000)
    action_job_ids = [a["job_id"] for a in all_actions]

    # Batch load all bq_jobs for these job_ids
    bq_docs = await db.bq_jobs.find({"job_id": {"$in": action_job_ids}}, {"_id": 0}).to_list(50000)
    bq_map = {d["job_id"]: d for d in bq_docs}

    misclassified = []
    summary = {"total_checked": 0, "correct": 0, "misclassified": 0, "missing_bq": 0, "by_stored_tier": {}, "reclassify_to": {}}

    for action in all_actions:
        summary["total_checked"] += 1
        job = bq_map.get(action["job_id"])
        if not job:
            summary["missing_bq"] += 1
            continue

        correct_tier = classify_tier(job)
        stored_tier = action.get("tier")
        if correct_tier != stored_tier:
            summary["misclassified"] += 1
            key = f"tier_{stored_tier}"
            summary["by_stored_tier"][key] = summary["by_stored_tier"].get(key, 0) + 1
            to_key = f"tier_{correct_tier}"
            summary["reclassify_to"][to_key] = summary["reclassify_to"].get(to_key, 0) + 1
            if len(misclassified) < 20:
                misclassified.append({
                    "job_id": action["job_id"],
                    "stored_tier": stored_tier,
                    "correct_tier": correct_tier,
                    "ltv": job.get("ltv"),
                    "label": job.get("classification_label"),
                    "category": (job.get("classification_category") or "")[:60],
                })
        else:
            summary["correct"] += 1

    return {"summary": summary, "sample_misclassified": misclassified}


@api_router.post("/admin/tier-reclassify")
async def tier_reclassify(request: Request):
    """Delete misclassified automated_actions so Phase 4 re-classifies them on next sync."""
    await get_current_user(request)
    from automation import classify_tier

    # Bulk load (mode-filtered)
    _dr = {"dry_run": get_dry_run()}
    all_actions = await db.automated_actions.find(_dr, {"job_id": 1, "tier": 1, "_id": 0}).to_list(50000)
    action_job_ids = [a["job_id"] for a in all_actions]
    bq_docs = await db.bq_jobs.find({"job_id": {"$in": action_job_ids}}, {"_id": 0}).to_list(50000)
    bq_map = {d["job_id"]: d for d in bq_docs}

    misclassified_ids = []
    for action in all_actions:
        job = bq_map.get(action["job_id"])
        if not job:
            continue
        if classify_tier(job) != action.get("tier"):
            misclassified_ids.append(action["job_id"])

    if not misclassified_ids:
        return {"status": "ok", "deleted": 0, "message": "No misclassified jobs found"}

    result = await db.automated_actions.delete_many({"job_id": {"$in": misclassified_ids}, **_dr})
    sched_result = await db.scheduled_takedowns.delete_many({"job_id": {"$in": misclassified_ids}, **_dr})

    return {
        "status": "ok",
        "deleted": result.deleted_count,
        "scheduled_deleted": sched_result.deleted_count,
        "message": f"Deleted {result.deleted_count} records. Trigger a sync to re-classify.",
    }


@api_router.post("/admin/pipeline-fix")
async def pipeline_fix(request: Request):
    """Fix stuck BQ write-back pipeline.

    1. Patches automated_actions with tier=null → tier=0 (unblocks BQ load job)
    2. Reports write-back sync status for both dry_run and live modes
    3. Shows sample jobs in MongoDB automated_actions not yet in BQ
    """
    user = await get_current_user(request)
    now = datetime.now(timezone.utc)

    # Step 1: Patch tier:null → tier:0
    patch_result = await db.automated_actions.update_many(
        {"tier": None},
        {"$set": {"tier": 0}}
    )
    patched_count = patch_result.modified_count
    logger.info(f"[pipeline-fix] Patched {patched_count} automated_actions with tier:null → 0 (by {user.get('email')})")

    # Step 2: Get write-back sync metadata for both modes
    sync_dry = await db.sync_metadata.find_one({"_id": "bq_write_sync_dry"})
    sync_live = await db.sync_metadata.find_one({"_id": "bq_write_sync"})
    if sync_dry:
        sync_dry.pop("_id", None)
    if sync_live:
        sync_live.pop("_id", None)

    # Step 3: Count actions pending write-back per mode
    pending = {}
    for mode_label, is_dry in [("dry_run", True), ("live", False)]:
        meta = sync_dry if is_dry else sync_live
        last_sync = meta.get("last_sync_at") if meta else None
        query = {"dry_run": is_dry}
        if last_sync:
            query["created_at"] = {"$gte": last_sync}
        count = await db.automated_actions.count_documents(query)
        total = await db.automated_actions.count_documents({"dry_run": is_dry})
        pending[mode_label] = {
            "last_bq_sync": last_sync,
            "pending_write_back": count,
            "total_in_mongo": total,
        }

    # Step 4: Sample recent actions not yet synced (by comparing created_at > last_sync)
    samples = []
    live_last = (sync_live or {}).get("last_sync_at")
    if live_last:
        sample_query = {"dry_run": False, "created_at": {"$gte": live_last}}
    else:
        sample_query = {"dry_run": False}
    cursor = db.automated_actions.find(
        sample_query,
        {"_id": 0, "job_id": 1, "tier": 1, "action": 1, "status": 1, "created_at": 1}
    ).sort("created_at", -1).limit(10)
    async for doc in cursor:
        samples.append(doc)

    # Step 5: Check for any remaining tier:null docs
    remaining_null = await db.automated_actions.count_documents({"tier": None})

    # Step 6: Get last 3 pipeline runs Phase 5 status
    phase5_history = []
    async for run in db.pipeline_runs.find({}, {"_id": 0, "timestamp": 1, "phases.phase_5": 1, "dry_run": 1}).sort("timestamp", -1).limit(3):
        phase5_history.append({
            "timestamp": run.get("timestamp"),
            "dry_run": run.get("dry_run"),
            "phase_5": run.get("phases", {}).get("phase_5"),
        })

    return {
        "status": "ok",
        "fixed_by": user.get("email"),
        "timestamp": now.isoformat(),
        "tier_null_patched": patched_count,
        "tier_null_remaining": remaining_null,
        "write_back_status": pending,
        "sync_metadata": {
            "dry_run": sync_dry,
            "live": sync_live,
        },
        "sample_unsynced_live_actions": samples,
        "recent_phase5_runs": phase5_history,
    }


# ---- Automation API Endpoints ----

@api_router.get("/automation/auto-takedowns")
async def list_auto_takedowns(request: Request):
    """List Tier 1 auto-takedowns."""
    await get_current_user(request)
    is_dry = get_dry_run()
    docs = await db.automated_actions.find(
        {"tier": 1, "action": "auto_takedown", "dry_run": is_dry},
        {"_id": 0}
    ).sort("created_at", -1).to_list(500)
    return {"takedowns": docs}


@api_router.get("/automation/scheduled-takedowns")
async def list_scheduled_takedowns(request: Request):
    """List Tier 2 scheduled takedowns with status."""
    await get_current_user(request)
    is_dry = get_dry_run()
    docs = await db.scheduled_takedowns.find({"dry_run": is_dry}, {"_id": 0}).sort("takedown_at", -1).to_list(500)
    return {"scheduled": docs}


@api_router.get("/automation/actions")
async def list_automation_actions(request: Request):
    """List all automated actions (all tiers)."""
    await get_current_user(request)
    limit = int(request.query_params.get("limit", "200"))
    tier = request.query_params.get("tier")
    is_dry = get_dry_run()
    query = {"dry_run": is_dry}
    if tier:
        query["tier"] = int(tier)
    docs = await db.automated_actions.find(query, {"_id": 0}).sort("created_at", -1).to_list(limit)
    return {"actions": docs}


@api_router.get("/automation/exclusions")
async def list_exclusions(request: Request):
    """List active exclusion rules."""
    await get_current_user(request)
    docs = await db.exclusion_list.find({"active": True}, {"_id": 0}).sort("added_at", -1).to_list(500)
    return {"exclusions": docs}


@api_router.get("/automation/excluded-jobs")
async def list_excluded_jobs(request: Request):
    """List individual jobs that were excluded during pipeline evaluation.
    Returns flat list with job_id, exclusion reason type, timestamp, and task preview."""
    await get_current_user(request)
    is_dry = get_dry_run()

    # Fetch all skipped_excluded actions
    excluded = await db.automated_actions.find(
        {"action": "skipped_excluded", "dry_run": is_dry},
        {"_id": 0, "job_id": 1, "user_id": 1, "tier": 1, "classification_label": 1,
         "created_at": 1, "exclude_pattern": 1}
    ).sort("created_at", -1).to_list(2000)

    if not excluded:
        return {"excluded_jobs": [], "total": 0}

    # Fetch task text from bq_jobs for all these job_ids
    job_ids = list({e["job_id"] for e in excluded})
    tasks_cursor = db.bq_jobs.find(
        {"job_id": {"$in": job_ids}},
        {"_id": 0, "job_id": 1, "task": 1}
    )
    task_map = {}
    async for doc in tasks_cursor:
        task_map[doc["job_id"]] = (doc.get("task") or "")[:200]

    # Load active exclusion rules to determine reason type
    rules = await db.exclusion_list.find({"active": True}).to_list(500)
    job_id_rules = {r["job_id"] for r in rules if r.get("job_id")}
    user_id_rules = {r["user_id"] for r in rules if r.get("user_id")}

    results = []
    for e in excluded:
        # Determine exclusion reason type
        if e.get("exclude_pattern"):
            reason_type = "pattern"
            reason_detail = e["exclude_pattern"]
        elif e["job_id"] in job_id_rules:
            reason_type = "job"
            reason_detail = e["job_id"]
        elif e.get("user_id") and e["user_id"] in user_id_rules:
            reason_type = "user"
            reason_detail = e["user_id"]
        else:
            reason_type = "rule"
            reason_detail = ""

        results.append({
            "job_id": e["job_id"],
            "user_id": e.get("user_id", ""),
            "tier": e.get("tier"),
            "classification_label": e.get("classification_label", ""),
            "excluded_at": e.get("created_at", ""),
            "reason_type": reason_type,
            "reason_detail": reason_detail,
            "task_preview": task_map.get(e["job_id"], ""),
        })

    return {"excluded_jobs": results, "total": len(results)}


@api_router.post("/automation/exclusions")
async def add_exclusion(request: Request):
    """Add a user/job to the exclusion list. Also cancels pending scheduled takedowns."""
    user = await get_current_user(request)
    body = await request.json()
    user_id = body.get("user_id")
    job_id = body.get("job_id")
    pattern = body.get("pattern")
    if not user_id and not job_id and not pattern:
        raise HTTPException(status_code=400, detail="user_id, job_id, or pattern is required")
    if pattern:
        try:
            re.compile(pattern)
        except re.error as e:
            raise HTTPException(status_code=400, detail=f"Invalid regex pattern: {e}")

    doc = {
        "user_id": user_id,
        "job_id": job_id,
        "pattern": pattern,
        "reason": body.get("reason", ""),
        "added_by": user.get("email", "unknown"),
        "added_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }
    await db.exclusion_list.insert_one(doc)

    # Cancel any pending scheduled takedowns matching user_id or job_id
    cancelled_sched = 0
    cancelled_actions = 0
    or_clauses = []
    if user_id:
        or_clauses.append({"user_id": user_id})
    if job_id:
        or_clauses.append({"job_id": job_id})
    if or_clauses:
        # Cancel scheduled takedowns
        result = await db.scheduled_takedowns.update_many(
            {"status": "pending", "dry_run": get_dry_run(), "$or": or_clauses},
            {"$set": {
                "status": "excluded",
                "excluded_at": doc["added_at"],
                "excluded_by": doc["added_by"],
                "exclude_reason": doc["reason"],
            }}
        )
        cancelled_sched = result.modified_count

        # Also cancel any pending automated_actions (not yet executed)
        pending_statuses = ["pending", "pending_opus_review", "pending_takedown"]
        result2 = await db.automated_actions.update_many(
            {"status": {"$in": pending_statuses}, "$or": or_clauses},
            {"$set": {
                "action": "skipped_excluded",
                "status": "skipped",
                "excluded_at": doc["added_at"],
                "excluded_by": doc["added_by"],
                "exclude_reason": doc["reason"],
            }}
        )
        cancelled_actions = result2.modified_count

    identifier = user_id or job_id or f"pattern:{pattern}"
    logger.info(f"Exclusion added for {identifier} by {doc['added_by']}, cancelled {cancelled_sched} scheduled + {cancelled_actions} actions")
    return {"status": "ok", "cancelled_scheduled": cancelled_sched, "cancelled_actions": cancelled_actions}


@api_router.delete("/automation/exclusions/{identifier:path}")
async def remove_exclusion(identifier: str, request: Request):
    """Remove a user, job, or pattern from the exclusion list."""
    await get_current_user(request)
    result = await db.exclusion_list.update_many(
        {"$or": [{"user_id": identifier}, {"job_id": identifier}, {"pattern": identifier}], "active": True},
        {"$set": {"active": False}}
    )
    return {"status": "ok", "deactivated": result.modified_count}


@api_router.get("/automation/exclusions/preview-pattern")
async def preview_pattern(request: Request, pattern: str = Query(...)):
    """Preview which bq_jobs match a regex pattern on task description."""
    await get_current_user(request)
    try:
        re.compile(pattern)
    except re.error as e:
        raise HTTPException(status_code=400, detail=f"Invalid regex: {e}")

    matched = await db.bq_jobs.find(
        {"task": {"$regex": pattern}},
        {"_id": 0, "job_id": 1, "user_id": 1, "task": 1, "classification_label": 1, "classification_category": 1, "user_email": 1, "timestamp": 1}
    ).to_list(500)

    return {"pattern": pattern, "match_count": len(matched), "matches": matched}


@api_router.get("/automation/stats")
async def automation_stats(request: Request):
    """Automation dashboard stats: pipeline runs, collection health, tier data.
    All data filtered by server's current DRY_RUN mode."""
    await get_current_user(request)

    is_dry = get_dry_run()
    _dr = {"dry_run": is_dry}

    # ---- Pipeline Run History (last 20 runs, filtered by mode) ----
    pipeline_runs = await db.pipeline_runs.find(
        _dr, {"_id": 0}
    ).sort("timestamp", -1).to_list(20)

    # ---- Collection Counts (data health — these are source data, not mode-filtered) ----
    bq_total = await db.bq_jobs.count_documents({})
    bq_cm = await db.bq_jobs.count_documents({"classification_label": "CONFIRMED_MALICIOUS"})
    bq_nhr = await db.bq_jobs.count_documents({"classification_label": "NEEDS_HUMAN_REVIEW"})
    bq_legit = await db.bq_jobs.count_documents({"classification_label": "LEGITIMATE"})
    bq_no_label = await db.bq_jobs.count_documents({"classification_label": None})
    bq_with_email = await db.bq_jobs.count_documents({"user_email": {"$exists": True, "$ne": None}})
    bq_escalated_missing_email = await db.bq_jobs.count_documents({
        "classification_label": {"$in": ["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW"]},
        "$or": [{"user_email": {"$exists": False}}, {"user_email": None}],
    })
    user_profiles_count = await db.user_profiles.count_documents({})

    collections = {
        "bq_jobs": {
            "total": bq_total,
            "confirmed_malicious": bq_cm,
            "needs_human_review": bq_nhr,
            "legitimate": bq_legit,
            "no_label": bq_no_label,
            "with_email": bq_with_email,
            "escalated_missing_email": bq_escalated_missing_email,
        },
        "user_profiles": user_profiles_count,
    }

    # ---- Sync Metadata ----
    sync_meta = await db.sync_metadata.find_one({"_id": "bq_sync"})
    if sync_meta:
        sync_meta.pop("_id", None)

    # ---- Tier Totals (filtered by mode) ----
    tier_totals = {}
    for t in [1, 2, 3, 4]:
        tier_totals[str(t)] = await db.automated_actions.count_documents({"tier": t, **_dr})

    # ---- Action Breakdown (filtered by mode) ----
    action_pipeline = [
        {"$match": _dr},
        {"$group": {
            "_id": {"action": "$action", "status": "$status"},
            "count": {"$sum": 1}
        }},
        {"$sort": {"_id": 1}},
    ]
    action_breakdown = await db.automated_actions.aggregate(action_pipeline).to_list(50)

    # ---- Scheduled Takedown Stats (filtered by mode) ----
    scheduled_stats = {}
    for status in ["pending", "executed", "excluded", "failed"]:
        scheduled_stats[status] = await db.scheduled_takedowns.count_documents({"status": status, **_dr})

    # ---- Manual Takedowns ----
    manual_takedowns = await db.takedowns.count_documents({})
    auto_takedowns = await db.takedowns.count_documents({"automated": True})

    # ---- Exclusion List ----
    active_exclusions = await db.exclusion_list.count_documents({"active": True})

    # ---- MCP / Exclusion skip counts (filtered by mode) ----
    mcp_skipped = await db.automated_actions.count_documents({"action": "skipped_mcp_error", **_dr})
    exclusion_skipped = await db.automated_actions.count_documents({"action": "skipped_excluded", **_dr})

    return {
        "pipeline_runs": pipeline_runs,
        "collections": collections,
        "sync_metadata": sync_meta or {},
        "tier_totals": tier_totals,
        "action_breakdown": action_breakdown,
        "scheduled_stats": scheduled_stats,
        "takedowns": {"manual": manual_takedowns, "automated": auto_takedowns},
        "active_exclusions": active_exclusions,
        "mcp_error_skipped": mcp_skipped,
        "exclusion_skipped": exclusion_skipped,
        "dry_run": is_dry,
        "mode": "dry_run" if is_dry else "live",
    }


@api_router.get("/prod/filter-options")
async def filter_options(request: Request):
    """Return available filter values for categories and severities."""
    await get_current_user(request)
    cat_pipeline = [
        {"$match": {"classification_category": {"$ne": None, "$nin": ["", "Legitimate"]}}},
        {"$group": {"_id": "$classification_category", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
        {"$limit": 30},
    ]
    categories = [{"value": r["_id"], "count": r["count"]} async for r in db.bq_jobs.aggregate(cat_pipeline)]
    sev_pipeline = [
        {"$match": {"classification_severity": {"$ne": None, "$nin": ["", "N/A"]}}},
        {"$group": {"_id": "$classification_severity", "count": {"$sum": 1}}},
        {"$sort": {"count": -1}},
    ]
    severities = [{"value": r["_id"], "count": r["count"]} async for r in db.bq_jobs.aggregate(sev_pipeline)]
    return {"categories": categories, "severities": severities}



@api_router.get("/prod/stats")
async def prod_stats(request: Request):
    """Stats computed entirely from MongoDB, including tier counts.
    Tier/action data filtered by server's current DRY_RUN mode."""
    await get_current_user(request)

    is_dry = get_dry_run()
    _dr = {"dry_run": is_dry}

    try:
        total = await db.bq_jobs.count_documents({})
        in_flight = await db.bq_jobs.count_documents({"classification_label": None})
        malicious = await db.bq_jobs.count_documents({"classification_label": "CONFIRMED_MALICIOUS"})

        # Verdict counts from eval_verdicts
        pipeline = [
            {"$match": {"human_verdict_s2": {"$in": ["correct", "incorrect", "disputed"]}}},
            {"$group": {"_id": "$human_verdict_s2", "count": {"$sum": 1}}},
        ]
        verdict_counts = {"correct": 0, "incorrect": 0, "disputed": 0}
        async for doc in db.eval_verdicts.aggregate(pipeline):
            verdict_counts[doc["_id"]] = doc["count"]

        correct = verdict_counts["correct"]
        incorrect = verdict_counts["incorrect"]
        disputed = verdict_counts["disputed"]
        untagged = max(0, total - correct - incorrect - disputed)

        # Tier counts from automated_actions (filtered by mode)
        tier_pipeline = [
            {"$match": _dr},
            {"$group": {"_id": "$tier", "count": {"$sum": 1}}},
        ]
        tier_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
        async for doc in db.automated_actions.aggregate(tier_pipeline):
            t = doc["_id"]
            if t in tier_counts:
                tier_counts[t] = doc["count"]

        # Takedown count
        takedown_count = await db.takedowns.count_documents({})

        return {
            "total": total,
            "correct": correct,
            "incorrect": incorrect,
            "disputed": disputed,
            "untagged": untagged,
            "in_flight": in_flight,
            "malicious": malicious,
            "tier_1": tier_counts[1],
            "tier_2": tier_counts[2],
            "tier_3": tier_counts[3],
            "tier_4": tier_counts[4],
            "tier_5": tier_counts[5],
            "takedown_count": takedown_count,
            "opus_pending": await db.automated_actions.count_documents({"status": "pending_opus_review", **_dr}),
            "opus_in_progress": await db.automated_actions.count_documents({"status": "opus_in_progress", **_dr}),
            "opus_reviewed": await db.opus_verdicts.count_documents(_dr),
            "opus_confirmed_malicious": await db.opus_verdicts.count_documents({"opus_label": "CONFIRMED_MALICIOUS", **_dr}),
            "opus_needs_review": await db.opus_verdicts.count_documents({"opus_label": "NEEDS_HUMAN_REVIEW", **_dr}),
            "opus_legitimate": await db.opus_verdicts.count_documents({"opus_label": "LEGITIMATE", **_dr}),
            "mode": "dry_run" if is_dry else "live",
        }
    except Exception as e:
        logger.error(f"Stats query failed: {e}")
        return {"total": 0, "correct": 0, "incorrect": 0, "disputed": 0, "untagged": 0, "in_flight": 0, "malicious": 0, "tier_1": 0, "tier_2": 0, "tier_3": 0, "tier_4": 0, "tier_5": 0, "takedown_count": 0, "opus_pending": 0, "opus_in_progress": 0, "opus_reviewed": 0, "opus_confirmed_malicious": 0, "opus_needs_review": 0, "opus_legitimate": 0}


@api_router.get("/automation/opus-stats")
async def opus_stats(request: Request):
    """Opus agent review statistics."""
    await get_current_user(request)
    is_dry = get_dry_run()
    _dr = {"dry_run": is_dry}

    pending = await db.automated_actions.count_documents({"status": "pending_opus_review", **_dr})
    in_progress = await db.automated_actions.count_documents({"status": "opus_in_progress", **_dr})
    reviewed = await db.opus_verdicts.count_documents(_dr)

    breakdown = {}
    async for doc in db.opus_verdicts.aggregate([
        {"$match": _dr},
        {"$group": {"_id": "$opus_label", "count": {"$sum": 1}}},
    ]):
        breakdown[doc["_id"] or "UNKNOWN"] = doc["count"]

    overrides = await db.automated_actions.count_documents({"opus_overridden": True, **_dr})
    fallbacks = await db.opus_verdicts.count_documents({"opus_fallback": True, **_dr})

    # Recent verdicts
    recent = await db.opus_verdicts.find(_dr, {"_id": 0}).sort("reviewed_at", -1).limit(20).to_list(20)

    return {
        "pending_opus_review": pending,
        "opus_in_progress": in_progress,
        "total_reviewed": reviewed,
        "verdict_breakdown": breakdown,
        "overrides": overrides,
        "fallbacks": fallbacks,
        "recent_verdicts": recent,
    }


@api_router.get("/prod/pending-review-count")
async def pending_review_count(request: Request):
    """Count NEEDS_HUMAN_REVIEW jobs without a verdict — from MongoDB."""
    await get_current_user(request)

    try:
        review_docs = await db.bq_jobs.find(
            {"classification_label": "NEEDS_HUMAN_REVIEW"},
            {"_id": 0, "job_id": 1}
        ).to_list(10000)
        review_job_ids = [d["job_id"] for d in review_docs]
        total_review = len(review_job_ids)

        if total_review == 0:
            return {"count": 0}

        review_eval_keys = [f"prod::{jid}" for jid in review_job_ids]
        reviewed_count = await db.eval_verdicts.count_documents({
            "eval_key": {"$in": review_eval_keys},
            "human_verdict_s2": {"$in": ["correct", "incorrect"]}
        })

        return {"count": max(0, total_review - reviewed_count)}
    except Exception as e:
        logger.error(f"Pending review count failed: {e}")
        return {"count": 0}


@api_router.get("/prod/analytics")
async def prod_analytics(request: Request):
    """Analytics computed from MongoDB bq_jobs."""
    await get_current_user(request)

    try:
        # Daily S2 categorization
        daily_pipeline = [
            {"$addFields": {"day": {"$substr": ["$timestamp", 0, 10]}}},
            {"$group": {
                "_id": "$day",
                "malicious": {"$sum": {"$cond": [{"$eq": ["$classification_label", "CONFIRMED_MALICIOUS"]}, 1, 0]}},
                "review": {"$sum": {"$cond": [{"$eq": ["$classification_label", "NEEDS_HUMAN_REVIEW"]}, 1, 0]}},
                "legit": {"$sum": {"$cond": [{"$eq": ["$classification_label", "LEGITIMATE"]}, 1, 0]}},
                "no_s2": {"$sum": {"$cond": [{"$eq": [{"$ifNull": ["$classification_label", None]}, None]}, 1, 0]}},
                "total": {"$sum": 1},
            }},
            {"$sort": {"_id": -1}},
            {"$limit": 30},
        ]
        daily_rows = []
        async for doc in db.bq_jobs.aggregate(daily_pipeline):
            daily_rows.append({
                "day": doc["_id"],
                "malicious": doc["malicious"],
                "review": doc["review"],
                "legit": doc["legit"],
                "no_s2": doc["no_s2"],
                "total": doc["total"],
            })

        # S2 accuracy by label
        accuracy = {}
        for label in ["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW", "LEGITIMATE"]:
            label_docs = await db.bq_jobs.find(
                {"classification_label": label},
                {"_id": 0, "job_id": 1}
            ).to_list(10000)
            label_job_ids = [d["job_id"] for d in label_docs]
            label_total = len(label_job_ids)

            correct = 0
            incorrect = 0
            if label_job_ids:
                eval_keys = [f"prod::{jid}" for jid in label_job_ids]
                verdict_docs = await db.eval_verdicts.find(
                    {"eval_key": {"$in": eval_keys}},
                    {"_id": 0, "human_verdict_s2": 1}
                ).to_list(len(eval_keys))
                correct = sum(1 for d in verdict_docs if d.get("human_verdict_s2") == "correct")
                incorrect = sum(1 for d in verdict_docs if d.get("human_verdict_s2") == "incorrect")

            accuracy[label] = {
                "total": label_total,
                "correct": correct,
                "incorrect": incorrect,
                "unmarked": max(0, label_total - correct - incorrect),
            }

        return {"daily": daily_rows, "accuracy": accuracy}
    except Exception as e:
        logger.error(f"Analytics query failed: {e}")
        return {"daily": [], "accuracy": {}, "error": str(e)}


@api_router.post("/admin/sync")
async def admin_sync(request: Request, full: bool = Query(False)):
    """Manual trigger for BQ → MongoDB sync."""
    await get_current_user(request)
    result = await run_bq_sync(full=full)
    return result


@api_router.get("/admin/sync-status")
async def sync_status(request: Request):
    """Get the last sync metadata."""
    await get_current_user(request)
    meta = await db.sync_metadata.find_one({"_id": "bq_sync"})
    if meta:
        meta.pop("_id", None)
    return meta or {"status": "never_synced"}


@api_router.get("/admin/pipeline-health")
async def pipeline_health_endpoint(request: Request):
    """Manually trigger a pipeline health check and return results."""
    await get_current_user(request)
    stats = await check_pipeline_health(bq_client, db)
    return stats or {"status": "no_data"}



ABUSE_API_KEY = os.environ.get("ABUSE_API_KEY")


@api_router.post("/abuse/lookup")
async def abuse_lookup(request: Request):
    """Webhook for dig bot / Zapier: lookup a URL and optionally reply in a Slack thread.
    
    Auth: Supabase Bearer token OR X-API-Key header.
    
    Body:
      url: str (required) — the reported domain/URL
      channel: str (optional) — Slack channel ID to reply in
      thread_ts: str (optional) — Slack thread timestamp to reply in
      
    If channel + thread_ts are provided, posts the result as a Slack thread reply.
    Always returns the lookup result in the response.
    """
    # Auth: accept either Supabase token or API key
    api_key = request.headers.get("X-API-Key") or request.query_params.get("api_key")
    if api_key and ABUSE_API_KEY and api_key == ABUSE_API_KEY:
        pass  # API key auth OK
    else:
        await get_current_user(request)  # Fall back to Supabase auth

    body = await request.json()
    url = body.get("url", "").strip()
    if not url:
        raise HTTPException(status_code=400, detail="url is required")

    # Extract domain from URL
    domains = extract_domains(url)
    if not domains:
        # Try using the raw input as domain
        domains = [url.replace("https://", "").replace("http://", "").rstrip("/")]

    results = []
    for domain in domains:
        rows = await asyncio.to_thread(lookup_url_via_redash, domain)
        reply = build_reply(domain, rows)
        results.append({"domain": domain, "jobs_found": len(rows) if rows else 0, "reply": reply})

        # Reply in Slack thread if channel + thread_ts provided
        channel = body.get("channel")
        thread_ts = body.get("thread_ts")
        if channel and thread_ts:
            await asyncio.to_thread(reply_in_thread, channel, thread_ts, reply)

    return {"status": "ok", "results": results}



@api_router.get("/automation/mode")
async def get_automation_mode(request: Request):
    """Get the current server-wide automation mode."""
    await get_current_user(request)
    return {"mode": "dry_run" if get_dry_run() else "live", "dry_run": get_dry_run()}


@api_router.post("/automation/mode")
async def set_automation_mode(request: Request):
    """Toggle server-wide automation mode between dry_run and live.
    Body: {"mode": "live"} or {"mode": "dry_run"}
    This affects ALL users, ALL queries, ALL pipeline runs."""
    user = await get_current_user(request)
    body = await request.json()
    mode = body.get("mode")
    if mode not in ("dry_run", "live"):
        raise HTTPException(status_code=400, detail="mode must be 'dry_run' or 'live'")

    # Require confirmation challenge when switching to live mode
    if mode == "live":
        confirm = body.get("confirm")
        if confirm != "CONFIRM_LIVE":
            raise HTTPException(status_code=400, detail="Switching to live mode requires confirm='CONFIRM_LIVE' in request body")

    new_dry_run = mode == "dry_run"
    old_mode = get_dry_run()
    set_dry_run(new_dry_run)

    # Persist mode to MongoDB
    await db.automation_config.update_one({"_id": "mode"}, {"$set": {"dry_run": new_dry_run, "changed_by": user.get("email", "unknown"), "changed_at": datetime.now(timezone.utc).isoformat()}}, upsert=True)

    # Audit log entry
    await db.audit_log.insert_one({"action": "mode_change", "from_mode": "dry_run" if old_mode else "live", "to_mode": mode, "changed_by": user.get("email", "unknown"), "changed_at": datetime.now(timezone.utc).isoformat()})

    logger.info(f"Automation mode changed: {'dry_run' if old_mode else 'live'} → {mode}")
    return {
        "status": "ok",
        "previous_mode": "dry_run" if old_mode else "live",
        "current_mode": mode,
        "dry_run": new_dry_run,
    }


# ---- Eval API ----

@api_router.get("/eval/jobs")
async def eval_jobs_endpoint(request: Request):
    await get_current_user(request)
    config = await get_eval_config()
    jobs = await db.eval_jobs.find({}, {"_id": 0}).to_list(5000)
    return {"config": config, "jobs": jobs}


@api_router.post("/eval/verdict/{eval_key:path}")
async def eval_verdict(eval_key: str, request: Request):
    await get_current_user(request)
    body = await request.json()

    update = {}
    if "verdict_s1" in body:
        update["human_verdict_s1"] = body["verdict_s1"]
    if "verdict_wc" in body:
        update["human_verdict_wc"] = body["verdict_wc"]
    if "verdict_s2" in body:
        update["human_verdict_s2"] = body["verdict_s2"]
    if "notes" in body:
        update["human_notes"] = body["notes"]

    if update:
        result = await db.eval_jobs.update_one({"eval_key": eval_key}, {"$set": update})
        if result.matched_count == 0:
            return {"error": f"No eval entry found for key: {eval_key}"}

    return {"status": "ok", "eval_key": eval_key}


@api_router.post("/eval/config")
async def eval_config_endpoint(request: Request):
    await get_current_user(request)
    body = await request.json()
    await db.eval_config.update_one({"_id": "global"}, {"$set": body}, upsert=True)
    return {"status": "ok"}


# ---- Trace Retrieval ----

@api_router.get("/trace/{job_id}")
async def get_job_trace(job_id: str, request: Request):
    await get_current_user(request)
    trace = await db.pipeline_traces.find_one({"job_id": job_id}, {"_id": 0})
    if not trace:
        return {"error": f"No trace found for job_id: {job_id}"}
    return trace


@api_router.get("/traces")
async def list_traces(request: Request):
    await get_current_user(request)
    traces = await db.pipeline_traces.find({}, {"_id": 0}).to_list(1000)
    summaries = []
    for trace in traces:
        s1 = trace.get("stage_1_classifier")
        s2 = trace.get("stage_2_escalation")
        summaries.append({
            "job_id": trace.get("job_id"),
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
    logger.info(f"Alert webhook received: {raw_body}")
    return {"status": "verified"}


# ---- Load persisted automation mode ----

@app.on_event("startup")
async def load_automation_mode():
    """Load the persisted automation mode from MongoDB on startup."""
    saved_mode = await db.automation_config.find_one({"_id": "mode"})
    if saved_mode is not None:
        set_dry_run(saved_mode.get("dry_run", True))
        logger.info(f"Loaded automation mode from DB: {'dry_run' if get_dry_run() else 'live'}")


# ---- Seed Data ----

@app.on_event("startup")
async def seed_data():
    """Seed existing eval_results.json into MongoDB if collections are empty."""
    count = await db.eval_jobs.count_documents({})
    if count > 0:
        return

    seed_file = ROOT_DIR / "eval_results_seed.json"
    if not seed_file.exists():
        return

    try:
        data = json.loads(seed_file.read_text())
        config = data.get("config", {})
        await db.eval_config.update_one({"_id": "global"}, {"$set": config}, upsert=True)

        jobs = data.get("jobs", {})
        if jobs:
            docs = []
            for key, job in jobs.items():
                job["eval_key"] = key
                docs.append(job)
            if docs:
                await db.eval_jobs.insert_many(docs)
                logger.info(f"Seeded {len(docs)} eval jobs into MongoDB")
    except Exception as e:
        logger.error(f"Failed to seed data: {e}")


@app.on_event("startup")
async def start_bq_sync():
    """Start the BigQuery → MongoDB background sync loop."""
    asyncio.create_task(bq_sync_loop())


@app.on_event("startup")
async def start_external_signals_poller():
    """Start the external signals poller (polls BQ every 5 min for pending takedowns)."""
    asyncio.create_task(external_signals_poller())


@app.on_event("startup")
async def start_opus_poller():
    """Start the Opus agent review poller (polls every 60s for pending_opus_review jobs)."""
    if os.environ.get("ANTHROPIC_API_KEY"):
        from opus_poller import opus_review_poller
        asyncio.create_task(opus_review_poller(db, resolve_fork_chain_fn=resolve_fork_chain))
        logger.info("Opus review poller registered")
    else:
        logger.warning("ANTHROPIC_API_KEY not set — Opus poller disabled, T1/T2/T3 jobs will stay pending_opus_review")


@app.on_event("startup")
async def start_pipeline_health_monitor():
    """Start the hourly pipeline health monitor."""
    asyncio.create_task(pipeline_health_loop(bq_client, db))




# ---- Mount Router ----

app.include_router(api_router)

app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get("CORS_ORIGINS", "*").split(","),
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("shutdown")
async def shutdown_db_client():
    mongo_client.close()
