"""
Pipeline Health Monitor — Hourly BQ funnel check + Slack alerts.

Runs every hour, queries the phishing pipeline funnel from BigQuery,
and sends alerts to Slack when any stage is down or degraded.

Alert conditions:
  1. No jobs at all in the last 2 hours
  2. Stage 1 stopped (phishing classifier not running)
  3. Stage 2 stopped (escalation agent not running)
  4. MCP error rate > 50%

Also sends recovery alerts when a previously-down stage comes back.
"""

import os
import asyncio
import logging
import httpx
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
HEALTH_ALERT_CHANNEL = "C0AVAPXB4QP"  # #phishing-eval-down-alert
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "https://phishing-eval.internal.emergent.host")
CHECK_INTERVAL = 60 * 60  # 1 hour

# Default state — used as fallback when MongoDB has no record
_DEFAULT_STATE = {
    "no_jobs": False,
    "s1_down": False,
    "s2_down": False,
    "mcp_spike": False,
    "phishing_rate_spike": False,
    "s2_lag": False,
    "zero_malicious": False,
    "legit_spike": False,
    "volume_drop": False,
}


async def _load_state(db):
    """Load alert state from MongoDB (survives container restarts)."""
    doc = await db.pipeline_health_state.find_one({"_id": "alert_state"})
    if doc:
        doc.pop("_id", None)
        doc.pop("updated_at", None)
        return doc
    return dict(_DEFAULT_STATE)


async def _save_state(db, state):
    """Persist alert state to MongoDB."""
    await db.pipeline_health_state.update_one(
        {"_id": "alert_state"},
        {"$set": {**state, "updated_at": datetime.now(timezone.utc).isoformat()}},
        upsert=True,
    )

FUNNEL_QUERY = """
WITH hourly_jobs AS (
  SELECT
    TIMESTAMP_TRUNC(created_at, HOUR) AS hour,
    id AS job_id
  FROM `analytics.jobs_full_view`
  WHERE created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 3 HOUR)
),
phishing_jobs AS (
  SELECT DISTINCT job_id
  FROM `hitl.PhishingClassification`
  WHERE is_phishing = true AND severity IN ('critical', 'high')
),
escalation_jobs AS (
  SELECT
    job_id,
    classification_label,
    (COALESCE(agent_trajectory_success, true) = false
     OR COALESCE(hitl_interactions_success, true) = false
     OR COALESCE(job_details_success, true) = false
     OR COALESCE(agent_trajectory_called, true) = false
     OR COALESCE(hitl_interactions_called, true) = false
     OR COALESCE(job_details_called, true) = false
    ) AS has_mcp_error
  FROM `phishing_eval.escalation_agent`
  QUALIFY ROW_NUMBER() OVER (PARTITION BY job_id ORDER BY emitted_at DESC) = 1
),
funnel AS (
  SELECT
    hj.hour,
    COUNT(DISTINCT hj.job_id) AS total_jobs,
    COUNT(DISTINCT CASE WHEN pj.job_id IS NOT NULL THEN hj.job_id END) AS s1_in_phishing,
    COUNT(DISTINCT CASE WHEN ej.job_id IS NOT NULL THEN hj.job_id END) AS s2_in_escalation,
    COUNT(DISTINCT CASE WHEN ej.job_id IS NOT NULL AND ej.has_mcp_error THEN hj.job_id END) AS s3_mcp_errored,
    COUNT(DISTINCT CASE WHEN ej.job_id IS NOT NULL AND NOT ej.has_mcp_error
      AND ej.classification_label = 'CONFIRMED_MALICIOUS' THEN hj.job_id END) AS s4_malicious,
    COUNT(DISTINCT CASE WHEN ej.job_id IS NOT NULL AND NOT ej.has_mcp_error
      AND ej.classification_label = 'NEEDS_HUMAN_REVIEW' THEN hj.job_id END) AS s4_review,
    COUNT(DISTINCT CASE WHEN ej.job_id IS NOT NULL AND NOT ej.has_mcp_error
      AND ej.classification_label = 'LEGITIMATE' THEN hj.job_id END) AS s4_legit
  FROM hourly_jobs hj
  LEFT JOIN phishing_jobs pj ON hj.job_id = pj.job_id
  LEFT JOIN escalation_jobs ej ON hj.job_id = ej.job_id
  GROUP BY 1
)
SELECT * FROM funnel ORDER BY hour DESC LIMIT 3
"""

MCP_ERROR_THRESHOLD = 0.5  # 50%

PAID_USER_RISK_QUERY = """
WITH paid_users AS (
  SELECT DISTINCT user_id
  FROM `analytics.user_revenue_events`
  WHERE mode = 'subscription'
),
paid_jobs AS (
  SELECT j.id, DATE(j.created_at) AS day
  FROM `analytics.jobs_full_view` j
  JOIN paid_users p ON p.user_id = j.user_id
  WHERE j.created_at >= TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 3 HOUR)
),
jm_flags AS (
  SELECT root_job_id,
         MAX(CASE WHEN phishing_status = 'RISKY' THEN 1 ELSE 0 END) AS is_risky,
         MAX(CASE WHEN is_suspended = TRUE THEN 1 ELSE 0 END) AS is_suspended
  FROM EXTERNAL_QUERY(
    "emergent-default.us-central1.agent_service_psql_connection",
    "SELECT root_job_id, phishing_status, is_suspended FROM job_metadata WHERE created_at >= NOW() - INTERVAL '1 day' AND root_job_id IS NOT NULL AND (phishing_status = 'RISKY' OR is_suspended = true)"
  )
  GROUP BY 1
)
SELECT
  COUNT(DISTINCT pj.id) AS total_paid_jobs,
  COUNT(DISTINCT CASE WHEN jm.is_risky = 1 THEN pj.id END) AS risky_jobs,
  ROUND(100.0 * COUNT(DISTINCT CASE WHEN jm.is_risky = 1 THEN pj.id END) / NULLIF(COUNT(DISTINCT pj.id), 0), 2) AS pct_risky,
  COUNT(DISTINCT CASE WHEN jm.is_suspended = 1 THEN pj.id END) AS suspended_jobs,
  ROUND(100.0 * COUNT(DISTINCT CASE WHEN jm.is_suspended = 1 THEN pj.id END) / NULLIF(COUNT(DISTINCT pj.id), 0), 2) AS pct_suspended
FROM paid_jobs pj
LEFT JOIN jm_flags jm ON jm.root_job_id = pj.id
"""


def _send_slack_alert(text, blocks):
    """Send alert to the phishing-eval-down-alert channel."""
    if not SLACK_BOT_TOKEN:
        logger.warning("SLACK_BOT_TOKEN not set, skipping health alert")
        return
    try:
        resp = httpx.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}", "Content-Type": "application/json"},
            json={"channel": HEALTH_ALERT_CHANNEL, "text": text, "blocks": blocks},
            timeout=10,
        )
        if resp.status_code == 200 and resp.json().get("ok"):
            logger.info(f"Health alert sent: {text}")
        else:
            logger.error(f"Slack health alert failed: {resp.text[:200]}")
    except Exception as e:
        logger.error(f"Slack health alert error: {e}")


ALERT_TAG_USER = "<@U0AS94DGH8T>"  # Tagged on critical alerts


def _alert_down(issue, details, stats, critical=True):
    """Send a DOWN alert. Tags user on critical issues only."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    tag = f"\n\ncc {ALERT_TAG_USER}" if critical else ""
    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": ":rotating_light: PIPELINE DOWN", "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{issue}*\n{details}{tag}"}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Total Jobs (last 2-3h):*\n{stats.get('total_jobs', 0):,}"},
            {"type": "mrkdwn", "text": f"*% Risky (Paid):*\n{stats.get('pct_risky', '—')}%"},
            {"type": "mrkdwn", "text": f"*S1 Phishing:*\n{stats.get('s1_in_phishing', 0)}"},
            {"type": "mrkdwn", "text": f"*% Suspended (Paid):*\n{stats.get('pct_suspended', '—')}%"},
            {"type": "mrkdwn", "text": f"*MCP Errors:*\n{stats.get('s3_mcp_errored', 0)} ({stats.get('mcp_error_rate', '—')})"},
            {"type": "mrkdwn", "text": f"*Malicious:*\n{stats.get('s4_malicious', 0)}"},
        ]},
        {"type": "actions", "elements": [
            {"type": "button", "text": {"type": "plain_text", "text": ":mag: Open Dashboard", "emoji": True},
             "url": DASHBOARD_URL, "style": "danger"},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Pipeline Health Monitor | {now} | {'CRITICAL' if critical else 'MEDIUM'}"}]},
    ]
    _send_slack_alert(f"PIPELINE DOWN: {issue}", blocks)


def _alert_recovery(issue, stats):
    """Send a RECOVERY alert with full health report."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    total = stats.get("total_jobs", 0)
    s1 = stats.get("s1_in_phishing", 0)
    s2 = stats.get("s2_in_escalation", 0)
    mcp = stats.get("s3_mcp_errored", 0)
    mal = stats.get("s4_malicious", 0)
    rev = stats.get("s4_review", 0)
    leg = stats.get("s4_legit", 0)
    s2_tp = f"{s2/s1*100:.0f}%" if s1 > 0 else "—"

    blocks = [
        {"type": "header", "text": {"type": "plain_text", "text": ":white_check_mark: PIPELINE RECOVERED", "emoji": True}},
        {"type": "section", "text": {"type": "mrkdwn", "text": f"*{issue}*\nPipeline is back to normal."}},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Total Jobs (last 2-3h):*\n{total:,}"},
            {"type": "mrkdwn", "text": f"*% Risky (Paid):*\n{stats.get('pct_risky', '—')}%"},
            {"type": "mrkdwn", "text": f"*S1 Flagged:*\n{s1}"},
            {"type": "mrkdwn", "text": f"*% Suspended (Paid):*\n{stats.get('pct_suspended', '—')}%"},
            {"type": "mrkdwn", "text": f"*MCP Errors:*\n{mcp} ({stats.get('mcp_error_rate', '—')})"},
            {"type": "mrkdwn", "text": f"*Malicious:*\n{mal}"},
        ]},
        {"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Needs Review:*\n{rev}"},
            {"type": "mrkdwn", "text": f"*Legitimate:*\n{leg}"},
        ]},
        {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Pipeline Health Monitor | {now}"}]},
    ]
    _send_slack_alert(f"PIPELINE RECOVERED: {issue}", blocks)


async def check_pipeline_health(bq_client, db):
    """Run the funnel query and check for issues. Returns dict of current state."""
    if not bq_client:
        logger.warning("Pipeline health check skipped: no BQ client")
        return

    try:
        rows = await asyncio.to_thread(lambda: [dict(r) for r in bq_client.query(FUNNEL_QUERY).result()])
    except Exception as e:
        logger.error(f"Pipeline health BQ query failed: {e}")
        return

    if not rows:
        logger.warning("Pipeline health: no funnel data returned")
        return

    # Aggregate last 2-3 hours
    total_jobs = sum(r.get("total_jobs", 0) for r in rows)
    s1 = sum(r.get("s1_in_phishing", 0) for r in rows)
    s2 = sum(r.get("s2_in_escalation", 0) for r in rows)
    mcp_err = sum(r.get("s3_mcp_errored", 0) for r in rows)
    malicious = sum(r.get("s4_malicious", 0) for r in rows)
    review = sum(r.get("s4_review", 0) for r in rows)
    legit = sum(r.get("s4_legit", 0) for r in rows)

    stats = {
        "total_jobs": total_jobs,
        "s1_in_phishing": s1,
        "s2_in_escalation": s2,
        "s3_mcp_errored": mcp_err,
        "s4_malicious": malicious,
        "s4_review": review,
        "s4_legit": legit,
    }

    mcp_rate = mcp_err / s2 if s2 > 0 else 0
    phishing_rate = (s1 / total_jobs * 100) if total_jobs > 0 else 0

    # Fetch paid user risky/suspended stats
    pct_risky = 0
    pct_suspended = 0
    try:
        risk_rows = await asyncio.to_thread(lambda: [dict(r) for r in bq_client.query(PAID_USER_RISK_QUERY).result()])
        if risk_rows:
            pct_risky = risk_rows[0].get("pct_risky", 0) or 0
            pct_suspended = risk_rows[0].get("pct_suspended", 0) or 0
    except Exception as e:
        logger.error(f"Paid user risk query failed (non-fatal): {e}")

    stats = {
        "total_jobs": total_jobs,
        "s1_in_phishing": s1,
        "s2_in_escalation": s2,
        "s3_mcp_errored": mcp_err,
        "s4_malicious": malicious,
        "s4_review": review,
        "s4_legit": legit,
        "mcp_error_rate": f"{mcp_rate:.0%}",
        "phishing_rate": f"{phishing_rate:.1f}",
        "pct_risky": f"{pct_risky:.2f}",
        "pct_suspended": f"{pct_suspended:.2f}",
    }

    logger.info(f"Pipeline health: jobs={total_jobs} s1={s1}({phishing_rate:.1f}%) s2={s2} mcp_err={mcp_err}({mcp_rate:.0%}) mal={malicious} rev={review} leg={legit}")

    # Load persisted state from MongoDB (survives container restarts)
    prev = await _load_state(db)

    # 1. Low/no jobs — fewer than 500 in last 2-3 hours means pipeline is stalled
    is_no_jobs = total_jobs < 500
    if is_no_jobs and not prev["no_jobs"]:
        _alert_down("Job Pipeline Stalled", f"Only {total_jobs} jobs in the last 2-3 hours (expected 2,000+). The pipeline appears to have stopped or severely degraded.", stats)
    elif not is_no_jobs and prev["no_jobs"]:
        _alert_recovery("Job pipeline resumed", stats)
    prev["no_jobs"] = is_no_jobs

    # 2. Stage 1 down — jobs exist but none flagged as phishing (need enough jobs to be meaningful)
    is_s1_down = total_jobs > 500 and s1 == 0
    if is_s1_down and not prev["s1_down"]:
        _alert_down("Stage 1 — Phishing Classifier DOWN", f"Jobs are being created ({total_jobs} in last 2-3h) but zero are being flagged by the phishing classifier.", stats)
    elif not is_s1_down and prev["s1_down"]:
        _alert_recovery("Stage 1 — Phishing Classifier resumed", stats)
    prev["s1_down"] = is_s1_down

    # 3. Stage 2 down — phishing flagged but none reaching escalation (need >=10 S1 flags)
    is_s2_down = s1 >= 10 and s2 == 0
    if is_s2_down and not prev["s2_down"]:
        _alert_down("Stage 2 — Escalation Agent DOWN", f"Phishing classifier flagged {s1} jobs but none reached the escalation agent.", stats)
    elif not is_s2_down and prev["s2_down"]:
        _alert_recovery("Stage 2 — Escalation Agent resumed", stats)
    prev["s2_down"] = is_s2_down

    # 4. MCP error spike — >50% of escalated jobs have MCP errors
    is_mcp_spike = s2 > 10 and mcp_rate > MCP_ERROR_THRESHOLD
    if is_mcp_spike and not prev["mcp_spike"]:
        _alert_down("MCP Error Rate Spike", f"MCP error rate is {mcp_rate:.0%} ({mcp_err}/{s2} jobs). Tool calls are failing at a high rate.", stats)
    elif not is_mcp_spike and prev["mcp_spike"]:
        _alert_recovery(f"MCP Error Rate normalized ({mcp_rate:.0%})", stats)
    prev["mcp_spike"] = is_mcp_spike

    # 5. Phishing rate spike — classifier flagging >=85% of all jobs (normal is 1-3%)
    is_phishing_spike = s1 >= 10 and phishing_rate >= 85
    if is_phishing_spike and not prev["phishing_rate_spike"]:
        _alert_down("Phishing Classifier Over-Flagging",
            f"Phishing rate is {phishing_rate:.1f}% — {s1} out of {total_jobs} jobs flagged as phishing (normal: 1-3%). The classifier may be malfunctioning.", stats)
    elif not is_phishing_spike and prev["phishing_rate_spike"]:
        _alert_recovery(f"Phishing rate normalized ({phishing_rate:.1f}%)", stats)
    prev["phishing_rate_spike"] = is_phishing_spike

    # 6. S2 Escalation Lag — escalation processing < 50% of flagged jobs
    s2_ratio = s2 / s1 if s1 > 0 else 1.0
    is_s2_lag = s1 >= 20 and s2_ratio < 0.5
    if is_s2_lag and not prev["s2_lag"]:
        _alert_down("Stage 2 — Escalation Lag",
            f"S2 only processed {s2} of {s1} flagged jobs ({s2_ratio:.0%}). Escalation agent is falling behind.", stats)
    elif not is_s2_lag and prev["s2_lag"]:
        _alert_recovery(f"Escalation lag resolved ({s2_ratio:.0%} throughput)", stats)
    prev["s2_lag"] = is_s2_lag

    # 7. Zero malicious with sufficient volume — classification model may be broken
    is_zero_mal = s2 > 30 and malicious == 0
    if is_zero_mal and not prev["zero_malicious"]:
        _alert_down("Zero Malicious Detected",
            f"{s2} jobs escalated but 0 classified as malicious. The classification model may be broken or misconfigured.", stats)
    elif not is_zero_mal and prev["zero_malicious"]:
        _alert_recovery(f"Malicious detection resumed ({malicious} detected)", stats)
    prev["zero_malicious"] = is_zero_mal

    # 8. Legitimate rate spike — >95% legitimate suggests rubber-stamping (MEDIUM)
    legit_rate = legit / s2 if s2 > 0 else 0
    is_legit_spike = s2 > 30 and legit_rate > 0.95
    if is_legit_spike and not prev["legit_spike"]:
        _alert_down("Legitimate Rate Spike",
            f"{legit_rate:.0%} of escalated jobs classified as LEGITIMATE ({legit}/{s2}). Model may be rubber-stamping everything.", stats, critical=False)
    elif not is_legit_spike and prev["legit_spike"]:
        _alert_recovery(f"Legitimate rate normalized ({legit_rate:.0%})", stats)
    prev["legit_spike"] = is_legit_spike

    # 9. Hour-over-hour volume drop >70% — sudden pipeline interruption (MEDIUM)
    if len(rows) >= 2:
        latest_hour = rows[0].get("total_jobs", 0)
        prev_hour = rows[1].get("total_jobs", 0)
        drop_pct = 1 - (latest_hour / prev_hour) if prev_hour > 0 else 0
        is_volume_drop = prev_hour > 1000 and drop_pct > 0.7
        if is_volume_drop and not prev.get("volume_drop", False):
            _alert_down("Sudden Volume Drop",
                f"Latest hour: {latest_hour} jobs vs previous hour: {prev_hour} jobs ({drop_pct:.0%} drop). Possible pipeline interruption.", stats, critical=False)
        elif not is_volume_drop and prev.get("volume_drop", False):
            _alert_recovery(f"Volume recovered (latest hour: {latest_hour} jobs)", stats)
        prev["volume_drop"] = is_volume_drop

    # Persist state to MongoDB
    await _save_state(db, prev)

    return stats


async def pipeline_health_loop(bq_client, db):
    """Background loop — checks pipeline health every hour."""
    await asyncio.sleep(30)  # Wait for app startup
    logger.info(f"Pipeline health monitor started (every {CHECK_INTERVAL // 60} min, channel: {HEALTH_ALERT_CHANNEL})")
    while True:
        try:
            await check_pipeline_health(bq_client, db)
        except Exception as e:
            logger.error(f"Pipeline health check failed: {e}")
        await asyncio.sleep(CHECK_INTERVAL)
