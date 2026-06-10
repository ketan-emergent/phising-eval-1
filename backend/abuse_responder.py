"""
Cloudflare Abuse Report Responder — Webhook approach.

Exposes POST /api/abuse/lookup endpoint that the dig bot calls with a reported URL.
Looks up the URL via Redash query 32448 and replies in the Slack thread via daily_update bot.
"""

import os
import re
import logging
import time
import httpx

logger = logging.getLogger(__name__)

SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
REDASH_URL = os.environ.get("REDASH_URL")
REDASH_API_KEY = os.environ.get("REDASH_API_KEY")
REDASH_QUERY_ID = 32448
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "https://phishing-eval.internal.emergent.host")

_DOMAIN_RE = re.compile(r'([a-zA-Z0-9\-]+\.emergent\.host)', re.IGNORECASE)


def extract_domains(text):
    """Extract emergent.host domains from text."""
    return list(set(m.group(1).lower().rstrip("/") for m in _DOMAIN_RE.finditer(text)))


def lookup_url_via_redash(domain):
    """Run Redash query 32448 to look up a domain. Returns list of rows."""
    if not REDASH_URL or not REDASH_API_KEY:
        logger.warning("Redash not configured")
        return None

    try:
        resp = httpx.post(
            f"{REDASH_URL}/api/queries/{REDASH_QUERY_ID}/results",
            headers={"Authorization": f"Key {REDASH_API_KEY}", "Content-Type": "application/json"},
            json={"parameters": {"url": domain}, "max_age": 0},
            timeout=30,
        )

        if resp.status_code == 200:
            data = resp.json()
            # max_age: 0 may return a job to poll even with 200
            if "job" in data:
                job_id = data["job"].get("id")
            else:
                return data.get("query_result", {}).get("data", {}).get("rows", [])
        else:
            job_id = resp.json().get("job", {}).get("id")

        # Async query — poll for results
        if not job_id:
            logger.error(f"Redash failed: {resp.status_code} {resp.text[:200]}")
            return None

        for _ in range(15):
            time.sleep(2)
            r = httpx.get(
                f"{REDASH_URL}/api/jobs/{job_id}",
                headers={"Authorization": f"Key {REDASH_API_KEY}"},
                timeout=15,
            )
            jdata = r.json().get("job", {})
            if jdata.get("status") == 3:
                qr_id = jdata.get("query_result_id")
                r2 = httpx.get(
                    f"{REDASH_URL}/api/query_results/{qr_id}",
                    headers={"Authorization": f"Key {REDASH_API_KEY}"},
                    timeout=15,
                )
                return r2.json().get("query_result", {}).get("data", {}).get("rows", [])
            elif jdata.get("status") == 4:
                logger.error(f"Redash error: {jdata.get('error')}")
                return None

        logger.error("Redash query timed out")
        return None

    except Exception as e:
        logger.error(f"Redash lookup failed for {domain}: {e}")
        return None


def build_reply(domain, rows):
    """Build Slack reply blocks from Redash results."""
    if not rows:
        return {
            "text": f"{domain} — NOT FOUND",
            "blocks": [
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*{domain}*\n:white_circle: *NOT FOUND* — No matching job found in our pipeline."}},
                {"type": "context", "elements": [{"type": "mrkdwn", "text": "Phishing Eval Auto-Lookup"}]},
            ],
        }

    # Deduplicate by job_id
    seen = {}
    for r in rows:
        jid = r.get("job_id")
        if jid not in seen:
            seen[jid] = r

    blocks = []
    text_parts = []

    for job_id, r in seen.items():
        verdict = r.get("takedown_verdict", "").strip()
        user_id = r.get("user_id", "—")
        ltv = r.get("user_ltv", 0) or 0
        label = r.get("classification_label", "—") or "—"
        action = r.get("pipeline_action", "—") or "—"
        taken_down_by = r.get("taken_down_by", "—") or "—"
        takedown_at = r.get("takedown_at", "—") or "—"
        subdomain = r.get("dynamic_preview_subdomain", "—") or "—"

        if "TAKEN DOWN" in verdict:
            status_line = ":red_circle: *TAKEN DOWN*"
            if taken_down_by != "—":
                status_line += f" (by `{taken_down_by}`)"
            if takedown_at != "—":
                status_line += f"\nTaken down at: {str(takedown_at)[:19]}"
        elif "FLAGGED" in verdict:
            status_line = f":large_orange_circle: *CONFIRMED MALICIOUS — pending takedown*\nLabel: `{label}`"
        elif "CLEARED" in verdict:
            status_line = ":large_green_circle: *CLEARED BY CLASSIFIER*"
        elif "EXECUTED" in verdict:
            status_line = f":yellow_circle: *ACTION EXECUTED*\nPipeline action: `{action}`"
        else:
            status_line = ":white_circle: *NEEDS REVIEW* — Not yet evaluated by pipeline"

        ltv_str = f"${ltv:,.0f}" if ltv else "Free"
        text_parts.append(f"{domain} → {verdict}")

        blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": f"*{domain}*\n{status_line}"}})
        blocks.append({"type": "section", "fields": [
            {"type": "mrkdwn", "text": f"*Job ID:*\n`{job_id}`"},
            {"type": "mrkdwn", "text": f"*User ID:*\n`{user_id}`"},
            {"type": "mrkdwn", "text": f"*User LTV:*\n{ltv_str}"},
            {"type": "mrkdwn", "text": f"*Subdomain:*\n{subdomain}"},
        ]})

    blocks.append({"type": "actions", "elements": [
        {"type": "button", "text": {"type": "plain_text", "text": ":mag: Open Dashboard", "emoji": True}, "url": DASHBOARD_URL},
    ]})
    blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": "Phishing Eval Auto-Lookup"}]})

    return {"text": "; ".join(text_parts), "blocks": blocks}


def reply_in_thread(channel, thread_ts, message):
    """Post a reply in a Slack thread using daily_update bot."""
    if not SLACK_BOT_TOKEN:
        logger.warning("No SLACK_BOT_TOKEN, skipping reply")
        return False

    try:
        resp = httpx.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}", "Content-Type": "application/json"},
            json={
                "channel": channel,
                "thread_ts": thread_ts,
                "text": message["text"],
                "blocks": message["blocks"],
            },
            timeout=10,
        )
        ok = resp.json().get("ok")
        if ok:
            logger.info(f"Abuse lookup reply sent in thread {thread_ts}")
        else:
            logger.error(f"Slack reply failed: {resp.json().get('error')}")
        return ok
    except Exception as e:
        logger.error(f"Slack reply error: {e}")
        return False
