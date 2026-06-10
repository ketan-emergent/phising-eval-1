"""
Opus Review Poller — Background task that picks up pending_opus_review jobs,
runs the Opus classifier, and executes enforcement based on the verdict.

Started as an asyncio.create_task() on app startup, same pattern as
bq_sync_loop and external_signals_poller.
"""

import asyncio
import logging
from datetime import datetime, timezone, timedelta

from opus_agent import run_classifier
from automation import (
    auto_takedown_job,
    check_exclusion_match,
    get_dry_run,
    _record_takedown_in_mongo,
    _slack_notify,
)

logger = logging.getLogger(__name__)

OPUS_POLL_INTERVAL = 60  # seconds
OPUS_STALE_THRESHOLD = timedelta(minutes=10)


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


async def opus_review_poller(db, resolve_fork_chain_fn=None):
    """Background loop: pick up pending_opus_review jobs, run Opus, execute actions."""
    await asyncio.sleep(45)  # Wait for app startup + first sync
    logger.info("Opus review poller started (every 60s)")

    while True:
        try:
            # Reset stale in-progress jobs first
            await _reset_stale_jobs(db)
            # Process one pending job
            await _process_next_pending_job(db, resolve_fork_chain_fn)
        except Exception as e:
            logger.error(f"Opus poller error: {e}")
        await asyncio.sleep(OPUS_POLL_INTERVAL)


async def _reset_stale_jobs(db):
    """Reset jobs stuck in opus_in_progress for too long."""
    dry_run = get_dry_run()
    cutoff = (datetime.now(timezone.utc) - OPUS_STALE_THRESHOLD).isoformat()

    result = await db.automated_actions.update_many(
        {
            "status": "opus_in_progress",
            "dry_run": dry_run,
            "opus_started_at": {"$lt": cutoff},
        },
        {"$set": {"status": "pending_opus_review"}, "$unset": {"opus_started_at": ""}},
    )
    if result.modified_count > 0:
        logger.warning(f"Reset {result.modified_count} stale opus_in_progress jobs")


async def _process_next_pending_job(db, resolve_fork_chain_fn=None):
    """Pick one pending_opus_review job (FIFO), run Opus, execute action."""
    dry_run = get_dry_run()

    pending = await db.automated_actions.find_one(
        {"status": "pending_opus_review", "dry_run": dry_run},
        sort=[("created_at", 1)],
    )
    if not pending:
        return

    job_id = pending["job_id"]
    tier = pending["tier"]
    now = _now_iso()

    # Mark as in-progress
    await db.automated_actions.update_one(
        {"job_id": job_id, "dry_run": dry_run},
        {"$set": {"status": "opus_in_progress", "opus_started_at": now}},
    )

    # Fetch full job data
    job = await db.bq_jobs.find_one({"job_id": job_id})
    if not job:
        logger.error(f"Opus poller: job {job_id} not found in bq_jobs")
        await db.automated_actions.update_one(
            {"job_id": job_id, "dry_run": dry_run},
            {"$set": {"status": "failed", "error": "job not found in bq_jobs"}},
        )
        return

    # Run Opus classifier
    try:
        verdict = await run_classifier(job_id)
    except Exception as e:
        logger.error(f"Opus classifier failed for {job_id}: {e}")
        verdict = {
            "label": "NEEDS_HUMAN_REVIEW",
            "error": str(e),
            "fallback": True,
            "recommended_action": "human_review",
        }

    # Store full verdict in opus_verdicts
    await db.opus_verdicts.update_one(
        {"job_id": job_id, "dry_run": dry_run},
        {"$set": {
            "job_id": job_id,
            "user_id": job.get("user_id"),
            "s2_tier": tier,
            "s2_label": job.get("classification_label"),
            "opus_label": verdict.get("label"),
            "opus_confidence": verdict.get("confidence"),
            "opus_severity": verdict.get("severity"),
            "opus_recommended_action": verdict.get("recommended_action"),
            "opus_verdict_summary": verdict.get("verdict_summary"),
            "opus_key_evidence": verdict.get("key_evidence"),
            "opus_policy_violated": verdict.get("cloudflare_policy_violated"),
            "opus_flagged_policies": verdict.get("flagged_policies"),
            "opus_false_positive_checks": verdict.get("false_positive_checks_passed"),
            "opus_tools_called": verdict.get("tools_called"),
            "opus_turns_used": verdict.get("turns_used"),
            "opus_duration_s": verdict.get("duration_s"),
            "opus_raw_output": verdict.get("raw_output", "")[:5000],
            "opus_error": verdict.get("error"),
            "opus_fallback": verdict.get("fallback", False),
            "dry_run": dry_run,
            "reviewed_at": now,
        }},
        upsert=True,
    )

    # Denormalize opus_label into bq_jobs for fast filtering
    await db.bq_jobs.update_one(
        {"job_id": job_id},
        {"$set": {"opus_label": verdict.get("label"), "opus_reviewed_at": now}},
    )

    # Execute enforcement based on verdict
    await _execute_opus_verdict(db, job, pending, verdict, dry_run, resolve_fork_chain_fn)


async def _execute_opus_verdict(db, job, action_doc, verdict, dry_run, resolve_fork_chain_fn):
    """
    Execute action based on Opus verdict. Only 3 paths:
      CONFIRMED_MALICIOUS → execute takedown + send RudderStack email
      NEEDS_HUMAN_REVIEW  → update UI only
      LEGITIMATE          → update UI only
    """
    job_id = job["job_id"]
    user_id = job.get("user_id")
    tier = action_doc["tier"]
    opus_label = verdict.get("label", "")
    now = _now_iso()

    # Re-check exclusion list
    excl_or = [{"job_id": job_id, "active": True}]
    if user_id:
        excl_or.append({"user_id": user_id, "active": True})
    excl_or.append({"pattern": {"$exists": True, "$ne": ""}, "active": True})
    exclusions = await db.exclusion_list.find({"$or": excl_or}).to_list(500)
    task_text = job.get("task", "") or ""
    if check_exclusion_match(job_id, user_id, exclusions, task=task_text):
        await db.automated_actions.update_one(
            {"job_id": job_id, "dry_run": dry_run},
            {"$set": {
                "status": "skipped", "action": "skipped_excluded",
                "opus_label": opus_label, "opus_reviewed_at": now,
            }},
        )
        logger.info(f"Opus [{job_id}]: excluded after Opus review")
        return

    if opus_label == "CONFIRMED_MALICIOUS":
        # Execute takedown immediately + send RudderStack notification email
        await _execute_takedown(db, job, tier, dry_run, resolve_fork_chain_fn, verdict)

    elif opus_label == "NEEDS_HUMAN_REVIEW":
        # Update UI only — no enforcement, no email
        await db.automated_actions.update_one(
            {"job_id": job_id, "dry_run": dry_run},
            {"$set": {
                "action": "human_review",
                "status": "completed",
                "opus_label": opus_label,
                "opus_reviewed_at": now,
                "opus_verdict_summary": verdict.get("verdict_summary", ""),
            }},
        )
        _slack_notify(3, job_id, user_id, job.get("classification_category", ""),
                      job.get("classification_label", ""),
                      extra_fields={"plan_type": job.get("plan_type"), "ltv": job.get("ltv")},
                      dry_run=dry_run)
        logger.info(f"Opus [{job_id}]: NEEDS_HUMAN_REVIEW — awaiting human decision")

    elif opus_label == "LEGITIMATE":
        # Update UI only — no enforcement, no email
        await db.automated_actions.update_one(
            {"job_id": job_id, "dry_run": dry_run},
            {"$set": {
                "status": "completed",
                "action": "legitimate",
                "opus_label": opus_label,
                "opus_overridden": True,
                "opus_reviewed_at": now,
                "opus_verdict_summary": verdict.get("verdict_summary", ""),
            }},
        )
        logger.info(f"Opus [{job_id}]: LEGITIMATE — no action taken")

    else:
        # Unknown label — treat as needs review
        await db.automated_actions.update_one(
            {"job_id": job_id, "dry_run": dry_run},
            {"$set": {
                "action": "human_review",
                "status": "completed",
                "opus_label": opus_label or "UNKNOWN",
                "opus_reviewed_at": now,
            }},
        )
        logger.warning(f"Opus [{job_id}]: unknown label '{opus_label}' — routed to human review")


async def _execute_takedown(db, job, tier, dry_run, resolve_fork_chain_fn, verdict):
    """
    CONFIRMED_MALICIOUS: execute takedown immediately + send RudderStack email.
    Policies come from Opus verdict (not S2 classification_category).
    """
    job_id = job["job_id"]
    user_id = job.get("user_id")
    email = job.get("user_email")
    now = _now_iso()

    # Build reason from Opus flagged_policies
    opus_policies = verdict.get("flagged_policies") or []
    policies_str = " + ".join(p.replace("_", " ").title() for p in opus_policies if p != "NONE")
    reason = f"Opus-confirmed takedown: {policies_str or 'CONFIRMED_MALICIOUS'}"

    # Resolve fork chain
    chain = [job_id]
    if resolve_fork_chain_fn:
        try:
            chain = await asyncio.get_event_loop().run_in_executor(None, resolve_fork_chain_fn, job_id)
            if len(chain) > 1:
                logger.info(f"Opus takedown: expanded {job_id} to {len(chain)} jobs via fork chain")
        except Exception as e:
            logger.error(f"Fork chain resolution failed for {job_id}: {e}")
            chain = [job_id]

    # Execute disable API for each job in chain
    chain_results = {}
    for chain_jid in chain:
        try:
            result = await auto_takedown_job(chain_jid, reason, dry_run=dry_run)
            chain_results[chain_jid] = {"status": "ok", "api_result": result}
            if not result.get("dry_run"):
                chain_job = job if chain_jid == job_id else (await db.bq_jobs.find_one({"job_id": chain_jid}) or {"job_id": chain_jid})
                await _record_takedown_in_mongo(db, chain_job, reason, result)
        except Exception as e:
            logger.error(f"Opus takedown failed for chain job {chain_jid}: {e}")
            chain_results[chain_jid] = {"status": "failed", "error": str(e)}

    ok_count = sum(1 for r in chain_results.values() if r["status"] == "ok")
    fail_count = len(chain_results) - ok_count
    status = "completed" if fail_count == 0 else "failed"

    # Update automated_actions
    await db.automated_actions.update_one(
        {"job_id": job_id, "dry_run": dry_run},
        {"$set": {
            "action": "auto_takedown",
            "status": status,
            "executed_at": now,
            "opus_label": verdict.get("label"),
            "opus_reviewed_at": now,
            "opus_verdict_summary": verdict.get("verdict_summary", ""),
            "metadata": {
                "api_result": chain_results.get(job_id, {}).get("api_result"),
                "fork_chain": chain,
                "chain_results_summary": {"ok": ok_count, "failed": fail_count},
            },
        }},
    )

    # Send RudderStack takedown notification email (using Opus verdict data)
    _send_opus_takedown_email(user_id, email, job, verdict, dry_run)

    # Slack notification
    _user_info = {"plan_type": job.get("plan_type"), "ltv": job.get("ltv")}
    _slack_notify(1, job_id, user_id, policies_str,
                  "CONFIRMED_MALICIOUS", status=status,
                  extra_fields=_user_info, dry_run=dry_run)
    logger.info(f"Opus [{job_id}]: takedown {status} (chain={len(chain)}, ok={ok_count}, policies={policies_str})")


def _send_opus_takedown_email(user_id, email, job, verdict, dry_run):
    """
    Send 'Job Flagged For Takedown' RudderStack event with Opus verdict data.
    Same event name + attribute keys as the old flow, but sourced from Opus.
    """
    from automation import _init_rudderstack, DRY_RUN as _AUTO_DRY

    _dry = dry_run if dry_run is not None else _AUTO_DRY
    if _dry:
        logger.info(f"[DRY_RUN] Would send takedown email to {email} for job {job.get('job_id')}")
        return

    if not email:
        logger.warning(f"No email for user {user_id}, skipping RudderStack event")
        return

    rudder = _init_rudderstack()
    if not rudder:
        return

    job_id = job.get("job_id", "")

    # Identify user
    rudder.identify(user_id, {
        "email": email,
        "name": "",
        "plan": job.get("plan_type") or "Free User",
    })

    # Build flagged_policies from Opus verdict (human-readable)
    opus_policies = verdict.get("flagged_policies") or []
    policies_readable = " + ".join(
        p.replace("_", " ").title() for p in opus_policies if p != "NONE"
    ) or "Policy Violation"

    # Build flagged_job_links
    link = f'https://app.emergent.sh/?job_id={job_id}'
    flagged_job_links = f'<a href="{link}">{job_id}</a> — {policies_readable}'

    now_str = datetime.now(timezone.utc).isoformat() + "Z"

    # Same event name + attribute keys as the existing template expects
    rudder.track(user_id, "Job Flagged For Takedown", {
        "flagged_job_ids": job_id,
        "flagged_job_links": flagged_job_links,
        "flagged_policies": policies_readable,
        "flagged_count": 1,
        "flagged_at": now_str,
        "review_deadline_hours": 0,  # Immediate takedown, no deadline
        "label": "CONFIRMED_MALICIOUS",
        "support_email": "support@emergent.sh",
    })
    rudder.flush()
    logger.info(f"Opus takedown email sent to {email} ({user_id}) for job {job_id} — policies: {policies_readable}")
