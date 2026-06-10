"""
Automated Takedown System — Tier Classification, Email, and Execution.

4-tier model:
  Tier 1: Auto takedown (CONFIRMED_MALICIOUS + HIGH confidence + CRITICAL/HIGH severity + ≥3 harm signals + LTV<=299)
  Tier 2: Email warning + scheduled takedown after 12h (remaining CONFIRMED_MALICIOUS)
  Tier 3: Human review only (NEEDS_HUMAN_REVIEW with actionable harm signals)
  Tier 4: Log only (NEEDS_HUMAN_REVIEW with zero signals or only service_replication)

Safety:
  - MCP error failsafe: skip automation if any MCP tool call failed/wasn't called
  - Exclusion list checked at execution time
  - DRY_RUN mode for testing
"""

import os
import time
import logging
import asyncio
import httpx
from datetime import datetime, timezone, timedelta
from collections import defaultdict

logger = logging.getLogger(__name__)

# ---- Config ----
DRY_RUN = os.environ.get("AUTOMATION_DRY_RUN", "true").lower() == "true"

def get_dry_run():
    """Return current DRY_RUN state (server-wide, mutable at runtime)."""
    return DRY_RUN

def set_dry_run(value: bool):
    """Set DRY_RUN state at runtime. Affects all future pipeline runs and queries."""
    global DRY_RUN
    DRY_RUN = value
SUPABASE_URL = os.environ.get("SUPABASE_URL", "")
SUPABASE_ANON_KEY = os.environ.get("SUPABASE_ANON_KEY", "")
SLACK_BOT_TOKEN = os.environ.get("SLACK_BOT_TOKEN")
SLACK_CHANNEL = os.environ.get("SLACK_CHANNEL_ID")
DASHBOARD_URL = os.environ.get("DASHBOARD_URL", "https://phishing-eval.internal.emergent.host")

# ---- Policy Category Labels ----
POLICY_LABELS = {
    # Credential & Authentication Attacks
    "CREDENTIAL_PHISHING": "Credential Phishing",
    "CREDENTIAL_STUFFING": "Credential Stuffing",
    "CREDENTIAL_THEFT": "Credential Theft",
    "CAPTCHA_MANIPULATION": "CAPTCHA Manipulation",
    # Financial Attacks
    "FINANCIAL_HARVESTING": "Financial Harvesting",
    "CRYPTO_WALLET_DRAINER": "Crypto Wallet Drainer",
    "INVESTMENT_FRAUD": "Investment Fraud",
    "LOTTERY_PRIZE_FRAUD": "Lottery / Prize Fraud",
    "INSURANCE_FRAUD": "Insurance Fraud",
    "ADVANCE_FEE_FRAUD": "Advance Fee Fraud",
    "PAYMENT_FRAUD_AUTOMATION": "Payment Fraud Automation",
    # Impersonation & Brand Abuse
    "BRAND_IMPERSONATION": "Brand Impersonation",
    "FAKE_SUPPORT": "Fake Support",
    "DOCUMENT_FRAUD": "Document Fraud",
    "TAX_GOVERNMENT_FRAUD": "Tax / Government Fraud",
    "GOVERNMENT_IMPERSONATION": "Government Impersonation",
    # Social Engineering & Manipulation
    "SOCIAL_ENGINEERING": "Social Engineering",
    "EXTORTION_BLACKMAIL": "Extortion / Blackmail",
    "SCAREWARE": "Scareware",
    # Employment & Opportunity Fraud
    "EMPLOYMENT_FRAUD": "Employment Fraud",
    "EDUCATION_FRAUD": "Education Fraud",
    # E-Commerce & Transaction Fraud
    "ECOMMERCE_FRAUD": "E-Commerce Fraud",
    "REAL_ESTATE_FRAUD": "Real Estate Fraud",
    "TRAVEL_FRAUD": "Travel Fraud",
    # Charity & Cause Exploitation
    "CHARITY_FRAUD": "Charity Fraud",
    # Business & Enterprise Fraud
    "BEC_FRAUD": "Business Email Compromise",
    "SUPPLY_CHAIN_FRAUD": "Supply Chain Fraud",
    "AD_FRAUD": "Ad Fraud",
    # Healthcare & Services Fraud
    "HEALTHCARE_FRAUD": "Healthcare Fraud",
    "UTILITIES_FRAUD": "Utilities Fraud",
    # Data & Identity Theft
    "PII_HARVESTING": "PII Harvesting",
    "DATA_EXFILTRATION": "Data Exfiltration",
    "UNAUTHORIZED_ACCESS": "Unauthorized Access",
    # Malware & Software Threats
    "MALWARE_DELIVERY": "Malware Delivery",
    "TOOL_FOR_SCALE_HARM": "Tool For Scale Harm",
    # Social Media & Platform Abuse
    "SOCIAL_MEDIA_FRAUD": "Social Media Fraud",
    # Emerging & AI-Related Threats
    "DEEPFAKE_AI_FRAUD": "Deepfake / AI Fraud",
    "EMERGING_THREATS": "Emerging Threats",
}

# Regex to split on comma, plus, or slash (with optional surrounding whitespace)
import re
_CATEGORY_SPLIT_RE = re.compile(r'\s*[,+/]\s*')


def format_policies(categories_raw: str) -> str:
    """Convert raw category string to readable policy labels.
    Handles all separator formats from BQ: comma, plus, slash.
    e.g. 'CREDENTIAL_PHISHING, FINANCIAL_HARVESTING' 
         'CREDENTIAL_PHISHING + BRAND_IMPERSONATION'
         'DOCUMENT_FRAUD / CREDENTIAL_PHISHING / BRAND_IMPERSONATION'
    """
    if not categories_raw:
        return ""
    cats = [c.strip() for c in _CATEGORY_SPLIT_RE.split(categories_raw) if c.strip()]
    return " + ".join(POLICY_LABELS.get(c, c.replace("_", " ").title()) for c in cats)


# ---- MCP Error Failsafe ----

def has_mcp_error(job: dict) -> bool:
    """
    Check if a job has MCP tool call failures.
    If any MCP tool was not called or failed, we cannot trust the classification
    and should NOT auto-takedown or send emails.

    Returns True if there IS an error (i.e., job should be SKIPPED from automation).
    """
    # Check if any tool call was not made or failed
    checks = [
        ("agent_trajectory_called", "agent_trajectory_success"),
        ("hitl_interactions_called", "hitl_interactions_success"),
        ("job_details_called", "job_details_success"),
        ("deployment_details_called", "deployment_details_success"),
    ]
    for called_field, success_field in checks:
        # COALESCE(field, true) = false  → field is explicitly False
        # If the field is None/missing, we treat it as True (COALESCE default)
        called = job.get(called_field)
        success = job.get(success_field)
        # If explicitly False, that's an error
        if called is False or success is False:
            return True
    return False


# ---- Tier Classification ----

HARM_SIGNAL_FIELDS = [
    "credential_theft_detected",
    "deceptive_exfiltration_detected",
    " t",
    "tool_for_scale_harm_detected",
    "user_deceived_detected",
    "violent_harmful_content_detected",
    "illegal_content_detected",
    "malware_delivery_detected",
]

ACTIONABLE_HARM_FIELDS = [
    "credential_theft_detected",
    "deceptive_exfiltration_detected",
    "tool_for_scale_harm_detected",
    "user_deceived_detected",
    "violent_harmful_content_detected",
    "illegal_content_detected",
    "malware_delivery_detected",
]

# High-risk category keywords — matches the REGEXP_CONTAINS in the BQ tier queries.
# If classification_category contains any of these, it counts as "actionable" even
# when no boolean harm signals fired.
_CAT_HIGH_RISK_RE = re.compile(
    r'CREDENTIAL|PHISHING|STUFFING|FINANCIAL|HARVESTING|INVESTMENT|CRYPTO|'
    r'WALLET|DRAINER|PII|IDENTITY|EXFILTRATION|MALWARE|SPYWARE|STALKER|'
    r'SURVEILLANCE|GOVERNMENT|TAX|DOCUMENT_FRAUD|SOCIAL_ENGINEERING|'
    r'EXTORTION|BLACKMAIL|ECOMMERCE|CHARITY|EMPLOYMENT|TRAVEL|'
    r'REAL_ESTATE|EMERGING|SPAM|BOMBING|VISHING|TELECOM',
    re.IGNORECASE,
)

# Label severity for dedup: higher = more severe
_LABEL_SEVERITY = {
    "CONFIRMED_MALICIOUS": 3,
    "NEEDS_HUMAN_REVIEW": 2,
    "LEGITIMATE": 1,
}


def check_exclusion_match(job_id: str, user_id: str, exclusions: list, task: str = None) -> bool:
    """Check if a job/user/task matches any active exclusion. Pure function for testability."""
    for exc in exclusions:
        if not exc.get("active", True):
            continue
        if exc.get("job_id") and exc["job_id"] == job_id:
            return True
        if exc.get("user_id") and user_id and exc["user_id"] == user_id:
            return True
        if exc.get("pattern") and task:
            try:
                if re.search(exc["pattern"], task):
                    return True
            except re.error:
                pass
    return False


def _has_actionable_signals(job: dict) -> bool:
    """Check if job has actionable signals via booleans OR high-risk category regex."""
    has_bool = any(job.get(f) is True for f in ACTIONABLE_HARM_FIELDS)
    if has_bool:
        return True
    cat = (job.get("classification_category") or "").upper()
    return bool(_CAT_HIGH_RISK_RE.search(cat))


def classify_tier(job: dict) -> int:
    """
    Classify a bq_jobs document into tier 1-5.

    Tier 1: CM + HIGH conf + CRITICAL/HIGH sev + >=3 harm signals + LTV<=299
    Tier 2: Remaining CM  +  NHR + Free + actionable (booleans OR cat regex)
    Tier 3: NHR + Paid (LTV>0) + actionable (booleans OR cat regex)
    Tier 4: NHR + no actionable booleans + no high-risk category
    Tier 5: LEGITIMATE — no action
    """
    label = job.get("classification_label")
    confidence = job.get("classification_confidence")
    severity = job.get("classification_severity")
    ltv = job.get("ltv") or 0

    # Tier 5: Legitimate
    if label == "LEGITIMATE":
        return 5

    harm_count = sum(1 for f in HARM_SIGNAL_FIELDS if job.get(f) is True)

    if label == "CONFIRMED_MALICIOUS":
        # Tier 1: HIGH confidence + CRITICAL/HIGH severity + >=3 harm signals + LTV<=299
        if (confidence == "HIGH"
                and severity in ("CRITICAL", "HIGH")
                and harm_count >= 3
                and float(ltv) <= 299):
            return 1
        # Tier 2a: All remaining CONFIRMED_MALICIOUS
        return 2

    if label == "NEEDS_HUMAN_REVIEW":
        actionable = _has_actionable_signals(job)
        is_free = float(ltv) == 0

        if actionable and is_free:
            # Tier 2b: NHR + Free + actionable signals
            return 2
        if actionable and not is_free:
            # Tier 3: NHR + Paid + actionable signals
            return 3
        # Tier 4: No actionable booleans + no high-risk category
        return 4

    # Unknown label: log only
    return 4


def deduplicate_jobs(jobs: list) -> list:
    """
    Deduplicate jobs by job_id — same job can appear multiple times with
    different classification labels (re-evaluations). Keep the most severe:
    CONFIRMED_MALICIOUS > NEEDS_HUMAN_REVIEW > LEGITIMATE, then by severity,
    then most recent emitted_at.
    """
    _SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1}
    by_job = {}
    for job in jobs:
        jid = job.get("job_id")
        if jid not in by_job:
            by_job[jid] = job
            continue
        existing = by_job[jid]
        # Compare label severity
        new_lsev = _LABEL_SEVERITY.get(job.get("classification_label"), 0)
        old_lsev = _LABEL_SEVERITY.get(existing.get("classification_label"), 0)
        if new_lsev > old_lsev:
            by_job[jid] = job
        elif new_lsev == old_lsev:
            # Compare classification_severity
            new_sev = _SEV_ORDER.get(job.get("classification_severity", ""), 0)
            old_sev = _SEV_ORDER.get(existing.get("classification_severity", ""), 0)
            if new_sev > old_sev:
                by_job[jid] = job
            elif new_sev == old_sev:
                # Take most recent
                new_t = job.get("emitted_at", "")
                old_t = existing.get("emitted_at", "")
                if str(new_t) > str(old_t):
                    by_job[jid] = job
    return list(by_job.values())


# ---- Supabase Programmatic Auth ----

_supabase_auto_token = {"token": None, "expires_at": 0}


async def get_automation_token() -> str:
    """Get a valid Supabase JWT for automated API calls. Caches + refreshes."""
    now = time.time()
    if _supabase_auto_token["token"] and now < _supabase_auto_token["expires_at"] - 60:
        return _supabase_auto_token["token"]

    email = os.environ.get("SUPABASE_SERVICE_EMAIL")
    password = os.environ.get("SUPABASE_SERVICE_PASSWORD")
    if not email or not password:
        raise RuntimeError("SUPABASE_SERVICE_EMAIL/PASSWORD not configured for automation")

    async with httpx.AsyncClient(timeout=10) as client:
        resp = await client.post(
            f"{SUPABASE_URL}/auth/v1/token?grant_type=password",
            headers={"apikey": SUPABASE_ANON_KEY, "Content-Type": "application/json"},
            json={"email": email, "password": password},
        )
        if resp.status_code != 200:
            raise RuntimeError(f"Supabase automation login failed: {resp.status_code} {resp.text[:200]}")
        data = resp.json()
        _supabase_auto_token["token"] = data["access_token"]
        _supabase_auto_token["expires_at"] = now + data.get("expires_in", 3600)
        return data["access_token"]


async def auto_takedown_job(job_id: str, reason: str, dry_run=None) -> dict:
    """Call the disable API programmatically. Returns API response dict."""
    _dry = dry_run if dry_run is not None else DRY_RUN
    if _dry:
        logger.info(f"[DRY_RUN] Would takedown job {job_id}: {reason}")
        return {"status_code": 200, "body": "DRY_RUN", "dry_run": True}

    token = await get_automation_token()
    disable_url = f"https://api.emergent.sh/jobs/v0/{job_id}/disable"
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(
            disable_url,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json={"is_suspended": True, "suspension_reason": reason},
        )
        result = {"status_code": resp.status_code, "body": resp.text[:500]}
        logger.info(f"Auto-takedown API response for {job_id}: {resp.status_code}")
        if resp.status_code >= 400:
            raise RuntimeError(f"Disable API {resp.status_code}: {resp.text[:300]}")
        return result


# ---- RudderStack Email ----

def _init_rudderstack():
    """Lazy init RudderStack SDK."""
    try:
        import rudderstack.analytics as rudder_analytics
        rudder_analytics.write_key = os.environ.get(
            "RUDDERSTACK_WRITE_KEY", "2z6c5VI9crVwzWdL3m1NpriHxVD"
        )
        rudder_analytics.dataPlaneUrl = os.environ.get(
            "RUDDERSTACK_DATA_PLANE_URL", "https://emergenthjpvbw.dataplane.rudderstack.com"
        )
        return rudder_analytics
    except ImportError:
        logger.error("rudder-sdk-python not installed, email sending disabled")
        return None


def send_takedown_warning_email(user_id: str, email: str, plan_type: str, jobs: list, dry_run=None):
    """
    Send 'Job Flagged For Takedown' event via RudderStack.
    One event per user, all jobs grouped.
    """
    _dry = dry_run if dry_run is not None else DRY_RUN
    if _dry:
        job_ids = [j.get("job_id", "?") for j in jobs]
        logger.info(f"[DRY_RUN] Would send takedown email to {email} for jobs: {job_ids}")
        return

    rudder = _init_rudderstack()
    if not rudder:
        return

    rudder.identify(user_id, {
        "email": email,
        "name": "",
        "plan": plan_type or "Free User",
    })

    job_lines = []
    all_policies = set()
    for j in jobs:
        policies = format_policies(j.get("classification_category", ""))
        link = f'https://app.emergent.sh/?job_id={j["job_id"]}'
        job_lines.append(f'<a href="{link}">{j["job_id"]}</a> — {policies}')
        if policies:
            all_policies.update(p.strip() for p in policies.split("+"))

    now_str = datetime.now(timezone.utc).isoformat() + "Z"
    rudder.track(user_id, "Job Flagged For Takedown", {
        "flagged_job_ids": ", ".join(j["job_id"] for j in jobs),
        "flagged_job_links": "<br>".join(job_lines),
        "flagged_policies": " + ".join(sorted(all_policies)),
        "flagged_count": len(jobs),
        "flagged_at": now_str,
        "review_deadline_hours": 12,
        "label": "CONFIRMED_MALICIOUS",
        "support_email": "support@emergent.sh",
    })
    rudder.flush()
    logger.info(f"Takedown warning email sent to {email} ({user_id}) for {len(jobs)} jobs")


def send_external_takedown_notification(user_id: str, email: str, plan_type: str, job_id: str, source: str, domain: str, category: str = ""):
    """
    Send 'Job Taken Down — External Report' event via RudderStack.
    Immediate notification — no warning period.
    Only fires in LIVE mode.
    """
    if DRY_RUN:
        logger.info(f"[DRY_RUN] Would send external takedown notification to {email} for job {job_id} (source={source})")
        return

    rudder = _init_rudderstack()
    if not rudder:
        return

    rudder.identify(user_id, {
        "email": email,
        "name": "",
        "plan": plan_type or "Free User",
    })

    policies = format_policies(category) if category else "Policy Violation"
    job_link = f'<a href="https://app.emergent.sh/?job_id={job_id}">{job_id}</a> — {policies}'
    source_label = {"cloudflare": "Cloudflare", "openai": "OpenAI"}.get(source, source.title())
    now_str = datetime.now(timezone.utc).isoformat() + "Z"

    rudder.track(user_id, "Job Taken Down External Report", {
        "job_id": job_id,
        "job_link": job_link,
        "takedown_source": source_label,
        "reported_domain": domain or "",
        "flagged_policies": policies,
        "taken_down_at": now_str,
        "review_deadline_hours": 0,
        "support_email": "support@emergent.sh",
    })
    rudder.flush()
    logger.info(f"External takedown notification sent to {email} ({user_id}) for job {job_id} (source={source})")


# ---- Core Automation Engine ----

async def run_automation_tick(db, resolve_fork_chain_fn=None):
    """
    Phase 4 of sync: Classify new jobs into tiers and take automated actions.
    Called from run_bq_sync() after Phase 3.
    """
    mode_snapshot = DRY_RUN
    # Collect jobs already processed in ANY mode to avoid mass re-processing on mode switch
    # (e.g., switching from dry_run to live should NOT re-process all dry_run jobs).
    # EXCEPTION: skipped_mcp_error is not terminal — when BQ re-emits the row with corrected
    # MCP flags we want to re-evaluate. _process_job_tier upserts on (job_id, dry_run), so
    # re-running is idempotent (re-writes the skip if mcp_err is still true, otherwise moves
    # the job into pending_opus_review / the proper tier action).
    all_processed_job_ids = set()
    async for doc in db.automated_actions.find(
        {"action": {"$ne": "skipped_mcp_error"}}, {"job_id": 1, "_id": 0}
    ):
        all_processed_job_ids.add(doc["job_id"])

    # Jobs processed in current mode specifically (used for stats/logging)
    current_mode_job_ids = set()
    async for doc in db.automated_actions.find({"dry_run": mode_snapshot}, {"job_id": 1, "_id": 0}):
        current_mode_job_ids.add(doc["job_id"])

    # Only process truly new jobs (never classified in ANY mode)
    candidates_raw = await db.bq_jobs.find({
        "classification_label": {"$in": ["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW", "LEGITIMATE"]},
        "job_id": {"$nin": list(all_processed_job_ids)},
    }).to_list(10000)

    if not candidates_raw:
        logger.info("Phase 4: No new jobs to classify")
        await execute_pending_takedowns(db, dry_run=mode_snapshot, resolve_fork_chain_fn=resolve_fork_chain_fn)
        return

    # Deduplicate: same job_id can have multiple rows (re-evaluations).
    # Keep the most severe label: CM > NHR > LEGITIMATE.
    candidates = deduplicate_jobs(candidates_raw)
    if len(candidates) < len(candidates_raw):
        logger.info(f"Phase 4: Deduplicated {len(candidates_raw)} rows → {len(candidates)} unique jobs")

    logger.info(f"Phase 4: Classifying {len(candidates)} new jobs")

    tier_counts = {1: 0, 2: 0, 3: 0, 4: 0, 5: 0}
    mcp_skipped_count = 0
    exclusion_skipped_count = 0
    t1_completed = 0
    t1_failed = 0
    tier2_pending = []  # Jobs that need email + scheduling

    for job in candidates:
        tier = classify_tier(job)
        tier_counts[tier] += 1
        mcp_err = has_mcp_error(job)
        action = None

        await _process_job_tier(db, job, tier, mcp_err, dry_run=mode_snapshot, resolve_fork_chain_fn=resolve_fork_chain_fn)
        if mcp_err and tier in (1, 2):
            mcp_skipped_count += 1
        elif tier in (1, 2):
            # Check if it was excluded (read back from DB)
            action = await db.automated_actions.find_one({"job_id": job["job_id"], "dry_run": mode_snapshot}, {"action": 1, "status": 1})
            if action and action.get("action") == "skipped_excluded":
                exclusion_skipped_count += 1
            elif tier == 1:
                if action and action.get("status") == "completed":
                    t1_completed += 1
                elif action and action.get("status") == "failed":
                    t1_failed += 1
        # T2 emails are now handled by the Opus poller after verdict confirmation.
        # No longer batch-queue here.

    logger.info(f"Phase 4 classification: {tier_counts}")

    # T2 batch emails skipped — Opus poller sends emails after confirming verdict.
    email_stats = {"users_emailed": 0, "emails_sent": 0, "emails_failed": 0, "jobs_scheduled": 0}

    # Execute any past-due scheduled takedowns
    exec_stats = await execute_pending_takedowns(db, dry_run=mode_snapshot, resolve_fork_chain_fn=resolve_fork_chain_fn)

    return {
        "new_jobs_classified": len(candidates),
        "tier_counts_this_run": {str(k): v for k, v in tier_counts.items()},
        "mcp_skipped": mcp_skipped_count,
        "exclusion_skipped": exclusion_skipped_count,
        "t1_completed": t1_completed,
        "t1_failed": t1_failed,
        "email_stats": email_stats,
        "exec_stats": exec_stats,
    }


def _slack_notify(tier: int, job_id: str, user_id: str, category: str, label: str, status: str = "", extra_fields=None, dry_run=None):
    """Send a Slack notification for T1/T2/T3 actions. Fire-and-forget, never raises."""
    try:
        _dry = dry_run if dry_run is not None else DRY_RUN
        mode_text = ":test_tube: DRY RUN" if _dry else ":zap: LIVE"
        ef = extra_fields or {}
        plan = ef.get("plan_type") or "—"
        ltv_val = ef.get("ltv")
        ltv_str = f"${float(ltv_val):,.2f}" if ltv_val is not None else "—"
        if tier == 1:
            header = ":rotating_light: Auto Takedown (Tier 1)"
            fields = [
                {"type": "mrkdwn", "text": f"*Job ID:*\n<{DASHBOARD_URL}?search={job_id}|{job_id}>"},
                {"type": "mrkdwn", "text": f"*User ID:*\n`{user_id or '—'}`"},
                {"type": "mrkdwn", "text": f"*Category:*\n{category or '—'}"},
                {"type": "mrkdwn", "text": f"*Label:*\n{label}"},
                {"type": "mrkdwn", "text": f"*Plan:*\n{plan}"},
                {"type": "mrkdwn", "text": f"*LTV:*\n{ltv_str}"},
                {"type": "mrkdwn", "text": f"*Status:*\n{':white_check_mark: Completed' if status == 'completed' else ':x: Failed'}"},
                {"type": "mrkdwn", "text": f"*Mode:*\n{mode_text}"},
            ]
            context = f"{mode_text} | Job disabled via API"
        elif tier == 2:
            email = ef.get("email", "—")
            header = ":email: Scheduled Takedown (Tier 2)"
            fields = [
                {"type": "mrkdwn", "text": f"*Job ID:*\n<{DASHBOARD_URL}?search={job_id}|{job_id}>"},
                {"type": "mrkdwn", "text": f"*User ID:*\n`{user_id or '—'}`"},
                {"type": "mrkdwn", "text": f"*Category:*\n{category or '—'}"},
                {"type": "mrkdwn", "text": f"*Label:*\n{label}"},
                {"type": "mrkdwn", "text": f"*Email:*\n{email}"},
                {"type": "mrkdwn", "text": f"*Plan:*\n{plan}"},
                {"type": "mrkdwn", "text": f"*LTV:*\n{ltv_str}"},
                {"type": "mrkdwn", "text": f"*Takedown In:*\n12 hours"},
            ]
            context = f"{mode_text} | Email sent + takedown scheduled"
        elif tier == 3:
            header = ":eyes: Needs Human Review (Tier 3)"
            fields = [
                {"type": "mrkdwn", "text": f"*Job ID:*\n<{DASHBOARD_URL}?search={job_id}|{job_id}>"},
                {"type": "mrkdwn", "text": f"*User ID:*\n`{user_id or '—'}`"},
                {"type": "mrkdwn", "text": f"*Category:*\n{category or '—'}"},
                {"type": "mrkdwn", "text": f"*Label:*\n{label}"},
                {"type": "mrkdwn", "text": f"*Plan:*\n{plan}"},
                {"type": "mrkdwn", "text": f"*LTV:*\n{ltv_str}"},
            ]
            context = f"{mode_text} | Awaiting human decision"
        else:
            return

        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": header, "emoji": True}},
            {"type": "section", "fields": fields},
        ]
        if tier == 3:
            blocks.append({"type": "actions", "elements": [
                {"type": "button", "text": {"type": "plain_text", "text": ":mag: Review in Dashboard", "emoji": True},
                 "url": DASHBOARD_URL, "style": "primary"},
            ]})
        blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"Phishing Eval Automation | {context}"}]})

        httpx.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}", "Content-Type": "application/json"},
            json={"channel": SLACK_CHANNEL, "text": f"Tier {tier}: {job_id}", "blocks": blocks},
            timeout=10,
        )
    except Exception as e:
        logger.warning(f"Slack notification failed for {job_id}: {e}")



def slack_notify_external(source: str, job_id: str, reason: str, status: str = "completed", dry_run=None):
    """Slack notification for external takedowns (OpenAI, Cloudflare, etc.). Fire-and-forget."""
    try:
        _dry = dry_run if dry_run is not None else DRY_RUN
        mode_text = ":test_tube: DRY RUN" if _dry else ":zap: LIVE"
        source_emoji = {"openai": ":robot_face:", "cloudflare": ":cloud:"}.get(source, ":warning:")
        header = f"{source_emoji} External Takedown ({source.title()})"
        fields = [
            {"type": "mrkdwn", "text": f"*Job ID:*\n<{DASHBOARD_URL}?search={job_id}|{job_id}>"},
            {"type": "mrkdwn", "text": f"*Source:*\n{source.title()}"},
            {"type": "mrkdwn", "text": f"*Reason:*\n{reason[:200]}"},
            {"type": "mrkdwn", "text": f"*Status:*\n{':white_check_mark: Completed' if status == 'completed' else ':x: Failed'}"},
            {"type": "mrkdwn", "text": f"*Mode:*\n{mode_text}"},
        ]
        blocks = [
            {"type": "header", "text": {"type": "plain_text", "text": header, "emoji": True}},
            {"type": "section", "fields": fields},
            {"type": "context", "elements": [{"type": "mrkdwn", "text": f"Phishing Eval Automation | {mode_text} | External signal from {source.title()}"}]},
        ]
        httpx.post(
            "https://slack.com/api/chat.postMessage",
            headers={"Authorization": f"Bearer {SLACK_BOT_TOKEN}", "Content-Type": "application/json"},
            json={"channel": SLACK_CHANNEL, "text": f"External Takedown ({source}): {job_id}", "blocks": blocks},
            timeout=10,
        )
    except Exception as e:
        logger.warning(f"Slack external notification failed for {job_id}: {e}")



async def _process_job_tier(db, job: dict, tier: int, mcp_err: bool, dry_run=None, resolve_fork_chain_fn=None):
    """Process a single job based on its tier."""
    _dry = dry_run if dry_run is not None else DRY_RUN
    now = datetime.now(timezone.utc).isoformat()
    job_id = job["job_id"]
    user_id = job.get("user_id")

    action_doc = {
        "job_id": job_id,
        "user_id": user_id,
        "tier": tier,
        "classification_category": job.get("classification_category", ""),
        "classification_label": job.get("classification_label", ""),
        "has_mcp_error": mcp_err,
        "created_at": now,
        "dry_run": _dry,
    }

    _upsert_key = {"job_id": job_id, "dry_run": _dry}

    # MCP error failsafe — skip automated actions for Tier 1 & 2
    if mcp_err and tier in (1, 2):
        action_doc["action"] = "skipped_mcp_error"
        action_doc["status"] = "skipped"
        logger.warning(f"Tier {tier} skipped for {job_id}: MCP error failsafe")
        await db.automated_actions.update_one(
            _upsert_key, {"$set": action_doc}, upsert=True
        )
        return

    # Check exclusion list (user_id, job_id, email, or task pattern — all tiers)
    excl_or = [{"job_id": job_id, "active": True}]
    if user_id:
        excl_or.append({"user_id": user_id, "active": True})
    user_email = job.get("user_email")
    if user_email:
        excl_or.append({"user_id": user_email, "active": True})
    excl_or.append({"pattern": {"$exists": True, "$ne": ""}, "active": True})
    exclusions = await db.exclusion_list.find({"$or": excl_or}).to_list(500)
    task_text = job.get("task", "") or ""
    if check_exclusion_match(job_id, user_id, exclusions, task=task_text):
        action_doc["action"] = "skipped_excluded"
        action_doc["status"] = "skipped"
        matched_pat = next((e.get("pattern") for e in exclusions if e.get("pattern") and re.search(e["pattern"], task_text)), None)
        if matched_pat:
            action_doc["exclude_pattern"] = matched_pat
        logger.info(f"Tier {tier} skipped for {job_id}: exclusion match")
        await db.automated_actions.update_one(
            _upsert_key, {"$set": action_doc}, upsert=True
        )
        return

    if tier in (1, 2, 3):
        # Queue for Opus agent review instead of executing immediately.
        # The opus_poller background task will pick this up, run the Opus classifier,
        # and execute the appropriate action based on the verdict.
        action_doc["action"] = {1: "auto_takedown", 2: "email_scheduled", 3: "human_review"}[tier]
        action_doc["status"] = "pending_opus_review"
        logger.info(f"Tier {tier} queued for Opus review: {job_id}")

    elif tier == 4:
        action_doc["action"] = "logged_only"
        action_doc["status"] = "completed"

    elif tier == 5:
        action_doc["action"] = "legitimate"
        action_doc["status"] = "completed"

    await db.automated_actions.update_one(
        _upsert_key, {"$set": action_doc}, upsert=True
    )


async def _send_tier2_batch_emails(db, jobs: list, dry_run=None):
    """Group Tier 2 jobs by user_id, send one email per user, schedule takedowns."""
    _dry = dry_run if dry_run is not None else DRY_RUN
    by_user = defaultdict(list)
    for job in jobs:
        uid = job.get("user_id")
        if uid:
            by_user[uid].append(job)

    now = datetime.now(timezone.utc)
    takedown_at = (now + timedelta(hours=12)).isoformat()
    emails_sent = 0
    emails_failed = 0

    for user_id, user_jobs in by_user.items():
        # Get user details
        sample = user_jobs[0]
        email = sample.get("user_email")
        plan_type = sample.get("plan_type")

        # Send email
        if email:
            try:
                send_takedown_warning_email(user_id, email, plan_type, user_jobs, dry_run=_dry)
                emails_sent += 1
            except Exception as e:
                emails_failed += 1
                logger.error(f"Tier 2 email failed for {user_id}: {e}")
        else:
            logger.warning(f"Tier 2: No email for user {user_id}, scheduling takedown without email")

        # Schedule takedowns for each job
        for job in user_jobs:
            await db.scheduled_takedowns.update_one(
                {"job_id": job["job_id"], "dry_run": _dry},
                {"$set": {
                    "job_id": job["job_id"],
                    "user_id": user_id,
                    "user_email": email,
                    "email_sent_at": now.isoformat(),
                    "takedown_at": takedown_at,
                    "status": "pending",
                    "classification_category": job.get("classification_category", ""),
                    "classification_label": job.get("classification_label", ""),
                    "dry_run": _dry,
                }},
                upsert=True,
            )
            # Update action status
            await db.automated_actions.update_one(
                {"job_id": job["job_id"], "dry_run": _dry},
                {"$set": {"status": "completed", "executed_at": now.isoformat()}}
            )

    logger.info(f"Tier 2: Sent emails to {len(by_user)} users, scheduled {len(jobs)} takedowns for +12h")
    return {"users_emailed": len(by_user), "emails_sent": emails_sent, "emails_failed": emails_failed, "jobs_scheduled": len(jobs)}


async def execute_pending_takedowns(db, dry_run=None, resolve_fork_chain_fn=None):
    """Phase B: Find scheduled takedowns past their deadline, check exclusion, execute."""
    _dry = dry_run if dry_run is not None else DRY_RUN
    now = datetime.now(timezone.utc).isoformat()
    exec_stats = {"past_due": 0, "executed": 0, "excluded": 0, "failed": 0}

    pending = await db.scheduled_takedowns.find({
        "status": "pending",
        "takedown_at": {"$lte": now},
        "dry_run": _dry,
    }).to_list(500)

    if not pending:
        return exec_stats
    exec_stats["past_due"] = len(pending)

    logger.info(f"Phase 4B: Executing {len(pending)} pending scheduled takedowns")

    for doc in pending:
        # Check exclusion at execution time (user_id, job_id, email, or task pattern)
        excl_or = [
            {"user_id": doc["user_id"], "active": True},
            {"job_id": doc["job_id"], "active": True},
            {"pattern": {"$exists": True, "$ne": ""}, "active": True},
        ]
        user_email = doc.get("user_email")
        if user_email:
            excl_or.append({"user_id": user_email, "active": True})
        exclusions = await db.exclusion_list.find({"$or": excl_or}).to_list(500)
        job_doc = await db.bq_jobs.find_one({"job_id": doc["job_id"]}, {"task": 1})
        task_text = (job_doc.get("task", "") if job_doc else "") or ""
        excluded = check_exclusion_match(doc["job_id"], doc["user_id"], exclusions, task=task_text)

        _sched_key = {"job_id": doc["job_id"], "dry_run": _dry}

        if excluded:
            await db.scheduled_takedowns.update_one(
                _sched_key,
                {"$set": {
                    "status": "excluded",
                    "excluded_at": now,
                    "exclude_reason": "exclusion_list",
                }}
            )
            logger.info(f"Scheduled takedown excluded for {doc['job_id']}")
            exec_stats["excluded"] += 1
            continue

        try:
            reason = f"Scheduled takedown (Tier 2, 12h): {doc.get('classification_category', 'CONFIRMED_MALICIOUS')}"

            # Resolve fork chain to get all related job IDs
            sched_job_id = doc["job_id"]
            chain = [sched_job_id]
            if resolve_fork_chain_fn:
                try:
                    chain = await asyncio.get_event_loop().run_in_executor(None, resolve_fork_chain_fn, sched_job_id)
                    if len(chain) > 1:
                        logger.info(f"Scheduled takedown: expanded {sched_job_id} to {len(chain)} jobs via fork chain")
                except Exception as e:
                    logger.error(f"Fork chain resolution failed for {sched_job_id}, proceeding with single job: {e}")
                    chain = [sched_job_id]

            # Takedown all jobs in fork chain
            chain_fail = 0
            for chain_jid in chain:
                try:
                    result = await auto_takedown_job(chain_jid, reason, dry_run=_dry)
                    if not result.get("dry_run"):
                        chain_job_doc = await db.bq_jobs.find_one({"job_id": chain_jid})
                        if chain_job_doc:
                            await _record_takedown_in_mongo(db, chain_job_doc, reason, result)
                except Exception as e:
                    logger.error(f"Scheduled takedown failed for fork chain job {chain_jid}: {e}")
                    chain_fail += 1

            if chain_fail == len(chain):
                raise RuntimeError(f"All {len(chain)} fork chain jobs failed")

            await db.scheduled_takedowns.update_one(
                _sched_key,
                {"$set": {"status": "executed", "executed_at": now, "fork_chain": chain}}
            )
            logger.info(f"Scheduled takedown executed for {sched_job_id} (chain={len(chain)}, failed={chain_fail})")
            exec_stats["executed"] += 1
        except Exception as e:
            logger.error(f"Scheduled takedown failed for {doc['job_id']}: {e}")
            await db.scheduled_takedowns.update_one(
                _sched_key,
                {"$set": {"status": "failed", "error": str(e)}}
            )
            exec_stats["failed"] += 1

    return exec_stats


async def _record_takedown_in_mongo(db, job: dict, reason: str, api_result: dict):
    """Record a takedown in takedowns collection + eval_verdicts for UI consistency."""
    job_id = job["job_id"]
    now = datetime.now(timezone.utc).isoformat()

    takedown_info = {
        "taken_down_by": "automation@emergent.sh",
        "taken_down_by_name": "Automation",
        "taken_down_at": now,
        "job_id": job_id,
        "task_preview": job.get("task", "")[:200] if job.get("task") else "",
        "s2_label": job.get("classification_label", ""),
        "suspension_reason": reason,
        "api_result": api_result,
        "automated": True,
    }

    try:
        await db.takedowns.insert_one({**takedown_info})
    except Exception as e:
        logger.error(f"Failed to record takedown for {job_id}: {e}")

    ek = f"prod::{job_id}"
    try:
        await db.eval_verdicts.update_one(
            {"eval_key": ek},
            {"$set": {"taken_down": True, "takedown_info": takedown_info}},
            upsert=True,
        )
    except Exception as e:
        logger.error(f"Failed to update eval_verdicts for {job_id}: {e}")


# ---- Pipeline Run Logging ----

def _stringify_keys(obj):
    """Recursively convert all dict keys to strings (MongoDB requires string keys)."""
    if isinstance(obj, dict):
        return {str(k): _stringify_keys(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_stringify_keys(i) for i in obj]
    return obj


async def log_pipeline_run(db, phases: dict, dry_run=None):
    """Log a complete pipeline run with per-phase stats to pipeline_runs collection."""
    _dry = dry_run if dry_run is not None else DRY_RUN
    now = datetime.now(timezone.utc).isoformat()
    doc = {
        "timestamp": now,
        "phases": _stringify_keys(phases),
        "dry_run": _dry,
    }
    try:
        await db.pipeline_runs.insert_one(doc)
    except Exception as e:
        logger.error(f"Failed to log pipeline run: {e}")


# ---- BQ Write-Back Sync ----

BQ_ACTIONS_TABLE = "emergent-default.phishing_eval.automation_actions"


async def sync_actions_to_bq(db, bq_client):
    """Sync automated_actions (joined with scheduled_takedowns + takedowns) to BigQuery.

    Uses load_table_from_json (load job) — free, reliable for bulk.
    High-water-mark timestamp in sync_metadata tracks incremental syncs.
    First run backfills everything.
    """
    if not bq_client:
        logger.warning("BQ write-back skipped: no bq_client")
        return {"status": "skipped", "reason": "no_bq_client"}

    from google.cloud import bigquery as _bq

    now = datetime.now(timezone.utc)
    meta = await db.sync_metadata.find_one({"_id": f"bq_write_sync_{'dry' if DRY_RUN else 'live'}"})
    last_sync = meta.get("last_sync_at") if meta else None

    # Query automated_actions that need syncing:
    # 1. Newly created since last sync
    # 2. Opus-reviewed since last sync
    # 3. Has opus_label but never synced to BQ (catch-up for missed rows)
    query = {"dry_run": DRY_RUN}
    if last_sync:
        query["$or"] = [
            {"created_at": {"$gte": last_sync}},
            {"opus_reviewed_at": {"$gte": last_sync}},
            {"opus_label": {"$exists": True}, "opus_synced_to_bq": {"$ne": True}},
        ]
    cursor = db.automated_actions.find(query)
    actions = await cursor.to_list(length=None)

    if not actions:
        logger.info("BQ write-back: 0 rows to sync")
        return {"status": "ok", "rows_synced": 0}

    # Batch-lookup scheduled_takedowns and takedowns by job_id
    job_ids = [a["job_id"] for a in actions]

    sched_docs = {}
    async for s in db.scheduled_takedowns.find({"job_id": {"$in": job_ids}, "dry_run": DRY_RUN}):
        sched_docs[s["job_id"]] = s

    takedown_docs = {}
    async for t in db.takedowns.find({"job_id": {"$in": job_ids}}):
        takedown_docs[t["job_id"]] = t

    opus_docs = {}
    async for o in db.opus_verdicts.find({"job_id": {"$in": job_ids}, "dry_run": DRY_RUN}):
        opus_docs[o["job_id"]] = o

    # Build BQ rows
    rows = []
    synced_at = now.isoformat()
    for a in actions:
        jid = a["job_id"]
        s = sched_docs.get(jid, {})
        t = takedown_docs.get(jid, {})
        o = opus_docs.get(jid, {})

        # Format opus_flagged_policies as pipe-separated string for BQ
        raw_policies = o.get("opus_flagged_policies") or a.get("opus_flagged_policies")
        policies_str = "|".join(raw_policies) if isinstance(raw_policies, list) else None

        rows.append({
            "job_id": jid,
            "user_id": a.get("user_id"),
            "tier": a.get("tier") or 0,
            "action": a.get("action"),
            "status": a.get("status"),
            "classification_label": a.get("classification_label"),
            "classification_category": a.get("classification_category"),
            "dry_run": a.get("dry_run", True),
            "has_mcp_error": a.get("has_mcp_error", False),
            "created_at": a.get("created_at"),
            "executed_at": a.get("executed_at"),
            # Scheduled takedown fields
            "user_email": s.get("user_email"),
            "email_sent_at": s.get("email_sent_at"),
            "scheduled_takedown_at": s.get("takedown_at"),
            "scheduled_status": s.get("status"),
            "scheduled_executed_at": s.get("executed_at"),
            # Manual takedown fields
            "taken_down_by": t.get("taken_down_by"),
            "taken_down_at": t.get("taken_down_at"),
            # Opus agent verdict fields
            "opus_label": o.get("opus_label") or a.get("opus_label"),
            "opus_flagged_policies": policies_str,
            "opus_verdict_summary": o.get("opus_verdict_summary") or a.get("opus_verdict_summary"),
            "opus_reviewed_at": o.get("reviewed_at") or a.get("opus_reviewed_at"),
            # Sync metadata
            "synced_at": synced_at,
        })

    # Load job — WRITE_TRUNCATE on first run (backfill), WRITE_APPEND on incremental
    job_config = _bq.LoadJobConfig(
        source_format=_bq.SourceFormat.NEWLINE_DELIMITED_JSON,
        write_disposition=_bq.WriteDisposition.WRITE_APPEND,
        schema_update_options=[_bq.SchemaUpdateOption.ALLOW_FIELD_ADDITION],
    )

    try:
        load_job = bq_client.load_table_from_json(rows, BQ_ACTIONS_TABLE, job_config=job_config)
        load_job.result()  # Wait for completion
        logger.info(f"BQ write-back: {len(rows)} rows loaded (job {load_job.job_id})")

        # Mark opus-reviewed rows as synced so they don't get re-synced on every cycle
        opus_job_ids = [a["job_id"] for a in actions if a.get("opus_label")]
        if opus_job_ids:
            await db.automated_actions.update_many(
                {"job_id": {"$in": opus_job_ids}, "dry_run": DRY_RUN},
                {"$set": {"opus_synced_to_bq": True}},
            )
    except Exception as e:
        logger.error(f"BQ write-back load job failed: {e}")
        return {"status": "error", "error": str(e), "rows_attempted": len(rows)}

    # Update high-water mark
    await db.sync_metadata.update_one(
        {"_id": f"bq_write_sync_{'dry' if DRY_RUN else 'live'}"},
        {"$set": {"last_sync_at": now.isoformat(), "rows_synced": len(rows), "bq_job_id": load_job.job_id}},
        upsert=True,
    )

    return {"status": "ok", "rows_synced": len(rows), "bq_job_id": load_job.job_id}


# ---- Ensure Indexes ----

async def ensure_automation_indexes(db):
    """Create indexes for automation collections."""
    try:
        # Drop old single-field unique indexes if they exist (migrating to compound)
        try:
            await db.automated_actions.drop_index("job_id_1")
        except Exception:
            pass
        try:
            await db.scheduled_takedowns.drop_index("job_id_1")
        except Exception:
            pass

        # Compound unique: same job can have both dry_run and live records
        await db.automated_actions.create_index([("job_id", 1), ("dry_run", 1)], unique=True)
        await db.automated_actions.create_index("user_id")
        await db.automated_actions.create_index("tier")
        await db.automated_actions.create_index("status")
        await db.automated_actions.create_index("created_at")
        await db.automated_actions.create_index("dry_run")

        await db.scheduled_takedowns.create_index([("job_id", 1), ("dry_run", 1)], unique=True)
        await db.scheduled_takedowns.create_index("user_id")
        await db.scheduled_takedowns.create_index("status")
        await db.scheduled_takedowns.create_index([("status", 1), ("takedown_at", 1)])

        await db.exclusion_list.create_index("user_id")
        await db.exclusion_list.create_index("job_id")
        await db.exclusion_list.create_index("active")

        await db.pipeline_runs.create_index("timestamp")

        # Opus verdicts indexes
        await db.opus_verdicts.create_index([("job_id", 1), ("dry_run", 1)], unique=True)
        await db.opus_verdicts.create_index("reviewed_at")
    except Exception as e:
        logger.error(f"Automation index creation failed (non-fatal): {e}")
