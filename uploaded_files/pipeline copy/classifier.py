#!/usr/bin/env python3
"""
Stage 1: Phishing Classifier (LLM-as-Judge)

Uses GPT-5.2 with the phishing_classifier.md prompt to classify
screenshots for phishing indicators. If flagged, triggers Stage 2
escalation workflow.

All output is sent to the server for consolidated tracing.

Usage:
    python classifier.py <job_id>
    python classifier.py <job_id> --classify-only
"""

import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests
from dotenv import load_dotenv
from google.cloud import bigquery
from openai import OpenAI

# Load .env from pipeline directory
load_dotenv(Path(__file__).parent / ".env")

# =============================================================================
# CONFIGURATION
# =============================================================================

BQ_PROJECT = "emergent-default"
CLASSIFIER_PROMPT_PATH = Path(__file__).parent / "phishing_classifier.md"
SERVER_URL = "http://localhost:3456"

WHITECIRCLE_API_URL = "https://us.whitecircle.ai/api/session/check"
WHITECIRCLE_API_KEY = os.environ.get("WHITECIRCLE_API_KEY", "")
WHITECIRCLE_DEPLOYMENT_ID = os.environ.get("WHITECIRCLE_DEPLOYMENT_ID", "")

# =============================================================================
# END CONFIGURATION
# =============================================================================


def post_to_server(endpoint: str, payload: dict):
    """Post data to server for tracing. Silent on failure."""
    try:
        requests.post(f"{SERVER_URL}/api/{endpoint}", json=payload, timeout=5)
    except requests.RequestException:
        pass


def fetch_job_data(job_id: str) -> dict:
    """Fetch job data from BigQuery for classification."""
    client = bigquery.Client(project=BQ_PROJECT)
    query = """
        WITH x AS (
            SELECT
                ph.job_id, ph.image_url, ph.is_phishing, ph.confidence_score,
                ph.severity, ph.reason, ph.user_id, jj.task,
                DENSE_RANK() OVER (PARTITION BY ph.job_id ORDER BY ph.timestamp DESC) AS rnk
            FROM `hitl.PhishingClassification` ph
            RIGHT JOIN `analytics.jobs_full_view` jj ON ph.job_id = jj.id
            WHERE jj.id = @job_id
        )
        SELECT *
        FROM x
        WHERE rnk = 1
    """
    job_config = bigquery.QueryJobConfig(
        query_parameters=[bigquery.ScalarQueryParameter("job_id", "STRING", job_id)]
    )
    results = client.query(query, job_config=job_config).result()
    rows = list(results)
    if not rows:
        print(f"No data found for job_id: {job_id}")
        sys.exit(1)

    row = rows[0]
    return {
        "job_id": row.job_id,
        "image_url": row.image_url,
        "user_id": row.user_id or "Unknown",
        "task": row.task or "",
        "existing_classification": {
            "is_phishing": row.is_phishing,
            "confidence_score": float(row.confidence_score) if row.confidence_score is not None else None,
            "severity": row.severity,
            "reason": row.reason,
        }
    }


def load_system_prompt() -> str:
    """Load the phishing classifier system prompt from markdown file."""
    if not CLASSIFIER_PROMPT_PATH.exists():
        print(f"Classifier prompt not found: {CLASSIFIER_PROMPT_PATH}")
        sys.exit(1)
    return CLASSIFIER_PROMPT_PATH.read_text()


def classify(task_description: str, image_url: str) -> tuple[dict, str]:
    """Run the GPT-5.2 phishing classifier. Returns (parsed dict, raw output)."""
    client = OpenAI()
    system_prompt = load_system_prompt()

    user_content = []
    if task_description:
        user_content.append({
            "type": "text",
            "text": f"Task description: {task_description}"
        })
    if image_url:
        user_content.append({
            "type": "image_url",
            "image_url": {"url": image_url}
        })

    if not user_content:
        print("No task description or image URL available for classification")
        sys.exit(1)

    response = client.chat.completions.create(
        model="gpt-5.2",
        max_completion_tokens=2048,
        reasoning_effort="none",
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_content},
        ],
    )

    raw_output = response.choices[0].message.content
    usage = {
        "prompt_tokens": response.usage.prompt_tokens,
        "completion_tokens": response.usage.completion_tokens,
        "total_tokens": response.usage.total_tokens,
    } if response.usage else None

    # Extract JSON between <phishing_analysis> tags
    match = re.search(r"<phishing_analysis>(.*?)</phishing_analysis>", raw_output, re.DOTALL)
    if not match:
        json_str = raw_output.strip()
    else:
        json_str = match.group(1).strip()

    result = json.loads(json_str)
    result["_usage"] = usage
    return result, raw_output


def check_whitecircle(job_id: str, task_description: str, image_url: str) -> dict | None:
    """Call WhiteCircle API to check session. Returns response dict or None on failure."""
    if not WHITECIRCLE_API_KEY:
        return None

    content = []
    if task_description:
        content.append({"type": "input_text", "text": task_description})
    if image_url:
        content.append({"type": "input_image", "image_url": image_url})

    if not content:
        return None

    payload = {
        "external_session_id": job_id,
        "messages": [{"role": "user", "content": content}],
    }
    if WHITECIRCLE_DEPLOYMENT_ID:
        payload["deployment_id"] = WHITECIRCLE_DEPLOYMENT_ID

    headers = {
        "Authorization": f"Bearer {WHITECIRCLE_API_KEY}",
        "Content-Type": "application/json",
        "whitecircle-version": "2025-12-01",
    }

    try:
        resp = requests.post(WHITECIRCLE_API_URL, headers=headers, json=payload, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except requests.RequestException as e:
        print(f"WhiteCircle API error: {e}")
        return None


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Phishing classifier (Stage 1)")
    parser.add_argument("job_id", help="Job ID to classify")
    parser.add_argument("--classify-only", action="store_true",
                        help="Only classify, don't trigger escalation workflow")
    args = parser.parse_args()

    # Step 1: Fetch from BigQuery
    print(f"Fetching job data for {args.job_id}...")
    job_data = fetch_job_data(args.job_id)

    # Report job data to server
    post_to_server("pipeline-event", {
        "job_id": args.job_id,
        "event": "bigquery_fetch",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": {
            "user_id": job_data["user_id"],
            "image_url": job_data["image_url"],
            "task_preview": job_data["task"][:300],
            "existing_classification": job_data["existing_classification"],
        }
    })

    # Step 2: Run classifier
    print(f"Running GPT-5.2 classifier...")
    started_at = datetime.now(timezone.utc)
    classification, raw_output = classify(
        task_description=job_data["task"],
        image_url=job_data["image_url"],
    )
    finished_at = datetime.now(timezone.utc)
    elapsed = (finished_at - started_at).total_seconds()

    # Report classification to server
    post_to_server("classifier-result", {
        "job_id": args.job_id,
        "timestamp": finished_at.isoformat(),
        "classification": classification,
        "raw_output": raw_output,
        "elapsed_seconds": elapsed,
        "image_url": job_data["image_url"],
        "user_id": job_data["user_id"],
        "task_preview": job_data["task"][:300],
    })

    is_phishing = classification.get("result")
    print(f"Result: {'PHISHING' if is_phishing else 'LEGITIMATE'} (confidence={classification.get('confidence')})")

    # Step 2b: Run WhiteCircle check (parallel comparison)
    if WHITECIRCLE_API_KEY:
        print("Running WhiteCircle check...")
        wc_started = datetime.now(timezone.utc)
        wc_result = check_whitecircle(
            job_id=args.job_id,
            task_description=job_data["task"],
            image_url=job_data["image_url"],
        )
        wc_finished = datetime.now(timezone.utc)
        wc_elapsed = (wc_finished - wc_started).total_seconds()

        post_to_server("whitecircle-result", {
            "job_id": args.job_id,
            "timestamp": wc_finished.isoformat(),
            "result": wc_result,
            "elapsed_seconds": wc_elapsed,
            "error": None if wc_result else "API call failed",
        })

        if wc_result:
            print(f"WhiteCircle: {'FLAGGED' if wc_result.get('flagged') else 'CLEAR'}")
        else:
            print("WhiteCircle: ERROR (check server logs)")

    # Step 3: Always trigger escalation (for eval comparison)
    if args.classify_only:
        print("Skipping escalation (--classify-only)")
        return

    print("Triggering Stage 2 escalation...")

    # Report workflow trigger to server
    post_to_server("pipeline-event", {
        "job_id": args.job_id,
        "event": "escalation_triggered",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    from escalation_workflow import run
    classifier_output = {
        "result": classification.get("result"),
        "confidence": classification.get("confidence"),
        "reason": classification.get("reason"),
        "severity": classification.get("severity", "Unknown"),
        "image_url": job_data["image_url"],
        "user_id": job_data["user_id"],
    }
    run(args.job_id, classifier_result=classifier_output)
    print("Done.")


if __name__ == "__main__":
    main()
