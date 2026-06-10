#!/usr/bin/env python3
"""
Stage 2: Phishing Escalation Workflow

Triggers the agentic escalation analysis via the Agent SDK API.
Can be run standalone or imported by classifier.py.

Usage:
    python escalation_workflow.py <job_id>
    python escalation_workflow.py <job_id> --curl
    python escalation_workflow.py <job_id> --payload
"""

import json
import sys
import requests
from google.cloud import bigquery

# =============================================================================
# CONFIGURATION
# =============================================================================

PROMPT_ID = "phishing_escalation_agent"
API_URL = "http://canary-agentsdk.int.apis.emergentagent.com/api/v1/workflows/general/trigger"
CALLBACK_URL = "https://preataxic-adela-biologically.ngrok-free.dev/api/webhook"
MCP_SERVER_URL = "https://cortex-bugbuster.internal.emergent.host/api/mcp/job-analytics"
BQ_PROJECT = "emergent-default"

TIMEOUT_SECONDS = 330
THINKING_BUDGET = 10000

# These globals get populated by fetch_from_bigquery()
JOB_ID = None
USER_ID = None
IMAGE_URL = None
TASK_PROMPT = None

# =============================================================================
# END CONFIGURATION
# =============================================================================


def fetch_from_bigquery(job_id: str):
    """Fetch phishing classification from BigQuery and populate globals."""
    global JOB_ID, USER_ID, IMAGE_URL, TASK_PROMPT

    client = bigquery.Client(project=BQ_PROJECT)
    query = """
        WITH x AS (
            SELECT
                job_id, image_url, is_phishing, confidence_score, severity, reason, user_id,
                DENSE_RANK() OVER (PARTITION BY job_id ORDER BY timestamp DESC) AS rnk
            FROM `hitl.PhishingClassification`
            WHERE job_id = @job_id
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
        print(f"No phishing classification found for job_id: {job_id}")
        sys.exit(1)

    row = rows[0]
    JOB_ID = row.job_id
    USER_ID = row.user_id or "Unknown"
    IMAGE_URL = row.image_url

    is_phishing = row.is_phishing
    confidence = str(row.confidence_score) if row.confidence_score is not None else "Unknown"
    severity = row.severity or "Unknown"
    reason = row.reason or "Unknown"

    TASK_PROMPT = f'''## Agentic Phishing Escalation Analysis Request

You are a phishing escalation agent (Stage 2). Stage 1 has flagged this job as potentially malicious. Stage 1 is intentionally permissive and over-flags to maximize recall — many flagged jobs are legitimate. Your role is to determine whether this flag is a true positive or a false positive by gathering concrete evidence of end-user harm.

Only escalate to CONFIRMED_MALICIOUS when you find specific evidence of deception or harm. When in doubt, classify as NEEDS_HUMAN_REVIEW or LEGITIMATE.

### Initial Phishing Classification Result
The Stage 1 classifier flagged this job with the following results:
- **Result**: {is_phishing}
- **Confidence**: {confidence}
- **Severity**: {severity}
- **Reason**: {reason}

### Available Tools
You have the following tools at your disposal:
- job-analytics: To gather context about this job (task, metadata, user)
- hitl-interactions: To see user messages during the build session
- agent-trajectory: To see what the agent actually built (actions, code, function calls)
- Phishing_escalation_result: Submit your final analysis. MUST be called before completion.

### Instructions
1. Use ALL three MCP tools (job-analytics, agent-trajectory, hitl-interactions) to gather evidence
2. Evaluate the evidence against the harm assessment criteria in your system prompt
3. Distinguish between suspicious surface patterns and concrete evidence of end-user harm
4. Do NOT expand your scope beyond phishing and deception — regulatory, licensing, and compliance concerns are outside your mandate
5. Call the Phishing_escalation_result tool with your final findings

Be thorough but efficient in your analysis.'''

    print(f"Job ID:     {JOB_ID}")
    print(f"User ID:    {USER_ID}")
    print(f"Image URL:  {IMAGE_URL}")
    print(f"Is Phishing: {is_phishing}")
    print(f"Confidence: {confidence}")
    print(f"Severity:   {severity}")
    print(f"Reason:     {reason}")


def populate_from_classifier(job_id: str, user_id: str, image_url: str,
                              is_phishing: bool, confidence: str,
                              severity: str, reason: str):
    """Populate globals directly from classifier output (skip BigQuery)."""
    global JOB_ID, USER_ID, IMAGE_URL, TASK_PROMPT

    JOB_ID = job_id
    USER_ID = user_id
    IMAGE_URL = image_url

    TASK_PROMPT = f'''## Agentic Phishing Escalation Analysis Request

You are a phishing escalation agent (Stage 2). Stage 1 has flagged this job as potentially malicious. Stage 1 is intentionally permissive and over-flags to maximize recall — many flagged jobs are legitimate. Your role is to determine whether this flag is a true positive or a false positive by gathering concrete evidence of end-user harm.

Only escalate to CONFIRMED_MALICIOUS when you find specific evidence of deception or harm. When in doubt, classify as NEEDS_HUMAN_REVIEW or LEGITIMATE.

### Initial Phishing Classification Result
The Stage 1 classifier flagged this job with the following results:
- **Result**: {is_phishing}
- **Confidence**: {confidence}
- **Severity**: {severity}
- **Reason**: {reason}

### Available Tools
You have the following tools at your disposal:
- job-analytics: To gather context about this job (task, metadata, user)
- hitl-interactions: To see user messages during the build session
- agent-trajectory: To see what the agent actually built (actions, code, function calls)
- Phishing_escalation_result: Submit your final analysis. MUST be called before completion.

### Instructions
1. Use ALL three MCP tools (job-analytics, agent-trajectory, hitl-interactions) to gather evidence
2. Evaluate the evidence against the harm assessment criteria in your system prompt
3. Distinguish between suspicious surface patterns and concrete evidence of end-user harm
4. Call the Phishing_escalation_result tool with your final findings

Be thorough but efficient in your analysis.'''


def build_payload() -> dict:
    """
    Build the request payload with configured values.

    Returns:
        dict: The complete request payload.
    """
    return {
        "job_id": JOB_ID,
        "prompt_id": PROMPT_ID,
        "task": TASK_PROMPT,
        "mcp_server_urls": [MCP_SERVER_URL],
        "http_tools": [
            {
                "name": "Phishing_escalation_result",
                "description": "Submit phishing escalation analysis results. Call this tool when you have completed your analysis of the phishing incident. MUST CALL THIS TOOL before completion/ending",
                "url": CALLBACK_URL,
                "method": "POST",
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "job_id": {
                            "type": "string",
                            "description": "The job ID being analyzed",
                            "const": JOB_ID
                        },
                        "user_id": {
                            "type": "string",
                            "description": "The user ID",
                            "const": USER_ID
                        },
                        "created_at": {
                            "type": "string",
                            "format": "date-time",
                            "description": "ISO timestamp of when analysis was created"
                        },
                        "image_url": {
                            "type": ["string", "null"],
                            "description": "URL of the analyzed image",
                            "const": IMAGE_URL
                        },
                        "image_analyzed": {
                            "type": ["boolean", "null"],
                            "description": "Whether image was analyzed"
                        },
                        "status": {
                            "type": "string",
                            "description": "Current status of the escalation analysis"
                        },
                        "image_analysis_note": {
                            "type": ["string", "null"],
                            "description": "Notes about image analysis"
                        },
                        "what_was_built": {
                            "type": "string",
                            "description": "Description of what was built by the user"
                        },
                        "harm_assessment": {
                            "type": "object",
                            "description": "Detailed harm assessment",
                            "properties": {
                                "credential_theft": {
                                    "type": "object",
                                    "properties": {
                                        "detected": {"type": "boolean"},
                                        "details": {"type": ["string", "null"]}
                                    },
                                    "required": ["detected"]
                                },
                                "deceptive_exfiltration": {
                                    "type": "object",
                                    "properties": {
                                        "detected": {"type": "boolean"},
                                        "details": {"type": ["string", "null"]}
                                    },
                                    "required": ["detected"]
                                },
                                "user_deceived": {
                                    "type": "object",
                                    "properties": {
                                        "detected": {"type": "boolean"},
                                        "details": {"type": ["string", "null"]}
                                    },
                                    "required": ["detected"]
                                },
                                "tool_for_scale_harm": {
                                    "type": "object",
                                    "properties": {
                                        "detected": {"type": "boolean"},
                                        "details": {"type": ["string", "null"]}
                                    },
                                    "required": ["detected"]
                                },
                                "service_replication": {
                                    "type": "object",
                                    "properties": {
                                        "detected": {"type": "boolean"},
                                        "details": {"type": ["string", "null"]}
                                    },
                                    "required": ["detected"]
                                }
                            },
                            "required": ["credential_theft", "deceptive_exfiltration", "user_deceived",
                                         "tool_for_scale_harm", "service_replication"]
                        },
                        "tool_findings": {
                            "type": "object",
                            "properties": {
                                "job_details": {
                                    "type": "object",
                                    "properties": {
                                        "called": {"type": "boolean"},
                                        "success": {"type": "boolean"},
                                        "task_description": {"type": ["string", "null"]},
                                        "model_used": {"type": ["string", "null"]},
                                        "key_findings": {"type": "array", "items": {"type": "string"}},
                                        "error": {"type": ["string", "null"]}
                                    },
                                    "required": ["called", "success"]
                                },
                                "agent_trajectory": {
                                    "type": "object",
                                    "properties": {
                                        "called": {"type": "boolean"},
                                        "success": {"type": "boolean"},
                                        "total_steps": {"type": ["string", "null"]},
                                        "key_findings": {"type": "array", "items": {"type": "string"}},
                                        "suspicious_actions": {"type": "array", "items": {"type": "string"}},
                                        "external_urls_detected": {"type": "array", "items": {"type": "string"}},
                                        "error": {"type": ["string", "null"]}
                                    },
                                    "required": ["called", "success"]
                                },
                                "hitl_interactions": {
                                    "type": "object",
                                    "properties": {
                                        "called": {"type": "boolean"},
                                        "success": {"type": "boolean"},
                                        "total_interactions": {"type": ["string", "null"]},
                                        "key_findings": {"type": "array", "items": {"type": "string"}},
                                        "notable_quotes": {
                                            "type": "array",
                                            "items": {
                                                "type": "object",
                                                "properties": {
                                                    "quote": {"type": "string"},
                                                    "translation": {"type": ["string", "null"]},
                                                    "significance": {"type": "string"}
                                                },
                                                "required": ["quote", "significance"]
                                            }
                                        },
                                        "error": {"type": ["string", "null"]}
                                    },
                                    "required": ["called", "success"]
                                }
                            },
                            "required": ["job_details", "agent_trajectory", "hitl_interactions"]
                        },
                        "classification": {
                            "type": "object",
                            "properties": {
                                "label": {
                                    "type": "string",
                                    "enum": ["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW", "LEGITIMATE"]
                                },
                                "category": {"type": "string"},
                                "severity": {
                                    "type": "string",
                                    "enum": ["CRITICAL", "HIGH", "MODERATE", "LOW", "N/A"]
                                },
                                "end_user_harm_confirmed": {"type": ["boolean", "null"]},
                                "confidence": {
                                    "type": "string",
                                    "enum": ["HIGH", "MEDIUM", "LOW"]
                                },
                                "reasoning": {"type": "string"}
                            },
                            "required": ["label", "category", "severity", "confidence", "reasoning"]
                        },
                        "recommended_actions": {
                            "type": "array",
                            "items": {"type": "string"}
                        },
                        "slack_summary": {
                            "type": "object",
                            "properties": {
                                "emoji": {"type": "string"},
                                "headline": {"type": "string"},
                                "verdict": {"type": "string"}
                            },
                            "required": ["emoji", "headline", "verdict"]
                        }
                    },
                    "required": [
                        "job_id", "user_id", "created_at", "what_was_built",
                        "harm_assessment", "classification", "tool_findings",
                        "recommended_actions", "slack_summary"
                    ]
                }
            }
        ],
        "thinking_budget": THINKING_BUDGET,
        "should_restart_environment": False
    }


def send_request():
    payload = build_payload()
    headers = {"Content-Type": "application/json"}

    print("\n" + "=" * 60)
    print("STAGE 2: Sending escalation request...")
    print("=" * 60)

    try:
        response = requests.post(
            API_URL,
            headers=headers,
            json=payload,
            timeout=TIMEOUT_SECONDS
        )

        print(f"\nStatus Code: {response.status_code}")
        print("-" * 60)

        try:
            response_json = response.json()
            print("Response JSON:")
            print(json.dumps(response_json, indent=2))
            return response_json
        except json.JSONDecodeError:
            print("Response Text:")
            print(response.text)
            return None

    except requests.Timeout:
        print(f"\nRequest timed out after {TIMEOUT_SECONDS} seconds")
        return None
    except requests.RequestException as e:
        print(f"\nRequest failed: {e}")
        return None


def run(job_id: str, classifier_result: dict = None):
    """Run the full escalation workflow. Called by classifier.py or standalone."""
    if classifier_result:
        populate_from_classifier(
            job_id=job_id,
            user_id=classifier_result.get("user_id", "Unknown"),
            image_url=classifier_result.get("image_url"),
            is_phishing=classifier_result.get("result"),
            confidence=str(classifier_result.get("confidence", "Unknown")),
            severity=classifier_result.get("severity", "Unknown"),
            reason=classifier_result.get("reason", "Unknown"),
        )
    else:
        print(f"Fetching phishing classification for {job_id} from BigQuery...\n")
        fetch_from_bigquery(job_id)

    return send_request()


def print_curl_command():
    payload = build_payload()
    print("\n" + "=" * 60)
    print("EQUIVALENT CURL COMMAND:")
    print("=" * 60)
    print(f"""
curl -X POST "{API_URL}" \\
  -H "Content-Type: application/json" \\
  --max-time {TIMEOUT_SECONDS} \\
  -d '{json.dumps(payload)}'
""")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Phishing escalation workflow (Stage 2)")
    parser.add_argument("job_id", help="Job ID to analyze")
    parser.add_argument("--curl", action="store_true", help="Print curl command instead of sending request")
    parser.add_argument("--payload", action="store_true", help="Print payload JSON only")
    args = parser.parse_args()

    print(f"Fetching phishing classification for {args.job_id} from BigQuery...\n")
    fetch_from_bigquery(args.job_id)

    if args.curl:
        print_curl_command()
    elif args.payload:
        print(json.dumps(build_payload(), indent=2))
    else:
        send_request()
