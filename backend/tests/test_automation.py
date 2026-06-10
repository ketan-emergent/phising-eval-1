"""Tests for automation.py — tier classification, MCP error check, policy formatting."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from automation import classify_tier, has_mcp_error, format_policies, deduplicate_jobs, _has_actionable_signals


# ---- Policy Formatting ----

def test_format_single_policy():
    assert format_policies("CREDENTIAL_PHISHING") == "Credential Phishing"

def test_format_multiple_comma_separated():
    result = format_policies("CREDENTIAL_PHISHING, FINANCIAL_HARVESTING, BRAND_IMPERSONATION")
    assert result == "Credential Phishing + Financial Harvesting + Brand Impersonation"

def test_format_comma_no_spaces():
    result = format_policies("CRYPTO_WALLET_DRAINER,INVESTMENT_FRAUD,CREDENTIAL_PHISHING")
    assert result == "Crypto Wallet Drainer + Investment Fraud + Credential Phishing"

def test_format_plus_separated():
    result = format_policies("CREDENTIAL_PHISHING + BRAND_IMPERSONATION + FINANCIAL_HARVESTING")
    assert result == "Credential Phishing + Brand Impersonation + Financial Harvesting"

def test_format_plus_no_spaces():
    result = format_policies("CREDENTIAL_PHISHING+FINANCIAL_HARVESTING")
    assert result == "Credential Phishing + Financial Harvesting"

def test_format_slash_separated():
    result = format_policies("DOCUMENT_FRAUD / CREDENTIAL_PHISHING / BRAND_IMPERSONATION")
    assert result == "Document Fraud + Credential Phishing + Brand Impersonation"

def test_format_slash_no_spaces():
    result = format_policies("MALWARE_DELIVERY/TOOL_FOR_SCALE_HARM")
    assert result == "Malware Delivery + Tool For Scale Harm"

def test_format_unknown_policy():
    result = format_policies("SOME_NEW_CATEGORY")
    assert result == "Some New Category"

def test_format_empty():
    assert format_policies("") == ""
    assert format_policies(None) == ""

def test_format_all_categories():
    """Verify all known categories have labels."""
    from automation import POLICY_LABELS
    for key, label in POLICY_LABELS.items():
        assert format_policies(key) == label, f"Mismatch for {key}"

# Real BQ data samples
def test_format_real_bq_row1():
    assert format_policies("CREDENTIAL_PHISHING, FINANCIAL_HARVESTING, BRAND_IMPERSONATION") == \
        "Credential Phishing + Financial Harvesting + Brand Impersonation"

def test_format_real_bq_row5():
    assert format_policies("MALWARE_DELIVERY / TOOL_FOR_SCALE_HARM") == \
        "Malware Delivery + Tool For Scale Harm"

def test_format_real_bq_row7():
    assert format_policies("ADVANCE_FEE_FRAUD / BRAND_IMPERSONATION / CREDENTIAL_PHISHING") == \
        "Advance Fee Fraud + Brand Impersonation + Credential Phishing"

def test_format_real_bq_row10():
    assert format_policies("CREDENTIAL_PHISHING / GOVERNMENT_IMPERSONATION") == \
        "Credential Phishing + Government Impersonation"

def test_format_real_bq_row15():
    assert format_policies("DATA_EXFILTRATION + UNAUTHORIZED_ACCESS + CREDENTIAL_PHISHING") == \
        "Data Exfiltration + Unauthorized Access + Credential Phishing"

def test_format_real_bq_row18():
    assert format_policies("SCAREWARE / CREDENTIAL_PHISHING") == \
        "Scareware + Credential Phishing"

def test_format_real_bq_row20():
    assert format_policies("CREDENTIAL_THEFT + MALWARE_DELIVERY") == \
        "Credential Theft + Malware Delivery"

def test_format_real_bq_row4():
    assert format_policies("PAYMENT_FRAUD_AUTOMATION / FINANCIAL_HARVESTING / CREDENTIAL_PHISHING") == \
        "Payment Fraud Automation + Financial Harvesting + Credential Phishing"


# ---- MCP Error Failsafe ----

def test_mcp_no_error_all_called_and_success():
    job = {
        "agent_trajectory_called": True, "agent_trajectory_success": True,
        "hitl_interactions_called": True, "hitl_interactions_success": True,
        "job_details_called": True, "job_details_success": True,
    }
    assert has_mcp_error(job) is False

def test_mcp_no_error_fields_missing():
    """Missing fields default to True (COALESCE behavior) — no error."""
    job = {}
    assert has_mcp_error(job) is False

def test_mcp_error_agent_trajectory_not_called():
    job = {"agent_trajectory_called": False}
    assert has_mcp_error(job) is True

def test_mcp_error_agent_trajectory_failed():
    job = {"agent_trajectory_called": True, "agent_trajectory_success": False}
    assert has_mcp_error(job) is True

def test_mcp_error_hitl_not_called():
    job = {"hitl_interactions_called": False}
    assert has_mcp_error(job) is True

def test_mcp_error_job_details_failed():
    job = {"job_details_called": True, "job_details_success": False}
    assert has_mcp_error(job) is True

def test_mcp_error_multiple_failures():
    job = {
        "agent_trajectory_called": False,
        "hitl_interactions_success": False,
        "job_details_called": False,
    }
    assert has_mcp_error(job) is True

def test_mcp_none_values_treated_as_no_error():
    """None means COALESCE to true — no error."""
    job = {
        "agent_trajectory_called": None,
        "hitl_interactions_called": None,
        "job_details_called": None,
    }
    assert has_mcp_error(job) is False


# ---- Tier Classification ----

def _make_job(**overrides):
    """Helper to create a bq_jobs-like dict with defaults."""
    base = {
        "job_id": "test-job-001",
        "user_id": "test-user-001",
        "classification_label": "CONFIRMED_MALICIOUS",
        "classification_confidence": "HIGH",
        "classification_severity": "CRITICAL",
        "classification_category": "CREDENTIAL_PHISHING",
        "ltv": 0,
        "credential_theft_detected": True,
        "deceptive_exfiltration_detected": True,
        "service_replication_detected": True,
        "tool_for_scale_harm_detected": False,
        "user_deceived_detected": False,
    }
    base.update(overrides)
    return base


# --- Tier 1: Auto Takedown ---

def test_tier1_confirmed_high_critical_3signals_free():
    """Classic Tier 1: CONFIRMED_MALICIOUS + HIGH + CRITICAL + ≥3 signals + LTV=0."""
    job = _make_job()  # defaults: 3 harm signals (cred, deceptive, service), LTV=0
    assert classify_tier(job) == 1

def test_tier1_high_severity():
    """HIGH severity also qualifies for Tier 1."""
    job = _make_job(classification_severity="HIGH")
    assert classify_tier(job) == 1

def test_tier1_all_5_signals():
    job = _make_job(
        tool_for_scale_harm_detected=True,
        user_deceived_detected=True,
    )
    assert classify_tier(job) == 1


# --- Tier 2: Remaining CONFIRMED_MALICIOUS ---

def test_tier1_paid_user_under_299():
    """Paid user (LTV <= 299) → Tier 1 if all other criteria match."""
    job = _make_job(ltv=49.99)
    assert classify_tier(job) == 1

def test_tier2_confirmed_but_paid_user_over_299():
    """Paid user (LTV > 299) → Tier 2 even if all other criteria match Tier 1."""
    job = _make_job(ltv=499.99)
    assert classify_tier(job) == 2

def test_tier2_confirmed_medium_confidence():
    """MEDIUM confidence → Tier 2."""
    job = _make_job(classification_confidence="MEDIUM")
    assert classify_tier(job) == 2

def test_tier2_confirmed_moderate_severity():
    """MODERATE severity → Tier 2."""
    job = _make_job(classification_severity="MODERATE")
    assert classify_tier(job) == 2

def test_tier2_confirmed_only_2_signals():
    """Only 2 harm signals → Tier 2."""
    job = _make_job(service_replication_detected=False)  # Now only 2: cred + deceptive
    assert classify_tier(job) == 2

def test_tier2_confirmed_low_severity():
    job = _make_job(classification_severity="LOW")
    assert classify_tier(job) == 2


# --- Tier 2b: NHR + Free + actionable signals ---

def test_tier2b_nhr_free_with_credential_theft():
    """NHR + Free + actionable boolean → Tier 2."""
    job = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        credential_theft_detected=True,
        deceptive_exfiltration_detected=False,
        service_replication_detected=False,
    )
    assert classify_tier(job) == 2

def test_tier2b_nhr_free_with_user_deceived():
    job = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        credential_theft_detected=False,
        deceptive_exfiltration_detected=False,
        service_replication_detected=False,
        user_deceived_detected=True,
    )
    assert classify_tier(job) == 2

def test_tier2b_nhr_free_cat_rescue_no_booleans():
    """NHR + Free + no boolean signals but high-risk category → Tier 2."""
    job = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        classification_category="CREDENTIAL_PHISHING",
        credential_theft_detected=False,
        deceptive_exfiltration_detected=False,
        service_replication_detected=False,
        tool_for_scale_harm_detected=False,
        user_deceived_detected=False,
    )
    assert classify_tier(job) == 2

def test_tier2b_nhr_free_cat_rescue_investment():
    """NHR + Free + INVESTMENT_FRAUD category → Tier 2 (cat rescue)."""
    job = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        classification_category="INVESTMENT_FRAUD",
        credential_theft_detected=False,
        deceptive_exfiltration_detected=False,
        service_replication_detected=False,
        tool_for_scale_harm_detected=False,
        user_deceived_detected=False,
    )
    assert classify_tier(job) == 2


# --- Tier 3: Human Review — NHR + Paid + actionable ---

def test_tier3_nhr_paid_with_credential_theft():
    """NHR + Paid (LTV>0) + actionable boolean → Tier 3."""
    job = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        ltv=49.99,
        credential_theft_detected=True,
        deceptive_exfiltration_detected=False,
        service_replication_detected=False,
    )
    assert classify_tier(job) == 3

def test_tier3_nhr_paid_with_tool_for_scale_harm():
    job = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        ltv=100,
        credential_theft_detected=False,
        deceptive_exfiltration_detected=False,
        service_replication_detected=False,
        tool_for_scale_harm_detected=True,
    )
    assert classify_tier(job) == 3

def test_tier3_nhr_paid_cat_rescue():
    """NHR + Paid + no booleans but high-risk cat → Tier 3."""
    job = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        ltv=200,
        classification_category="CRYPTO_WALLET_DRAINER",
        credential_theft_detected=False,
        deceptive_exfiltration_detected=False,
        service_replication_detected=False,
        tool_for_scale_harm_detected=False,
        user_deceived_detected=False,
    )
    assert classify_tier(job) == 3

def test_tier3_nhr_paid_deceptive_exfil():
    job = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        ltv=50,
        credential_theft_detected=False,
        deceptive_exfiltration_detected=True,
        service_replication_detected=False,
    )
    assert classify_tier(job) == 3


# --- Tier 4: Do Nothing ---

def test_tier4_nhr_zero_signals_no_cat():
    """NHR + zero signals + non-risky category → Tier 4."""
    job = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        classification_category="SERVICE_REPLICATION",
        credential_theft_detected=False,
        deceptive_exfiltration_detected=False,
        service_replication_detected=False,
        tool_for_scale_harm_detected=False,
        user_deceived_detected=False,
    )
    assert classify_tier(job) == 4

def test_tier4_nhr_only_service_replication_no_cat():
    """Only service_replication + non-risky category → Tier 4."""
    job = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        classification_category="SERVICE_REPLICATION",
        credential_theft_detected=False,
        deceptive_exfiltration_detected=False,
        service_replication_detected=True,
        tool_for_scale_harm_detected=False,
        user_deceived_detected=False,
    )
    assert classify_tier(job) == 4

def test_tier4_no_label():
    """No classification_label → Tier 4."""
    job = _make_job(classification_label=None)
    assert classify_tier(job) == 4


# --- Tier 5: Legitimate ---

def test_tier5_legitimate_label():
    """LEGITIMATE label → Tier 5."""
    job = _make_job(classification_label="LEGITIMATE")
    assert classify_tier(job) == 5


# ---- Edge Cases ----

def test_tier1_ltv_none_treated_as_zero():
    """LTV=None should be treated as 0 (free user)."""
    job = _make_job(ltv=None)
    assert classify_tier(job) == 1

def test_tier1_ltv_string_zero():
    """LTV as string '0' should still be Tier 1."""
    job = _make_job(ltv="0")
    assert classify_tier(job) == 1

def test_tier1_ltv_string_under_299():
    """LTV as string <= 299 should be Tier 1."""
    job = _make_job(ltv="100")
    assert classify_tier(job) == 1

def test_tier2_ltv_string_over_299():
    """LTV as string > 299 should be Tier 2."""
    job = _make_job(ltv="500")
    assert classify_tier(job) == 2

def test_tier2_nhr_free_service_replication_plus_actionable():
    """NHR + Free + service_replication + actionable bool → Tier 2."""
    job = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        credential_theft_detected=True,
        deceptive_exfiltration_detected=False,
        service_replication_detected=True,
    )
    assert classify_tier(job) == 2

def test_tier3_nhr_paid_service_replication_plus_actionable():
    """NHR + Paid + service_replication + actionable bool → Tier 3."""
    job = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        ltv=75,
        credential_theft_detected=True,
        deceptive_exfiltration_detected=False,
        service_replication_detected=True,
    )
    assert classify_tier(job) == 3


# ---- Category Regex (actionable signal) ----

def test_actionable_signals_bool_only():
    job = _make_job(
        classification_category="CAPTCHA_MANIPULATION",
        credential_theft_detected=True,
    )
    assert _has_actionable_signals(job) is True

def test_actionable_signals_cat_only():
    """No bool signals but high-risk category → actionable."""
    job = _make_job(
        classification_category="FINANCIAL_HARVESTING",
        credential_theft_detected=False,
        deceptive_exfiltration_detected=False,
        tool_for_scale_harm_detected=False,
        user_deceived_detected=False,
    )
    assert _has_actionable_signals(job) is True

def test_actionable_signals_cat_not_matching():
    """Non-risky category + no booleans → not actionable."""
    job = _make_job(
        classification_category="CAPTCHA_MANIPULATION",
        credential_theft_detected=False,
        deceptive_exfiltration_detected=False,
        tool_for_scale_harm_detected=False,
        user_deceived_detected=False,
    )
    assert _has_actionable_signals(job) is False

def test_actionable_signals_cat_multi_keyword():
    """Category with multiple keywords, one matches → actionable."""
    job = _make_job(
        classification_category="CAPTCHA_MANIPULATION / CREDENTIAL_PHISHING",
        credential_theft_detected=False,
        deceptive_exfiltration_detected=False,
        tool_for_scale_harm_detected=False,
        user_deceived_detected=False,
    )
    assert _has_actionable_signals(job) is True


# ---- Deduplication ----

def test_dedup_single_job():
    jobs = [_make_job(job_id="j1")]
    assert len(deduplicate_jobs(jobs)) == 1

def test_dedup_same_job_cm_wins_over_nhr():
    """CM is more severe than NHR → CM row kept."""
    jobs = [
        _make_job(job_id="j1", classification_label="NEEDS_HUMAN_REVIEW"),
        _make_job(job_id="j1", classification_label="CONFIRMED_MALICIOUS"),
    ]
    result = deduplicate_jobs(jobs)
    assert len(result) == 1
    assert result[0]["classification_label"] == "CONFIRMED_MALICIOUS"

def test_dedup_same_job_cm_wins_over_legitimate():
    jobs = [
        _make_job(job_id="j1", classification_label="LEGITIMATE"),
        _make_job(job_id="j1", classification_label="CONFIRMED_MALICIOUS"),
    ]
    result = deduplicate_jobs(jobs)
    assert len(result) == 1
    assert result[0]["classification_label"] == "CONFIRMED_MALICIOUS"

def test_dedup_same_job_nhr_wins_over_legitimate():
    jobs = [
        _make_job(job_id="j1", classification_label="LEGITIMATE"),
        _make_job(job_id="j1", classification_label="NEEDS_HUMAN_REVIEW"),
    ]
    result = deduplicate_jobs(jobs)
    assert len(result) == 1
    assert result[0]["classification_label"] == "NEEDS_HUMAN_REVIEW"

def test_dedup_same_label_higher_severity_wins():
    """Same label, CRITICAL beats HIGH."""
    jobs = [
        _make_job(job_id="j1", classification_severity="HIGH"),
        _make_job(job_id="j1", classification_severity="CRITICAL"),
    ]
    result = deduplicate_jobs(jobs)
    assert len(result) == 1
    assert result[0]["classification_severity"] == "CRITICAL"

def test_dedup_different_jobs_kept():
    jobs = [
        _make_job(job_id="j1"),
        _make_job(job_id="j2"),
        _make_job(job_id="j3"),
    ]
    assert len(deduplicate_jobs(jobs)) == 3



# ---- Exclusion Matching ----

from automation import check_exclusion_match

def test_exclusion_match_by_user_id():
    """User-level exclusion blocks the job."""
    exclusions = [{"user_id": "u1", "active": True}]
    assert check_exclusion_match("j1", "u1", exclusions) is True

def test_exclusion_match_by_job_id():
    """Job-level exclusion blocks even without matching user_id."""
    exclusions = [{"job_id": "j1", "active": True}]
    assert check_exclusion_match("j1", "u999", exclusions) is True

def test_exclusion_no_match():
    """No matching exclusion → not blocked."""
    exclusions = [{"user_id": "u2", "active": True}, {"job_id": "j2", "active": True}]
    assert check_exclusion_match("j1", "u1", exclusions) is False

def test_exclusion_inactive_ignored():
    """Inactive exclusion does not block."""
    exclusions = [{"user_id": "u1", "active": False}, {"job_id": "j1", "active": False}]
    assert check_exclusion_match("j1", "u1", exclusions) is False

def test_exclusion_job_id_only_no_user_id():
    """Job-id-only exclusion (no user_id in exclusion doc) still matches."""
    exclusions = [{"job_id": "j1", "active": True}]
    assert check_exclusion_match("j1", None, exclusions) is True

def test_exclusion_user_id_only_no_job_id():
    """User-id-only exclusion (no job_id in exclusion doc) matches any job from that user."""
    exclusions = [{"user_id": "u1", "active": True}]
    assert check_exclusion_match("j999", "u1", exclusions) is True

def test_exclusion_empty_list():
    """Empty exclusion list → not blocked."""
    assert check_exclusion_match("j1", "u1", []) is False

def test_exclusion_multiple_one_matches():
    """Multiple exclusions, only one matches → blocked."""
    exclusions = [
        {"user_id": "u2", "active": True},
        {"job_id": "j1", "active": True},
        {"user_id": "u3", "job_id": "j3", "active": True},
    ]
    assert check_exclusion_match("j1", "u1", exclusions) is True

def test_exclusion_both_user_and_job_in_doc():
    """Exclusion doc has both user_id and job_id — matches if either matches."""
    exclusions = [{"user_id": "u1", "job_id": "j2", "active": True}]
    # Matches by user_id
    assert check_exclusion_match("j999", "u1", exclusions) is True
    # Matches by job_id
    assert check_exclusion_match("j2", "u999", exclusions) is True
    # Neither matches
    assert check_exclusion_match("j999", "u999", exclusions) is False

def test_exclusion_only_applies_to_tier1_and_tier2():
    """Verify that tiers 3/4/5 would NOT be checked for exclusion (classification test)."""
    # Tier 3 job — NHR + paid + actionable
    job_t3 = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW", ltv=100,
        credential_theft_detected=True, deceptive_exfiltration_detected=False,
        service_replication_detected=False,
    )
    assert classify_tier(job_t3) == 3  # exclusion check skipped for tier 3

    # Tier 4 job
    job_t4 = _make_job(
        classification_label="NEEDS_HUMAN_REVIEW",
        classification_category="SERVICE_REPLICATION",
        credential_theft_detected=False, deceptive_exfiltration_detected=False,
        service_replication_detected=False, tool_for_scale_harm_detected=False,
        user_deceived_detected=False,
    )
    assert classify_tier(job_t4) == 4  # exclusion check skipped for tier 4

    # Tier 5 job
    job_t5 = _make_job(classification_label="LEGITIMATE")
    assert classify_tier(job_t5) == 5  # exclusion check skipped for tier 5

def test_exclusion_tier1_would_be_checked():
    """Tier 1 jobs should be subject to exclusion checking."""
    job = _make_job()  # defaults = tier 1
    assert classify_tier(job) == 1
    # If user is excluded, it would be caught
    exclusions = [{"user_id": "test-user-001", "active": True}]
    assert check_exclusion_match(job["job_id"], job["user_id"], exclusions) is True

def test_exclusion_tier2_would_be_checked():
    """Tier 2 jobs should be subject to exclusion checking."""
    job = _make_job(ltv=499.99)  # paid > 299 → tier 2
    assert classify_tier(job) == 2
    exclusions = [{"job_id": "test-job-001", "active": True}]
    assert check_exclusion_match(job["job_id"], job["user_id"], exclusions) is True
