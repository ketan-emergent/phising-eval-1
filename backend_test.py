#!/usr/bin/env python3
"""
Backend API Testing for Phishing Eval UI
Tests verdicts, takedowns, pending count, and other production endpoints
"""

import requests
import json
import sys
from datetime import datetime

class PhishingEvalTester:
    def __init__(self):
        self.base_url = "https://phishing-eval-1.preview.emergentagent.com"
        self.session_token = "test_session_1771696765122"
        self.tests_run = 0
        self.tests_passed = 0
        self.session = requests.Session()
        self.session.cookies.set('session_token', self.session_token)

    def log(self, message):
        print(f"[{datetime.now().strftime('%H:%M:%S')}] {message}")

    def run_test(self, name, method, endpoint, expected_status, data=None, check_response=None):
        """Run a single API test"""
        url = f"{self.base_url}/api/{endpoint}"
        headers = {'Content-Type': 'application/json'}
        
        self.tests_run += 1
        self.log(f"🔍 Testing {name}...")
        
        try:
            if method == 'GET':
                response = self.session.get(url, headers=headers)
            elif method == 'POST':
                response = self.session.post(url, json=data, headers=headers)
            else:
                response = self.session.request(method, url, json=data, headers=headers)

            success = response.status_code == expected_status
            if success:
                self.tests_passed += 1
                self.log(f"✅ {name} - Status: {response.status_code}")
                
                # Additional response checks
                if check_response and response.status_code < 400:
                    try:
                        response_data = response.json()
                        check_success = check_response(response_data)
                        if not check_success:
                            self.log(f"❌ {name} - Response check failed")
                            success = False
                            self.tests_passed -= 1
                    except Exception as e:
                        self.log(f"❌ {name} - Response check error: {e}")
                        success = False
                        self.tests_passed -= 1
            else:
                self.log(f"❌ {name} - Expected {expected_status}, got {response.status_code}")
                if response.status_code >= 400:
                    try:
                        self.log(f"   Error details: {response.json()}")
                    except:
                        self.log(f"   Error body: {response.text[:200]}")

            return success, response.json() if success and response.content else {}

        except Exception as e:
            self.log(f"❌ {name} - Exception: {str(e)}")
            return False, {}

    def test_health_check(self):
        """Test basic health endpoint"""
        return self.run_test(
            "Health Check",
            "GET", 
            "health",
            200,
            check_response=lambda r: "status" in r and r["status"] == "ok"
        )

    def test_auth_me(self):
        """Test authentication with session token"""
        return self.run_test(
            "Auth Me",
            "GET",
            "auth/me", 
            200,
            check_response=lambda r: "email" in r
        )

    def test_get_prod_jobs(self):
        """Test GET /api/prod/jobs - loads saved verdicts"""
        success, response = self.run_test(
            "Get Production Jobs",
            "GET",
            "prod/jobs?limit=5",
            200,
            check_response=lambda r: "jobs" in r and isinstance(r["jobs"], list)
        )
        
        if success and response:
            jobs = response.get("jobs", [])
            self.log(f"   Retrieved {len(jobs)} jobs")
            
            # Check if jobs have expected fields including human_verdict_s2
            for job in jobs[:2]:  # Check first 2 jobs
                if "human_verdict_s2" in job:
                    self.log(f"   ✅ Job {job.get('job_id', 'unknown')} has human_verdict_s2 field")
                else:
                    self.log(f"   ⚠️  Job {job.get('job_id', 'unknown')} missing human_verdict_s2 field")
            
            return jobs
        
        return []

    def test_save_verdict(self, job_id, verdict_s2="correct"):
        """Test POST /api/prod/verdict/{job_id} - saves verdict_s2"""
        if not job_id:
            self.log("❌ No job_id provided for verdict test")
            return False, {}
            
        return self.run_test(
            f"Save S2 Verdict for {job_id}",
            "POST",
            f"prod/verdict/{job_id}",
            200,
            data={"verdict_s2": verdict_s2},
            check_response=lambda r: "status" in r and r["status"] == "ok"
        )

    def test_takedown_job(self, job_id, task_preview="", s2_label=""):
        """Test POST /api/prod/takedown/{job_id}"""
        if not job_id:
            self.log("❌ No job_id provided for takedown test")
            return False, {}
            
        return self.run_test(
            f"Takedown Job {job_id}",
            "POST",
            f"prod/takedown/{job_id}",
            200,
            data={
                "task_preview": task_preview,
                "s2_label": s2_label
            },
            check_response=lambda r: "status" in r and r["status"] == "ok" and "takedown_info" in r
        )

    def test_get_takedowns(self):
        """Test GET /api/prod/takedowns"""
        success, response = self.run_test(
            "Get Takedowns List",
            "GET",
            "prod/takedowns",
            200,
            check_response=lambda r: "takedowns" in r and isinstance(r["takedowns"], list)
        )
        
        if success and response:
            takedowns = response.get("takedowns", [])
            self.log(f"   Found {len(takedowns)} takedowns")
            
            # Check takedown record structure
            for takedown in takedowns[:2]:
                required_fields = ["job_id", "taken_down_by", "taken_down_at"]
                missing = [f for f in required_fields if f not in takedown]
                if not missing:
                    self.log(f"   ✅ Takedown record complete: {takedown.get('job_id')}")
                else:
                    self.log(f"   ⚠️  Missing fields in takedown: {missing}")
                    
        return response.get("takedowns", []) if success else []

    def test_pending_review_count(self):
        """Test GET /api/prod/pending-review-count"""
        success, response = self.run_test(
            "Pending Review Count",
            "GET",
            "prod/pending-review-count",
            200,
            check_response=lambda r: "count" in r and isinstance(r["count"], int)
        )
        
        if success and response:
            count = response.get("count", 0)
            self.log(f"   Pending review count: {count}")
            
        return response.get("count", 0) if success else 0

    def run_comprehensive_test(self):
        """Run all tests in sequence"""
        self.log("🚀 Starting Phishing Eval Backend Testing")
        self.log("="*50)
        
        # 1. Health and Auth
        health_ok, _ = self.test_health_check()
        auth_ok, _ = self.test_auth_me()
        
        if not auth_ok:
            self.log("❌ Authentication failed - cannot proceed with protected endpoints")
            return False
            
        # 2. Get production jobs and check for saved verdicts
        jobs = self.test_get_prod_jobs()
        
        # 3. Test verdict saving if we have jobs
        test_job_id = None
        if jobs:
            # Find a job we can test verdict on
            for job in jobs:
                stage_2 = job.get("stage_2") or {}
                classification = stage_2.get("classification") or {}
                if classification.get("label") == "CONFIRMED_MALICIOUS":
                    test_job_id = job.get("job_id")
                    break
            
            if not test_job_id and jobs:
                test_job_id = jobs[0].get("job_id")
                
        if test_job_id:
            verdict_ok, _ = self.test_save_verdict(test_job_id)
            
            # 4. Test takedown (only if we have a job with correct verdict)
            if verdict_ok:
                takedown_ok, _ = self.test_takedown_job(
                    test_job_id, 
                    task_preview="Test takedown task",
                    s2_label="CONFIRMED_MALICIOUS"
                )
        else:
            self.log("⚠️  No suitable job found for verdict/takedown testing")
            
        # 5. Test takedowns list
        takedowns = self.test_get_takedowns()
        
        # 6. Test pending review count
        pending_count = self.test_pending_review_count()
        
        # Summary
        self.log("="*50)
        self.log(f"📊 Test Results: {self.tests_passed}/{self.tests_run} passed")
        
        # Critical checks
        critical_failures = []
        if not health_ok:
            critical_failures.append("Health check failed")
        if not auth_ok:
            critical_failures.append("Authentication failed")
            
        if critical_failures:
            self.log(f"❌ Critical failures: {', '.join(critical_failures)}")
            return False
            
        success_rate = (self.tests_passed / self.tests_run) * 100 if self.tests_run > 0 else 0
        self.log(f"✅ Backend test success rate: {success_rate:.1f}%")
        
        return success_rate >= 70  # Consider 70%+ a success

def main():
    """Main test execution"""
    tester = PhishingEvalTester()
    success = tester.run_comprehensive_test()
    return 0 if success else 1

if __name__ == "__main__":
    sys.exit(main())