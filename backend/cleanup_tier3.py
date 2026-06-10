#!/usr/bin/env python3
"""
Tier 3 Misclassification Cleanup Script
========================================

Finds Tier 3 jobs in automated_actions that should be a different tier
based on the current classify_tier() logic, deletes them so they get
re-classified on the next sync.

Usage:
  # Dry run (default) — shows what would be deleted
  python3 cleanup_tier3.py

  # Actually delete
  python3 cleanup_tier3.py --execute

  # Custom MongoDB URI (for Atlas)
  python3 cleanup_tier3.py --execute --mongo-uri "mongodb+srv://user:pass@cluster.mongodb.net/dbname"

  # Custom DB name
  python3 cleanup_tier3.py --execute --mongo-uri "mongodb+srv://..." --db-name "my_database"

After running with --execute, trigger a sync to re-classify:
  curl -s -X POST -H "Authorization: Bearer <TOKEN>" https://<DEPLOYED_URL>/api/admin/sync
"""

import argparse
import sys
import os

# Add the backend directory to path so we can import automation
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from pymongo import MongoClient
from automation import classify_tier


def main():
    parser = argparse.ArgumentParser(description="Clean up misclassified Tier 3 jobs")
    parser.add_argument("--execute", action="store_true", help="Actually delete records (default is dry run)")
    parser.add_argument("--mongo-uri", default=None, help="MongoDB connection URI (default: from MONGO_URL env or localhost)")
    parser.add_argument("--db-name", default=None, help="Database name (default: from DB_NAME env or test_database)")
    args = parser.parse_args()

    # Resolve MongoDB connection
    mongo_uri = args.mongo_uri or os.environ.get("MONGO_URL", "mongodb://localhost:27017")
    db_name = args.db_name or os.environ.get("DB_NAME", "test_database")

    print(f"Connecting to: {mongo_uri[:40]}...")
    print(f"Database: {db_name}")
    print(f"Mode: {'EXECUTE' if args.execute else 'DRY RUN'}")
    print("=" * 60)

    client = MongoClient(mongo_uri)
    db = client[db_name]

    # Verify collections exist
    total_actions = db.automated_actions.count_documents({})
    total_bq = db.bq_jobs.count_documents({})
    print(f"automated_actions: {total_actions} records")
    print(f"bq_jobs: {total_bq} records")

    if total_actions == 0:
        print("No automated_actions found. Nothing to clean up.")
        return

    # Find all Tier 3 jobs
    tier3_actions = list(db.automated_actions.find({"tier": 3}, {"job_id": 1, "_id": 0}))
    print(f"\nTier 3 jobs found: {len(tier3_actions)}")

    if not tier3_actions:
        print("No Tier 3 jobs to check.")
        return

    # Check which ones are misclassified
    misclassified = []
    correct = 0
    missing_bq = 0
    reclassify_to = {}

    for a in tier3_actions:
        job = db.bq_jobs.find_one({"job_id": a["job_id"]}, {"_id": 0})
        if not job:
            missing_bq += 1
            continue

        correct_tier = classify_tier(job)
        if correct_tier != 3:
            misclassified.append(a["job_id"])
            reclassify_to[correct_tier] = reclassify_to.get(correct_tier, 0) + 1
        else:
            correct += 1

    print(f"\nResults:")
    print(f"  Correctly Tier 3: {correct}")
    print(f"  Misclassified: {len(misclassified)}")
    print(f"  Missing from bq_jobs: {missing_bq}")

    if reclassify_to:
        print(f"\n  Will re-classify to:")
        for tier, count in sorted(reclassify_to.items()):
            print(f"    Tier {tier}: {count}")

    if not misclassified:
        print("\nNo misclassified jobs found. All clean!")
        return

    if not args.execute:
        print(f"\n[DRY RUN] Would delete {len(misclassified)} records from automated_actions.")
        print(f"Run with --execute to actually delete them.")
        print(f"After deletion, trigger a sync: POST /api/admin/sync")
        return

    # Execute deletion
    result = db.automated_actions.delete_many({"job_id": {"$in": misclassified}})
    print(f"\nDeleted {result.deleted_count} misclassified records from automated_actions.")

    # Also clean up any scheduled_takedowns for these jobs (shouldn't exist for Tier 3, but safety)
    sched_result = db.scheduled_takedowns.delete_many({"job_id": {"$in": misclassified}})
    if sched_result.deleted_count > 0:
        print(f"Also deleted {sched_result.deleted_count} orphaned scheduled_takedowns.")

    # Verify
    remaining_tier3 = db.automated_actions.count_documents({"tier": 3})
    print(f"\nRemaining Tier 3 after cleanup: {remaining_tier3}")
    print(f"\nNext step: Trigger a sync to re-classify these jobs:")
    print(f'  curl -s -X POST -H "Authorization: Bearer <TOKEN>" https://<DEPLOYED_URL>/api/admin/sync')


if __name__ == "__main__":
    main()
