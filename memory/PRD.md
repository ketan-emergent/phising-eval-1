# Phishing Eval UI - PRD

## Original Problem Statement
Migrate a Phishing Pipeline Eval UI from a monolith to React + FastAPI on Emergent platform. Replace eval_results.json with MongoDB. Keep BigQuery as source of truth for production phishing data.

## Architecture
- **Backend**: FastAPI (Python) on port 8001
  - MongoDB collections: bq_jobs (BQ cache), eval_verdicts, eval_jobs, eval_config, pipeline_traces, takedowns, sync_metadata
  - Google BigQuery: source of truth, synced to MongoDB every 30 min. Receives takedown logs.
  - **Supabase Auth** (Bearer token + cookie + query param fallback for proxy)
- **Frontend**: React 19 + Tailwind CSS
  - Supabase email/password auth (@emergent.sh only)
- **Database**: MongoDB (test_database)

## What's Been Implemented

### Job Search (Ctrl+F)
- Ctrl+F or Search button in header opens modal overlay
- Enter job_id → shows full job details (S1, S2, screenshot) in centered popup
- Background greyed out with backdrop blur
- "No job found" message for non-existent IDs
- Escape to close, click backdrop to close
- Backend: `GET /api/prod/job/{job_id}` single job lookup

### BQ → MongoDB Sync
- Background asyncio loop syncs BigQuery → MongoDB `bq_jobs` every 30 minutes
- Full sync on boot, incremental after. All production endpoints read from MongoDB.
- Admin endpoints: `POST /api/admin/sync`, `GET /api/admin/sync-status`

### BQ Takedown Logging
- Takedowns log to `phishing_eval.job_takedowns` in BigQuery (background, non-blocking)

### Auth (Supabase)
- Email/password with @emergent.sh domain restriction
- Token in localStorage + cookie + query param for proxy resilience

### Takedown
- Production takedown: verdict check + Emergent disable API + MongoDB + BQ log
- QA Test Takedown: Eval mode, no verdict checks

### UI
- Full UUID display, IST timestamps, S2 labels sorted first

## Key API Endpoints
- `GET /api/prod/jobs` - Jobs from MongoDB
- `GET /api/prod/job/{job_id}` - Single job lookup
- `GET /api/prod/stats` - Stats from MongoDB
- `GET /api/prod/pending-review-count` - From MongoDB
- `GET /api/prod/analytics` - From MongoDB aggregation
- `POST /api/prod/verdict/{job_id}` - Save verdict
- `POST /api/prod/takedown/{job_id}` - Takedown (verdict check + BQ log)
- `POST /api/test/takedown/{job_id}` - QA takedown (no checks + BQ log)
- `GET /api/prod/takedowns` - List takedowns
- `POST /api/admin/sync` - Manual BQ sync
- `GET /api/admin/sync-status` - Sync metadata

## Prioritized Backlog
### P1
- Bulk verdict assignment

### P2
- WebSocket for real-time eval mode updates
- Keyboard shortcuts for verdict assignment
