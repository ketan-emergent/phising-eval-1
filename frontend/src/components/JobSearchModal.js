import { useState, useEffect, useRef } from "react";
import { Search, X, Loader2, AlertCircle, Ban, Clock, ChevronLeft } from "lucide-react";
import { API } from "@/App";
import axios from "axios";
import JobDetailPanel from "@/components/JobDetailPanel";

export default function JobSearchModal({ onClose, initialQuery }) {
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [job, setJob] = useState(null);
  const [searchResults, setSearchResults] = useState(null);
  const [error, setError] = useState("");
  const [showTakedown, setShowTakedown] = useState(false);
  const [takedownReason, setTakedownReason] = useState("");
  const [takedownLoading, setTakedownLoading] = useState(false);
  const [takedownResult, setTakedownResult] = useState(null);
  const [showScheduleTakedown, setShowScheduleTakedown] = useState(false);
  const [scheduleTakedownReason, setScheduleTakedownReason] = useState("");
  const [scheduleTakedownLoading, setScheduleTakedownLoading] = useState(false);
  const [scheduleTakedownResult, setScheduleTakedownResult] = useState(null);
  const [fromMultiResult, setFromMultiResult] = useState(false);
  const inputRef = useRef(null);

  useEffect(() => {
    if (initialQuery) {
      setQuery(initialQuery);
    }
    inputRef.current?.focus();
  }, [initialQuery]);

  const [takedownResults, setTakedownResults] = useState(null);

  const doSearch = async (q) => {
    setLoading(true);
    setError("");
    setJob(null);
    setSearchResults(null);
    setTakedownResults(null);
    setFromMultiResult(false);
    setShowTakedown(false);
    setTakedownResult(null);
    try {
      const res = await axios.get(`${API}/prod/search`, { params: { q } });
      const jobs = res.data.jobs || [];
      const takedowns = res.data.takedowns || [];
      if (jobs.length === 0 && takedowns.length === 0) {
        setError(`No jobs found for: ${q}`);
      } else if (jobs.length === 1 && takedowns.length === 0) {
        setJob(jobs[0]);
      } else if (jobs.length > 0) {
        if (jobs.length === 1) setJob(jobs[0]);
        else setSearchResults(jobs);
        if (takedowns.length > 0) setTakedownResults(takedowns);
      } else {
        // Only takedown results, no bq_jobs
        setTakedownResults(takedowns);
      }
    } catch (err) {
      setError(err.response?.data?.detail || err.message || "Search failed");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (initialQuery) doSearch(initialQuery);
  }, [initialQuery]);

  useEffect(() => {
    const handleKeyDown = (e) => {
      if (e.key === "Escape") {
        if (showTakedown) setShowTakedown(false);
        else onClose();
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, [onClose, showTakedown]);

  const handleSearch = async (e) => {
    e.preventDefault();
    const trimmed = query.trim();
    if (!trimmed) return;
    doSearch(trimmed);
  };

  const handleTakedown = async () => {
    if (!takedownReason.trim() || !job) return;
    setTakedownLoading(true);
    setTakedownResult(null);
    try {
      await axios.post(`${API}/prod/takedown/${job.job_id}`, {
        suspension_reason: takedownReason.trim(),
      });
      setTakedownResult({ success: true, message: `Job ${job.job_id} has been taken down` });
      setJob((prev) => prev ? { ...prev, taken_down: true } : prev);
      setShowTakedown(false);
      setTakedownReason("");
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || "Takedown failed";
      setTakedownResult({ success: false, message: msg });
    } finally {
      setTakedownLoading(false);
    }
  };

  const handleScheduleTakedown = async () => {
    if (!scheduleTakedownReason.trim() || !job) return;
    setScheduleTakedownLoading(true);
    setScheduleTakedownResult(null);
    try {
      await axios.post(`${API}/prod/schedule-takedown/${job.job_id}`, {
        suspension_reason: scheduleTakedownReason.trim(),
      });
      setScheduleTakedownResult({ success: true, message: `Job ${job.job_id} scheduled for takedown in 24h` });
      setJob((prev) => prev ? {
        ...prev,
        scheduled_takedown: { status: "pending", takedown_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() },
        automation_action: "schedule_takedown",
        automation_status: "pending",
      } : prev);
      setShowScheduleTakedown(false);
      setScheduleTakedownReason("");
    } catch (err) {
      const msg = err.response?.data?.detail || err.message || "Schedule takedown failed";
      setScheduleTakedownResult({ success: false, message: msg });
    } finally {
      setScheduleTakedownLoading(false);
    }
  };

  const isTakenDown = job?.taken_down === true;
  const isScheduled = job?.scheduled_takedown?.status === "pending";

  return (
    <div className="fixed inset-0 z-[70] flex items-start justify-center pt-[8vh]" data-testid="job-search-modal">
      <div className="fixed inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative z-10 w-full max-w-4xl mx-4 max-h-[80vh] flex flex-col">
        {/* Search bar */}
        <form onSubmit={handleSearch} className="flex items-center gap-2 bg-card border border-border rounded-t-sm px-4 py-3">
          <Search className="w-4 h-4 text-muted-foreground shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search by job ID, user ID, or email"
            data-testid="job-search-input"
            className="flex-1 bg-transparent text-foreground font-mono text-sm focus:outline-none placeholder:text-muted-foreground/40"
          />
          {loading && <Loader2 className="w-4 h-4 text-primary animate-spin shrink-0" />}
          <button
            type="submit"
            disabled={loading || !query.trim()}
            data-testid="job-search-submit"
            className="bg-primary/10 border border-primary/30 text-primary px-3 py-1 rounded-sm text-xs font-mono hover:bg-primary/20 transition-all disabled:opacity-30"
          >
            Search
          </button>
          <button
            type="button"
            onClick={onClose}
            data-testid="job-search-close"
            className="text-muted-foreground hover:text-foreground transition-colors"
          >
            <X className="w-4 h-4" />
          </button>
        </form>

        {/* Results */}
        {error && (
          <div className="bg-card border border-t-0 border-border rounded-b-sm px-4 py-8 text-center">
            <AlertCircle className="w-6 h-6 text-muted-foreground/30 mx-auto mb-2" />
            <p className="text-sm text-muted-foreground font-mono" data-testid="job-search-error">{error}</p>
          </div>
        )}

        {/* Multi-result list */}
        {searchResults && (
          <div className="bg-card border border-t-0 border-border rounded-b-sm overflow-y-auto" data-testid="job-search-results">
            <div className="px-4 py-2 border-b border-border">
              <span className="text-xs font-mono text-muted-foreground">{searchResults.length} results found</span>
            </div>
            {searchResults.map((r) => (
              <button
                key={r.job_id}
                onClick={() => { setJob(r); setSearchResults(null); setFromMultiResult(true); }}
                className="w-full text-left px-4 py-2.5 border-b border-border/50 hover:bg-muted/30 transition-colors flex items-center gap-3"
              >
                <span className="text-xs font-mono text-blue-400 truncate w-[260px]">{r.job_id}</span>
                {r.user_email && <span className="text-xs font-mono text-muted-foreground truncate max-w-[200px]">{r.user_email}</span>}
                {r.stage_2?.classification?.label && (
                  <span className={`inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[9px] font-mono font-semibold uppercase shrink-0 ${
                    r.stage_2.classification.label === "CONFIRMED_MALICIOUS"
                      ? "bg-red-500/10 text-red-400 border-red-500/20"
                      : r.stage_2.classification.label === "NEEDS_HUMAN_REVIEW"
                      ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                      : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                  }`}>
                    {r.stage_2.classification.label.replace("CONFIRMED_", "").replace("NEEDS_HUMAN_", "")}
                  </span>
                )}
                {r.automation_tier && (
                  <span className={`inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[9px] font-mono font-semibold shrink-0 ${
                    r.automation_tier === 1 ? "bg-red-500/10 text-red-400 border-red-500/20"
                    : r.automation_tier === 2 ? "bg-orange-500/10 text-orange-400 border-orange-500/20"
                    : "bg-zinc-500/10 text-zinc-400 border-zinc-500/20"
                  }`}>
                    T{r.automation_tier}
                  </span>
                )}
                {r.taken_down && (
                  <span className="inline-flex items-center gap-1 text-[9px] font-mono text-red-500 font-semibold shrink-0">
                    <Ban className="w-3 h-3" /> DOWN
                  </span>
                )}
                {r.automation_action && (
                  <span className={`inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[9px] font-mono font-semibold shrink-0 ${
                    r.automation_action === "skipped_mcp_error" ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                    : r.automation_action === "skipped_excluded" ? "bg-purple-500/10 text-purple-400 border-purple-500/20"
                    : "bg-blue-500/10 text-blue-400 border-blue-500/20"
                  }`}>
                    {r.automation_action === "skipped_mcp_error" ? "MCP ERR" : r.automation_action === "skipped_excluded" ? "EXCLUDED" : r.automation_action.replace(/_/g, " ")}
                  </span>
                )}
              </button>
            ))}
          </div>
        )}

        {/* External takedown results */}
        {takedownResults && (
          <div className="bg-card border border-t-0 border-border rounded-b-sm overflow-y-auto" data-testid="job-search-takedowns">
            <div className="px-4 py-2 border-b border-border">
              <span className="text-xs font-mono text-muted-foreground">{takedownResults.length} external takedown{takedownResults.length !== 1 ? "s" : ""} found</span>
            </div>
            {takedownResults.map((t, i) => (
              <div key={t.job_id || i} className="px-4 py-2.5 border-b border-border/50 bg-red-950/10 flex items-center gap-3">
                <Ban className="w-3.5 h-3.5 text-red-500 shrink-0" />
                <span className="text-xs font-mono text-red-400/60 line-through truncate w-[260px] select-all">{t.job_id}</span>
                {t.source && (
                  <span className={`inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[9px] font-semibold uppercase shrink-0 ${
                    t.source === "openai" ? "border-blue-500/20 bg-blue-500/10 text-blue-400"
                    : t.source === "cloudflare" ? "border-orange-500/20 bg-orange-500/10 text-orange-400"
                    : "border-border bg-card text-muted-foreground"
                  }`}>{t.source}</span>
                )}
                <span className="text-xs font-mono text-muted-foreground truncate max-w-[300px]" title={t.suspension_reason}>{t.suspension_reason || "--"}</span>
                <span className="text-xs font-mono text-muted-foreground/50 shrink-0 ml-auto">
                  {t.taken_down_at ? new Date(t.taken_down_at).toLocaleDateString() + " " + new Date(t.taken_down_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : ""}
                </span>
                {t.dry_run && (
                  <span className="inline-flex items-center rounded-sm border border-yellow-500/20 bg-yellow-500/10 text-yellow-400 px-1.5 py-0.5 text-[9px] font-semibold shrink-0">DRY RUN</span>
                )}
              </div>
            ))}
          </div>
        )}

        {job && (
          <div className="bg-card border border-t-0 border-border rounded-b-sm overflow-y-auto" data-testid="job-search-result">
            {/* Job header */}
            <div className="px-4 py-3 border-b border-border flex items-center gap-3 flex-wrap">
              {fromMultiResult && (
                <button
                  onClick={() => { setJob(null); setFromMultiResult(false); doSearch(query.trim()); }}
                  className="inline-flex items-center gap-1 text-xs font-mono text-muted-foreground hover:text-foreground transition-colors mr-1"
                >
                  <ChevronLeft className="w-3 h-3" /> Back
                </button>
              )}
              <span className="text-xs font-mono text-muted-foreground">Job ID:</span>
              <span className="text-sm font-mono text-blue-400 select-all">{job.job_id}</span>
              <a
                href={`https://app.emergent.sh/?job_id=${job.job_id}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-muted-foreground hover:text-blue-400 font-mono transition-colors"
              >
                Open in Emergent
              </a>
              {job.stage_2?.classification?.label && (
                <span className={`inline-flex items-center rounded-sm border px-2 py-0.5 text-[10px] font-mono font-semibold uppercase ${
                  job.stage_2.classification.label === "CONFIRMED_MALICIOUS"
                    ? "bg-red-500/10 text-red-400 border-red-500/20"
                    : job.stage_2.classification.label === "NEEDS_HUMAN_REVIEW"
                    ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                    : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                }`}>
                  {job.stage_2.classification.label}
                </span>
              )}
              {!job.stage_2 && (
                <span className="inline-flex items-center rounded-sm border border-blue-500/20 bg-blue-500/10 text-blue-400 px-2 py-0.5 text-[10px] font-mono font-semibold uppercase">
                  IN-FLIGHT
                </span>
              )}
              {job.automation_tier && (
                <span className={`inline-flex items-center rounded-sm border px-2 py-0.5 text-[10px] font-mono font-semibold uppercase ${
                  job.automation_tier === 1 ? "bg-red-500/10 text-red-400 border-red-500/20"
                  : job.automation_tier === 2 ? "bg-orange-500/10 text-orange-400 border-orange-500/20"
                  : job.automation_tier === 3 ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                  : job.automation_tier === 4 ? "bg-zinc-500/10 text-zinc-400 border-zinc-500/20"
                  : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                }`}>
                  T{job.automation_tier}
                </span>
              )}
              {job.automation_action && (
                <span className={`inline-flex items-center gap-1 rounded-sm border px-2 py-0.5 text-[10px] font-mono font-semibold ${
                  job.automation_action === "skipped_mcp_error" ? "bg-amber-500/10 text-amber-400 border-amber-500/20"
                  : job.automation_action === "skipped_excluded" ? "bg-purple-500/10 text-purple-400 border-purple-500/20"
                  : job.automation_status === "completed" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20"
                  : job.automation_status === "failed" ? "bg-red-500/10 text-red-400 border-red-500/20"
                  : "bg-blue-500/10 text-blue-400 border-blue-500/20"
                }`}>
                  {job.automation_action === "skipped_mcp_error" ? "MCP ERROR" : job.automation_action === "skipped_excluded" ? "EXCLUDED" : job.automation_action.replace(/_/g, " ")}{" "}
                  {job.automation_status === "completed" || job.automation_action.startsWith("skipped_") ? "" : `(${job.automation_status})`}
                </span>
              )}

              {/* Takedown / Schedule Takedown buttons */}
              <div className="ml-auto flex items-center gap-2">
                {isTakenDown ? (
                  <span className="inline-flex items-center gap-1 text-[10px] font-mono text-red-500 font-semibold">
                    <Ban className="w-3 h-3" /> TAKEN DOWN {job.takedown_info?.taken_down_by === "automation" ? "(auto)" : ""}
                  </span>
                ) : (
                  <>
                    {isScheduled ? (
                      <span className="inline-flex items-center gap-1 text-[10px] font-mono text-orange-400 font-semibold">
                        <Clock className="w-3 h-3" /> SCHEDULED {job.scheduled_takedown?.takedown_at ? `@ ${new Date(job.scheduled_takedown.takedown_at).toLocaleString()}` : ""}
                      </span>
                    ) : (
                      <button
                        onClick={() => { setShowScheduleTakedown(!showScheduleTakedown); setShowTakedown(false); }}
                        data-testid="search-schedule-takedown-btn"
                        className="bg-orange-500/10 border border-orange-500/40 text-orange-400 px-3 py-1 rounded-sm text-[11px] font-mono font-semibold hover:bg-orange-500/25 hover:border-orange-500/60 transition-all"
                      >
                        {showScheduleTakedown ? "Cancel" : "Schedule Takedown"}
                      </button>
                    )}
                    <button
                      onClick={() => { setShowTakedown(!showTakedown); setShowScheduleTakedown(false); }}
                      data-testid="search-takedown-btn"
                      className="bg-red-500/10 border border-red-500/40 text-red-400 px-3 py-1 rounded-sm text-[11px] font-mono font-semibold hover:bg-red-500/25 hover:border-red-500/60 transition-all"
                    >
                      {showTakedown ? "Cancel" : "Takedown"}
                    </button>
                  </>
                )}
              </div>
            </div>

            {/* Takedown form */}
            {showTakedown && !isTakenDown && (
              <div className="px-4 py-3 border-b border-red-500/30 bg-red-950/20" data-testid="search-takedown-form">
                <div className="flex items-center gap-2 mb-2">
                  <Ban className="w-4 h-4 text-red-400" />
                  <span className="text-xs font-mono font-semibold text-red-400 uppercase">Takedown Job</span>
                </div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={takedownReason}
                    onChange={(e) => setTakedownReason(e.target.value)}
                    placeholder="Suspension reason (required)"
                    data-testid="search-takedown-reason"
                    className="flex-1 bg-red-950/30 border border-red-500/30 text-foreground px-3 py-2 rounded-sm font-mono text-xs focus:outline-none focus:border-red-500/60 placeholder:text-red-400/30"
                    onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); handleTakedown(); } }}
                  />
                  <button
                    onClick={handleTakedown}
                    disabled={!takedownReason.trim() || takedownLoading}
                    data-testid="search-takedown-confirm"
                    className="bg-red-600 border border-red-500 text-white px-4 py-2 rounded-sm text-xs font-mono font-semibold hover:bg-red-500 transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                  >
                    {takedownLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : "CONFIRM"}
                  </button>
                </div>
              </div>
            )}

            {/* Schedule Takedown form */}
            {showScheduleTakedown && !isTakenDown && !isScheduled && (
              <div className="px-4 py-3 border-b border-orange-500/30 bg-orange-950/20" data-testid="search-schedule-takedown-form">
                <div className="flex items-center gap-2 mb-2">
                  <Clock className="w-4 h-4 text-orange-400" />
                  <span className="text-xs font-mono font-semibold text-orange-400 uppercase">Schedule Takedown (24h)</span>
                </div>
                <div className="flex gap-2">
                  <input
                    type="text"
                    value={scheduleTakedownReason}
                    onChange={(e) => setScheduleTakedownReason(e.target.value)}
                    placeholder="Suspension reason (required)"
                    data-testid="search-schedule-takedown-reason"
                    className="flex-1 bg-orange-950/30 border border-orange-500/30 text-foreground px-3 py-2 rounded-sm font-mono text-xs focus:outline-none focus:border-orange-500/60 placeholder:text-orange-400/30"
                    onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); handleScheduleTakedown(); } }}
                  />
                  <button
                    onClick={handleScheduleTakedown}
                    disabled={!scheduleTakedownReason.trim() || scheduleTakedownLoading}
                    data-testid="search-schedule-takedown-confirm"
                    className="bg-orange-600 border border-orange-500 text-white px-4 py-2 rounded-sm text-xs font-mono font-semibold hover:bg-orange-500 transition-all disabled:opacity-30 disabled:cursor-not-allowed"
                  >
                    {scheduleTakedownLoading ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : "SCHEDULE"}
                  </button>
                </div>
              </div>
            )}

            {/* Schedule Takedown result */}
            {scheduleTakedownResult && (
              <div className={`px-4 py-2 border-b text-xs font-mono ${
                scheduleTakedownResult.success
                  ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                  : "bg-red-500/10 border-red-500/30 text-red-400"
              }`} data-testid="search-schedule-takedown-result">
                {scheduleTakedownResult.message}
              </div>
            )}

            {/* Takedown result */}
            {takedownResult && (
              <div className={`px-4 py-2 border-b text-xs font-mono ${
                takedownResult.success
                  ? "bg-emerald-500/10 border-emerald-500/30 text-emerald-400"
                  : "bg-red-500/10 border-red-500/30 text-red-400"
              }`} data-testid="search-takedown-result">
                {takedownResult.message}
              </div>
            )}

            {/* Reuse existing detail panel */}
            <JobDetailPanel job={job} isProd={true} saveNotes={() => {}} />
          </div>
        )}

        {!error && !job && !searchResults && !loading && (
          <div className="bg-card border border-t-0 border-border rounded-b-sm px-4 py-6 text-center">
            <p className="text-xs text-muted-foreground/50 font-mono">Search by job ID, user ID, or email address</p>
            <p className="text-[10px] text-muted-foreground/30 font-mono mt-1">Tip: Ctrl+F to open this search anytime</p>
          </div>
        )}
      </div>
    </div>
  );
}
