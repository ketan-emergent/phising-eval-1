import { useState, useEffect, useCallback } from "react";
import { useAuth, API } from "@/App";
import axios from "axios";
import { Shield, Bot, Clock, ShieldOff, BarChart3, ArrowLeft, RefreshCw, AlertTriangle, Check, X, UserX, Timer, Ban, Mail, Eye, Wrench, Loader2, ChevronDown, ChevronRight, RotateCcw } from "lucide-react";
import ConfirmLiveModal from "@/components/ConfirmLiveModal";
import ConfirmModal from "@/components/ConfirmModal";

const TAB_KEYS = ["pipeline", "exclusions", "enable", "admin"];
const TAB_LABELS = { "pipeline": "Pipeline", "exclusions": "Exclusion List", "enable": "Enable Job", "admin": "Admin" };
const TAB_ICONS = { "pipeline": BarChart3, "exclusions": ShieldOff, "enable": RotateCcw, "admin": Wrench };

export default function AutomationDashboard() {
  const { user, logout } = useAuth();
  const [tab, setTab] = useState("pipeline");
  const [refreshKey, setRefreshKey] = useState(0);

  const refresh = () => setRefreshKey((k) => k + 1);

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <div className="bg-card border-b border-border px-4 py-2.5 flex items-center gap-4 sticky top-0 z-40">
        <a href="/" className="flex items-center gap-1.5 text-muted-foreground hover:text-foreground transition-colors text-xs font-mono">
          <ArrowLeft className="w-3.5 h-3.5" /> Dashboard
        </a>
        <div className="flex items-center gap-2">
          <Bot className="w-5 h-5 text-primary" />
          <h1 className="text-sm font-mono font-bold tracking-wider uppercase text-primary">Automation</h1>
        </div>
        <div className="flex bg-background border border-border rounded-sm overflow-hidden">
          {TAB_KEYS.map((k) => {
            const Icon = TAB_ICONS[k];
            return (
              <button key={k} onClick={() => setTab(k)}
                className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-mono font-medium transition-all ${tab === k ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"}`}>
                <Icon className="w-3.5 h-3.5" /> {TAB_LABELS[k]}
              </button>
            );
          })}
        </div>
        <div className="ml-auto flex items-center gap-2">
          <button onClick={refresh} className="flex items-center gap-1.5 bg-card border border-border text-muted-foreground hover:text-foreground hover:border-primary/30 px-2.5 py-1.5 rounded-sm text-xs font-mono transition-all">
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          <span className="text-xs text-muted-foreground font-mono">{user?.name || user?.email}</span>
        </div>
      </div>

      {/* Content */}
      <div className="px-4 py-4">
        {tab === "pipeline" && <PipelineTab key={refreshKey} />}
        {tab === "exclusions" && <ExclusionsTab key={refreshKey} />}
        {tab === "enable" && <EnableTab key={refreshKey} />}
        {tab === "admin" && <AdminTab key={refreshKey} onRefresh={refresh} />}
      </div>
    </div>
  );
}

/* ---- Status Badge ---- */
function StatusBadge({ status }) {
  const colors = {
    completed: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    pending: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    executed: "bg-red-500/10 text-red-400 border-red-500/20",
    excluded: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    failed: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    skipped: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
  };
  return (
    <span className={`inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[9px] font-semibold font-mono uppercase ${colors[status] || colors.skipped}`}>
      {status}
    </span>
  );
}

function TierBadge({ tier }) {
  const colors = {
    1: "bg-red-500/10 text-red-400 border-red-500/20",
    2: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    3: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    4: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
  };
  const labels = { 1: "T1 Auto", 2: "T2 Email", 3: "T3 Review", 4: "T4 Log" };
  return (
    <span className={`inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[9px] font-semibold font-mono uppercase ${colors[tier] || colors[4]}`}>
      {labels[tier] || `T${tier}`}
    </span>
  );
}

function TimeAgo({ iso }) {
  if (!iso) return <span className="text-muted-foreground">--</span>;
  const d = new Date(iso);
  return <span className="text-muted-foreground" title={d.toISOString()}>{d.toLocaleDateString()} {d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" })}</span>;
}

function Countdown({ iso }) {
  if (!iso) return null;
  const ms = new Date(iso) - Date.now();
  if (ms <= 0) return <span className="text-red-400 font-semibold">Overdue</span>;
  const hrs = Math.floor(ms / 3600000);
  const mins = Math.floor((ms % 3600000) / 60000);
  return <span className="text-amber-400 font-semibold">{hrs}h {mins}m</span>;
}


/* ---- Shared Helper Components ---- */
function Loader({ text }) {
  return (
    <div className="flex items-center justify-center gap-2 py-12 text-muted-foreground text-xs font-mono">
      <Loader2 className="w-4 h-4 animate-spin" /> {text || "Loading..."}
    </div>
  );
}

function Empty({ text, icon: Icon }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-12 text-muted-foreground text-xs font-mono">
      {Icon && <Icon className="w-6 h-6 opacity-40" />}
      <span>{text || "No data"}</span>
    </div>
  );
}

function MiniCard({ label, value, color }) {
  return (
    <div className="bg-card border border-border rounded-sm p-2.5 text-center">
      <div className={`text-lg font-bold font-mono ${color || "text-foreground"}`}>{value ?? "--"}</div>
      <div className="text-[9px] text-muted-foreground font-mono uppercase">{label}</div>
    </div>
  );
}

function Th({ children }) {
  return <th className="text-left py-1.5 px-3 text-[10px] text-muted-foreground font-mono uppercase">{children}</th>;
}

function Td({ children, mono, truncate, title }) {
  return (
    <td className={`py-1.5 px-3 text-xs ${mono ? "font-mono" : ""} ${truncate ? "truncate overflow-hidden whitespace-nowrap max-w-0" : ""}`} title={title}>
      {children}
    </td>
  );
}

function ActionRow({ label, action, count, total, color, note }) {
  const pct = total > 0 ? ((count / total) * 100).toFixed(1) : "0.0";
  return (
    <tr className="border-b border-border/30">
      <td className="py-1.5 px-3 text-xs font-mono font-semibold">{label}</td>
      <td className="py-1.5 px-3 text-xs font-mono text-muted-foreground">{action}{note && <span className="text-[9px] ml-1 text-orange-400">({note})</span>}</td>
      <td className="py-1.5 px-3 text-xs font-mono font-semibold">{count}</td>
      <td className="py-1.5 px-3 text-xs font-mono text-muted-foreground">{pct}%</td>
      <td className="py-1.5 px-3 w-40">
        <div className="w-full bg-background rounded-sm h-2 overflow-hidden">
          <div className={`h-full ${color} rounded-sm`} style={{ width: `${Math.min(100, pct)}%` }} />
        </div>
      </td>
    </tr>
  );
}

function PhaseDot({ status }) {
  const colors = { ok: "bg-emerald-500", error: "bg-red-500", skipped: "bg-zinc-500" };
  return <span className={`inline-block w-2.5 h-2.5 rounded-full ${colors[status] || colors.skipped}`} title={status} />;
}

function PhaseCard({ num, name, status, duration, rows }) {
  const borderColor = status === "error" ? "border-red-500/40" : status === "ok" ? "border-emerald-500/20" : "border-border";
  return (
    <div className={`bg-background border ${borderColor} rounded-sm p-2.5`}>
      <div className="flex items-center justify-between mb-1.5">
        <span className="text-[9px] font-mono text-muted-foreground uppercase">Phase {num}: {name}</span>
        {duration != null && <span className="text-[9px] font-mono text-muted-foreground">{duration.toFixed(1)}s</span>}
      </div>
      <div className="space-y-0.5">
        {rows.filter(([, v]) => v != null).map(([label, value], i) => (
          <div key={label || i} className="flex justify-between text-[10px] font-mono">
            <span className="text-muted-foreground">{label}</span>
            <span className="text-foreground">{value}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function KV({ label, value }) {
  return (
    <div className="flex items-center gap-1.5">
      <span className="text-muted-foreground">{label}:</span>
      <span className="text-foreground font-semibold">{value ?? 0}</span>
    </div>
  );
}

/* ====== Tab: Pipeline ====== */
function PipelineTab() {
  const [stats, setStats] = useState(null);
  const [loading, setLoading] = useState(true);
  const [expandedRun, setExpandedRun] = useState(null);
  const [toggling, setToggling] = useState(false);
  const [showLiveModal, setShowLiveModal] = useState(false);

  const fetchStats = async () => {
    try {
      const res = await axios.get(`${API}/automation/stats`);
      setStats(res.data);
    } catch (e) { console.error(e); }
  };

  useEffect(() => {
    fetchStats().finally(() => setLoading(false));
  }, []);

  const doSwitchToLive = async () => {
    setToggling(true);
    try {
      await axios.post(`${API}/automation/mode`, { mode: "live", confirm: "CONFIRM_LIVE" });
      await fetchStats();
    } catch (e) {
      console.error(e);
      throw e;
    } finally {
      setToggling(false);
    }
  };

  const toggleMode = async (newMode) => {
    if (toggling) return;
    if (newMode === "live") {
      setShowLiveModal(true);
      return;
    }
    setToggling(true);
    try {
      await axios.post(`${API}/automation/mode`, { mode: newMode });
      await fetchStats();
    } catch (e) { console.error(e); }
    setToggling(false);
  };

  if (loading) return <Loader text="Loading pipeline..." />;
  if (!stats) return <Empty text="No pipeline data" icon={BarChart3} />;

  const runs = stats.pipeline_runs || [];
  const collections = stats.collections || {};
  const bq = collections.bq_jobs || {};
  const tierTotals = stats.tier_totals || {};
  const schedStats = stats.scheduled_stats || {};
  const actionBreakdown = stats.action_breakdown || [];
  const actionMap = {};
  actionBreakdown.forEach((a) => { actionMap[`${a._id?.action}/${a._id?.status}`] = a.count; });
  const totalClassified = Object.values(tierTotals).reduce((a, b) => a + b, 0);

  const currentMode = stats.mode || (stats.dry_run === false ? "live" : "dry_run");

  return (
    <div className="space-y-6">
      {/* Server-wide mode toggle — affects ALL users */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          {currentMode === "dry_run" ? (
            <div className="flex items-center gap-2 bg-amber-500/10 border border-amber-500/30 text-amber-400 px-3 py-2 rounded-sm text-xs font-mono">
              <AlertTriangle className="w-4 h-4" /> DRY RUN MODE — No real takedowns or emails
            </div>
          ) : (
            <div className="flex items-center gap-2 bg-red-500/10 border border-red-500/30 text-red-400 px-3 py-2 rounded-sm text-xs font-mono">
              <AlertTriangle className="w-4 h-4" /> LIVE MODE — Real takedowns and emails active
            </div>
          )}
        </div>
        <div>
          <div className="flex items-center gap-1 bg-card border border-border rounded-sm p-0.5">
            <button
              onClick={() => toggleMode("dry_run")}
              disabled={toggling || currentMode === "dry_run"}
              className={`px-3 py-1 text-xs font-mono rounded-sm transition-colors ${currentMode === "dry_run" ? "bg-amber-500/20 text-amber-400 border border-amber-500/40" : "text-muted-foreground hover:text-foreground"}`}
            >{toggling ? "..." : "DRY RUN"}</button>
            <button
              onClick={() => toggleMode("live")}
              disabled={toggling || currentMode === "live"}
              className={`px-3 py-1 text-xs font-mono rounded-sm transition-colors ${currentMode === "live" ? "bg-red-500/20 text-red-400 border border-red-500/40" : "text-red-300 hover:text-red-200"}`}
            >{toggling ? "..." : "LIVE"}</button>
          </div>
          {currentMode === "live" && (
              <p className="text-[10px] text-red-400 mt-1">Live mode active — real actions will execute</p>
          )}
        </div>
      </div>

      {showLiveModal && (
        <ConfirmLiveModal
          onConfirm={doSwitchToLive}
          onClose={() => setShowLiveModal(false)}
        />
      )}

      {/* Cumulative Totals */}
      <div>
        <h3 className="text-xs font-mono font-semibold text-muted-foreground uppercase tracking-wider mb-3">Cumulative Totals</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-2">
          <MiniCard label="bq_jobs" value={bq.total} />
          <MiniCard label="Classified" value={totalClassified} />
          <MiniCard label="Unclassified" value={Math.max(0, (bq.total || 0) - totalClassified)} color={Math.max(0, (bq.total || 0) - totalClassified) > 0 ? "text-amber-400" : "text-emerald-400"} />
          <MiniCard label="With Email" value={bq.with_email} color="text-blue-400" />
          <MiniCard label="Missing Email" value={bq.escalated_missing_email} color={bq.escalated_missing_email > 0 ? "text-orange-400" : "text-emerald-400"} />
          <MiniCard label="Exclusions" value={stats.active_exclusions || 0} color="text-blue-400" />
          <MiniCard label="MCP Skipped" value={stats.mcp_error_skipped || 0} color="text-orange-400" />
          <MiniCard label="Takedowns" value={(stats.takedowns?.manual || 0) + (stats.takedowns?.automated || 0)} color="text-red-400" />
        </div>
      </div>

      {/* Tier Funnel */}
      <div>
        <h3 className="text-xs font-mono font-semibold text-muted-foreground uppercase tracking-wider mb-3">Tier Classification (All Time)</h3>
        <div className="bg-card border border-border rounded-sm overflow-hidden">
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="border-b border-border bg-background/50">
                <Th>Tier</Th><Th>Action</Th><Th>Count</Th><Th>% of Total</Th><Th>Visual</Th>
              </tr>
            </thead>
            <tbody>
              <ActionRow label="T1" action="Auto Takedown" count={actionMap["auto_takedown/completed"] || 0} total={totalClassified} color="bg-red-500" />
              {(actionMap["auto_takedown/failed"] || 0) > 0 && <ActionRow label="T1" action="Failed" count={actionMap["auto_takedown/failed"] || 0} total={totalClassified} color="bg-red-800" note="error" />}
              <ActionRow label="T2" action="Email + Schedule" count={actionMap["email_scheduled/completed"] || 0} total={totalClassified} color="bg-orange-500" />
              <ActionRow label="T3" action="Human Review" count={actionMap["human_review/completed"] || 0} total={totalClassified} color="bg-amber-500" />
              <ActionRow label="T4" action="Log Only" count={actionMap["logged_only/completed"] || 0} total={totalClassified} color="bg-zinc-600" />
              <ActionRow label="T5" action="Legitimate" count={actionMap["legitimate/completed"] || 0} total={totalClassified} color="bg-emerald-600" />
              {(actionMap["skipped_mcp_error/skipped"] || 0) > 0 && <ActionRow label="--" action="MCP Skipped" count={actionMap["skipped_mcp_error/skipped"] || 0} total={totalClassified} color="bg-orange-800" note="failsafe" />}
              {(actionMap["skipped_excluded/skipped"] || 0) > 0 && <ActionRow label="--" action="Excluded" count={actionMap["skipped_excluded/skipped"] || 0} total={totalClassified} color="bg-blue-800" note="exclusion" />}
            </tbody>
          </table>
        </div>
      </div>

      {/* Scheduled Takedown Funnel */}
      <div>
        <h3 className="text-xs font-mono font-semibold text-muted-foreground uppercase tracking-wider mb-3">Scheduled Takedown Funnel</h3>
        <div className="grid grid-cols-4 gap-2">
          <MiniCard label="Pending" value={schedStats.pending || 0} color="text-amber-400" />
          <MiniCard label="Executed" value={schedStats.executed || 0} color="text-red-400" />
          <MiniCard label="Excluded" value={schedStats.excluded || 0} color="text-blue-400" />
          <MiniCard label="Failed" value={schedStats.failed || 0} color={schedStats.failed > 0 ? "text-orange-400" : "text-emerald-400"} />
        </div>
      </div>

      {/* Pipeline Run History — expandable */}
      {runs.length > 0 && (
        <div>
          <h3 className="text-xs font-mono font-semibold text-muted-foreground uppercase tracking-wider mb-3">Pipeline Runs (Last {runs.length})</h3>
          <div className="space-y-1">
            {runs.map((run, i) => {
              const p1 = run.phases?.phase_1 || {};
              const p2 = run.phases?.phase_2 || {};
              const p3 = run.phases?.phase_3 || {};
              const p4 = run.phases?.phase_4 || {};
              const thisRun = p4.this_run || {};
              const isExpanded = expandedRun === i;
              const totalDuration = [p1.duration_s, p2.duration_s, p3.duration_s, p4.duration_s].filter(Boolean).reduce((a, b) => a + b, 0).toFixed(1);
              const anyError = [p1.status, p2.status, p3.status, p4.status].includes("error");

              return (
                <div key={j.job_id || i} className="border border-border rounded-sm overflow-hidden">
                  {/* Collapsed header */}
                  <button onClick={() => setExpandedRun(isExpanded ? null : i)}
                    className="w-full flex items-center gap-3 px-3 py-2 text-xs font-mono hover:bg-card/50 transition-colors text-left">
                    <span className="text-muted-foreground">{isExpanded ? "▼" : "▶"}</span>
                    <span className="text-muted-foreground">Run #{runs.length - i}</span>
                    <span className="text-muted-foreground"><TimeAgo iso={run.timestamp} /></span>
                    <span className="text-muted-foreground">{totalDuration}s</span>
                    <span className="flex items-center gap-1.5 ml-2">
                      <PhaseDot status={p1.status} /> <span className="text-muted-foreground">→</span>
                      <PhaseDot status={p2.status} /> <span className="text-muted-foreground">→</span>
                      <PhaseDot status={p3.status} /> <span className="text-muted-foreground">→</span>
                      <PhaseDot status={p4.status} />
                    </span>
                    {anyError && <AlertTriangle className="w-3 h-3 text-red-400 ml-1" />}
                    {thisRun.new_jobs_classified > 0 && (
                      <span className="text-muted-foreground ml-auto">{thisRun.new_jobs_classified} new jobs</span>
                    )}
                    {run.dry_run ? <span className="text-amber-400 ml-2">DRY</span> : <span className="text-red-400 ml-2">LIVE</span>}
                  </button>

                  {/* Expanded detail */}
                  {isExpanded && (
                    <div className="border-t border-border px-3 py-3 bg-card/30 space-y-4">
                      {/* Phase cards in a row */}
                      <div className="grid grid-cols-4 gap-2">
                        <PhaseCard num={1} name="BQ Sync" status={p1.status} duration={p1.duration_s} rows={[
                          ["Rows Fetched", p1.rows_fetched],
                          ["New (Upserted)", p1.upserted],
                          ["Updated", p1.modified],
                          ["Failed Batches", p1.failed_batches],
                          ["Sync Type", p1.is_full_sync ? "full" : "incremental"],
                        ]} />
                        <PhaseCard num={2} name="User Enrichment" status={p2.status} duration={p2.duration_s} rows={[
                          ["Jobs Enriched", p2.jobs_enriched],
                          ["Still Missing Email", p2.still_missing],
                        ]} />
                        <PhaseCard num={3} name="User Profiles" status={p3.status} duration={p3.duration_s} rows={[
                          ["Profiles Rebuilt", p3.profiles_rebuilt],
                        ]} />
                        <PhaseCard num={4} name="Automation" status={p4.status} duration={p4.duration_s} rows={[
                          ["New Classified", thisRun.new_jobs_classified],
                          ...(thisRun.tier_counts_this_run ? Object.entries(thisRun.tier_counts_this_run).map(([t, c]) => [`  T${t}`, c]) : []),
                        ]} />
                      </div>

                      {/* Phase 4 detail panels */}
                      {thisRun.new_jobs_classified > 0 && (
                        <div className="grid grid-cols-3 gap-2">
                          <div className="bg-background border border-border rounded-sm p-2.5">
                            <div className="text-[9px] text-muted-foreground font-mono uppercase mb-1.5">Safety Gates</div>
                            <div className="space-y-1 text-[10px] font-mono">
                              <div className="flex justify-between"><span className="text-muted-foreground">MCP skipped</span><span className={thisRun.mcp_skipped > 0 ? "text-orange-400 font-bold" : "text-foreground"}>{thisRun.mcp_skipped || 0}</span></div>
                              <div className="flex justify-between"><span className="text-muted-foreground">Exclusion skipped</span><span className={thisRun.exclusion_skipped > 0 ? "text-blue-400 font-bold" : "text-foreground"}>{thisRun.exclusion_skipped || 0}</span></div>
                              <div className="flex justify-between"><span className="text-muted-foreground">DRY_RUN</span><span className={run.dry_run ? "text-amber-400 font-bold" : "text-emerald-400"}>{run.dry_run ? "ON" : "OFF"}</span></div>
                            </div>
                          </div>
                          <div className="bg-background border border-border rounded-sm p-2.5">
                            <div className="text-[9px] text-muted-foreground font-mono uppercase mb-1.5">T1: Auto Takedowns</div>
                            <div className="space-y-1 text-[10px] font-mono">
                              <div className="flex justify-between"><span className="text-muted-foreground">Completed</span><span className="text-foreground">{thisRun.t1_completed || 0}{run.dry_run ? " (dry)" : ""}</span></div>
                              <div className="flex justify-between"><span className="text-muted-foreground">Failed</span><span className={thisRun.t1_failed > 0 ? "text-red-400 font-bold" : "text-foreground"}>{thisRun.t1_failed || 0}</span></div>
                            </div>
                          </div>
                          <div className="bg-background border border-border rounded-sm p-2.5">
                            <div className="text-[9px] text-muted-foreground font-mono uppercase mb-1.5">T2: Emails & Scheduled</div>
                            <div className="space-y-1 text-[10px] font-mono">
                              <div className="flex justify-between"><span className="text-muted-foreground">Users emailed</span><span className="text-foreground">{thisRun.email_stats?.users_emailed || 0}</span></div>
                              <div className="flex justify-between"><span className="text-muted-foreground">Emails sent</span><span className="text-foreground">{thisRun.email_stats?.emails_sent || 0}{run.dry_run ? " (dry)" : ""}</span></div>
                              <div className="flex justify-between"><span className="text-muted-foreground">Emails failed</span><span className={thisRun.email_stats?.emails_failed > 0 ? "text-red-400 font-bold" : "text-foreground"}>{thisRun.email_stats?.emails_failed || 0}</span></div>
                              <div className="flex justify-between"><span className="text-muted-foreground">Jobs scheduled</span><span className="text-foreground">{thisRun.email_stats?.jobs_scheduled || 0}</span></div>
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Execution stats if any */}
                      {thisRun.exec_stats && thisRun.exec_stats.past_due > 0 && (
                        <div className="bg-background border border-border rounded-sm p-2.5">
                          <div className="text-[9px] text-muted-foreground font-mono uppercase mb-1.5">Scheduled Takedown Execution (Past-Due)</div>
                          <div className="flex gap-6 text-[10px] font-mono">
                            <KV label="Past Due" value={thisRun.exec_stats.past_due} />
                            <KV label="Executed" value={thisRun.exec_stats.executed} />
                            <KV label="Excluded" value={thisRun.exec_stats.excluded} />
                            <KV label="Failed" value={thisRun.exec_stats.failed} />
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}


/* ====== REMOVED: Auto Takedowns & Scheduled tabs (now on main dashboard) ====== */

/* ====== REMOVED: Old StatsTab (merged into PipelineTab) ====== */

/* ====== Tab: Exclusion List ====== */
function ExclusionsTab() {
  const [rules, setRules] = useState([]);
  const [excludedJobs, setExcludedJobs] = useState([]);
  const [loading, setLoading] = useState(true);
  const [addUserId, setAddUserId] = useState("");
  const [addJobId, setAddJobId] = useState("");
  const [addPattern, setAddPattern] = useState("");
  const [addReason, setAddReason] = useState("");
  const [previewMatches, setPreviewMatches] = useState(null);
  const [previewing, setPreviewing] = useState(false);
  const [removeTarget, setRemoveTarget] = useState(null);
  const [expandedRows, setExpandedRows] = useState(new Set());

  const toggleRow = (jobId) => {
    setExpandedRows((prev) => {
      const next = new Set(prev);
      next.has(jobId) ? next.delete(jobId) : next.add(jobId);
      return next;
    });
  };

  const fetchData = useCallback(async () => {
    try {
      const [rulesRes, jobsRes] = await Promise.all([
        axios.get(`${API}/automation/exclusions`),
        axios.get(`${API}/automation/excluded-jobs`),
      ]);
      setRules(rulesRes.data.exclusions || []);
      setExcludedJobs(jobsRes.data.excluded_jobs || []);
    } catch (e) { console.error(e); }
    setLoading(false);
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const handleAdd = async () => {
    if (!addUserId.trim() && !addJobId.trim() && !addPattern.trim()) return;
    try {
      const body = { reason: addReason.trim() || "Manual exclusion" };
      if (addUserId.trim()) body.user_id = addUserId.trim();
      if (addJobId.trim()) body.job_id = addJobId.trim();
      if (addPattern.trim()) body.pattern = addPattern.trim();
      await axios.post(`${API}/automation/exclusions`, body);
      setAddUserId("");
      setAddJobId("");
      setAddPattern("");
      setAddReason("");
      setPreviewMatches(null);
      fetchData();
    } catch (e) {
      const msg = e.response?.data?.detail || e.message;
      console.error(e);
      alert("Failed: " + msg);
    }
  };

  const handlePreview = async () => {
    if (!addPattern.trim()) return;
    setPreviewing(true);
    setPreviewMatches(null);
    try {
      const res = await axios.get(`${API}/automation/exclusions/preview-pattern`, { params: { pattern: addPattern.trim() } });
      setPreviewMatches(res.data);
    } catch (e) {
      const msg = e.response?.data?.detail || e.message;
      alert("Preview failed: " + msg);
    }
    setPreviewing(false);
  };

  const doRemove = async () => {
    if (!removeTarget) return;
    await axios.delete(`${API}/automation/exclusions/${encodeURIComponent(removeTarget.identifier)}`);
    setRemoveTarget(null);
    fetchData();
  };

  if (loading) return <Loader text="Loading exclusions..." />;

  const reasonBadge = (type) => {
    const colors = { pattern: "bg-purple-500/20 text-purple-400", user: "bg-blue-500/20 text-blue-400", job: "bg-amber-500/20 text-amber-400", rule: "bg-zinc-500/20 text-zinc-400" };
    return <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold uppercase ${colors[type] || colors.rule}`}>{type}</span>;
  };

  return (
    <div>
      {/* Add Exclusion Rule Form */}
      <div className="mb-4 bg-card border border-border rounded-sm p-4">
        <h2 className="text-sm font-mono font-semibold text-foreground mb-3">Add Exclusion Rule</h2>
        <div className="flex gap-2 items-end">
          <div>
            <label className="text-[10px] text-muted-foreground font-mono uppercase block mb-1">User ID</label>
            <input value={addUserId} onChange={(e) => setAddUserId(e.target.value)}
              placeholder="user-uuid-here"
              className="bg-background border border-border text-foreground px-2.5 py-1.5 rounded-sm font-mono text-xs w-56 focus:outline-none focus:border-primary" />
          </div>
          <div>
            <label className="text-[10px] text-muted-foreground font-mono uppercase block mb-1">Job ID</label>
            <input value={addJobId} onChange={(e) => setAddJobId(e.target.value)}
              placeholder="job-uuid-here"
              className="bg-background border border-border text-foreground px-2.5 py-1.5 rounded-sm font-mono text-xs w-56 focus:outline-none focus:border-primary" />
          </div>
          <div>
            <label className="text-[10px] text-muted-foreground font-mono uppercase block mb-1">Reason</label>
            <input value={addReason} onChange={(e) => setAddReason(e.target.value)}
              placeholder="User disputed, legitimate use case"
              className="bg-background border border-border text-foreground px-2.5 py-1.5 rounded-sm font-mono text-xs w-72 focus:outline-none focus:border-primary" />
          </div>
          <button onClick={handleAdd}
            className="flex items-center gap-1.5 bg-blue-500/10 border border-blue-500/30 text-blue-400 hover:bg-blue-500/20 px-3 py-1.5 rounded-sm text-xs font-mono font-semibold transition-all">
            <ShieldOff className="w-3.5 h-3.5" /> Add Exclusion
          </button>
        </div>
        <div className="flex gap-2 items-end mt-2">
          <div className="flex-1">
            <label className="text-[10px] text-muted-foreground font-mono uppercase block mb-1">Task Pattern (regex)</label>
            <input value={addPattern} onChange={(e) => setAddPattern(e.target.value)}
              placeholder="MoltBot|OpenClaw|Clawdbot"
              className="bg-background border border-border text-foreground px-2.5 py-1.5 rounded-sm font-mono text-xs w-full focus:outline-none focus:border-primary" />
          </div>
          <button onClick={handlePreview} disabled={!addPattern.trim() || previewing}
            className="flex items-center gap-1.5 bg-purple-500/10 border border-purple-500/30 text-purple-400 hover:bg-purple-500/20 px-3 py-1.5 rounded-sm text-xs font-mono font-semibold transition-all disabled:opacity-30 disabled:cursor-not-allowed whitespace-nowrap">
            <Eye className="w-3.5 h-3.5" /> {previewing ? "..." : "Preview Matches"}
          </button>
        </div>
        {previewMatches && (
          <div className="mt-3 bg-purple-500/5 border border-purple-500/20 rounded-sm">
            <div className="px-4 py-2 border-b border-purple-500/20 flex items-center justify-between">
              <span className="text-xs font-mono text-purple-400 font-semibold">
                Pattern /{previewMatches.pattern}/ matches {previewMatches.match_count} jobs
              </span>
              <button onClick={() => setPreviewMatches(null)} className="text-muted-foreground hover:text-foreground text-xs font-mono">dismiss</button>
            </div>
            {previewMatches.matches.length > 0 && (
              <div className="max-h-[300px] overflow-y-auto">
                <table className="w-full text-xs font-mono">
                  <thead><tr className="border-b border-border text-left"><Th>Job ID</Th><Th>User ID</Th><Th>Label</Th><Th>Task Preview</Th></tr></thead>
                  <tbody>
                    {previewMatches.matches.map((m, i) => (
                      <tr key={m.job_id || i} className="border-b border-border/50 hover:bg-muted/20">
                        <Td><span className="text-blue-400">{m.job_id?.slice(0, 12)}...</span></Td>
                        <Td>{m.user_id?.slice(0, 12) || "--"}...</Td>
                        <Td><span className={m.classification_label === "CONFIRMED_MALICIOUS" ? "text-red-400" : m.classification_label === "NEEDS_HUMAN_REVIEW" ? "text-amber-400" : "text-emerald-400"}>{m.classification_label || "--"}</span></Td>
                        <Td><span className="text-muted-foreground truncate block max-w-[400px]">{(m.task || "").slice(0, 100)}{(m.task || "").length > 100 ? "..." : ""}</span></Td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* Active Rules Summary */}
        {rules.length > 0 && (
          <div className="mt-3 border-t border-border pt-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] text-muted-foreground font-mono uppercase font-semibold">Active Rules ({rules.length})</span>
            </div>
            <div className="flex flex-wrap gap-2">
              {rules.map((r, i) => {
                const rtype = r.pattern ? "pattern" : r.user_id ? "user" : "job";
                const ident = r.user_id || r.job_id || r.pattern || "--";
                const label = rtype === "pattern" ? `/${r.pattern}/` : ident.length > 20 ? ident.slice(0, 20) + "..." : ident;
                return (
                  <div key={ident || i} className="flex items-center gap-1.5 bg-background border border-border rounded-sm px-2 py-1">
                    {reasonBadge(rtype)}
                    <span className="text-xs font-mono text-foreground" title={ident}>{label}</span>
                    <button onClick={() => setRemoveTarget({ identifier: ident, type: rtype, label })} className="text-red-400 hover:text-red-300 ml-1" title="Remove rule">
                      <X className="w-3 h-3" />
                    </button>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      {/* Excluded Jobs Table */}
      <div className="flex items-center justify-between mb-2">
        <h2 className="text-sm font-mono font-semibold text-foreground">Excluded Jobs ({excludedJobs.length})</h2>
      </div>

      {!excludedJobs.length ? (
        <Empty text="No excluded jobs yet — jobs will appear here as the pipeline evaluates them" icon={ShieldOff} />
      ) : (
        <div className="border border-border rounded-sm overflow-hidden">
          <div className="max-h-[600px] overflow-y-auto">
            <table className="w-full text-xs font-mono" style={{ tableLayout: "fixed" }}>
              <colgroup>
                <col style={{ width: "3%" }} />
                <col style={{ width: "27%" }} />
                <col style={{ width: "8%" }} />
                <col style={{ width: "8%" }} />
                <col style={{ width: "14%" }} />
                <col style={{ width: "40%" }} />
              </colgroup>
              <thead className="sticky top-0 bg-card z-10">
                <tr className="border-b border-border">
                  <Th></Th><Th>Job ID</Th><Th>Reason</Th><Th>Tier</Th><Th>Excluded At</Th><Th>Task Preview</Th>
                </tr>
              </thead>
              <tbody>
                {excludedJobs.map((j, i) => {
                  const isExpanded = expandedRows.has(j.job_id);
                  return (
                    <>
                      <tr key={j.job_id || i} className="border-b border-border/50 hover:bg-card/50 transition-colors cursor-pointer" onClick={() => toggleRow(j.job_id)}>
                        <Td>
                          {isExpanded ? <ChevronDown className="w-3 h-3 text-muted-foreground" /> : <ChevronRight className="w-3 h-3 text-muted-foreground" />}
                        </Td>
                        <Td>
                          <span className="text-blue-400 font-mono text-[11px] select-all break-all" title={j.job_id}>{j.job_id}</span>
                        </Td>
                        <Td>
                          {reasonBadge(j.reason_type)}
                        </Td>
                        <Td>
                          <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold ${j.tier === 1 ? "bg-red-500/20 text-red-400" : j.tier === 2 ? "bg-orange-500/20 text-orange-400" : j.tier === 3 ? "bg-amber-500/20 text-amber-400" : j.tier === 4 ? "bg-emerald-500/20 text-emerald-400" : "bg-zinc-500/20 text-zinc-400"}`}>T{j.tier}</span>
                        </Td>
                        <Td><TimeAgo iso={j.excluded_at} /></Td>
                        <Td>
                          <span className="text-muted-foreground truncate block" title={j.task_preview}>
                            {j.task_preview ? (j.task_preview.length > 120 ? j.task_preview.slice(0, 120) + "..." : j.task_preview) : "--"}
                          </span>
                        </Td>
                      </tr>
                      {isExpanded && (
                        <tr key={`${i}-detail`} className="border-b border-border/50 bg-muted/10">
                          <td colSpan={6} className="px-4 py-3">
                            <div className="space-y-2 text-xs font-mono">
                              <div className="flex gap-3">
                                <span className="text-muted-foreground min-w-[100px]">Job ID</span>
                                <span className="text-foreground select-all">{j.job_id}</span>
                              </div>
                              <div className="flex gap-3">
                                <span className="text-muted-foreground min-w-[100px]">User ID</span>
                                <span className="text-foreground select-all">{j.user_id || "--"}</span>
                              </div>
                              <div className="flex gap-3">
                                <span className="text-muted-foreground min-w-[100px]">Classification</span>
                                <span className={j.classification_label === "CONFIRMED_MALICIOUS" ? "text-red-400 font-semibold" : j.classification_label === "NEEDS_HUMAN_REVIEW" ? "text-amber-400" : "text-emerald-400"}>{j.classification_label || "--"}</span>
                              </div>
                              <div className="flex gap-3">
                                <span className="text-muted-foreground min-w-[100px]">Exclusion Type</span>
                                <span className="text-foreground">{j.reason_type}{j.reason_detail ? `: ${j.reason_detail}` : ""}</span>
                              </div>
                              <div className="flex gap-3">
                                <span className="text-muted-foreground min-w-[100px]">Excluded At</span>
                                <span className="text-foreground">{j.excluded_at ? new Date(j.excluded_at).toLocaleString() : "--"}</span>
                              </div>
                              <div>
                                <span className="text-muted-foreground block mb-1">Task Description</span>
                                <div className="bg-background border border-border rounded-sm px-3 py-2 text-foreground/80 whitespace-pre-wrap max-h-[200px] overflow-y-auto">
                                  {j.task_preview || "--"}
                                </div>
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Remove Exclusion Confirm Modal */}
      {removeTarget && (
        <ConfirmModal
          title="Remove Exclusion Rule"
          message={`This will deactivate the exclusion rule. Future pipeline runs will no longer skip jobs matching this rule — they will be classified and acted on normally.`}
          details={[
            { label: "Type", value: removeTarget.type },
            { label: "Identifier", value: removeTarget.identifier },
          ]}
          confirmLabel="Remove Rule"
          color="amber"
          onConfirm={doRemove}
          onClose={() => setRemoveTarget(null)}
        />
      )}
    </div>
  );
}

/* ---- Admin Tab ---- */
function AdminTab({ onRefresh }) {
  const [auditResult, setAuditResult] = useState(null);
  const [auditing, setAuditing] = useState(false);
  const [reclassifying, setReclassifying] = useState(false);
  const [reclassifyResult, setReclassifyResult] = useState(null);
  const [syncing, setSyncing] = useState(false);
  const [syncResult, setSyncResult] = useState(null);
  const [showReclassifyConfirm, setShowReclassifyConfirm] = useState(false);

  const runAudit = async () => {
    setAuditing(true);
    setAuditResult(null);
    setReclassifyResult(null);
    try {
      const res = await axios.get(`${API}/admin/tier-audit`);
      setAuditResult(res.data);
    } catch (e) {
      setAuditResult({ error: e.response?.data?.detail || e.message });
    }
    setAuditing(false);
  };

  const doReclassify = async () => {
    setShowReclassifyConfirm(false);
    setReclassifying(true);
    setReclassifyResult(null);
    try {
      const res = await axios.post(`${API}/admin/tier-reclassify`);
      setReclassifyResult(res.data);
    } catch (e) {
      setReclassifyResult({ error: e.response?.data?.detail || e.message });
    }
    setReclassifying(false);
  };

  const triggerSync = async () => {
    setSyncing(true);
    setSyncResult(null);
    try {
      const res = await axios.post(`${API}/admin/sync`);
      setSyncResult(res.data);
      onRefresh();
    } catch (e) {
      setSyncResult({ error: e.response?.data?.detail || e.message });
    }
    setSyncing(false);
  };

  const s = auditResult?.summary;

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Wrench className="w-5 h-5 text-primary" />
        <h2 className="text-sm font-mono font-bold text-foreground uppercase tracking-wider">Admin Tools</h2>
      </div>

      {/* Step 1: Audit */}
      <div className="bg-card border border-border rounded-sm p-4">
        <h3 className="text-xs font-mono font-semibold text-primary uppercase tracking-wider mb-2">Step 1: Audit Tier Classification</h3>
        <p className="text-xs text-muted-foreground font-mono mb-3">
          Scans all automated_actions and compares stored tier with current classify_tier() logic. Shows mismatches.
        </p>
        <button onClick={runAudit} disabled={auditing} data-testid="admin-audit-btn"
          className="bg-primary/10 border border-primary/30 text-primary px-4 py-2 rounded-sm text-xs font-mono font-semibold hover:bg-primary/20 transition-all disabled:opacity-50">
          {auditing ? <><Loader2 className="w-3.5 h-3.5 animate-spin inline mr-1" /> Auditing...</> : "Run Audit"}
        </button>

        {auditResult?.error && (
          <div className="mt-3 bg-red-500/10 border border-red-500/30 rounded-sm px-3 py-2 text-xs font-mono text-red-400">{auditResult.error}</div>
        )}

        {s && (
          <div className="mt-4 space-y-3">
            <div className="grid grid-cols-4 gap-3">
              <div className="bg-background border border-border rounded-sm p-3 text-center">
                <div className="text-lg font-bold font-mono text-foreground">{s.total_checked}</div>
                <div className="text-[10px] text-muted-foreground font-mono">Total Checked</div>
              </div>
              <div className="bg-background border border-border rounded-sm p-3 text-center">
                <div className="text-lg font-bold font-mono text-emerald-400">{s.correct}</div>
                <div className="text-[10px] text-muted-foreground font-mono">Correct</div>
              </div>
              <div className={`bg-background border rounded-sm p-3 text-center ${s.misclassified > 0 ? "border-amber-500/30" : "border-border"}`}>
                <div className={`text-lg font-bold font-mono ${s.misclassified > 0 ? "text-amber-400" : "text-foreground"}`}>{s.misclassified}</div>
                <div className="text-[10px] text-muted-foreground font-mono">Misclassified</div>
              </div>
              <div className="bg-background border border-border rounded-sm p-3 text-center">
                <div className="text-lg font-bold font-mono text-muted-foreground">{s.missing_bq}</div>
                <div className="text-[10px] text-muted-foreground font-mono">Missing BQ Data</div>
              </div>
            </div>

            {s.misclassified > 0 && (
              <>
                <div className="grid grid-cols-2 gap-3">
                  <div className="bg-background border border-border rounded-sm p-3">
                    <div className="text-[10px] font-mono text-muted-foreground uppercase mb-1">Currently stored as</div>
                    {Object.entries(s.by_stored_tier || {}).map(([k, v]) => (
                      <div key={k} className="text-xs font-mono text-foreground">{k.replace("_", " ")}: <span className="text-amber-400">{v}</span></div>
                    ))}
                  </div>
                  <div className="bg-background border border-border rounded-sm p-3">
                    <div className="text-[10px] font-mono text-muted-foreground uppercase mb-1">Should be reclassified to</div>
                    {Object.entries(s.reclassify_to || {}).map(([k, v]) => (
                      <div key={k} className="text-xs font-mono text-foreground">{k.replace("_", " ")}: <span className="text-emerald-400">{v}</span></div>
                    ))}
                  </div>
                </div>

                {auditResult.sample_misclassified?.length > 0 && (
                  <div>
                    <div className="text-[10px] font-mono text-muted-foreground uppercase mb-1">Sample misclassified jobs (max 20)</div>
                    <div className="max-h-48 overflow-y-auto">
                      <table className="w-full text-xs font-mono">
                        <thead><tr className="border-b border-border">
                          <th className="text-left py-1 px-2 text-[10px] text-muted-foreground">Job ID</th>
                          <th className="text-left py-1 px-2 text-[10px] text-muted-foreground">Stored</th>
                          <th className="text-left py-1 px-2 text-[10px] text-muted-foreground">Correct</th>
                          <th className="text-left py-1 px-2 text-[10px] text-muted-foreground">Label</th>
                          <th className="text-left py-1 px-2 text-[10px] text-muted-foreground">LTV</th>
                          <th className="text-left py-1 px-2 text-[10px] text-muted-foreground">Category</th>
                        </tr></thead>
                        <tbody>
                          {auditResult.sample_misclassified.map((m) => (
                            <tr key={m.job_id} className="border-b border-border/30">
                              <td className="py-1 px-2 text-blue-400">{m.job_id.substring(0, 12)}...</td>
                              <td className="py-1 px-2 text-amber-400">Tier {m.stored_tier}</td>
                              <td className="py-1 px-2 text-emerald-400">Tier {m.correct_tier}</td>
                              <td className="py-1 px-2">{m.label}</td>
                              <td className="py-1 px-2">${m.ltv || 0}</td>
                              <td className="py-1 px-2 text-muted-foreground">{m.category}</td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </>
            )}
          </div>
        )}
      </div>

      {/* Step 2: Reclassify */}
      <div className="bg-card border border-border rounded-sm p-4">
        <h3 className="text-xs font-mono font-semibold text-amber-400 uppercase tracking-wider mb-2">Step 2: Fix Misclassifications</h3>
        <p className="text-xs text-muted-foreground font-mono mb-3">
          Deletes misclassified records from automated_actions. They will be re-classified correctly on the next sync.
        </p>
        <button onClick={() => setShowReclassifyConfirm(true)} disabled={reclassifying || (s && s.misclassified === 0)} data-testid="admin-reclassify-btn"
          className="bg-amber-500/10 border border-amber-500/30 text-amber-400 px-4 py-2 rounded-sm text-xs font-mono font-semibold hover:bg-amber-500/20 transition-all disabled:opacity-30">
          {reclassifying ? <><Loader2 className="w-3.5 h-3.5 animate-spin inline mr-1" /> Reclassifying...</> : "Delete & Reclassify"}
        </button>

        {reclassifyResult && (
          <div className={`mt-3 rounded-sm px-3 py-2 text-xs font-mono ${reclassifyResult.error ? "bg-red-500/10 border border-red-500/30 text-red-400" : "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400"}`}>
            {reclassifyResult.error || `Deleted ${reclassifyResult.deleted} records (${reclassifyResult.scheduled_deleted} scheduled). ${reclassifyResult.message}`}
          </div>
        )}
      </div>

      {/* Step 3: Trigger Sync */}
      <div className="bg-card border border-border rounded-sm p-4">
        <h3 className="text-xs font-mono font-semibold text-primary uppercase tracking-wider mb-2">Step 3: Trigger Sync</h3>
        <p className="text-xs text-muted-foreground font-mono mb-3">
          Runs a full BQ sync + Phase 4 classification. Deleted records will be re-classified with the current tier logic.
        </p>
        <button onClick={triggerSync} disabled={syncing} data-testid="admin-sync-btn"
          className="bg-primary/10 border border-primary/30 text-primary px-4 py-2 rounded-sm text-xs font-mono font-semibold hover:bg-primary/20 transition-all disabled:opacity-50">
          {syncing ? <><Loader2 className="w-3.5 h-3.5 animate-spin inline mr-1" /> Syncing...</> : "Trigger Sync"}
        </button>

        {syncResult && (
          <div className={`mt-3 rounded-sm px-3 py-2 text-xs font-mono ${syncResult.error ? "bg-red-500/10 border border-red-500/30 text-red-400" : "bg-emerald-500/10 border border-emerald-500/30 text-emerald-400"}`}>
            {syncResult.error || `Sync complete: ${syncResult.fetched || 0} fetched, ${syncResult.upserted || 0} upserted`}
          </div>
        )}
      </div>

      {/* Reclassify Confirm Modal */}
      {showReclassifyConfirm && (
        <ConfirmModal
          title="Reclassify Jobs"
          message="This will delete misclassified records from automated_actions so they get re-classified on the next sync. This action cannot be undone."
          confirmLabel="Delete & Reclassify"
          color="red"
          onConfirm={doReclassify}
          onClose={() => setShowReclassifyConfirm(false)}
        />
      )}
    </div>
  );
}


/* ====== Tab: Enable Job ====== */
function EnableTab() {
  const [jobId, setJobId] = useState("");
  const [reason, setReason] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [showConfirm, setShowConfirm] = useState(false);
  const [history, setHistory] = useState([]);

  useEffect(() => {
    axios.get(`${API}/prod/enables-history`).then((r) => setHistory(r.data.enables || [])).catch(() => {});
  }, [result]);

  const doEnable = async () => {
    setLoading(true);
    setResult(null);
    try {
      const res = await axios.post(`${API}/prod/enable/${jobId.trim()}`, { reason: reason.trim() });
      setResult({ success: true, message: `Job ${jobId.trim()} has been re-enabled` });
      setJobId("");
      setReason("");
    } catch (err) {
      setResult({ success: false, message: err.response?.data?.detail || err.message || "Enable failed" });
    } finally {
      setLoading(false);
      setShowConfirm(false);
    }
  };

  return (
    <div className="max-w-3xl mx-auto space-y-4">
      <div className="bg-card border border-border rounded-sm p-4">
        <div className="flex items-center gap-2 mb-4">
          <RotateCcw className="w-4 h-4 text-emerald-400" />
          <h2 className="text-sm font-mono font-semibold text-foreground">Re-enable a Taken Down Job</h2>
        </div>
        <p className="text-xs text-muted-foreground font-mono mb-4">
          Calls the enable API directly to unsuspend the job so the user can work on it again.
        </p>

        <div className="space-y-3">
          <div>
            <label className="block text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1">Job ID</label>
            <input
              type="text"
              value={jobId}
              onChange={(e) => { setJobId(e.target.value); setResult(null); }}
              placeholder="e.g. 940d741b-7d0d-4ba1-a633-a09059be9770"
              className="w-full bg-background border border-border text-foreground px-3 py-2 rounded-sm font-mono text-xs focus:outline-none focus:border-primary/60 placeholder:text-muted-foreground/30"
            />
          </div>

          <div>
            <label className="block text-[10px] font-mono text-muted-foreground uppercase tracking-wider mb-1">Reason</label>
            <input
              type="text"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="e.g. User replied to takedown email, legitimate use case confirmed"
              className="w-full bg-background border border-border text-foreground px-3 py-2 rounded-sm font-mono text-xs focus:outline-none focus:border-emerald-500/60 placeholder:text-muted-foreground/30"
              onKeyDown={(e) => { if (e.key === "Enter") { e.preventDefault(); if (jobId.trim() && reason.trim()) setShowConfirm(true); } }}
            />
          </div>

          <button
            onClick={() => setShowConfirm(true)}
            disabled={!jobId.trim() || !reason.trim() || loading}
            className="bg-emerald-500/10 border border-emerald-500/40 text-emerald-400 px-4 py-2 rounded-sm text-xs font-mono font-semibold hover:bg-emerald-500/25 hover:border-emerald-500/60 transition-all disabled:opacity-30"
          >
            {loading ? <Loader2 className="w-3.5 h-3.5 animate-spin inline mr-1.5" /> : null}
            Enable Job
          </button>

          {/* Result */}
          {result && (
            <div className={`flex items-center gap-2 text-xs font-mono px-3 py-2 rounded-sm border ${
              result.success
                ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/20"
                : "text-red-400 bg-red-500/10 border-red-500/20"
            }`}>
              {result.success ? <Check className="w-3.5 h-3.5 shrink-0" /> : <X className="w-3.5 h-3.5 shrink-0" />}
              {result.message}
            </div>
          )}
        </div>
      </div>

      {/* Enable history */}
      <div className="bg-card border border-border rounded-sm p-4">
        <h3 className="text-xs font-mono font-semibold text-muted-foreground uppercase tracking-wider mb-3">Enable History</h3>
        {history.length === 0 ? (
          <p className="text-xs text-muted-foreground/50 font-mono">No jobs have been re-enabled yet.</p>
        ) : (
          <table className="w-full text-xs font-mono">
            <thead>
              <tr className="text-muted-foreground/60 border-b border-border">
                <th className="text-left py-1.5 px-2 font-medium">Job ID</th>
                <th className="text-left py-1.5 px-2 font-medium">Enabled By</th>
                <th className="text-left py-1.5 px-2 font-medium">Reason</th>
                <th className="text-left py-1.5 px-2 font-medium">When</th>
              </tr>
            </thead>
            <tbody>
              {history.map((h, i) => (
                <tr key={h.timestamp || i} className="border-b border-border/30">
                  <td className="py-1.5 px-2 text-blue-400 truncate max-w-[200px]">{h.job_id}</td>
                  <td className="py-1.5 px-2 text-foreground">{h.enabled_by}</td>
                  <td className="py-1.5 px-2 text-muted-foreground truncate max-w-[200px]">{h.reason}</td>
                  <td className="py-1.5 px-2 text-muted-foreground">{h.enabled_at ? new Date(h.enabled_at).toLocaleString() : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      {/* Confirm modal */}
      {showConfirm && (
        <ConfirmModal
          title="Re-enable Job"
          message="This will unsuspend the job and allow the user to continue working on it."
          details={[
            { label: "Job ID", value: jobId.trim() },
            { label: "Reason", value: reason.trim() },
          ]}
          confirmLabel="Enable Job"
          color="purple"
          onConfirm={doEnable}
          onClose={() => setShowConfirm(false)}
        />
      )}
    </div>
  );
}
