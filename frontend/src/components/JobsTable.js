import { Fragment } from "react";
import { ChevronDown, ChevronRight, Ban, ExternalLink, AlertTriangle, ShieldOff, Clock, Check, ArrowRightLeft } from "lucide-react";
import JobDetailPanel from "@/components/JobDetailPanel";

function truncate(s, n) {
  return s && s.length > n ? s.substring(0, n - 1) + "..." : s || "";
}

function fmtIST(ts) {
  if (!ts) return "--";
  try {
    const d = new Date(ts);
    return d.toLocaleString("en-IN", { timeZone: "Asia/Kolkata", day: "2-digit", month: "short", hour: "2-digit", minute: "2-digit", hour12: false });
  } catch (e) { return "--"; }
}

function fmtConf(c) {
  return c != null ? (typeof c === "number" ? c.toFixed(2) : c) : "";
}

function Badge({ variant, children }) {
  const styles = {
    phishing: "bg-red-500/10 text-red-400 border-red-500/20",
    legit: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    review: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    malicious: "bg-red-500/20 text-red-400 border-red-500/30",
    pending: "bg-muted text-muted-foreground border-border",
    running: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    flagged: "bg-red-500/10 text-red-400 border-red-500/20",
    clear: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  };
  return (
    <span className={`inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wide ${styles[variant] || styles.pending}`}>
      {children}
    </span>
  );
}

function UserTags({ job }) {
  const s2Label = job.stage_2?.classification?.label;
  if (s2Label !== "CONFIRMED_MALICIOUS" && s2Label !== "NEEDS_HUMAN_REVIEW") return null;
  if (!job.user_email && !job.plan_type) return null;

  const isFree = !job.plan_type || job.plan_type === "Free User";
  const planColor = isFree ? "bg-zinc-500/10 text-zinc-400 border-zinc-500/20" : "bg-emerald-500/10 text-emerald-400 border-emerald-500/20";

  return (
    <div className="flex gap-1 mt-1 flex-wrap">
      {job.user_email && (
        <span className="inline-flex items-center rounded-sm border border-blue-500/20 bg-blue-500/10 text-blue-400 px-1 py-0 text-[9px] font-mono truncate max-w-[160px]" title={job.user_email}>
          {job.user_email}
        </span>
      )}
      {job.plan_type && (
        <span className={`inline-flex items-center rounded-sm border px-1 py-0 text-[9px] font-mono ${planColor}`}>
          {job.plan_type}
        </span>
      )}
      {job.ltv > 0 && (
        <span className="inline-flex items-center rounded-sm border border-amber-500/20 bg-amber-500/10 text-amber-400 px-1 py-0 text-[9px] font-mono">
          ${job.ltv.toFixed(0)}
        </span>
      )}
    </div>
  );
}

function VerdictSelect({ value, onChange, testId }) {
  const colorClass = value === "correct" ? "border-emerald-500 text-emerald-400" : value === "incorrect" ? "border-red-500 text-red-400" : value === "disputed" ? "border-amber-500 text-amber-400" : "border-border text-muted-foreground";
  return (
    <select
      value={value || ""}
      onChange={(e) => onChange(e.target.value)}
      data-testid={testId}
      className={`bg-background border rounded-sm px-1.5 py-1 font-mono text-[11px] cursor-pointer focus:outline-none focus:ring-1 focus:ring-primary ${colorClass}`}
      onClick={(e) => e.stopPropagation()}
    >
      <option value="">--</option>
      <option value="correct">Correct</option>
      <option value="incorrect">Incorrect</option>
      <option value="disputed">Disputed</option>
    </select>
  );
}

function TierBadge({ tier, opusStatus }) {
  if (tier == null) return <span className="text-muted-foreground/30">--</span>;
  const styles = {
    1: "bg-red-500/20 text-red-400 border-red-500/30",
    2: "bg-orange-500/15 text-orange-400 border-orange-500/25",
    3: "bg-amber-500/15 text-amber-400 border-amber-500/25",
    4: "bg-zinc-500/10 text-zinc-400 border-zinc-500/20",
    5: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  };
  const labels = { 1: "T1 Auto", 2: "T2 Sched", 3: "T3 Review", 4: "T4 Log", 5: "T5 Legit" };
  return (
    <span className={`inline-flex items-center gap-0.5 rounded-sm border px-1.5 py-0.5 text-[9px] font-mono font-semibold tracking-wide ${styles[tier] || styles[4]}`}>
      {labels[tier] || `T${tier}`}
      {opusStatus === "pending" && <Clock className="w-2.5 h-2.5 animate-pulse" />}
      {opusStatus === "confirmed" && <Check className="w-2.5 h-2.5" />}
      {opusStatus === "overridden" && <ArrowRightLeft className="w-2.5 h-2.5" />}
    </span>
  );
}

function OpusBadge({ opus }) {
  if (!opus) return <span className="text-muted-foreground/30">--</span>;
  const label = opus.label;
  const style =
    label === "CONFIRMED_MALICIOUS" ? "bg-red-500/20 text-red-400 border-red-500/30" :
    label === "NEEDS_HUMAN_REVIEW" ? "bg-amber-500/15 text-amber-400 border-amber-500/25" :
    label === "LEGITIMATE" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" :
    "bg-muted text-muted-foreground border-border";
  const short =
    label === "CONFIRMED_MALICIOUS" ? "MALICIOUS" :
    label === "NEEDS_HUMAN_REVIEW" ? "REVIEW" :
    label === "LEGITIMATE" ? "LEGIT" : label;
  return (
    <span className={`inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[9px] font-mono font-semibold tracking-wide ${style}`}>
      {short}
    </span>
  );
}

const TH = "text-left py-2 px-2 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider";

export default function JobsTable({ jobs, mode, expandedKey, setExpandedKey, setVerdict, saveNotes, onTakedownClick, onScheduleTakedown }) {
  const isProd = mode === "production";

  if (jobs.length === 0) {
    return (
      <div className="text-center py-20" data-testid="empty-state">
        <h2 className="text-sm font-mono font-bold text-foreground mb-2">No pipeline runs yet</h2>
        <p className="text-xs text-muted-foreground font-mono">
          {isProd ? "No production phishing detections found in BigQuery" : "Run classifier.py <job_id> to start evaluating"}
        </p>
      </div>
    );
  }

  const prodCols = [
    { key: "chevron", w: "2%" },
    { key: "jobid", w: "17%", label: "Job ID" },
    { key: "timestamp", w: "8%", label: "Timestamp (IST)" },
    { key: "task", w: "17%", label: "Task" },
    { key: "s1", w: "6%", label: "S1" },
    { key: "opus", w: "10%", label: "Opus Verdict" },
    { key: "policies", w: "12%", label: "Flagged Policies" },
    { key: "s2v", w: "7%", label: "Human Verdict" },
    { key: "takedown", w: "10%", label: "Takedown" },
    { key: "actioned", w: "8%", label: "Actioned By" },
  ];

  const evalCols = [
    { key: "chevron", w: "2%" },
    { key: "jobid", w: "18%", label: "Job ID" },
    { key: "timestamp", w: "8%", label: "Timestamp (IST)" },
    { key: "task", w: "18%", label: "Task" },
    { key: "s1", w: "7%", label: "S1" },
    { key: "s1v", w: "6%", label: "S1 Verdict" },
    { key: "wc", w: "5%", label: "WC" },
    { key: "wcv", w: "6%", label: "WC Verdict" },
    { key: "s2", w: "12%", label: "S2" },
    { key: "s2v", w: "6%", label: "S2 Verdict" },
    { key: "ver", w: "7%", label: "Version" },
    { key: "time", w: "5%", label: "Time" },
  ];

  const cols = isProd ? prodCols : evalCols;
  const colCount = cols.length;

  return (
    <div className="px-4 pb-4" data-testid="jobs-table">
      <table className="w-full text-xs font-mono" style={{ tableLayout: "fixed" }}>
        <colgroup>
          {cols.map((c) => (
            <col key={c.key} style={{ width: c.w }} />
          ))}
        </colgroup>
        <thead>
          <tr className="border-b border-border">
            {cols.map((c) => (
              <th key={c.key} className={TH}>{c.label || ""}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {jobs.map((j) => {
            const ekey = j.eval_key || j.job_id;
            const isExpanded = expandedKey === ekey;
            const s1 = j.stage_1?.classification || {};
            const s2 = j.stage_2?.classification || {};
            const pv = j.prompt_versions || {};

            let s1Badge = <Badge variant="pending">waiting</Badge>;
            if (s1.result === true) s1Badge = <Badge variant="phishing">PHISH {fmtConf(s1.confidence)}</Badge>;
            else if (s1.result === false) s1Badge = <Badge variant="legit">LEGIT {fmtConf(s1.confidence)}</Badge>;

            // Primary classification badge: Opus verdict takes priority
            let classificationBadge;
            if (j.opus_verdict) {
              const olbl = j.opus_verdict.label;
              if (olbl === "CONFIRMED_MALICIOUS") classificationBadge = <Badge variant="malicious">{olbl}</Badge>;
              else if (olbl === "NEEDS_HUMAN_REVIEW") classificationBadge = <Badge variant="review">{olbl}</Badge>;
              else if (olbl === "LEGITIMATE") classificationBadge = <Badge variant="legit">{olbl}</Badge>;
              else classificationBadge = <Badge variant="pending">{olbl}</Badge>;
            } else if (j.automation_status === "pending_opus_review") {
              classificationBadge = <span className="inline-flex items-center gap-1 rounded-sm border border-purple-500/30 bg-purple-500/10 text-purple-400 px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wide"><Clock className="w-2.5 h-2.5 animate-pulse" />OPUS PENDING</span>;
            } else if (j.stage_2) {
              // Legacy S2 label shown grayed out for pre-Opus jobs
              const lbl = s2.label || "?";
              classificationBadge = <span className="inline-flex items-center rounded-sm border border-zinc-500/20 bg-zinc-500/10 text-zinc-500 px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wide opacity-60">{lbl} (S2)</span>;
            } else if (s1.result === true) {
              classificationBadge = <Badge variant="running">in-flight</Badge>;
            } else {
              classificationBadge = <span className="text-muted-foreground">--</span>;
            }

            // Legacy S2 badge (always shown in the S2 Initial column)
            let s2Badge;
            if (j.stage_2) {
              const lbl = s2.label || "?";
              if (lbl === "CONFIRMED_MALICIOUS") s2Badge = <Badge variant="malicious">{lbl}</Badge>;
              else if (lbl === "NEEDS_HUMAN_REVIEW") s2Badge = <Badge variant="review">{lbl}</Badge>;
              else if (lbl === "LEGITIMATE") s2Badge = <Badge variant="legit">{lbl}</Badge>;
              else s2Badge = <Badge variant="pending">{lbl}</Badge>;
            } else if (s1.result === true) {
              s2Badge = <Badge variant="running">in-flight</Badge>;
            } else {
              s2Badge = <span className="text-muted-foreground">--</span>;
            }

            const wc = j.whitecircle || {};
            let wcBadge = <span className="text-muted-foreground">--</span>;
            if (wc.error) wcBadge = <Badge variant="pending">ERROR</Badge>;
            else if (wc.flagged === true) wcBadge = <Badge variant="flagged">FLAGGED</Badge>;
            else if (wc.flagged === false) wcBadge = <Badge variant="clear">CLEAR</Badge>;

            const verStr = [pv.llm_classifier, pv.escalation_agent].filter(Boolean).join("/") || "--";
            let timeStr = "--";
            if (j.pipeline_time) timeStr = j.pipeline_time.toFixed(0) + "s";
            else if (j.stage_1?.elapsed_seconds) timeStr = j.stage_1.elapsed_seconds.toFixed(1) + "s";

            const isTakenDown = j.taken_down === true;
            const isVerdictCorrect = j.human_verdict_s2 === "correct";
            const isNHR = s2.label === "NEEDS_HUMAN_REVIEW";
            const isCM = s2.label === "CONFIRMED_MALICIOUS";
            const hasScheduled = j.scheduled_takedown?.status === "pending";
            const scheduledExecuted = j.scheduled_takedown?.status === "executed";
            const autoAction = j.automation_action;
            // Takedown eligible: verdict=correct AND (CM or NHR) AND not already taken down
            const takedownEligible = isVerdictCorrect && (isCM || isNHR) && !isTakenDown && !hasScheduled && !scheduledExecuted;
            const scheduleEligible = isVerdictCorrect && isNHR && !isTakenDown && !hasScheduled && !scheduledExecuted;

            return (
              <Fragment key={ekey}>
                <tr
                  onClick={() => setExpandedKey(isExpanded ? null : ekey)}
                  data-testid={`job-row-${j.job_id}`}
                  className={`border-b border-border cursor-pointer transition-colors hover:bg-card ${isExpanded ? "bg-card" : ""} ${isTakenDown ? "bg-red-950/20" : ""}`}
                >
                  <td className="py-2 px-2">
                    {isExpanded ? <ChevronDown className="w-3.5 h-3.5 text-primary" /> : <ChevronRight className="w-3.5 h-3.5 text-muted-foreground" />}
                  </td>
                  <td className={`py-2 px-2 font-medium break-all ${isTakenDown ? "text-red-400/50 line-through" : "text-blue-400"}`}>
                    <span className="select-all cursor-text" onClick={(e) => e.stopPropagation()}>{j.job_id}</span>
                    <a
                      href={`https://app.emergent.sh/?job_id=${j.job_id}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      onClick={(e) => e.stopPropagation()}
                      className="inline-block ml-1.5 text-muted-foreground hover:text-blue-400 transition-colors align-middle"
                      title="Open in Emergent"
                      data-testid={`job-link-${j.job_id}`}
                    >
                      <ExternalLink className="w-3 h-3" />
                    </a>
                  </td>
                  <td className="py-2 px-2 text-muted-foreground whitespace-nowrap" data-testid={`job-ts-${j.job_id}`}>
                    {fmtIST(j.created_at)}
                  </td>
                  <td className={`py-2 px-2 overflow-hidden ${isTakenDown ? "line-through text-muted-foreground/40" : ""}`} title={j.task_preview || ""}>
                    <div className="text-ellipsis whitespace-nowrap overflow-hidden">{truncate(j.task_preview || j.stage_1?.task_preview || "--", 80)}</div>
                    <UserTags job={j} />
                  </td>
                  <td className="py-2 px-2">{s1Badge}</td>
                  {!isProd && (
                    <td className="py-2 px-2">
                      <VerdictSelect value={j.human_verdict_s1} onChange={(v) => setVerdict(ekey, "s1", v)} testId={`verdict-s1-${j.job_id}`} />
                    </td>
                  )}
                  {!isProd && <td className="py-2 px-2">{wcBadge}</td>}
                  {!isProd && (
                    <td className="py-2 px-2">
                      <VerdictSelect value={j.human_verdict_wc} onChange={(v) => setVerdict(ekey, "wc", v)} testId={`verdict-wc-${j.job_id}`} />
                    </td>
                  )}
                  {/* Opus Verdict column */}
                  {isProd ? (() => {
                    if (j.opus_verdict) return <td className="py-2 px-2"><OpusBadge opus={j.opus_verdict} /></td>;
                    if (j.automation_status === "pending_opus_review") return <td className="py-2 px-2"><span className="inline-flex items-center gap-1 text-[9px] font-mono text-purple-400"><Clock className="w-2.5 h-2.5 animate-pulse" />pending</span></td>;
                    return <td className="py-2 px-2"><span className="text-muted-foreground/30">--</span></td>;
                  })() : (
                    <td className="py-2 px-2">{s2Badge}</td>
                  )}
                  {/* Flagged Policies column */}
                  {isProd && (
                    <td className="py-2 px-2">
                      {j.opus_verdict?.flagged_policies?.length > 0 && j.opus_verdict.flagged_policies[0] !== "NONE" ? (
                        <div className="flex gap-0.5 flex-wrap">
                          {j.opus_verdict.flagged_policies.map((p, i) => (
                            <span key={p + i} className="inline-flex items-center rounded-sm border border-red-500/20 bg-red-500/10 text-red-400 px-1 py-0 text-[8px] font-mono font-semibold leading-tight">
                              {p.replace(/_/g, " ")}
                            </span>
                          ))}
                        </div>
                      ) : j.opus_verdict?.label === "LEGITIMATE" ? (
                        <span className="text-[9px] font-mono text-emerald-400/60">NONE</span>
                      ) : (
                        <span className="text-muted-foreground/30">--</span>
                      )}
                    </td>
                  )}
                  <td className="py-2 px-2">
                    <VerdictSelect value={j.human_verdict_s2} onChange={(v) => setVerdict(ekey, "s2", v)} testId={`verdict-s2-${j.job_id}`} />
                  </td>
                  {isProd && (
                    <td className="py-2 px-2" onClick={(e) => e.stopPropagation()}>
                      {isTakenDown || scheduledExecuted ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-mono text-red-500 font-semibold">
                          <Ban className="w-3 h-3" /> TAKEN DOWN
                        </span>
                      ) : autoAction === "auto_takedown" && j.opus_verdict ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-mono text-red-400 font-semibold">
                          <Ban className="w-3 h-3" /> AUTO
                        </span>
                      ) : autoAction === "auto_takedown" && !j.opus_verdict ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-mono text-zinc-500 font-semibold opacity-60" title="Legacy auto-takedown (pre-Opus)">
                          <Ban className="w-3 h-3" /> AUTO (legacy)
                        </span>
                      ) : autoAction === "skipped_mcp_error" ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-mono text-amber-400 font-semibold" title="Skipped: MCP error detected — automation could not verify job safely">
                          <AlertTriangle className="w-3 h-3" /> MCP ERROR
                        </span>
                      ) : autoAction === "skipped_excluded" ? (
                        <span className="inline-flex items-center gap-1 text-[10px] font-mono text-purple-400 font-semibold" title="Skipped: job matches an exclusion rule">
                          <ShieldOff className="w-3 h-3" /> EXCLUDED
                        </span>
                      ) : hasScheduled ? (
                        <span className="inline-flex items-center text-[10px] font-mono text-orange-400 font-semibold" title={`Takedown at ${j.scheduled_takedown?.takedown_at}`}>
                          SCHEDULED
                        </span>
                      ) : (
                        <div className="flex flex-col gap-1">
                          {takedownEligible && (
                            <button
                              onClick={() => onTakedownClick(j)}
                              data-testid={`takedown-btn-${j.job_id}`}
                              className="bg-red-500/10 border border-red-500/40 text-red-400 px-2 py-0.5 rounded-sm text-[10px] font-mono font-semibold hover:bg-red-500/25 hover:border-red-500/60 transition-all"
                            >
                              /takedown-job
                            </button>
                          )}
                          {scheduleEligible && onScheduleTakedown && (
                            <button
                              onClick={() => onScheduleTakedown(j)}
                              data-testid={`schedule-btn-${j.job_id}`}
                              className="bg-orange-500/10 border border-orange-500/30 text-orange-400 px-2 py-0.5 rounded-sm text-[10px] font-mono font-semibold hover:bg-orange-500/20 hover:border-orange-500/50 transition-all"
                            >
                              /schedule-takedown
                            </button>
                          )}
                          {!takedownEligible && !scheduleEligible && (
                            <span className="text-[10px] font-mono text-muted-foreground/30">--</span>
                          )}
                        </div>
                      )}
                    </td>
                  )}
                  {isProd ? (
                    <td className="py-2 px-2 text-muted-foreground overflow-hidden text-ellipsis whitespace-nowrap" title={j.takedown_info?.taken_down_by || ""}>
                      {j.opus_verdict ? (
                        <span className="text-[10px] font-mono text-purple-400 font-semibold">Opus Agent</span>
                      ) : j.takedown_info?.taken_down_by === "automation" ? (
                        <span className="text-[10px] font-mono text-blue-400 font-semibold">automated</span>
                      ) : j.takedown_info?.taken_down_by ? (
                        <span className="text-[10px] font-mono">{j.takedown_info.taken_down_by}</span>
                      ) : (
                        <span className="text-muted-foreground/30">--</span>
                      )}
                    </td>
                  ) : (
                    <td className="py-2 px-2 text-muted-foreground overflow-hidden text-ellipsis whitespace-nowrap">{verStr}</td>
                  )}
                  {!isProd && <td className="py-2 px-2 text-muted-foreground">{timeStr}</td>}
                </tr>
                {isExpanded && (
                  <tr className="bg-card">
                    <td colSpan={colCount} className="p-0">
                      <JobDetailPanel job={j} isProd={isProd} saveNotes={saveNotes} />
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
