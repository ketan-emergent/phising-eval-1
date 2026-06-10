import { useState, useRef, useCallback } from "react";
import { ExternalLink, AlertTriangle, MessageSquareQuote, Languages } from "lucide-react";

function KV({ label, value, full = false }) {
  if (value == null || value === "" || value === "--") return null;
  return (
    <div className={`flex gap-2 mb-1.5 text-xs ${full ? "flex-col" : ""}`}>
      <span className="text-muted-foreground min-w-[100px] shrink-0 font-medium">{label}</span>
      <span className={`break-words whitespace-pre-wrap ${full ? "mt-0.5" : ""}`}>{value}</span>
    </div>
  );
}

function Section({ title, children, fullWidth = false, variant = "default" }) {
  const borderColor = variant === "danger" ? "border-red-500/20" : "border-border";
  const titleColor = variant === "danger" ? "text-red-400" : "text-primary";
  return (
    <div className={`bg-secondary/50 border ${borderColor} rounded-sm p-3 ${fullWidth ? "col-span-2" : ""}`}>
      <h3 className={`text-[10px] font-mono font-semibold ${titleColor} uppercase tracking-wider mb-2`}>{title}</h3>
      {children}
    </div>
  );
}

function HarmItem({ label, detected, details }) {
  return (
    <div className={`text-[11px] px-2 py-1.5 rounded-sm ${detected ? "bg-red-500/10 text-red-400" : "bg-muted text-muted-foreground"}`}>
      <span className="font-semibold">{detected ? "X" : "-"} {label}</span>
      {detected && details && <div className="mt-0.5 text-[10px] opacity-80 whitespace-pre-wrap">{details}</div>}
    </div>
  );
}

function JsonBlock({ title, data }) {
  const [show, setShow] = useState(false);
  return (
    <div>
      <button onClick={() => setShow(!show)} className="text-[11px] text-primary cursor-pointer hover:underline font-mono">
        {show ? "Hide" : "Show"} {title}
      </button>
      {show && (
        <pre className="bg-background border border-border rounded-sm p-3 mt-2 max-h-96 overflow-auto text-[11px] text-muted-foreground whitespace-pre-wrap font-mono">
          {JSON.stringify(data, null, 2)}
        </pre>
      )}
    </div>
  );
}

function QuoteCard({ quote, significance, translation }) {
  return (
    <div className="bg-background border border-border rounded-sm p-2.5 mb-2">
      <div className="flex items-start gap-2 mb-1.5">
        <MessageSquareQuote className="w-3.5 h-3.5 text-blue-400 shrink-0 mt-0.5" />
        <p className="text-xs text-foreground italic whitespace-pre-wrap">"{quote}"</p>
      </div>
      {translation && (
        <div className="flex items-start gap-2 mb-1.5 ml-5">
          <Languages className="w-3 h-3 text-muted-foreground shrink-0 mt-0.5" />
          <p className="text-[11px] text-muted-foreground italic">{translation}</p>
        </div>
      )}
      {significance && (
        <p className="text-[11px] text-amber-400/80 ml-5 whitespace-pre-wrap">{significance}</p>
      )}
    </div>
  );
}

export default function JobDetailPanel({ job, isProd, saveNotes }) {
  const j = job;
  const s1 = j.stage_1 || {};
  const s1cls = s1.classification || {};
  const s2 = j.stage_2 || {};
  const s2cls = s2.classification || {};
  const harm = s2.harm_assessment || {};
  const tools = s2.tool_findings || {};
  const slack = s2.slack_summary || {};

  const harmKeys = ["credential_theft", "deceptive_exfiltration", "user_deceived", "tool_for_scale_harm", "service_replication", "violent_harmful_content", "illegal_content", "malware_delivery"];
  const toolKeys = ["job_details", "agent_trajectory", "hitl_interactions", "deployment_details"];

  const notesTimerRef = useRef(null);
  const handleNotesChange = useCallback((text) => {
    clearTimeout(notesTimerRef.current);
    notesTimerRef.current = setTimeout(() => saveNotes(j.eval_key || j.job_id, text), 800);
  }, [j.eval_key, j.job_id, saveNotes]);

  // Parse notable quotes
  let notableQuotes = [];
  const rawQuotes = tools.hitl_interactions?.notable_quotes;
  if (rawQuotes) {
    if (typeof rawQuotes === "string") {
      try { notableQuotes = JSON.parse(rawQuotes); } catch { /* ignore */ }
    } else if (Array.isArray(rawQuotes)) {
      notableQuotes = rawQuotes;
    }
  }

  // Parse recommended actions
  let recommendedActions = [];
  const rawActions = s2.recommended_actions;
  if (rawActions) {
    if (typeof rawActions === "string") {
      try { recommendedActions = JSON.parse(rawActions); } catch { /* ignore */ }
    } else if (Array.isArray(rawActions)) {
      recommendedActions = rawActions;
    }
  }

  const hasUserInfo = j.user_email || j.plan_type || j.ltv || j.model_name;
  const taskText = j.task_full || j.task_preview;
  const taskTruncated = taskText && taskText.length > 400 ? taskText.substring(0, 400) + "..." : taskText;

  return (
    <div className="p-4 grid grid-cols-2 gap-3" data-testid={`detail-panel-${j.job_id}`}>
      {/* User Info */}
      {hasUserInfo && (
        <Section title="User Info" fullWidth>
          <div className="flex gap-6 flex-wrap">
            <KV label="Email" value={j.user_email} />
            <KV label="Plan" value={j.plan_type} />
            <KV label="LTV" value={j.ltv != null ? `$${Number(j.ltv).toFixed(2)}` : null} />
            <KV label="Gateway" value={j.payment_gateway} />
            <KV label="Discount" value={j.discount_amount ? `$${Number(j.discount_amount).toFixed(2)}` : null} />
            <KV label="Model" value={j.model_name} />
          </div>
        </Section>
      )}

      {/* Stage 3 — Opus Agent Verdict (shown first as primary classification) */}
      {j.opus_verdict && (
        <Section title="Stage 3 -- Opus Agent (Claude Opus 4)" fullWidth variant={j.opus_verdict.label === "CONFIRMED_MALICIOUS" ? "danger" : "default"}>
          <div className="flex gap-4 flex-wrap mb-2">
            <div className="flex items-center gap-1.5">
              <span className="text-muted-foreground text-[10px] font-medium">Verdict</span>
              <span className={`inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wide ${
                j.opus_verdict.label === "CONFIRMED_MALICIOUS" ? "bg-red-500/20 text-red-400 border-red-500/30" :
                j.opus_verdict.label === "NEEDS_HUMAN_REVIEW" ? "bg-amber-500/15 text-amber-400 border-amber-500/25" :
                j.opus_verdict.label === "LEGITIMATE" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" :
                "bg-muted text-muted-foreground border-border"
              }`}>{j.opus_verdict.label}</span>
            </div>
            <KV label="Confidence" value={j.opus_verdict.confidence} />
            <KV label="Severity" value={j.opus_verdict.severity} />
            <KV label="Action" value={j.opus_verdict.recommended_action} />
          </div>
          {j.opus_verdict.flagged_policies?.length > 0 && j.opus_verdict.flagged_policies[0] !== "NONE" && (
            <div className="flex items-center gap-1.5 mb-2 flex-wrap">
              <span className="text-muted-foreground text-[10px] font-medium">Flagged Policies:</span>
              {j.opus_verdict.flagged_policies.map((p, i) => (
                <span key={p + i} className="inline-flex items-center rounded-sm border border-red-500/20 bg-red-500/10 text-red-400 px-1.5 py-0.5 text-[9px] font-mono font-semibold">
                  {p.replace(/_/g, " ")}
                </span>
              ))}
            </div>
          )}
          {j.opus_verdict.verdict_summary && (
            <p className="text-xs mb-2 whitespace-pre-wrap">{j.opus_verdict.verdict_summary}</p>
          )}
          {j.opus_verdict.key_evidence?.length > 0 && (
            <div className="mt-1">
              <div className="text-[10px] text-muted-foreground font-semibold mb-1">Key Evidence:</div>
              {j.opus_verdict.key_evidence.map((e, i) => (
                <div key={e.slice(0, 30) + i} className="text-[11px] text-muted-foreground pl-3 mb-0.5">- {e}</div>
              ))}
            </div>
          )}
          {/* Opus Tool Execution Status */}
          {j.opus_verdict.tools_called && (
            <div className="mt-3 pt-2 border-t border-border">
              <div className="text-[10px] text-muted-foreground font-semibold mb-1.5">Redash Tools Executed:</div>
              <div className="flex gap-2 flex-wrap">
                {["get_job_details", "get_agent_trajectory", "get_hitl_interactions", "get_deployment_details", "get_user_jobs", "get_user_ltv"].map((tool) => {
                  const called = j.opus_verdict.tools_called.includes(tool);
                  return (
                    <span key={tool} className={`inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 text-[9px] font-mono ${
                      called ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-red-500/10 text-red-400 border-red-500/20"
                    }`}>
                      {called ? "\u2713" : "\u2717"} {tool.replace(/^get_/, "").replace(/_/g, " ")}
                    </span>
                  );
                })}
              </div>
              <div className="flex gap-4 mt-1.5 text-[10px] text-muted-foreground">
                {j.opus_verdict.turns_used && <span>Turns: {j.opus_verdict.turns_used}</span>}
                {j.opus_verdict.duration_s && <span>Duration: {j.opus_verdict.duration_s}s</span>}
              </div>
            </div>
          )}
          {j.opus_verdict.is_fallback && (
            <div className="mt-2 text-[10px] bg-amber-500/10 text-amber-400 border border-amber-500/20 rounded-sm px-2 py-1">
              Opus classifier error -- fell back to human review
            </div>
          )}
          {j.opus_verdict.overridden && (
            <div className="mt-2 text-[10px] bg-purple-500/10 text-purple-400 border border-purple-500/20 rounded-sm px-2 py-1">
              Opus overrode S2 tier classification
            </div>
          )}
          {j.opus_verdict.reviewed_at && (
            <div className="text-[10px] text-muted-foreground mt-2">Reviewed: {new Date(j.opus_verdict.reviewed_at).toLocaleString()}</div>
          )}
        </Section>
      )}
      {j.automation_status === "pending_opus_review" && !j.opus_verdict && (
        <Section title="Stage 3 -- Opus Agent (Pending)" fullWidth>
          <div className="flex items-center gap-2 text-xs text-purple-400">
            <span className="inline-block w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
            Pending Opus agent review -- verdict will appear here once processed
          </div>
        </Section>
      )}

      {/* Stage 1 */}
      <Section title="Stage 1 -- LLM Classifier">
        <KV label="Result" value={s1cls.result === true ? "PHISHING" : s1cls.result === false ? "LEGITIMATE" : null} />
        <KV label="Confidence" value={s1cls.confidence} />
        <KV label="Severity" value={s1cls.severity} />
        <KV label="Category" value={Array.isArray(s1cls.category) ? s1cls.category.join(", ") : s1cls.category} />
        <KV label="Reason" value={s1cls.reason} full />
        <KV label="Latency" value={s1.elapsed_seconds ? s1.elapsed_seconds.toFixed(1) + "s" : null} />
        <KV label="Tokens" value={s1cls._usage?.total_tokens} />
        {j.image_url && (
          <div className="mt-2">
            <div className="flex items-center gap-2 mb-1.5 text-xs">
              <span className="text-muted-foreground font-medium">Screenshot</span>
              <a href={j.image_url} target="_blank" rel="noopener noreferrer" className="text-blue-400 hover:underline flex items-center gap-0.5 text-[10px]">
                open full <ExternalLink className="w-2.5 h-2.5" />
              </a>
            </div>
            <a href={j.image_url} target="_blank" rel="noopener noreferrer" className="block">
              <img
                src={j.image_url}
                alt="Job screenshot"
                loading="lazy"
                className="rounded-sm border border-border max-h-64 w-auto object-contain bg-black/50 hover:border-primary/50 transition-colors cursor-pointer"
                data-testid={`job-image-${j.job_id}`}
              />
            </a>
          </div>
        )}
      </Section>

      {/* Stage 2 — Escalation Agent */}
      <Section title="Stage 2 -- Haiku/Sonnet (Initial Signal)">
        <KV label="Label" value={s2cls.label} />
        <KV label="Severity" value={s2cls.severity} />
        <KV label="Confidence" value={s2cls.confidence} />
        <KV label="Category" value={s2cls.category} />
        <KV label="Reasoning" value={s2cls.reasoning} full />
        <KV label="Task Desc" value={s2.task_description} full />
        <KV label="What Built" value={s2.what_was_built} full />
        {slack.headline && <KV label="Slack" value={`${slack.emoji || ""} ${slack.headline}`} />}
        {slack.verdict && <KV label="Slack Verdict" value={slack.verdict} full />}
      </Section>

      {/* Image Analysis */}
      {s2.image_analysis_note && (
        <Section title="Image Analysis" fullWidth>
          <p className="text-xs whitespace-pre-wrap">{s2.image_analysis_note}</p>
        </Section>
      )}

      {/* Recommended Actions */}
      {recommendedActions.length > 0 && (
        <Section title="Recommended Actions" fullWidth variant="danger">
          <ul className="space-y-1">
            {recommendedActions.map((action, i) => (
              <li key={typeof action === 'string' ? action.slice(0, 40) + i : i} className="flex items-start gap-2 text-xs">
                <AlertTriangle className="w-3 h-3 text-red-400 shrink-0 mt-0.5" />
                <span className="whitespace-pre-wrap">{typeof action === "string" ? action : JSON.stringify(action)}</span>
              </li>
            ))}
          </ul>
        </Section>
      )}

      {/* Harm Assessment */}
      <Section title="Harm Assessment" fullWidth>
        <div className="grid grid-cols-2 gap-1.5">
          {harmKeys.map((k) => {
            const h = harm[k] || {};
            return <HarmItem key={k} label={k.replace(/_/g, " ")} detected={h.detected} details={h.details} />;
          })}
        </div>
      </Section>

      {/* Tool Findings */}
      <Section title="Tool Findings" fullWidth>
        <div className="flex gap-3 mb-3">
          {toolKeys.map((k) => {
            const t = tools[k] || {};
            const status = !t.called ? "skip" : t.success ? "ok" : "fail";
            const color = status === "ok" ? "text-emerald-400" : status === "fail" ? "text-red-400" : "text-muted-foreground";
            return <span key={k} className={`text-[11px] ${color}`}>{k.replace(/_/g, " ")}: {status}</span>;
          })}
        </div>
        {toolKeys.map((k) => {
          const t = tools[k] || {};
          if (!t.called || !t.key_findings?.length) return null;
          return (
            <div key={k} className="mb-3">
              <div className="text-[10px] text-muted-foreground font-semibold mb-1">{k.replace(/_/g, " ")}:</div>
              {t.key_findings.map((f, i) => (
                <div key={typeof f === 'string' ? f.slice(0, 40) + i : i} className="text-[11px] text-muted-foreground pl-3 whitespace-pre-wrap mb-0.5">- {typeof f === "string" ? f : JSON.stringify(f)}</div>
              ))}
            </div>
          );
        })}
        {/* Deployment Info */}
        {tools.deployment_details?.has_active_deployment != null && (
            <div className="mb-3">
                <div className="text-[10px] text-muted-foreground font-semibold mb-1">deployment status:</div>
                <div className="text-[11px] pl-3">
                    <span className={tools.deployment_details.has_active_deployment ? "text-red-400" : "text-emerald-400"}>
                        {tools.deployment_details.has_active_deployment ? "ACTIVE DEPLOYMENT" : "No active deployment"}
                    </span>
                    {tools.deployment_details.deployment_url && (
                        <a href={tools.deployment_details.deployment_url} target="_blank" rel="noopener noreferrer"
                           className="ml-2 text-blue-400 hover:underline text-[10px]">
                            {tools.deployment_details.deployment_url}
                        </a>
                    )}
                </div>
            </div>
        )}
      </Section>

      {/* Notable Quotes */}
      {notableQuotes.length > 0 && (
        <Section title="Notable Quotes -- User Intent" fullWidth>
          {notableQuotes.map((q, i) => (
            <QuoteCard
              key={q.quote ? q.quote.slice(0, 30) + i : i}
              quote={typeof q === "string" ? q : q.quote || JSON.stringify(q)}
              significance={q.significance}
              translation={q.translation}
            />
          ))}
        </Section>
      )}

      {/* Notes */}
      <Section title="Human Eval Notes" fullWidth>
        <textarea
          defaultValue={j.human_notes || ""}
          onChange={(e) => handleNotesChange(e.target.value)}
          placeholder="Add evaluation notes..."
          data-testid={`notes-${j.job_id}`}
          className="w-full bg-background border border-border text-foreground px-3 py-2 rounded-sm font-mono text-xs resize-y min-h-[50px] focus:outline-none focus:border-primary"
        />
      </Section>

      {/* Task */}
      {taskTruncated && (
        <Section title="Task" fullWidth>
          <p className="text-xs whitespace-pre-wrap">{taskTruncated}</p>
        </Section>
      )}

      {/* Raw JSON */}
      <Section title="Raw JSON" fullWidth>
        <div className="flex gap-4 flex-wrap">
          <JsonBlock title="Stage 1" data={s1} />
          {!isProd && <JsonBlock title="WhiteCircle" data={j.whitecircle || {}} />}
          <JsonBlock title="Stage 2" data={s2} />
        </div>
      </Section>
    </div>
  );
}
