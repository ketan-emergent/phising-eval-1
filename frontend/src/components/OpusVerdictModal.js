import { useState } from "react";
import { Brain, X, Check, Clock, AlertTriangle } from "lucide-react";
import axios from "axios";

const API = process.env.REACT_APP_BACKEND_URL || "";

export default function OpusVerdictModal({ onClose }) {
  const [jobId, setJobId] = useState("");
  const [loading, setLoading] = useState(false);
  const [verdict, setVerdict] = useState(null);
  const [error, setError] = useState(null);

  const triggerOpus = async () => {
    if (!jobId.trim()) return;
    setLoading(true);
    setVerdict(null);
    setError(null);
    try {
      const res = await axios.post(`${API}/admin/opus-verdict/${jobId.trim()}`);
      if (res.data.status === "ok") {
        setVerdict(res.data.verdict);
      } else {
        setError(res.data.error || "Unknown error");
      }
    } catch (e) {
      setError(e.response?.data?.detail || e.message || "Request failed");
    }
    setLoading(false);
  };

  const labelStyle = {
    CONFIRMED_MALICIOUS: "bg-red-500/20 text-red-400 border-red-500/30",
    NEEDS_HUMAN_REVIEW: "bg-amber-500/15 text-amber-400 border-amber-500/25",
    LEGITIMATE: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
  };

  const requiredTools = ["get_job_details", "get_agent_trajectory", "get_hitl_interactions", "get_deployment_details", "get_user_jobs", "get_user_ltv"];

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-start justify-center pt-20 px-4" onClick={onClose}>
      <div className="bg-card border border-border rounded-lg shadow-xl w-full max-w-2xl max-h-[80vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-center justify-between px-4 py-3 border-b border-border">
          <div className="flex items-center gap-2">
            <Brain className="w-4 h-4 text-purple-400" />
            <span className="text-sm font-mono font-bold">Trigger Opus Agent Verdict</span>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Input */}
        <div className="px-4 py-3 border-b border-border">
          <div className="flex gap-2">
            <input
              type="text"
              value={jobId}
              onChange={(e) => setJobId(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && !loading && triggerOpus()}
              placeholder="Enter job_id (UUID)"
              className="flex-1 bg-background border border-border text-foreground px-3 py-1.5 rounded text-xs font-mono focus:outline-none focus:border-purple-500"
              disabled={loading}
            />
            <button
              onClick={triggerOpus}
              disabled={loading || !jobId.trim()}
              className="px-4 py-1.5 rounded text-xs font-mono font-bold bg-purple-500/20 text-purple-400 border border-purple-500/40 hover:bg-purple-500/30 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              {loading ? "Running..." : "Run Opus"}
            </button>
          </div>
          {loading && (
            <div className="flex items-center gap-2 mt-2 text-xs text-purple-400">
              <Clock className="w-3 h-3 animate-spin" />
              Opus agent is investigating... this takes 1-4 minutes
            </div>
          )}
        </div>

        {/* Error */}
        {error && (
          <div className="px-4 py-3 text-xs text-red-400 bg-red-500/10 border-b border-border">
            <AlertTriangle className="w-3 h-3 inline mr-1" />
            {error}
          </div>
        )}

        {/* Verdict */}
        {verdict && (
          <div className="px-4 py-3 space-y-3">
            {/* Label + Confidence + Severity + Action */}
            <div className="flex gap-3 flex-wrap items-center">
              <div className="flex items-center gap-1.5">
                <span className="text-muted-foreground text-[10px] font-medium">Verdict</span>
                <span className={`inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[10px] font-mono font-semibold uppercase tracking-wide ${labelStyle[verdict.label] || "bg-muted text-muted-foreground border-border"}`}>
                  {verdict.label}
                </span>
              </div>
              <span className="text-[10px] text-muted-foreground">Confidence: <span className="text-foreground">{verdict.confidence}</span></span>
              <span className="text-[10px] text-muted-foreground">Severity: <span className="text-foreground">{verdict.severity}</span></span>
              <span className="text-[10px] text-muted-foreground">Action: <span className="text-foreground">{verdict.recommended_action}</span></span>
            </div>

            {/* Flagged Policies */}
            {verdict.flagged_policies?.length > 0 && verdict.flagged_policies[0] !== "NONE" && (
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-muted-foreground text-[10px] font-medium">Flagged Policies:</span>
                {verdict.flagged_policies.map((p, i) => (
                  <span key={p + i} className="inline-flex items-center rounded-sm border border-red-500/20 bg-red-500/10 text-red-400 px-1.5 py-0.5 text-[9px] font-mono font-semibold">
                    {p.replace(/_/g, " ")}
                  </span>
                ))}
              </div>
            )}

            {/* Summary */}
            {verdict.verdict_summary && (
              <p className="text-xs whitespace-pre-wrap">{verdict.verdict_summary}</p>
            )}

            {/* Key Evidence */}
            {verdict.key_evidence?.length > 0 && (
              <div>
                <div className="text-[10px] text-muted-foreground font-semibold mb-1">Key Evidence:</div>
                {verdict.key_evidence.map((e, i) => (
                  <div key={e.slice(0, 30) + i} className="text-[11px] text-muted-foreground pl-3 mb-0.5">- {e}</div>
                ))}
              </div>
            )}

            {/* Tools Executed */}
            {verdict.tools_called && (
              <div className="pt-2 border-t border-border">
                <div className="text-[10px] text-muted-foreground font-semibold mb-1.5">Redash Tools Executed:</div>
                <div className="flex gap-2 flex-wrap">
                  {requiredTools.map((tool) => {
                    const called = verdict.tools_called.includes(tool);
                    return (
                      <span key={tool} className={`inline-flex items-center gap-1 rounded-sm border px-1.5 py-0.5 text-[9px] font-mono ${called ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/20" : "bg-red-500/10 text-red-400 border-red-500/20"}`}>
                        {called ? "\u2713" : "\u2717"} {tool.replace(/^get_/, "").replace(/_/g, " ")}
                      </span>
                    );
                  })}
                </div>
                <div className="flex gap-4 mt-1.5 text-[10px] text-muted-foreground">
                  {verdict.turns_used && <span>Turns: {verdict.turns_used}</span>}
                  {verdict.duration_s && <span>Duration: {verdict.duration_s}s</span>}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Footer */}
        {!verdict && !loading && (
          <div className="px-4 py-4 text-center text-xs text-muted-foreground">
            Enter a job ID and click "Run Opus" to trigger the Claude Opus 4 classifier agent.
          </div>
        )}
      </div>
    </div>
  );
}
