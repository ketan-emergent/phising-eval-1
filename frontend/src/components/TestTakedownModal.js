import { useState } from "react";
import { AlertTriangle, X, Loader2 } from "lucide-react";
import { API } from "@/App";
import axios from "axios";

export default function TestTakedownModal({ onClose }) {
  const [jobId, setJobId] = useState("");
  const [reason, setReason] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");

  const canSubmit = jobId.trim().length > 0 && reason.trim().length > 0 && !confirming;

  const handleConfirm = async () => {
    if (!canSubmit) return;
    setConfirming(true);
    setError("");
    setResult(null);
    try {
      const res = await axios.post(`${API}/admin/test-takedown/${jobId.trim()}`, {
        suspension_reason: reason.trim(),
      });
      setResult(res.data);
    } catch (e) {
      const msg = e.response?.data?.detail || e.message || "Unknown error";
      setError(msg);
    } finally {
      setConfirming(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 z-[60] flex items-center justify-center" data-testid="test-takedown-modal">
      <div className="bg-card border-2 border-amber-500/50 rounded-sm w-full max-w-lg mx-4 shadow-[0_0_40px_rgba(245,158,11,0.15)]">
        <div className="flex items-center justify-between px-5 py-3 border-b border-amber-500/30">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
            <h2 className="text-sm font-mono font-bold text-amber-400 uppercase tracking-wider">Test Takedown</h2>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors" data-testid="test-takedown-close-btn">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-sm px-4 py-3">
            <p className="text-sm text-amber-300 font-mono font-semibold mb-1">QA TEST MODE</p>
            <p className="text-xs text-amber-400/80 font-mono">
              This will call the production disable API directly. No verdict checks are performed.
            </p>
          </div>

          <div>
            <label className="block text-xs font-mono text-muted-foreground mb-1.5">
              Job ID <span className="text-amber-500">*</span>
            </label>
            <input
              type="text"
              value={jobId}
              onChange={(e) => setJobId(e.target.value)}
              placeholder="e.g. eeab2647-5a43-4dd7-a3be-85430f92626d"
              data-testid="test-takedown-job-id-input"
              className="w-full bg-background border border-border text-foreground px-3 py-2 rounded-sm font-mono text-xs focus:outline-none focus:border-amber-500/50 placeholder:text-muted-foreground/40"
            />
          </div>

          <div>
            <label className="block text-xs font-mono text-muted-foreground mb-1.5">
              Suspension Reason <span className="text-amber-500">*</span>
            </label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Enter the reason for taking down this job..."
              data-testid="test-takedown-reason-input"
              className="w-full bg-background border border-border text-foreground px-3 py-2 rounded-sm font-mono text-xs resize-y min-h-[70px] focus:outline-none focus:border-amber-500/50 placeholder:text-muted-foreground/40"
            />
            {reason.trim().length === 0 && (
              <p className="text-[10px] text-muted-foreground/50 font-mono mt-1">Required: reason must be provided to proceed</p>
            )}
          </div>

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-sm px-4 py-2.5 text-xs font-mono text-red-400" data-testid="test-takedown-error">
              {error}
            </div>
          )}

          {result && (
            <div className="bg-emerald-500/10 border border-emerald-500/30 rounded-sm px-4 py-2.5 text-xs font-mono text-emerald-400" data-testid="test-takedown-success">
              Takedown successful for job {jobId}
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-3 px-5 py-3 border-t border-amber-500/30">
          <button
            onClick={onClose}
            data-testid="test-takedown-cancel-btn"
            className="bg-transparent border border-border text-muted-foreground px-4 py-2 rounded-sm text-xs font-mono hover:text-foreground hover:border-primary/30 transition-all"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={!canSubmit}
            data-testid="test-takedown-confirm-btn"
            className="bg-amber-600 border border-amber-500 text-white px-4 py-2 rounded-sm text-xs font-mono font-semibold hover:bg-amber-500 transition-all disabled:opacity-30 disabled:cursor-not-allowed"
          >
            {confirming ? <Loader2 className="w-3.5 h-3.5 animate-spin inline" /> : "CONFIRM TAKEDOWN"}
          </button>
        </div>
      </div>
    </div>
  );
}
