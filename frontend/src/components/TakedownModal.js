import { useState } from "react";
import { AlertTriangle, X } from "lucide-react";

export default function TakedownModal({ job, onClose, onConfirm }) {
  const [reason, setReason] = useState("");
  const [confirming, setConfirming] = useState(false);

  const canSubmit = reason.trim().length > 0 && !confirming;

  const handleConfirm = async () => {
    if (!canSubmit) return;
    setConfirming(true);
    await onConfirm(job, reason.trim());
    setConfirming(false);
  };

  return (
    <div className="fixed inset-0 bg-black/70 z-[60] flex items-center justify-center" data-testid="takedown-modal">
      <div className="bg-red-950 border-2 border-red-500/50 rounded-sm w-full max-w-lg mx-4 shadow-[0_0_40px_rgba(239,68,68,0.2)]">
        <div className="flex items-center justify-between px-5 py-3 border-b border-red-500/30">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <h2 className="text-sm font-mono font-bold text-red-400 uppercase tracking-wider">Job Takedown</h2>
          </div>
          <button onClick={onClose} className="text-red-400/50 hover:text-red-400 transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          <div className="bg-red-500/10 border border-red-500/30 rounded-sm px-4 py-3">
            <p className="text-sm text-red-300 font-mono font-semibold mb-1">WARNING: PRODUCTION ACTION</p>
            <p className="text-xs text-red-400/80 font-mono">
              This job will be taken down on production. This action is logged and cannot be easily reversed.
            </p>
          </div>

          <div className="space-y-2 text-xs font-mono">
            <div className="flex gap-2">
              <span className="text-red-400/60 min-w-[70px]">Job ID</span>
              <span className="text-foreground select-all">{job.job_id}</span>
            </div>
            <div className="flex gap-2">
              <span className="text-red-400/60 min-w-[70px]">S2 Label</span>
              <span className="text-red-400 font-semibold">{job.stage_2?.classification?.label || "--"}</span>
            </div>
            <div className="flex gap-2">
              <span className="text-red-400/60 min-w-[70px]">Task</span>
              <span className="text-foreground/80">{(job.task_preview || "--").substring(0, 200)}</span>
            </div>
            <div className="flex gap-2">
              <span className="text-red-400/60 min-w-[70px]">User ID</span>
              <span className="text-foreground/80">{job.user_id || "--"}</span>
            </div>
          </div>

          {/* Required Reason */}
          <div>
            <label className="block text-xs font-mono text-red-400/80 mb-1.5">
              Suspension Reason <span className="text-red-500">*</span>
            </label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              placeholder="Enter the reason for taking down this job..."
              data-testid="takedown-reason-input"
              className="w-full bg-red-950/50 border border-red-500/30 text-foreground px-3 py-2 rounded-sm font-mono text-xs resize-y min-h-[70px] focus:outline-none focus:border-red-500/60 placeholder:text-red-400/30"
            />
            {reason.trim().length === 0 && (
              <p className="text-[10px] text-red-400/50 font-mono mt-1">Required: reason must be provided to proceed</p>
            )}
          </div>
        </div>

        <div className="flex items-center justify-end gap-3 px-5 py-3 border-t border-red-500/30">
          <button
            onClick={onClose}
            data-testid="takedown-cancel-btn"
            className="bg-transparent border border-red-500/30 text-red-400/70 px-4 py-2 rounded-sm text-xs font-mono hover:text-red-400 hover:border-red-500/50 transition-all"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={!canSubmit}
            data-testid="takedown-confirm-btn"
            className="bg-red-600 border border-red-500 text-white px-4 py-2 rounded-sm text-xs font-mono font-semibold hover:bg-red-500 transition-all disabled:opacity-30 disabled:cursor-not-allowed shadow-[0_0_12px_rgba(239,68,68,0.3)]"
          >
            {confirming ? "Taking down..." : "CONFIRM TAKEDOWN"}
          </button>
        </div>
      </div>
    </div>
  );
}
