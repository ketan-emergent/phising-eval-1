import { useState } from "react";
import { AlertTriangle, X, Loader2 } from "lucide-react";

export default function ConfirmLiveModal({ onConfirm, onClose }) {
  const [input, setInput] = useState("");
  const [confirming, setConfirming] = useState(false);
  const [error, setError] = useState("");

  const isValid = input === "CONFIRM_LIVE";

  const handleConfirm = async () => {
    if (!isValid || confirming) return;
    setConfirming(true);
    setError("");
    try {
      await onConfirm();
      onClose();
    } catch (e) {
      setError(e.response?.data?.detail || e.message || "Failed to switch mode");
      setConfirming(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 z-[60] flex items-center justify-center" data-testid="confirm-live-modal">
      <div className="bg-card border-2 border-red-500/50 rounded-sm w-full max-w-lg mx-4 shadow-[0_0_40px_rgba(239,68,68,0.15)]">
        <div className="flex items-center justify-between px-5 py-3 border-b border-red-500/30">
          <div className="flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <h2 className="text-sm font-mono font-bold text-red-400 uppercase tracking-wider">Switch to Live Mode</h2>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors" data-testid="confirm-live-close-btn">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          <div className="bg-red-500/10 border border-red-500/30 rounded-sm px-4 py-3">
            <p className="text-sm text-red-300 font-mono font-semibold mb-2">DANGER ZONE</p>
            <ul className="text-xs text-red-400/80 font-mono space-y-1.5">
              <li>Real takedowns will be executed via the disable API</li>
              <li>Real warning emails will be sent to users</li>
              <li>Scheduled takedowns will execute after 24h delay</li>
              <li>This affects ALL pipeline runs until switched back</li>
            </ul>
          </div>

          <div>
            <label className="block text-xs font-mono text-muted-foreground mb-1.5">
              Type <span className="text-red-400 font-bold">CONFIRM_LIVE</span> to proceed
            </label>
            <input
              type="text"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder="CONFIRM_LIVE"
              autoFocus
              data-testid="confirm-live-input"
              className="w-full bg-background border border-border text-foreground px-3 py-2 rounded-sm font-mono text-xs focus:outline-none focus:border-red-500/50 placeholder:text-muted-foreground/40"
              onKeyDown={(e) => { if (e.key === "Enter" && isValid) handleConfirm(); }}
            />
            {input.length > 0 && !isValid && (
              <p className="text-[10px] text-red-400/60 font-mono mt-1">Must type exactly: CONFIRM_LIVE</p>
            )}
          </div>

          {error && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-sm px-4 py-2.5 text-xs font-mono text-red-400" data-testid="confirm-live-error">
              {error}
            </div>
          )}
        </div>

        <div className="flex items-center justify-end gap-3 px-5 py-3 border-t border-red-500/30">
          <button
            onClick={onClose}
            data-testid="confirm-live-cancel-btn"
            className="bg-transparent border border-border text-muted-foreground px-4 py-2 rounded-sm text-xs font-mono hover:text-foreground hover:border-primary/30 transition-all"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={!isValid || confirming}
            data-testid="confirm-live-confirm-btn"
            className="bg-red-600 border border-red-500 text-white px-4 py-2 rounded-sm text-xs font-mono font-semibold hover:bg-red-500 transition-all disabled:opacity-30 disabled:cursor-not-allowed"
          >
            {confirming ? <Loader2 className="w-3.5 h-3.5 animate-spin inline" /> : "SWITCH TO LIVE"}
          </button>
        </div>
      </div>
    </div>
  );
}
