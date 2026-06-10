import { useState } from "react";
import { AlertTriangle, X, Loader2 } from "lucide-react";

/**
 * Generic confirmation modal matching the TakedownModal style.
 * Props:
 *   title        - modal header text
 *   message      - warning/description text
 *   details      - optional array of {label, value} pairs shown as metadata
 *   confirmLabel - button text (default "Confirm")
 *   color        - "red" | "amber" | "purple" (default "amber")
 *   onConfirm    - async callback, called on confirm click
 *   onClose      - close callback
 */
export default function ConfirmModal({ title, message, details, confirmLabel = "Confirm", color = "amber", onConfirm, onClose }) {
  const [confirming, setConfirming] = useState(false);

  const colors = {
    red:    { border: "border-red-500/50", bg: "bg-red-950", accent: "text-red-400", btnBg: "bg-red-600 border-red-500 hover:bg-red-500", warnBg: "bg-red-500/10 border-red-500/30", shadow: "shadow-[0_0_40px_rgba(239,68,68,0.15)]" },
    amber:  { border: "border-amber-500/50", bg: "bg-card", accent: "text-amber-400", btnBg: "bg-amber-600 border-amber-500 hover:bg-amber-500", warnBg: "bg-amber-500/10 border-amber-500/30", shadow: "shadow-[0_0_40px_rgba(245,158,11,0.1)]" },
    purple: { border: "border-purple-500/50", bg: "bg-card", accent: "text-purple-400", btnBg: "bg-purple-600 border-purple-500 hover:bg-purple-500", warnBg: "bg-purple-500/10 border-purple-500/30", shadow: "shadow-[0_0_40px_rgba(168,85,247,0.1)]" },
  };
  const c = colors[color] || colors.amber;

  const handleConfirm = async () => {
    if (confirming) return;
    setConfirming(true);
    try {
      await onConfirm();
    } catch (e) {
      console.error(e);
    }
    setConfirming(false);
  };

  return (
    <div className="fixed inset-0 bg-black/70 z-[60] flex items-center justify-center" data-testid="confirm-modal">
      <div className={`${c.bg} border-2 ${c.border} rounded-sm w-full max-w-lg mx-4 ${c.shadow}`}>
        <div className={`flex items-center justify-between px-5 py-3 border-b ${c.border}`}>
          <div className="flex items-center gap-2">
            <AlertTriangle className={`w-5 h-5 ${c.accent}`} />
            <h2 className={`text-sm font-mono font-bold ${c.accent} uppercase tracking-wider`}>{title}</h2>
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-5 py-4 space-y-4">
          <div className={`${c.warnBg} border rounded-sm px-4 py-3`}>
            <p className={`text-xs ${c.accent} font-mono`}>{message}</p>
          </div>

          {details && details.length > 0 && (
            <div className="space-y-2 text-xs font-mono">
              {details.map((d, i) => (
                <div key={d.label || i} className="flex gap-2">
                  <span className="text-muted-foreground min-w-[80px]">{d.label}</span>
                  <span className="text-foreground break-all select-all">{d.value}</span>
                </div>
              ))}
            </div>
          )}
        </div>

        <div className={`flex items-center justify-end gap-3 px-5 py-3 border-t ${c.border}`}>
          <button
            onClick={onClose}
            className="bg-transparent border border-border text-muted-foreground px-4 py-2 rounded-sm text-xs font-mono hover:text-foreground hover:border-primary/30 transition-all"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            disabled={confirming}
            className={`${c.btnBg} text-white px-4 py-2 rounded-sm text-xs font-mono font-semibold transition-all disabled:opacity-30 disabled:cursor-not-allowed`}
          >
            {confirming ? <Loader2 className="w-3.5 h-3.5 animate-spin inline" /> : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
