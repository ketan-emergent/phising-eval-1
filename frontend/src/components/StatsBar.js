import { useState } from "react";
import { Ban, AlertTriangle, Brain } from "lucide-react";
import TestTakedownModal from "./TestTakedownModal";
import OpusVerdictModal from "./OpusVerdictModal";

export default function StatsBar({ stats, takedownCount, mode }) {
  const [showTestModal, setShowTestModal] = useState(false);
  const [showOpusModal, setShowOpusModal] = useState(false);

  if (mode === "production") {
    const serverMode = stats.mode || "dry_run";
    return (
      <>
        <div className="bg-card border-b border-border px-4 py-2 flex gap-6 text-xs font-mono items-center" data-testid="stats-bar">
          {serverMode === "live" ? (
            <span className="px-2 py-0.5 rounded bg-red-500/20 text-red-400 border border-red-500/40 font-bold text-[10px] uppercase tracking-wider">LIVE</span>
          ) : (
            <span className="px-2 py-0.5 rounded bg-amber-500/20 text-amber-400 border border-amber-500/40 font-bold text-[10px] uppercase tracking-wider">DRY RUN</span>
          )}
          <Stat label="total" value={stats.total} />
          <div className="border-l border-border ml-1 pl-4 flex gap-6">
            <Brain className="w-3.5 h-3.5 text-purple-400 self-center" />
            <Stat label="malicious" value={stats.opus_confirmed_malicious || 0} color="text-red-400" />
            <Stat label="needs review" value={stats.opus_needs_review || 0} color="text-amber-400" />
            <Stat label="legitimate" value={stats.opus_legitimate || 0} color="text-emerald-400" />
          </div>
          {(stats.opus_pending > 0) && (
            <div className="flex items-center gap-1.5 pl-4 ml-1 border-l border-border">
              <span className="inline-block w-2 h-2 rounded-full bg-purple-400 animate-pulse" />
              <span className="font-bold text-base text-purple-400">{stats.opus_pending}</span>
              <span className="text-purple-400/70">opus queue</span>
            </div>
          )}
          {(takedownCount > 0 || stats.takedown_count > 0) && (
            <div className="flex items-center gap-1.5 pl-4 ml-1 border-l border-border">
              <Ban className="w-3 h-3 text-red-400" />
              <span className="font-bold text-base text-red-400">{takedownCount || stats.takedown_count}</span>
              <span className="text-red-400/70">takedowns</span>
            </div>
          )}
          <button
            onClick={() => setShowOpusModal(true)}
            className="ml-2 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-purple-500/20 text-purple-400 border border-purple-500/40 hover:bg-purple-500/30 transition-colors"
          >
            Trigger Opus for Verdict
          </button>
          <button
            onClick={() => setShowTestModal(true)}
            className="ml-2 px-2 py-0.5 rounded text-[10px] font-bold uppercase tracking-wider bg-orange-500/20 text-orange-400 border border-orange-500/40 hover:bg-orange-500/30 transition-colors"
          >
            Takedown in Prod
          </button>
        </div>
        {showOpusModal && <OpusVerdictModal onClose={() => setShowOpusModal(false)} />}
        {showTestModal && <TestTakedownModal onClose={() => setShowTestModal(false)} />}
      </>
    );
  }

  return (
    <div className="bg-card border-b border-border px-4 py-2 flex gap-6 text-xs font-mono" data-testid="stats-bar">
      <Stat label="total" value={stats.total} />
      <Stat label="correct" value={stats.correct} color="text-emerald-400" />
      <Stat label="incorrect" value={stats.incorrect} color="text-red-400" />
      <Stat label="disputed" value={stats.disputed} color="text-amber-400" />
      <Stat label="untagged" value={stats.untagged} color="text-muted-foreground" />
      <Stat label="in-flight" value={stats.in_flight} color="text-blue-400" />
      <div className="flex items-center gap-1.5 pl-4 ml-2 border-l border-border">
        <AlertTriangle className="w-3 h-3 text-red-400" />
        <span className="font-bold text-base text-red-400">{stats.malicious}</span>
        <span className="text-red-400/70">malicious</span>
      </div>
      {takedownCount > 0 && (
        <div className="flex items-center gap-1.5">
          <Ban className="w-3 h-3 text-red-400" />
          <span className="font-bold text-base text-red-400">{takedownCount}</span>
          <span className="text-red-400/70">takedowns</span>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value, color = "text-foreground" }) {
  return (
    <div className="flex items-center gap-1.5" data-testid={`stat-${label}`}>
      <span className={`font-bold text-base ${color}`}>{value}</span>
      <span className="text-muted-foreground">{label}</span>
    </div>
  );
}
