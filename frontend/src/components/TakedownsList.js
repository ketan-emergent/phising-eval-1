import { useState, useEffect } from "react";
import { Ban, User, Clock } from "lucide-react";
import { API } from "@/App";
import axios from "axios";

export default function TakedownsList() {
  const [takedowns, setTakedowns] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetch = async () => {
      try {
        const res = await axios.get(`${API}/prod/takedowns`);
        setTakedowns(res.data.takedowns || []);
      } catch (e) {
        console.error("Failed to fetch takedowns:", e);
      }
      setLoading(false);
    };
    fetch();
  }, []);

  if (loading) {
    return (
      <div className="bg-card border-b border-border px-4 py-6 text-center">
        <div className="w-6 h-6 border-2 border-border border-t-red-400 rounded-full animate-spin mx-auto mb-2" />
        <span className="text-xs text-muted-foreground font-mono">Loading takedowns...</span>
      </div>
    );
  }

  return (
    <div className="bg-card border-b border-border px-4 py-4" data-testid="takedowns-panel">
      <h3 className="text-[10px] font-mono font-semibold text-red-400 uppercase tracking-wider mb-3 flex items-center gap-1.5">
        <Ban className="w-3.5 h-3.5" /> Job Takedowns ({takedowns.length})
      </h3>

      {takedowns.length === 0 ? (
        <p className="text-xs text-muted-foreground text-center py-6 font-mono">No jobs have been taken down yet</p>
      ) : (
        <div className="space-y-2">
          {takedowns.map((t, i) => (
            <div key={t.job_id || i} className="bg-red-950/30 border border-red-500/20 rounded-sm px-4 py-3 flex items-start gap-4">
              <Ban className="w-4 h-4 text-red-500 mt-0.5 shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-3 mb-1">
                  <span className="text-xs text-blue-400 font-mono select-all">{t.job_id}</span>
                  <span className="inline-flex items-center rounded-sm border border-red-500/30 bg-red-500/10 px-1.5 py-0.5 text-[10px] font-mono font-semibold text-red-400 uppercase">
                    {t.s2_label || "MALICIOUS"}
                  </span>
                </div>
                <div className="text-[11px] text-muted-foreground font-mono truncate mb-1">
                  {t.task_preview || "--"}
                </div>
                <div className="flex items-center gap-4 text-[10px] text-muted-foreground font-mono">
                  <span className="flex items-center gap-1">
                    <User className="w-3 h-3" /> {t.taken_down_by || "unknown"}
                  </span>
                  <span className="flex items-center gap-1">
                    <Clock className="w-3 h-3" /> {t.taken_down_at ? new Date(t.taken_down_at).toLocaleString() : "--"}
                  </span>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
