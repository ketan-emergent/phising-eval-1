import { useState, useEffect } from "react";
import { Ban, User, Clock } from "lucide-react";
import { API } from "@/App";
import axios from "axios";

export default function TakedownsView({ sourceFilter }) {
  const [takedowns, setTakedowns] = useState([]);
  const [loading, setLoading] = useState(true);

  const fetchTakedowns = async () => {
    setLoading(true);
    try {
      if (sourceFilter && (sourceFilter === "cloudflare" || sourceFilter === "openai")) {
        // Fetch from BQ-backed endpoint for complete external source data
        const res = await axios.get(`${API}/prod/external-takedowns?source=${sourceFilter}`);
        setTakedowns(res.data.takedowns || []);
      } else {
        // Default: fetch from MongoDB takedowns collection
        const res = await axios.get(`${API}/prod/takedowns`);
        const data = res.data.takedowns || [];
        setTakedowns(sourceFilter ? data.filter((t) => t.source === sourceFilter) : data);
      }
    } catch (e) {
      console.error("Failed to fetch takedowns:", e);
    }
    setLoading(false);
  };

  useEffect(() => { fetchTakedowns(); }, [sourceFilter]);

  // Expose refresh for parent to call after new takedown
  useEffect(() => {
    window.__refreshTakedownsView = fetchTakedowns;
    return () => { delete window.__refreshTakedownsView; };
  });

  if (loading) {
    return (
      <div className="px-4 py-12 text-center">
        <div className="w-7 h-7 border-2 border-border border-t-red-400 rounded-full animate-spin mx-auto mb-3" />
        <span className="text-sm text-muted-foreground font-mono">Loading takedowns...</span>
      </div>
    );
  }

  if (takedowns.length === 0) {
    return (
      <div className="px-4 py-16 text-center">
        <Ban className="w-8 h-8 text-muted-foreground/20 mx-auto mb-3" />
        <p className="text-sm text-muted-foreground font-mono">
          {sourceFilter ? `No ${sourceFilter} takedowns found` : "No jobs have been taken down yet"}
        </p>
      </div>
    );
  }

  return (
    <div className="px-4 pb-4" data-testid="takedowns-view">
      <table className="w-full text-xs font-mono" style={{ tableLayout: "fixed" }}>
        <colgroup>
          <col style={{ width: "2%" }} />
          <col style={{ width: "18%" }} />
          <col style={{ width: "22%" }} />
          <col style={{ width: "8%" }} />
          <col style={{ width: "10%" }} />
          <col style={{ width: "15%" }} />
          <col style={{ width: "13%" }} />
          <col style={{ width: "12%" }} />
        </colgroup>
        <thead>
          <tr className="border-b border-border">
            <th className="text-left py-2 px-2 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider" />
            <th className="text-left py-2 px-2 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Job ID</th>
            <th className="text-left py-2 px-2 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Task</th>
            <th className="text-left py-2 px-2 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">S2 Label</th>
            <th className="text-left py-2 px-2 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Source</th>
            <th className="text-left py-2 px-2 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Reason</th>
            <th className="text-left py-2 px-2 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Taken Down By</th>
            <th className="text-left py-2 px-2 text-[10px] font-semibold text-muted-foreground uppercase tracking-wider">Date</th>
          </tr>
        </thead>
        <tbody>
          {takedowns.map((t, i) => (
            <tr key={t.job_id || i} className="border-b border-border bg-red-950/10 hover:bg-red-950/20 transition-colors">
              <td className="py-2.5 px-2"><Ban className="w-3.5 h-3.5 text-red-500" /></td>
              <td className="py-2.5 px-2 text-red-400/60 line-through overflow-hidden text-ellipsis whitespace-nowrap select-all" title={t.job_id}>{t.job_id}</td>
              <td className="py-2.5 px-2 text-muted-foreground/50 line-through overflow-hidden text-ellipsis whitespace-nowrap" title={t.task_preview}>{t.task_preview || "--"}</td>
              <td className="py-2.5 px-2">
                <span className="inline-flex items-center rounded-sm border border-red-500/20 bg-red-500/10 px-1.5 py-0.5 text-[9px] font-semibold text-red-400 uppercase">{t.s2_label || "MALICIOUS"}</span>
              </td>
              <td className="py-2.5 px-2">
                {t.source ? (
                  <span className={`inline-flex items-center rounded-sm border px-1.5 py-0.5 text-[9px] font-semibold uppercase ${
                    t.source === "openai" ? "border-blue-500/20 bg-blue-500/10 text-blue-400" :
                    t.source === "cloudflare" ? "border-orange-500/20 bg-orange-500/10 text-orange-400" :
                    "border-border bg-card text-muted-foreground"
                  }`}>{t.source}</span>
                ) : (
                  <span className="inline-flex items-center rounded-sm border border-border bg-card px-1.5 py-0.5 text-[9px] font-semibold text-muted-foreground uppercase">internal</span>
                )}
              </td>
              <td className="py-2.5 px-2 text-muted-foreground overflow-hidden text-ellipsis whitespace-nowrap" title={t.suspension_reason}>{t.suspension_reason || "--"}</td>
              <td className="py-2.5 px-2">
                <span className="flex items-center gap-1 text-muted-foreground"><User className="w-2.5 h-2.5 shrink-0" /><span className="overflow-hidden text-ellipsis whitespace-nowrap">{t.taken_down_by || "external:" + (t.source || "unknown")}</span></span>
              </td>
              <td className="py-2.5 px-2">
                <span className="flex items-center gap-1 text-muted-foreground"><Clock className="w-2.5 h-2.5 shrink-0" />{t.taken_down_at ? new Date(t.taken_down_at).toLocaleDateString() + " " + new Date(t.taken_down_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : "--"}</span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
