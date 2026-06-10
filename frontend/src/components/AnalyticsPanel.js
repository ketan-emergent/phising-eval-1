import { useState, useEffect } from "react";
import { CheckCircle2, XCircle, HelpCircle } from "lucide-react";
import { API } from "@/App";
import axios from "axios";

export default function AnalyticsPanel() {
  const [daily, setDaily] = useState([]);
  const [accuracy, setAccuracy] = useState({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    const fetchAnalytics = async () => {
      try {
        const res = await axios.get(`${API}/prod/analytics`);
        setDaily(res.data.daily || []);
        setAccuracy(res.data.accuracy || {});
        if (res.data.error) setError(res.data.error);
      } catch (e) {
        setError(e.message);
      }
      setLoading(false);
    };
    fetchAnalytics();
  }, []);

  function pct(num, den) {
    if (!den) return "--";
    return ((num / den) * 100).toFixed(0) + "%";
  }
  const accColor = (v) => (v >= 70 ? "text-emerald-400" : v >= 40 ? "text-amber-400" : "text-red-400");

  if (loading) {
    return (
      <div className="bg-card border-b border-border px-4 py-8 text-center">
        <div className="w-6 h-6 border-2 border-border border-t-primary rounded-full animate-spin mx-auto mb-2" />
        <span className="text-xs text-muted-foreground font-mono">Loading analytics from BigQuery...</span>
      </div>
    );
  }

  return (
    <div className="bg-card border-b border-border px-4 py-4" data-testid="analytics-panel">
      {error && (
        <div className="text-xs text-red-400 font-mono mb-3 bg-red-500/10 border border-red-500/20 rounded-sm px-3 py-1.5">
          BigQuery error: {error}
        </div>
      )}
      <div className="grid grid-cols-2 gap-4">
        {/* Daily S2 Categorization — from BigQuery */}
        <div className="bg-secondary/50 border border-border rounded-sm p-3">
          <h3 className="text-[10px] font-mono font-semibold text-primary uppercase tracking-wider mb-1">Daily S2 Categorization</h3>
          <p className="text-[10px] text-muted-foreground mb-3">Source: BigQuery (full dataset)</p>
          <div className="max-h-72 overflow-y-auto">
            <table className="w-full text-xs font-mono">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-1 px-1 text-[10px] text-muted-foreground uppercase">Date</th>
                  <th className="text-center py-1 px-1 text-[10px] text-red-400 uppercase">Malicious</th>
                  <th className="text-center py-1 px-1 text-[10px] text-amber-400 uppercase">Review</th>
                  <th className="text-center py-1 px-1 text-[10px] text-emerald-400 uppercase">Legit</th>
                  <th className="text-center py-1 px-1 text-[10px] text-muted-foreground uppercase">Total</th>
                </tr>
              </thead>
              <tbody>
                {daily.map((d) => (
                  <tr key={d.day} className="border-b border-border/30">
                    <td className="py-1.5 px-1 text-blue-400">{d.day}</td>
                    <td className="py-1.5 px-1 text-center text-red-400">{d.malicious} <span className="text-muted-foreground">({pct(d.malicious, d.total)})</span></td>
                    <td className="py-1.5 px-1 text-center text-amber-400">{d.review} <span className="text-muted-foreground">({pct(d.review, d.total)})</span></td>
                    <td className="py-1.5 px-1 text-center text-emerald-400">{d.legit} <span className="text-muted-foreground">({pct(d.legit, d.total)})</span></td>
                    <td className="py-1.5 px-1 text-center">{d.total}</td>
                  </tr>
                ))}
                {daily.length === 0 && (
                  <tr><td colSpan={5} className="py-4 text-center text-muted-foreground">No data available</td></tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* S2 Accuracy — BQ totals + MongoDB verdicts */}
        <div className="bg-secondary/50 border border-border rounded-sm p-3">
          <h3 className="text-[10px] font-mono font-semibold text-primary uppercase tracking-wider mb-1">S2 Accuracy by Label</h3>
          <p className="text-[10px] text-muted-foreground mb-3">Source: BigQuery totals + MongoDB verdicts (disputed excluded)</p>

          {["CONFIRMED_MALICIOUS", "NEEDS_HUMAN_REVIEW", "LEGITIMATE"].map((label) => {
            const a = accuracy[label] || { correct: 0, incorrect: 0, unmarked: 0, total: 0 };
            const reviewed = a.correct + a.incorrect;
            const accPct = reviewed > 0 ? (a.correct / reviewed) * 100 : null;
            const labelColor = label === "CONFIRMED_MALICIOUS" ? "text-red-400" : label === "NEEDS_HUMAN_REVIEW" ? "text-amber-400" : "text-emerald-400";
            const shortLabel = label === "CONFIRMED_MALICIOUS" ? "S2 says CONFIRMED MALICIOUS" : label === "NEEDS_HUMAN_REVIEW" ? "S2 says NEEDS HUMAN REVIEW" : "S2 says LEGITIMATE";

            return (
              <div key={label} className="mb-3 pb-3 border-b border-border/30 last:border-0 last:mb-0 last:pb-0">
                <div className="flex items-center justify-between mb-2">
                  <span className={`text-[11px] font-semibold font-mono ${labelColor}`}>{shortLabel}</span>
                  <span className="text-[10px] text-muted-foreground font-mono">{a.total} total in BQ</span>
                </div>
                <div className="grid grid-cols-4 gap-3 text-center">
                  <div>
                    <div className="text-xl font-bold font-mono text-emerald-400">{a.correct}</div>
                    <div className="text-[9px] text-muted-foreground flex items-center justify-center gap-0.5"><CheckCircle2 className="w-2.5 h-2.5" /> correct</div>
                  </div>
                  <div>
                    <div className="text-xl font-bold font-mono text-red-400">{a.incorrect}</div>
                    <div className="text-[9px] text-muted-foreground flex items-center justify-center gap-0.5"><XCircle className="w-2.5 h-2.5" /> incorrect</div>
                  </div>
                  <div>
                    <div className="text-xl font-bold font-mono text-muted-foreground">{a.unmarked}</div>
                    <div className="text-[9px] text-muted-foreground flex items-center justify-center gap-0.5"><HelpCircle className="w-2.5 h-2.5" /> not marked</div>
                  </div>
                  <div>
                    <div className={`text-xl font-bold font-mono ${accPct != null ? accColor(accPct) : "text-muted-foreground"}`}>
                      {accPct != null ? accPct.toFixed(0) + "%" : "--"}
                    </div>
                    <div className="text-[9px] text-muted-foreground">accuracy</div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
