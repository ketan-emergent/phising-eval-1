import { useState, useEffect } from "react";
import { Shield, BarChart3, Download, RefreshCw, LogOut, User, AlertTriangle, X, Zap, Search, Bot } from "lucide-react";
import { API } from "@/App";
import axios from "axios";

export default function Header({ mode, setMode, showAnalytics, setShowAnalytics, exportCSV, refresh, evalConfig, saveConfig, user, logout, toast, clearToast, onTestTakedown, onSearch }) {
  const [cfgLlm, setCfgLlm] = useState(evalConfig.llm_classifier_prompt_version || "");
  const [cfgAgent, setCfgAgent] = useState(evalConfig.escalation_agent_prompt_version || "");
  const [cfgMsg, setCfgMsg] = useState(evalConfig.user_message_prompt_version || "");
  const [pendingCount, setPendingCount] = useState(0);

  useEffect(() => {
    if (mode !== "production") return;
    const fetchPending = async () => {
      try {
        const res = await axios.get(`${API}/prod/pending-review-count`);
        setPendingCount(res.data.count || 0);
      } catch { /* ignore */ }
    };
    fetchPending();
  }, [mode]);

  const handleSaveConfig = () => {
    saveConfig({
      llm_classifier_prompt_version: cfgLlm,
      escalation_agent_prompt_version: cfgAgent,
      user_message_prompt_version: cfgMsg,
    });
  };

  return (
    <>
      {/* Toast notification */}
      {toast && (
        <div className="bg-red-950 border-b-2 border-red-500/50 px-4 py-2.5 flex items-center gap-3 animate-in" data-testid="takedown-toast">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span className="text-xs font-mono text-red-300 flex-1">{toast}</span>
          <button onClick={clearToast} className="text-red-400/50 hover:text-red-400 transition-colors shrink-0" data-testid="toast-dismiss-btn">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      <div className="bg-card border-b border-border px-4 py-2.5 flex items-center gap-4 sticky top-0 z-40" data-testid="header">
        <div className="flex items-center gap-2">
          <Shield className="w-5 h-5 text-primary" />
          <h1 className="text-sm font-mono font-bold tracking-wider uppercase text-primary">Phishing Eval</h1>
        </div>

        <div className="flex bg-background border border-border rounded-sm overflow-hidden" data-testid="mode-toggle">
          <button onClick={() => setMode("production")} data-testid="mode-production-btn"
            className={`px-3 py-1.5 text-xs font-mono font-medium transition-all ${mode === "production" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"}`}>
            Production
          </button>
          <button onClick={() => setMode("eval")} data-testid="mode-eval-btn"
            className={`px-3 py-1.5 text-xs font-mono font-medium transition-all ${mode === "eval" ? "bg-primary text-primary-foreground" : "text-muted-foreground hover:text-foreground"}`}>
            Eval
          </button>
        </div>

        {mode === "production" && pendingCount > 0 && (
          <div className="flex items-center gap-1.5 bg-amber-500/10 border border-amber-500/30 text-amber-400 px-2.5 py-1 rounded-sm text-xs font-mono" data-testid="pending-review-badge">
            <AlertTriangle className="w-3.5 h-3.5" />
            <span className="font-semibold">{pendingCount}</span>
            <span>needs human review</span>
          </div>
        )}

        {mode === "eval" && (
          <div className="flex items-center gap-2 text-xs" data-testid="prompt-versions">
            <label className="flex items-center gap-1 text-muted-foreground">
              LLM
              <input value={cfgLlm} onChange={(e) => setCfgLlm(e.target.value)}
                className="bg-background border border-border text-foreground px-2 py-1 rounded-sm font-mono text-xs w-16 focus:outline-none focus:border-primary" data-testid="cfg-llm-input" />
            </label>
            <label className="flex items-center gap-1 text-muted-foreground">
              Agent
              <input value={cfgAgent} onChange={(e) => setCfgAgent(e.target.value)}
                className="bg-background border border-border text-foreground px-2 py-1 rounded-sm font-mono text-xs w-16 focus:outline-none focus:border-primary" data-testid="cfg-agent-input" />
            </label>
            <label className="flex items-center gap-1 text-muted-foreground">
              Msg
              <input value={cfgMsg} onChange={(e) => setCfgMsg(e.target.value)}
                className="bg-background border border-border text-foreground px-2 py-1 rounded-sm font-mono text-xs w-16 focus:outline-none focus:border-primary" data-testid="cfg-msg-input" />
            </label>
            <button onClick={handleSaveConfig} data-testid="save-versions-btn" className="bg-primary/10 border border-primary/30 text-primary px-2 py-1 rounded-sm text-xs font-mono hover:bg-primary/20 transition-all">
              Save
            </button>
          </div>
        )}

        <div className="ml-auto flex items-center gap-2">
          {mode === "production" && (
            <a href="/automation"
              className="flex items-center gap-1.5 bg-card border border-border text-muted-foreground hover:text-foreground hover:border-primary/30 px-2.5 py-1.5 rounded-sm text-xs font-mono transition-all">
              <Bot className="w-3.5 h-3.5" /> Automation
            </a>
          )}
          {mode === "eval" && (
            <button onClick={onTestTakedown} data-testid="test-takedown-btn"
              className="flex items-center gap-1.5 bg-amber-500/10 border border-amber-500/30 text-amber-400 hover:bg-amber-500/20 hover:border-amber-500/50 px-2.5 py-1.5 rounded-sm text-xs font-mono font-semibold transition-all">
              <Zap className="w-3.5 h-3.5" /> Test Takedown
            </button>
          )}
          <button onClick={onSearch} data-testid="job-search-btn"
            className="flex items-center gap-1.5 bg-card border border-border text-muted-foreground hover:text-foreground hover:border-primary/30 px-2.5 py-1.5 rounded-sm text-xs font-mono transition-all"
            title="Search job by ID (Ctrl+F)">
            <Search className="w-3.5 h-3.5" /> <span className="hidden sm:inline">Search</span> <kbd className="hidden sm:inline text-[9px] text-muted-foreground/50 bg-background px-1 py-0.5 rounded border border-border/50 ml-0.5">Ctrl+F</kbd>
          </button>
          <button onClick={() => setShowAnalytics(!showAnalytics)} data-testid="toggle-analytics-btn"
            className={`flex items-center gap-1.5 border px-2.5 py-1.5 rounded-sm text-xs font-mono transition-all ${showAnalytics ? "bg-primary/10 border-primary/30 text-primary" : "bg-card border-border text-muted-foreground hover:text-foreground hover:border-primary/30"}`}>
            <BarChart3 className="w-3.5 h-3.5" /> Analytics
          </button>
          <button onClick={exportCSV} data-testid="export-csv-btn" className="flex items-center gap-1.5 bg-card border border-border text-muted-foreground hover:text-foreground hover:border-primary/30 px-2.5 py-1.5 rounded-sm text-xs font-mono transition-all">
            <Download className="w-3.5 h-3.5" /> CSV
          </button>
          <button onClick={refresh} data-testid="refresh-btn" className="flex items-center gap-1.5 bg-card border border-border text-muted-foreground hover:text-foreground hover:border-primary/30 px-2.5 py-1.5 rounded-sm text-xs font-mono transition-all">
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
          {mode === "eval" && <div className="w-2 h-2 bg-primary rounded-full animate-pulse-slow" title="Auto-refresh active" />}

          <div className="flex items-center gap-2 ml-2 pl-2 border-l border-border">
            <User className="w-4 h-4 text-muted-foreground" />
            <span className="text-xs text-muted-foreground font-mono hidden sm:inline">{user?.name || user?.email}</span>
            <button onClick={logout} data-testid="logout-btn" className="text-muted-foreground hover:text-destructive transition-colors" title="Logout">
              <LogOut className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </>
  );
}
