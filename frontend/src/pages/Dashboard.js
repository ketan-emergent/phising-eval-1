import { useState, useEffect, useCallback, useRef } from "react";
import { useAuth, API } from "@/App";
import axios from "axios";
import Header from "@/components/Header";
import StatsBar from "@/components/StatsBar";
import FilterBar from "@/components/FilterBar";
import JobsTable from "@/components/JobsTable";
import AnalyticsPanel from "@/components/AnalyticsPanel";
import TakedownsView from "@/components/TakedownsView";
import TakedownModal from "@/components/TakedownModal";
import ScheduleTakedownModal from "@/components/ScheduleTakedownModal";
import TestTakedownModal from "@/components/TestTakedownModal";
import JobSearchModal from "@/components/JobSearchModal";
import LoadingOverlay from "@/components/LoadingOverlay";

const PROD_PAGE_SIZE = 20;

export default function Dashboard() {
  const { user, logout } = useAuth();
  const [mode, setMode] = useState("production");
  const [jobs, setJobs] = useState({});
  const [currentFilter, setCurrentFilter] = useState("review");
  const [expandedKey, setExpandedKey] = useState(null);
  const [showAnalytics, setShowAnalytics] = useState(false);
  const [showPastTakedowns, setShowPastTakedowns] = useState(false);
  const [takedownSourceFilter, setTakedownSourceFilter] = useState(null);
  const [loading, setLoading] = useState(false);
  const [evalConfig, setEvalConfig] = useState({});
  const [toast, setToast] = useState(null);
  const [takedownModal, setTakedownModal] = useState(null);
  const [showTestTakedown, setShowTestTakedown] = useState(false);
  const [showJobSearch, setShowJobSearch] = useState(false);
  const [scheduleTakedownModal, setScheduleTakedownModal] = useState(null);
  const [jobSearchQuery, setJobSearchQuery] = useState(null);
  const [takedownCount, setTakedownCount] = useState(0);
  const [globalStats, setGlobalStats] = useState({ total: 0, correct: 0, incorrect: 0, disputed: 0, untagged: 0, in_flight: 0, malicious: 0 });

  const [prodHasMore, setProdHasMore] = useState(false);
  const [prodTotalCount, setProdTotalCount] = useState(null);

  // Restore filters from localStorage
  const getInitialFilters = () => {
    const saved = localStorage.getItem("phishing_eval_filters");
    const fromStorage = saved ? JSON.parse(saved) : {};
    return {
      dateFrom: fromStorage.dateFrom || "",
      dateTo: fromStorage.dateTo || "",
      severity: fromStorage.severity || "",
      category: fromStorage.category || "",
      verdict: fromStorage.verdict || "",
      deployment: fromStorage.deployment || "",
    };
  };
  const getInitialProdFilter = () => {
    const saved = localStorage.getItem("phishing_eval_prod_filter");
    return saved || "opus_review";
  };

  const [prodS2Filters, setProdS2Filters] = useState(() => new Set([getInitialProdFilter()]));
  const [advFilters, setAdvFilters] = useState(getInitialFilters);  // applied (triggers search)
  const [draftFilters, setDraftFilters] = useState(getInitialFilters);  // what user is editing

  const refreshRef = useRef(null);
  const prodCacheRef = useRef({});

  // Ctrl+F → open job search
  useEffect(() => {
    const handleKeyDown = (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === "f") {
        e.preventDefault();
        setShowJobSearch(true);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Auto-open job search from URL ?search=xxx
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const searchId = params.get("search");
    if (searchId) {
      setShowJobSearch(true);
      setJobSearchQuery(searchId);
      // Clean URL
      window.history.replaceState({}, "", window.location.pathname);
    }
  }, []);

  const fetchTakedownCount = useCallback(async () => {
    try {
      const res = await axios.get(`${API}/prod/takedowns`);
      setTakedownCount((res.data.takedowns || []).length);
    } catch (e) { console.error("fetchTakedownCount failed:", e); }
  }, []);

  const fetchGlobalStats = useCallback(async () => {
    try {
      const res = await axios.get(`${API}/prod/stats`);
      setGlobalStats(res.data);
    } catch (e) { console.error("fetchGlobalStats failed:", e); }
  }, []);

  const fetchProdJobs = useCallback(
    async ({ append = false, forceRefresh = false } = {}) => {
      const opusMap = { opus_malicious: "CONFIRMED_MALICIOUS", opus_review: "NEEDS_HUMAN_REVIEW", opus_legitimate: "LEGITIMATE" };
      const externalMap = { src_openai: "openai", src_cloudflare: "cloudflare" };
      const opusValues = Object.keys(opusMap);
      const externalValues = Object.keys(externalMap);
      const activeOpus = opusValues.find((t) => prodS2Filters.has(t));
      const activeExternal = externalValues.find((t) => prodS2Filters.has(t));
      const ck = (activeOpus || activeExternal || "all") + `|${advFilters.dateFrom}|${advFilters.dateTo}|${advFilters.severity}|${advFilters.category}|${advFilters.verdict}|${advFilters.deployment}`;
      const cached = prodCacheRef.current[ck];
      if (!append && !forceRefresh && cached) {
        setJobs({ ...cached.jobs });
        setProdHasMore(cached.hasMore);
        return;
      }
      const offset = append && cached ? cached.offset : 0;
      setLoading(!append);
      try {
        let url = `${API}/prod/jobs?offset=${offset}&limit=${PROD_PAGE_SIZE}`;
        if (activeOpus) url += `&opus_label=${opusMap[activeOpus]}`;
        if (activeExternal) url += `&external_source=${externalMap[activeExternal]}`;
        if (advFilters.dateFrom) url += `&date_from=${advFilters.dateFrom}`;
        if (advFilters.dateTo) url += `&date_to=${advFilters.dateTo}`;
        if (advFilters.severity) url += `&severity=${advFilters.severity}`;
        if (advFilters.category) url += `&category=${encodeURIComponent(advFilters.category)}`;
        if (advFilters.verdict) url += `&verdict=${advFilters.verdict}`;
        if (advFilters.deployment) url += `&deployment=${advFilters.deployment}`;
        const res = await axios.get(url);
        const data = res.data;
        if (data.error) { setLoading(false); return; }
        const newJobs = data.jobs || [];
        const hasMore = data.has_more || false;
        let jobMap;
        if (append && cached) {
          jobMap = { ...cached.jobs };
          newJobs.forEach((j) => (jobMap[j.eval_key || j.job_id] = j));
        } else {
          jobMap = {};
          newJobs.forEach((j) => (jobMap[j.eval_key || j.job_id] = j));
        }
        prodCacheRef.current[ck] = { jobs: jobMap, hasMore, offset: offset + newJobs.length };
        setJobs({ ...jobMap });
        setProdHasMore(hasMore);
        if (data.total_count != null) setProdTotalCount(data.total_count);
      } catch (e) { console.error("Prod fetch failed:", e); }
      setLoading(false);
    },
    [prodS2Filters, advFilters]
  );

  const fetchEvalJobs = useCallback(async () => {
    try {
      const res = await axios.get(`${API}/eval/jobs`);
      const data = res.data;
      const map = {};
      (data.jobs || []).forEach((j) => (map[j.eval_key || j.job_id] = j));
      setJobs(map);
      if (data.config) setEvalConfig(data.config);
    } catch (e) { console.error("Eval fetch failed:", e); }
  }, []);

  useEffect(() => {
    setExpandedKey(null);
    setCurrentFilter(mode === "production" ? "review" : "all");
    setProdS2Filters(mode === "production" ? new Set(["opus_review"]) : new Set(["all"]));
    setJobs({});
    setShowPastTakedowns(false);
    if (mode === "production") {
      if (refreshRef.current) clearInterval(refreshRef.current);
      refreshRef.current = null;
      prodCacheRef.current = {};
      fetchTakedownCount();
      fetchGlobalStats();
    } else {
      fetchEvalJobs();
      refreshRef.current = setInterval(fetchEvalJobs, 5000);
    }
    return () => { if (refreshRef.current) clearInterval(refreshRef.current); };
  }, [mode, fetchEvalJobs, fetchTakedownCount, fetchGlobalStats]);

  useEffect(() => {
    if (mode === "production" && !showPastTakedowns) {
      fetchProdJobs({ append: false, forceRefresh: true });

      // Persist filters to localStorage only (no URL changes)
      const filterKey = [...prodS2Filters][0] || "all";
      localStorage.setItem("phishing_eval_filters", JSON.stringify(advFilters));
      localStorage.setItem("phishing_eval_prod_filter", filterKey);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, prodS2Filters, advFilters]);


  const emptyFilters = { dateFrom: "", dateTo: "", severity: "", category: "", verdict: "", deployment: "" };

  const handleApplyFilters = () => {
    setAdvFilters({ ...draftFilters });
  };

  const handleResetFilters = () => {
    setDraftFilters({ ...emptyFilters });
    setAdvFilters({ ...emptyFilters });
  };

  const handleRemoveFilterTag = (key) => {
    const next = { ...advFilters, [key]: "" };
    setAdvFilters(next);
    setDraftFilters(next);
  };


  const loadMoreProd = () => fetchProdJobs({ append: true, forceRefresh: false });

  const handleRefresh = () => {
    if (mode === "production") {
      prodCacheRef.current = {};
      fetchProdJobs({ append: false, forceRefresh: true });
      fetchTakedownCount();
      fetchGlobalStats();
    } else {
      fetchEvalJobs();
    }
  };

  const setVerdict = async (evalKey, stage, verdict) => {
    const keyMap = { s1: "verdict_s1", wc: "verdict_wc", s2: "verdict_s2" };
    const jobKeyMap = { s1: "human_verdict_s1", wc: "human_verdict_wc", s2: "human_verdict_s2" };
    const key = keyMap[stage];
    let url;
    if (mode === "production") url = `${API}/prod/verdict/${evalKey.replace("prod::", "")}`;
    else url = `${API}/eval/verdict/${evalKey}`;
    try {
      await axios.post(url, { [key]: verdict || null });
      setJobs((prev) => {
        const updated = { ...prev };
        if (updated[evalKey]) updated[evalKey] = { ...updated[evalKey], [jobKeyMap[stage]]: verdict || null };
        return updated;
      });
      if (mode === "production") {
        for (const ck of Object.keys(prodCacheRef.current)) {
          const entry = prodCacheRef.current[ck];
          if (entry.jobs[evalKey]) entry.jobs[evalKey] = { ...entry.jobs[evalKey], [jobKeyMap[stage]]: verdict || null };
        }
      }
    } catch (e) { console.error("setVerdict failed:", e); }
    // Refresh global stats since verdict changed
    if (mode === "production") fetchGlobalStats();
  };

  const saveNotes = async (evalKey, text) => {
    let url;
    if (mode === "production") url = `${API}/prod/verdict/${evalKey.replace("prod::", "")}`;
    else url = `${API}/eval/verdict/${evalKey}`;
    try {
      await axios.post(url, { notes: text });
      setJobs((prev) => {
        const updated = { ...prev };
        if (updated[evalKey]) updated[evalKey] = { ...updated[evalKey], human_notes: text };
        return updated;
      });
      if (mode === "production") {
        for (const ck of Object.keys(prodCacheRef.current)) {
          const entry = prodCacheRef.current[ck];
          if (entry.jobs[evalKey]) entry.jobs[evalKey] = { ...entry.jobs[evalKey], human_notes: text };
        }
      }
    } catch (e) { console.error("saveNotes failed:", e); }
  };

  // Takedown: sends reason to backend, backend calls actual API + stores to mongo
  const handleTakedownConfirm = async (job, reason) => {
    try {
      await axios.post(
        `${API}/prod/takedown/${job.job_id}`,
        {
          task_preview: job.task_preview || "",
          s2_label: job.stage_2?.classification?.label || "",
          suspension_reason: reason,
        }
      );
      const ek = job.eval_key || job.job_id;
      setJobs((prev) => {
        const updated = { ...prev };
        if (updated[ek]) updated[ek] = { ...updated[ek], taken_down: true };
        return updated;
      });
      for (const ck of Object.keys(prodCacheRef.current)) {
        const entry = prodCacheRef.current[ck];
        if (entry.jobs[ek]) entry.jobs[ek] = { ...entry.jobs[ek], taken_down: true };
      }
      setTakedownCount((prev) => prev + 1);
      setToast(`Job ${job.job_id} has been taken down on production`);
      setTakedownModal(null);
      if (window.__refreshTakedownsView) window.__refreshTakedownsView();
      fetchGlobalStats();
    } catch (e) {
      console.error("Takedown failed:", e);
      const msg = e.response?.data?.detail || e.message || "Unknown error";
      setToast(`Takedown failed: ${msg}`);
      setTakedownModal(null);
    }
  };

  const handleScheduleTakedownConfirm = async (job, reason) => {
    try {
      await axios.post(`${API}/prod/schedule-takedown/${job.job_id}`, { suspension_reason: reason });
      const ek = job.eval_key || job.job_id;
      setJobs((prev) => {
        const updated = { ...prev };
        if (updated[ek]) updated[ek] = {
          ...updated[ek],
          scheduled_takedown: { status: "pending", takedown_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() },
          automation_action: "schedule_takedown",
          automation_status: "pending",
        };
        return updated;
      });
      for (const ck of Object.keys(prodCacheRef.current)) {
        const entry = prodCacheRef.current[ck];
        if (entry.jobs[ek]) entry.jobs[ek] = {
          ...entry.jobs[ek],
          scheduled_takedown: { status: "pending", takedown_at: new Date(Date.now() + 24 * 60 * 60 * 1000).toISOString() },
          automation_action: "schedule_takedown",
          automation_status: "pending",
        };
      }
      setToast(`Job ${job.job_id} scheduled for takedown in 24h (email sent to user)`);
      setScheduleTakedownModal(null);
    } catch (e) {
      console.error("Schedule takedown failed:", e);
      const msg = e.response?.data?.detail || e.message || "Unknown error";
      setToast(`Schedule takedown failed: ${msg}`);
      setScheduleTakedownModal(null);
    }
  };

  const saveConfig = async (config) => {
    try {
      await axios.post(`${API}/eval/config`, config);
      setEvalConfig(config);
    } catch (e) { console.error("saveConfig failed:", e); }
  };

  const jobList = Object.values(jobs).sort((a, b) => (b.created_at || "").localeCompare(a.created_at || ""));

  // For production mode, use BQ+Mongo global stats. For eval mode, compute client-side.
  let stats;
  if (mode === "production") {
    stats = globalStats;
  } else {
    stats = { total: 0, correct: 0, incorrect: 0, disputed: 0, untagged: 0, in_flight: 0, malicious: 0 };
    jobList.forEach((j) => {
      stats.total++;
      if (j.human_verdict_s1 === "correct" || j.human_verdict_s2 === "correct") stats.correct++;
      if (j.human_verdict_s1 === "incorrect" || j.human_verdict_s2 === "incorrect") stats.incorrect++;
      if (j.human_verdict_s1 === "disputed" || j.human_verdict_s2 === "disputed") stats.disputed++;
      if (!j.human_verdict_s1 && !j.human_verdict_s2) stats.untagged++;
      if (j.stage_1 && !j.stage_2 && j.stage_1.classification?.result) stats.in_flight++;
      if (j.stage_2?.classification?.label === "CONFIRMED_MALICIOUS") stats.malicious++;
    });
  }

  const filtered = jobList.filter((j) => {
    if (mode === "production") {
      if (prodS2Filters.has("all")) return true;

      const opusValues = ["opus_malicious", "opus_review", "opus_legitimate"];
      const externalValues = ["src_openai", "src_cloudflare"];
      const activeOpus = opusValues.filter((v) => prodS2Filters.has(v));
      const activeExternal = externalValues.filter((v) => prodS2Filters.has(v));

      // External source filter: show jobs with matching takedown_source
      if (activeExternal.length > 0) {
        const sourceMap = { src_openai: "openai", src_cloudflare: "cloudflare" };
        const allowedSources = activeExternal.map((s) => sourceMap[s]);
        const jobSource = j.takedown_info?.source || j.takedown_source;
        if (!allowedSources.includes(jobSource)) return false;
        return true;
      }

      // Opus verdict filter: server-side only (via ?opus_label= param).
      // No client-side re-filtering needed — API already returns only matching jobs.

      return true;
    }
    if (currentFilter === "all") return true;
    if (currentFilter === "untagged") return !j.human_verdict_s1 && !j.human_verdict_s2;
    if (currentFilter === "correct") return j.human_verdict_s1 === "correct" || j.human_verdict_s2 === "correct";
    if (currentFilter === "incorrect") return j.human_verdict_s1 === "incorrect" || j.human_verdict_s2 === "incorrect";
    if (currentFilter === "disputed") return j.human_verdict_s1 === "disputed" || j.human_verdict_s2 === "disputed";
    if (currentFilter === "phishing") return j.stage_1?.classification?.result === true;
    if (currentFilter === "legit") return j.stage_1?.classification?.result === false;
    if (currentFilter === "wc_flagged") return j.whitecircle?.flagged === true;
    if (currentFilter === "wc_clear") return j.whitecircle?.flagged === false;
    if (currentFilter === "disagree") {
      const s1v = j.stage_1?.classification?.result;
      const wcv = j.whitecircle?.flagged;
      return s1v != null && wcv != null && s1v !== wcv;
    }
    if (currentFilter === "malicious") return j.stage_2?.classification?.label === "CONFIRMED_MALICIOUS";
    if (currentFilter === "review") return j.automation_tier === 3;
    return true;
  });

  const exportCSV = () => {
    const rows = [["eval_key","job_id","task","s1_result","s1_confidence","s1_severity","s1_verdict","wc_flagged","wc_verdict","s2_label","s2_severity","s2_confidence","s2_verdict","notes","llm_version","agent_version","pipeline_time"]];
    Object.values(jobs).forEach((j) => {
      const s1 = j.stage_1?.classification || {};
      const s2c = j.stage_2?.classification || {};
      const pv = j.prompt_versions || {};
      rows.push([`"${j.eval_key||j.job_id}"`,j.job_id,`"${(j.task_preview||"").replace(/"/g,'""')}"`,s1.result===true?"PHISHING":s1.result===false?"LEGITIMATE":"",s1.confidence??"",s1.severity??"",j.human_verdict_s1??"",j.whitecircle?.flagged===true?"FLAGGED":j.whitecircle?.flagged===false?"CLEAR":"",j.human_verdict_wc??"",s2c.label??"",s2c.severity??"",s2c.confidence??"",j.human_verdict_s2??"",`"${(j.human_notes||"").replace(/"/g,'""')}"`,pv.llm_classifier??"",pv.escalation_agent??"",j.pipeline_time?j.pipeline_time.toFixed(1):""]);
    });
    const csv = rows.map((r)=>r.join(",")).join("\n");
    const blob = new Blob([csv],{type:"text/csv"});
    const a = document.createElement("a");
    a.href=URL.createObjectURL(blob);
    a.download=`phishing_eval_${new Date().toISOString().slice(0,10)}.csv`;
    a.click();
  };

  return (
    <div className="min-h-screen bg-background" data-testid="dashboard">
      <LoadingOverlay visible={loading} />
      {takedownModal && (
        <TakedownModal
          job={takedownModal}
          onClose={() => setTakedownModal(null)}
          onConfirm={handleTakedownConfirm}
        />
      )}
      {scheduleTakedownModal && (
        <ScheduleTakedownModal
          job={scheduleTakedownModal}
          onClose={() => setScheduleTakedownModal(null)}
          onConfirm={handleScheduleTakedownConfirm}
        />
      )}
      {showTestTakedown && (
        <TestTakedownModal onClose={() => setShowTestTakedown(false)} />
      )}
      {showJobSearch && (
        <JobSearchModal onClose={() => { setShowJobSearch(false); setJobSearchQuery(null); }} initialQuery={jobSearchQuery} />
      )}
      <Header
        mode={mode} setMode={setMode}
        showAnalytics={showAnalytics} setShowAnalytics={setShowAnalytics}
        exportCSV={exportCSV} refresh={handleRefresh}
        evalConfig={evalConfig} saveConfig={saveConfig}
        user={user} logout={logout}
        toast={toast} clearToast={() => setToast(null)}
        onTestTakedown={() => setShowTestTakedown(true)}
        onSearch={() => setShowJobSearch(true)}
      />
      <StatsBar stats={stats} takedownCount={takedownCount} mode={mode} />
      {showAnalytics && <AnalyticsPanel />}
      <FilterBar
        mode={mode} currentFilter={currentFilter} setCurrentFilter={setCurrentFilter}
        prodS2Filters={prodS2Filters} setProdS2Filters={setProdS2Filters}
        showPastTakedowns={showPastTakedowns} setShowPastTakedowns={setShowPastTakedowns}
        sourceFilter={takedownSourceFilter} setSourceFilter={setTakedownSourceFilter}
        draftFilters={draftFilters} setDraftFilters={setDraftFilters}
        appliedFilters={advFilters}
        onApply={handleApplyFilters}
        onReset={handleResetFilters}
        onRemoveTag={handleRemoveFilterTag}
        totalCount={prodTotalCount}
      />
      {showPastTakedowns || prodS2Filters.has("src_openai") || prodS2Filters.has("src_cloudflare") ? (
        <TakedownsView sourceFilter={
          prodS2Filters.has("src_openai") ? "openai" :
          prodS2Filters.has("src_cloudflare") ? "cloudflare" :
          takedownSourceFilter
        } />
      ) : (
        <>
          <JobsTable
            jobs={filtered} mode={mode}
            expandedKey={expandedKey} setExpandedKey={setExpandedKey}
            setVerdict={setVerdict} saveNotes={saveNotes}
            onTakedownClick={(j) => setTakedownModal(j)}
            onScheduleTakedown={(j) => setScheduleTakedownModal(j)}
          />
          {mode === "production" && prodHasMore && (
            <div className="text-center py-4 pb-8">
              <button onClick={loadMoreProd} data-testid="load-more-btn"
                className="bg-card border border-border hover:border-primary/50 text-foreground px-8 py-2 rounded-sm font-mono text-sm transition-all">
                Load More
              </button>
            </div>
          )}
        </>
      )}
    </div>
  );
}
