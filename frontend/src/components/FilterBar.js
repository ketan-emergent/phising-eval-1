import { useState, useEffect } from "react";
import { Ban, Filter, X, ChevronDown, CalendarIcon, Search } from "lucide-react";
import { API } from "@/App";
import axios from "axios";
import { Calendar } from "@/components/ui/calendar";
import { Popover, PopoverTrigger, PopoverContent } from "@/components/ui/popover";
import { format } from "date-fns";

export default function FilterBar({ mode, currentFilter, setCurrentFilter, prodS2Filters, setProdS2Filters, showPastTakedowns, setShowPastTakedowns, sourceFilter, setSourceFilter, draftFilters, setDraftFilters, appliedFilters, onApply, onReset, onRemoveTag, totalCount }) {
  if (mode === "eval") {
    const evalFilters = [
      { key: "all", label: "All" },
      { key: "untagged", label: "Untagged" },
      { key: "correct", label: "Correct" },
      { key: "incorrect", label: "Incorrect" },
      { key: "disputed", label: "Disputed" },
      { key: "phishing", label: "S1: Phishing" },
      { key: "legit", label: "S1: Legit" },
      { key: "wc_flagged", label: "WC: Flagged" },
      { key: "wc_clear", label: "WC: Clear" },
      { key: "disagree", label: "S1 vs WC Disagree" },
      { key: "malicious", label: "S2: Malicious" },
      { key: "review", label: "S2: Review" },
    ];
    return (
      <div className="px-4 py-2 flex gap-1.5 flex-wrap" data-testid="filters-eval">
        {evalFilters.map((f) => (
          <FilterChip key={f.key} active={currentFilter === f.key} onClick={() => setCurrentFilter(f.key)} label={f.label} testId={`filter-eval-${f.key}`} />
        ))}
      </div>
    );
  }

  return <ProdFilters
    prodS2Filters={prodS2Filters} setProdS2Filters={setProdS2Filters}
    showPastTakedowns={showPastTakedowns} setShowPastTakedowns={setShowPastTakedowns}
    sourceFilter={sourceFilter} setSourceFilter={setSourceFilter}
    draftFilters={draftFilters} setDraftFilters={setDraftFilters}
    appliedFilters={appliedFilters}
    onApply={onApply} onReset={onReset} onRemoveTag={onRemoveTag}
    totalCount={totalCount}
  />;
}

const FILTER_LABELS = {
  dateFrom: "From",
  dateTo: "To",
  severity: "Severity",
  verdict: "Verdict",
  deployment: "Deployment Status",
};

const VERDICT_LABEL_MAP = {
  correct: "Correct",
  incorrect: "Incorrect",
  disputed: "Disputed",
  unreviewed: "Unreviewed",
};

function formatTagValue(key, value) {
  if (key === "dateFrom" || key === "dateTo") {
    try { return format(new Date(value + "T00:00:00"), "dd MMM yyyy"); } catch (e) { return value; }
  }
  if (key === "verdict") {
    return value.split(",").map((v) => VERDICT_LABEL_MAP[v] || v).join(", ");
  }
  if (key === "deployment") {
    const DEPLOY_MAP = { active: "Active Deployment", inactive: "No Active Deployment" };
    return value.split(",").map((v) => DEPLOY_MAP[v] || v).join(", ");
  }
  return value;
}

function ProdFilters({ prodS2Filters, setProdS2Filters, showPastTakedowns, setShowPastTakedowns, sourceFilter, setSourceFilter, draftFilters, setDraftFilters, appliedFilters, onApply, onReset, onRemoveTag, totalCount }) {
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [filterOptions, setFilterOptions] = useState({ categories: [], severities: [] });

  useEffect(() => {
    axios.get(`${API}/prod/filter-options`).then((r) => setFilterOptions(r.data)).catch(() => {});
  }, []);

  const hasAppliedFilters = appliedFilters?.dateFrom || appliedFilters?.dateTo || appliedFilters?.severity || appliedFilters?.verdict || appliedFilters?.deployment;
  const hasDraftValues = draftFilters?.dateFrom || draftFilters?.dateTo || draftFilters?.severity || draftFilters?.verdict || draftFilters?.deployment;
  const hasDraftChanges = JSON.stringify(draftFilters) !== JSON.stringify(appliedFilters);

  const labelFilters = [
    { key: "opus_malicious", label: "Confirmed Malicious" },
    { key: "opus_review", label: "Needs Review" },
    { key: "opus_legitimate", label: "Legitimate" },
    { key: "all", label: "All" },
  ];
  const externalFilters = [
    { key: "src_openai", label: "OpenAI" },
    { key: "src_cloudflare", label: "Cloudflare" },
  ];

  const labelKeys = new Set(labelFilters.map((f) => f.key));
  const externalKeys = new Set(externalFilters.map((f) => f.key));

  const toggleFilter = (value) => {
    if (showPastTakedowns) setShowPastTakedowns(false);
    if (setSourceFilter) setSourceFilter(null);
    if (labelKeys.has(value) || value === "all" || externalKeys.has(value)) {
      setProdS2Filters(new Set([value]));
    }
  };

  // Active filter tags (from applied filters)
  const activeTags = Object.entries(appliedFilters || {}).filter(([_, v]) => v).map(([k, v]) => ({ key: k, label: FILTER_LABELS[k] || k, value: formatTagValue(k, v) }));

  return (
    <div data-testid="filters-prod">
      {/* Row 1: Primary filters */}
      <div className="px-4 py-2 flex gap-1.5 flex-wrap items-center">
        <span className="text-muted-foreground text-xs font-mono mr-1">Opus:</span>
        {labelFilters.map((f) => {
          const isActive = f.key === "all"
            ? !showPastTakedowns && prodS2Filters.has("all")
            : !showPastTakedowns && prodS2Filters.has(f.key);
          return <FilterChip key={f.key} active={isActive} onClick={() => toggleFilter(f.key)} label={f.label} testId={`filter-prod-${f.key}`} />;
        })}
        <span className="text-muted-foreground text-xs font-mono ml-3 mr-1">External:</span>
        {externalFilters.map((f) => (
          <FilterChip key={f.key} active={!showPastTakedowns && prodS2Filters.has(f.key)} onClick={() => toggleFilter(f.key)} label={f.label} testId={`filter-prod-${f.key}`} />
        ))}

        <div className="border-l border-border ml-3 pl-3 flex items-center gap-2">
          <button
            onClick={() => { setShowPastTakedowns(!showPastTakedowns); if (setSourceFilter) setSourceFilter(null); }}
            data-testid="filter-prod-takedowns"
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-sm text-xs font-mono transition-all border ${
              showPastTakedowns ? "bg-red-500/15 text-red-400 border-red-500/40" : "bg-card border-border text-red-400/60 hover:border-red-500/30 hover:text-red-400"
            }`}
          >
            <Ban className="w-3 h-3" /> Past Takedowns
          </button>
          <button
            onClick={() => setShowAdvanced(!showAdvanced)}
            data-testid="toggle-advanced-filters"
            className={`flex items-center gap-1.5 px-2.5 py-1 rounded-sm text-xs font-mono transition-all border ${
              showAdvanced || hasAppliedFilters ? "bg-primary/10 text-primary border-primary/30" : "bg-card border-border text-muted-foreground hover:border-primary/30 hover:text-foreground"
            }`}
          >
            <Filter className="w-3 h-3" /> Filters
            {hasAppliedFilters && <span className="w-1.5 h-1.5 bg-primary rounded-full" />}
            <ChevronDown className={`w-3 h-3 transition-transform ${showAdvanced ? "rotate-180" : ""}`} />
          </button>
          {totalCount != null && (
            <span className="text-xs font-mono text-muted-foreground ml-1" data-testid="filter-count">
              <span className="text-foreground font-semibold">{totalCount.toLocaleString()}</span> jobs
            </span>
          )}
        </div>

        {showPastTakedowns && (
          <>
            <span className="text-muted-foreground text-xs font-mono ml-3 mr-1">Source:</span>
            {[
              { key: "openai", label: "OpenAI" },
              { key: "cloudflare", label: "Cloudflare" },
            ].map((f) => (
              <FilterChip key={f.key} active={sourceFilter === f.key} onClick={() => setSourceFilter(sourceFilter === f.key ? null : f.key)} label={f.label} testId={`filter-source-${f.key}`} />
            ))}
          </>
        )}
      </div>

      {/* Row 2: Active filter tags */}
      {activeTags.length > 0 && !showAdvanced && (
        <div className="px-4 pb-1 flex gap-1.5 flex-wrap items-center">
          {activeTags.map((t) => (
            <span key={t.key} className="inline-flex items-center gap-1 bg-primary/10 border border-primary/20 text-primary px-2 py-0.5 rounded-sm text-[11px] font-mono">
              {t.label}: {t.value}
              <button onClick={() => onRemoveTag(t.key)} className="hover:text-foreground transition-colors">
                <X className="w-3 h-3" />
              </button>
            </span>
          ))}
          <button onClick={onReset} className="text-[10px] text-muted-foreground hover:text-foreground font-mono transition-colors">
            Clear all
          </button>
        </div>
      )}

      {/* Row 3: Advanced filter panel */}
      {showAdvanced && (
        <div className="px-4 pb-2" data-testid="advanced-filters">
          <div className="flex gap-4 flex-wrap items-end">
            {/* Date From */}
            <DatePickerField
              label="From"
              value={draftFilters?.dateFrom}
              onChange={(v) => setDraftFilters((p) => ({ ...p, dateFrom: v }))}
              testId="filter-date-from"
            />
            {/* Date To */}
            <DatePickerField
              label="To"
              value={draftFilters?.dateTo}
              onChange={(v) => setDraftFilters((p) => ({ ...p, dateTo: v }))}
              testId="filter-date-to"
            />
            {/* Severity */}
            <div>
              <label className="block text-[10px] text-muted-foreground font-mono mb-1">Severity</label>
              <select
                value={draftFilters?.severity || ""}
                onChange={(e) => setDraftFilters((p) => ({ ...p, severity: e.target.value }))}
                data-testid="filter-severity"
                className="bg-background border border-border text-foreground px-2 py-1.5 rounded-sm font-mono text-xs focus:outline-none focus:border-primary/50 h-[30px]"
              >
                <option value="">All</option>
                {filterOptions.severities.map((s) => (
                  <option key={s.value} value={s.value}>{s.value} ({s.count})</option>
                ))}
              </select>
            </div>
            {/* Human Verdict chips */}
            <div>
              <label className="block text-[10px] text-muted-foreground font-mono mb-1">Human Verdict</label>
              <VerdictChips
                value={draftFilters?.verdict || ""}
                onChange={(v) => setDraftFilters((p) => ({ ...p, verdict: v }))}
              />
            </div>
            {/* Deployment Status */}
            <div>
              <label className="block text-[10px] text-muted-foreground font-mono mb-1">Deployment Status</label>
              <DeploymentDropdown
                value={draftFilters?.deployment || ""}
                onChange={(v) => setDraftFilters((p) => ({ ...p, deployment: v }))}
              />
            </div>
          </div>

          {/* Apply / Reset buttons */}
          <div className="flex items-center gap-2 mt-3">
            <button
              onClick={onApply}
              disabled={!hasDraftValues && !hasDraftChanges}
              data-testid="apply-filters-btn"
              className={`flex items-center gap-1.5 px-4 py-1.5 rounded-sm text-xs font-mono font-semibold transition-all border ${
                hasDraftValues || hasDraftChanges
                  ? "bg-primary text-primary-foreground border-primary hover:bg-primary/90"
                  : "bg-card border-border text-muted-foreground/50 cursor-not-allowed"
              }`}
            >
              <Search className="w-3 h-3" /> Apply Filters
            </button>
            <button
              onClick={onReset}
              data-testid="reset-filters-btn"
              className="px-3 py-1.5 rounded-sm text-xs font-mono text-muted-foreground border border-border hover:text-foreground hover:border-primary/30 transition-all"
            >
              Reset
            </button>
            {/* Active tags inline when panel is open */}
            {activeTags.length > 0 && (
              <div className="flex gap-1.5 flex-wrap items-center ml-2 pl-2 border-l border-border">
                <span className="text-[10px] text-muted-foreground font-mono">Active:</span>
                {activeTags.map((t) => (
                  <span key={t.key} className="inline-flex items-center gap-1 bg-primary/10 border border-primary/20 text-primary px-1.5 py-0.5 rounded-sm text-[10px] font-mono">
                    {t.label}: {t.value}
                    <button onClick={() => onRemoveTag(t.key)} className="hover:text-foreground transition-colors">
                      <X className="w-2.5 h-2.5" />
                    </button>
                  </span>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}

/* ---- Date Picker with Calendar Popover ---- */
function DatePickerField({ label, value, onChange, testId }) {
  const [open, setOpen] = useState(false);
  const dateObj = value ? new Date(value + "T00:00:00") : undefined;

  const handleSelect = (day) => {
    if (day) {
      onChange(format(day, "yyyy-MM-dd"));
    } else {
      onChange("");
    }
    setOpen(false);
  };

  return (
    <div>
      <label className="block text-[10px] text-muted-foreground font-mono mb-1">{label}</label>
      <Popover open={open} onOpenChange={setOpen}>
        <PopoverTrigger asChild>
          <button
            data-testid={testId}
            className={`flex items-center gap-1.5 bg-background border border-border px-2 py-1.5 rounded-sm font-mono text-xs h-[30px] min-w-[130px] transition-all hover:border-primary/50 ${
              value ? "text-foreground" : "text-muted-foreground/50"
            }`}
          >
            <CalendarIcon className="w-3 h-3 shrink-0" />
            {value ? format(dateObj, "dd MMM yyyy") : "Pick date"}
            {value && (
              <X className="w-3 h-3 ml-auto text-muted-foreground hover:text-foreground shrink-0"
                onClick={(e) => { e.stopPropagation(); onChange(""); }}
              />
            )}
          </button>
        </PopoverTrigger>
        <PopoverContent className="w-auto p-0" align="start">
          <Calendar
            mode="single"
            selected={dateObj}
            onSelect={handleSelect}
            initialFocus
          />
        </PopoverContent>
      </Popover>
    </div>
  );
}

/* ---- Verdict Multi-Select Dropdown ---- */
const VERDICT_OPTIONS = [
  { key: "correct", label: "Correct", color: "text-emerald-400" },
  { key: "incorrect", label: "Incorrect", color: "text-red-400" },
  { key: "disputed", label: "Disputed", color: "text-amber-400" },
  { key: "unreviewed", label: "Unreviewed (--)", color: "text-muted-foreground" },
];

function VerdictChips({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const activeSet = new Set(value ? value.split(",").filter(Boolean) : []);
  const isAll = activeSet.size === 0;

  const toggle = (key) => {
    const next = new Set(activeSet);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    if (next.size >= VERDICT_OPTIONS.length) {
      onChange("");
      return;
    }
    onChange([...next].join(","));
  };

  const selectAll = () => onChange("");

  const selectedLabel = isAll
    ? "All"
    : VERDICT_OPTIONS.filter((v) => activeSet.has(v.key)).map((v) => v.label).join(", ");

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          data-testid="filter-verdict-trigger"
          className={`flex items-center gap-1.5 bg-background border px-2.5 py-1.5 rounded-sm font-mono text-xs h-[30px] min-w-[140px] max-w-[250px] transition-all hover:border-primary/50 ${
            isAll ? "border-border text-muted-foreground" : "border-primary/40 text-foreground"
          }`}
        >
          <span className="truncate">{selectedLabel}</span>
          <ChevronDown className="w-3 h-3 shrink-0 ml-auto" />
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-52 p-1" align="start">
        <button
          onClick={selectAll}
          data-testid="filter-verdict-all"
          className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-sm text-xs font-mono transition-all ${
            isAll ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted"
          }`}
        >
          <div className={`w-3.5 h-3.5 rounded-sm border flex items-center justify-center ${isAll ? "bg-primary border-primary" : "border-border"}`}>
            {isAll && <span className="text-[9px] text-primary-foreground font-bold">✓</span>}
          </div>
          All
        </button>
        <div className="h-px bg-border my-1" />
        {VERDICT_OPTIONS.map((v) => {
          const active = activeSet.has(v.key);
          return (
            <button
              key={v.key}
              onClick={() => toggle(v.key)}
              data-testid={`filter-verdict-${v.key}`}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-sm text-xs font-mono transition-all ${
                active ? "bg-muted/50" : "hover:bg-muted/30"
              } ${v.color}`}
            >
              <div className={`w-3.5 h-3.5 rounded-sm border flex items-center justify-center ${active ? "bg-primary border-primary" : "border-border"}`}>
                {active && <span className="text-[9px] text-primary-foreground font-bold">✓</span>}
              </div>
              {v.label}
            </button>
          );
        })}
      </PopoverContent>
    </Popover>
  );
}

/* ---- Deployment Status Multi-Select Dropdown ---- */
const DEPLOYMENT_OPTIONS = [
  { key: "active", label: "Active Deployment", color: "text-red-400" },
  { key: "inactive", label: "No Active Deployment", color: "text-emerald-400" },
];

function DeploymentDropdown({ value, onChange }) {
  const [open, setOpen] = useState(false);
  const activeSet = new Set(value ? value.split(",").filter(Boolean) : []);
  const isAll = activeSet.size === 0;

  const toggle = (key) => {
    const next = new Set(activeSet);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    if (next.size >= DEPLOYMENT_OPTIONS.length) {
      onChange("");
      return;
    }
    onChange([...next].join(","));
  };

  const selectAll = () => onChange("");

  const selectedLabel = isAll
    ? "All"
    : DEPLOYMENT_OPTIONS.filter((v) => activeSet.has(v.key)).map((v) => v.label).join(", ");

  return (
    <Popover open={open} onOpenChange={setOpen}>
      <PopoverTrigger asChild>
        <button
          data-testid="filter-deployment-trigger"
          className={`flex items-center gap-1.5 bg-background border px-2.5 py-1.5 rounded-sm font-mono text-xs h-[30px] min-w-[160px] max-w-[280px] transition-all hover:border-primary/50 ${
            isAll ? "border-border text-muted-foreground" : "border-primary/40 text-foreground"
          }`}
        >
          <span className="truncate">{selectedLabel}</span>
          <ChevronDown className="w-3 h-3 shrink-0 ml-auto" />
        </button>
      </PopoverTrigger>
      <PopoverContent className="w-56 p-1" align="start">
        <button
          onClick={selectAll}
          data-testid="filter-deployment-all"
          className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-sm text-xs font-mono transition-all ${
            isAll ? "bg-primary/10 text-primary" : "text-muted-foreground hover:bg-muted"
          }`}
        >
          <div className={`w-3.5 h-3.5 rounded-sm border flex items-center justify-center ${isAll ? "bg-primary border-primary" : "border-border"}`}>
            {isAll && <span className="text-[9px] text-primary-foreground font-bold">✓</span>}
          </div>
          All
        </button>
        <div className="h-px bg-border my-1" />
        {DEPLOYMENT_OPTIONS.map((v) => {
          const active = activeSet.has(v.key);
          return (
            <button
              key={v.key}
              onClick={() => toggle(v.key)}
              data-testid={`filter-deployment-${v.key}`}
              className={`w-full flex items-center gap-2 px-2.5 py-1.5 rounded-sm text-xs font-mono transition-all ${
                active ? "bg-muted/50" : "hover:bg-muted/30"
              } ${v.color}`}
            >
              <div className={`w-3.5 h-3.5 rounded-sm border flex items-center justify-center ${active ? "bg-primary border-primary" : "border-border"}`}>
                {active && <span className="text-[9px] text-primary-foreground font-bold">✓</span>}
              </div>
              {v.label}
            </button>
          );
        })}
      </PopoverContent>
    </Popover>
  );
}



function FilterChip({ active, onClick, label, testId }) {
  return (
    <button onClick={onClick} data-testid={testId}
      className={`px-2.5 py-1 rounded-sm text-xs font-mono transition-all border ${
        active ? "bg-primary text-primary-foreground border-primary" : "bg-card border-border text-muted-foreground hover:border-primary/30 hover:text-foreground"
      }`}>
      {label}
    </button>
  );
}
