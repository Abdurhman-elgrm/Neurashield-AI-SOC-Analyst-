import { useState, useEffect, useRef, useCallback, type ReactNode } from "react";
import { useNavigate } from "react-router-dom";
import {
  Play, Plus, Trash2, Save, ChevronDown, Search, Crosshair,
  Cpu, FileSearch, AlertTriangle, Globe, Shield, Activity, X, ExternalLink,
  History, Clock,
} from "lucide-react";
import { huntApi } from "@/api/hunt";
import type {
  HuntFilter, HuntResultEntry, SavedHunt, FilterLogic,
  EventHuntFilter, EventHuntResultEntry, EventHuntSummary,
} from "@/api/hunt";
import { formatRelativeTime, extractApiError, cn } from "@/lib/utils";
import { toastError } from "@/lib/toast";
import { Button } from "@/components/ui/Button";
import { useKeyboard } from "@/hooks/useKeyboard";
import { useInvestigationHunt, loadHuntHistory } from "./hooks/useInvestigationHunt";
import { useEventHunt } from "./hooks/useEventHunt";
import { KQLQueryInput } from "./components/KQLQueryInput";
import { HypothesisTemplates } from "./components/HypothesisTemplates";
import { HuntTimeSeriesOverlay } from "./components/HuntTimeSeriesOverlay";
import { HuntExportButton } from "./components/HuntExportButton";
import type { HuntTemplate } from "@/data/huntTemplates";

// ─── Types ────────────────────────────────────────────────────────────────────

type HuntMode  = "investigation" | "event";
type FieldType = "number" | "text" | "status" | "confidence" | "verdict";
type EvtField  = "text" | "number";

// ─── Constants ────────────────────────────────────────────────────────────────

const INV_HUNT_FIELDS: Array<{ label: string; value: string; type: FieldType }> = [
  { label: "Threat Score",    value: "threat_score", type: "number"     },
  { label: "Status",          value: "status",       type: "status"     },
  { label: "Confidence",      value: "confidence",   type: "confidence" },
  { label: "Verdict",         value: "verdict",      type: "verdict"    },
  { label: "Title / Summary", value: "title",        type: "text"       },
];

const INV_OPS_BY_TYPE: Record<FieldType, Array<{ label: string; value: HuntFilter["operator"] }>> = {
  number:     [{ label: ">=", value: "gte" }, { label: "<=", value: "lte" }, { label: ">", value: "gt" }, { label: "<", value: "lt" }, { label: "=", value: "eq" }],
  text:       [{ label: "contains", value: "contains" }, { label: "equals", value: "eq" }, { label: "starts with", value: "startswith" }],
  status:     [{ label: "equals", value: "eq" }],
  confidence: [{ label: "equals", value: "eq" }],
  verdict:    [{ label: "equals", value: "eq" }],
};

const STATUS_OPTIONS     = ["new", "active", "triaged", "investigating", "contained", "resolved", "closed", "false_positive"];
const CONFIDENCE_OPTIONS = ["high", "medium", "low"];
const VERDICT_OPTIONS    = ["true_positive", "false_positive", "benign_positive", "suspicious", "inconclusive"];

const EVT_HUNT_FIELDS: Array<{ label: string; value: string; type: EvtField; placeholder?: string }> = [
  { label: "Hostname",       value: "host_name",      type: "text",   placeholder: "e.g. DESKTOP-01 or *srv*" },
  { label: "Username",       value: "username",       type: "text",   placeholder: "e.g. john.doe or SYSTEM"  },
  { label: "Process Name",   value: "process_name",   type: "text",   placeholder: "e.g. powershell.exe"      },
  { label: "Source IP",      value: "source_ip",      type: "text",   placeholder: "e.g. 192.168.1.100"       },
  { label: "Dest IP",        value: "dest_ip",        type: "text",   placeholder: "e.g. 10.0.0.1"            },
  { label: "Country",        value: "geo_country",    type: "text",   placeholder: "e.g. CN, RU"              },
  { label: "Correlation ID", value: "correlation_id", type: "text",   placeholder: "group correlation ID"     },
  { label: "Severity",       value: "severity",       type: "number", placeholder: "1 = low … 4 = critical"   },
];

const EVT_OPS_BY_TYPE: Record<EvtField, Array<{ label: string; value: EventHuntFilter["operator"] }>> = {
  text:   [{ label: "contains", value: "contains" }, { label: "equals", value: "eq" }, { label: "starts with", value: "startswith" }],
  number: [{ label: ">=", value: "gte" }, { label: "<=", value: "lte" }, { label: ">", value: "gt" }, { label: "<", value: "lt" }, { label: "=", value: "eq" }],
};

const EVENT_CATEGORIES = ["auth", "process", "network", "file", "registry", "dns", "system", "other"];
const UEBA_FLAG_OPTIONS = [
  "after_hours", "new_source_ip", "new_process_on_host", "privileged_user",
  "impossible_travel", "brute_force", "brute_force_success",
  "lateral_movement", "lateral_movement_xdomain", "credential_stuffing",
  "insider_offhours_data", "insider_rapid_access", "insider_sensitive_access",
];
const TIME_RANGES = [
  { label: "Last Hour",    value: "1h"  },
  { label: "Last 24h",     value: "24h" },
  { label: "Last 7 days",  value: "7d"  },
  { label: "Last 30 days", value: "30d" },
  { label: "All time",     value: ""    },
];
const MITRE_TACTICS = [
  "Reconnaissance", "Resource Development", "Initial Access", "Execution", "Persistence",
  "Privilege Escalation", "Defense Evasion", "Credential Access", "Discovery",
  "Lateral Movement", "Collection", "Command and Control", "Exfiltration", "Impact",
];

// ─── Helpers ──────────────────────────────────────────────────────────────────

function scoreColors(s: number) {
  return s >= 80 ? { bg: "rgba(239,68,68,0.12)",  color: "#F87171" }
       : s >= 50 ? { bg: "rgba(245,158,11,0.12)", color: "#FBBF24" }
                 : { bg: "rgba(75,85,99,0.15)",   color: "#6B7280" };
}

function statusColor(st: string): string {
  const map: Record<string, string> = {
    new: "#60A5FA", active: "#F59E0B", triaged: "#A78BFA",
    investigating: "#EC4899", contained: "#34D399",
    resolved: "#10B981", closed: "#6B7280", false_positive: "#10B981",
  };
  return map[st] ?? "#8B95A7";
}

function severityLabel(sev: number) {
  return sev >= 4 ? { label: "CRITICAL", color: "#F87171" }
       : sev >= 3 ? { label: "HIGH",     color: "#FBBF24" }
       : sev >= 2 ? { label: "MEDIUM",   color: "#60A5FA" }
                  : { label: "LOW",      color: "#6B7280" };
}

function categoryColor(cat: string): string {
  const map: Record<string, string> = {
    auth: "#818CF8", process: "#34D399", network: "#60A5FA",
    file: "#FBBF24", registry: "#F59E0B", dns: "#A78BFA",
    system: "#8B95A7", other: "#6B7280",
  };
  return map[cat] ?? "#6B7280";
}

function fmtTs(iso: string): string {
  try {
    return new Date(iso).toLocaleString("en-US", {
      month: "2-digit", day: "2-digit",
      hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
    });
  } catch { return iso; }
}

// ─── TagChipInput ─────────────────────────────────────────────────────────────

function TagChipInput({ tags, onChange, placeholder = "Add tag, press Enter..." }: {
  tags: string[]; onChange: (t: string[]) => void; placeholder?: string;
}) {
  const [input, setInput] = useState("");
  const commit = () => {
    const v = input.trim().replace(/,+$/, "");
    if (v && !tags.includes(v)) onChange([...tags, v]);
    setInput("");
  };
  return (
    <div className="flex flex-wrap gap-1.5 items-center px-2 py-1.5 rounded-md border border-border bg-white/3 min-h-[34px]">
      {tags.map((t) => (
        <span key={t} className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-2xs font-semibold bg-purple-500/12 border border-purple-500/25 text-purple-300">
          {t}
          <button onClick={() => onChange(tags.filter((x) => x !== t))} className="text-purple-400 hover:text-purple-200 leading-none p-0 bg-transparent border-none cursor-pointer text-sm">×</button>
        </span>
      ))}
      <input
        value={input} onChange={(e) => setInput(e.target.value)}
        onKeyDown={(e) => {
          if (e.key === "Enter" || e.key === ",") { e.preventDefault(); commit(); }
          if (e.key === "Backspace" && !input && tags.length) onChange(tags.slice(0, -1));
        }}
        onBlur={commit}
        placeholder={tags.length === 0 ? placeholder : ""}
        className="bg-transparent border-none outline-none text-xs text-text-primary flex-1 min-w-[120px]"
      />
    </div>
  );
}

// ─── BoolToggle ───────────────────────────────────────────────────────────────

function BoolToggle({ value, onChange, label }: {
  value: boolean | null; onChange: (v: boolean | null) => void; label: string;
}) {
  return (
    <button
      onClick={() => onChange(value === true ? null : true)}
      className={cn(
        "flex items-center gap-1.5 px-2.5 py-1 rounded-md text-xs font-semibold border transition-all",
        value === true
          ? "bg-sev-medium/12 border-sev-medium/40 text-sev-medium"
          : "bg-white/4 border-white/10 text-text-disabled hover:text-text-muted",
      )}
    >
      {label}
    </button>
  );
}

// ─── MultiSelectDropdown ──────────────────────────────────────────────────────

function MultiSelectDropdown({ label: labelText, options, selected, onChange, accentColor = "#3B82F6" }: {
  label: string; options: string[]; selected: string[];
  onChange: (v: string[]) => void; accentColor?: string;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const h = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", h);
    return () => document.removeEventListener("mousedown", h);
  }, []);
  const toggle = (v: string) => onChange(selected.includes(v) ? selected.filter((x) => x !== v) : [...selected, v]);
  const displayLabel = selected.length === 0 ? labelText : selected.length === 1 ? selected[0] : `${selected.length} selected`;
  return (
    <div ref={ref} className="relative">
      <button onClick={() => setOpen(!open)} className="inp flex items-center gap-1.5 cursor-pointer w-full justify-between">
        <span className={cn("text-xs", selected.length ? "text-text-primary" : "text-text-disabled")}>{displayLabel}</span>
        <ChevronDown size={13} className="text-text-disabled flex-shrink-0" />
      </button>
      {open && (
        <div className="absolute top-full left-0 right-0 z-50 bg-bg-card border border-white/10 rounded-lg mt-1 max-h-60 overflow-y-auto shadow-2xl">
          {options.map((opt) => {
            const checked = selected.includes(opt);
            return (
              <label key={opt} onClick={() => toggle(opt)} className="flex items-center gap-2 px-3 py-1.5 cursor-pointer border-b border-white/3" style={{ background: checked ? `${accentColor}0d` : "transparent" }}>
                <div className="w-3.5 h-3.5 rounded flex-shrink-0 flex items-center justify-center" style={{ background: checked ? accentColor : "rgba(255,255,255,0.08)", border: `1px solid ${checked ? accentColor : "rgba(255,255,255,0.12)"}` }}>
                  {checked && <div className="w-2 h-2 rounded-sm bg-white" />}
                </div>
                <span className={cn("text-xs", checked ? "text-text-primary" : "text-tx-3")}>{opt}</span>
              </label>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ─── MitreTacticsDropdown ─────────────────────────────────────────────────────

function MitreTacticsDropdown({ selected, onChange }: { selected: string[]; onChange: (v: string[]) => void }) {
  return (
    <MultiSelectDropdown
      label="Any tactic"
      options={MITRE_TACTICS}
      selected={selected}
      onChange={onChange}
      accentColor="#3B82F6"
    />
  );
}

// ─── SaveModal ────────────────────────────────────────────────────────────────

function SaveModal({ onSave, onClose }: { onSave: (name: string, desc: string) => Promise<void>; onClose: () => void }) {
  const [name, setName] = useState("");
  const [desc, setDesc] = useState("");
  const [saving, setSaving] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const handleSave = async () => {
    if (!name.trim()) return;
    setSaving(true); setErr(null);
    try { await onSave(name.trim(), desc.trim()); onClose(); }
    catch (e) { setErr(extractApiError(e)); }
    finally { setSaving(false); }
  };
  return (
    <>
      <div onClick={onClose} className="fixed inset-0 bg-black/70 z-[49]" />
      <div className="fixed top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 z-50 p-6 bg-bg-card border border-accent/20 rounded-xl shadow-2xl">
        <div className="text-sm font-bold font-display text-text-primary mb-1">Save Hunt</div>
        <p className="text-xs text-text-disabled mb-5">Save current query for quick re-use</p>
        {[
          { lbl: "Name", val: name, set: setName, ph: "e.g. Lateral Movement Off-hours", kb: true },
          { lbl: "Description (optional)", val: desc, set: setDesc, ph: "Brief description...", kb: false },
        ].map(({ lbl, val, set, ph, kb }) => (
          <div key={lbl} className="mb-3">
            <label className="block text-2xs font-bold uppercase tracking-widest text-text-disabled mb-1.5">{lbl}</label>
            <input className="inp w-full" placeholder={ph} value={val} onChange={(e) => set(e.target.value)}
              onKeyDown={kb ? (e) => e.key === "Enter" && handleSave() : undefined} autoFocus={kb} />
          </div>
        ))}
        {err && <p className="text-xs text-sev-critical mb-3">{err}</p>}
        <div className="flex gap-2 justify-end mt-4">
          <Button variant="ghost" size="sm" onClick={onClose}>Cancel</Button>
          <Button variant="primary" size="sm" disabled={!name.trim()} loading={saving} onClick={handleSave}>
            <Save size={12} /> Save
          </Button>
        </div>
      </div>
    </>
  );
}

// ─── SummaryBar ───────────────────────────────────────────────────────────────

function SummaryBar({ summary }: { summary: EventHuntSummary }) {
  const stats = [
    { icon: Cpu,           label: "Unique Hosts", value: summary.unique_hosts,     color: "#60A5FA" },
    { icon: Activity,      label: "Unique Users", value: summary.unique_users,     color: "#818CF8" },
    { icon: Globe,         label: "Unique IPs",   value: summary.unique_ips,       color: "#34D399" },
    { icon: AlertTriangle, label: "Anomalies",    value: summary.total_anomalies,  color: "#FBBF24" },
    { icon: Shield,        label: "Threat IPs",   value: summary.total_threat_ips, color: "#F87171" },
  ];
  return (
    <div className="flex gap-2.5 mb-4 flex-wrap">
      {stats.map(({ icon: Icon, label, value, color }) => (
        <div key={label} className="flex items-center gap-2 px-3.5 py-2 rounded-lg flex-1 min-w-[110px]" style={{ background: `${color}0d`, border: `1px solid ${color}22` }}>
          <Icon size={14} style={{ color, flexShrink: 0 }} />
          <div>
            <div className="text-lg font-bold leading-none font-display" style={{ color }}>{value}</div>
            <div className="text-2xs text-text-disabled mt-0.5">{label}</div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── DrawerField / DrawerSection ──────────────────────────────────────────────

function DrawerField({ label, value, mono = false }: { label: string; value?: string | null; mono?: boolean }) {
  if (!value) return null;
  return (
    <div className="flex justify-between items-baseline mb-2">
      <span className="text-2xs font-bold uppercase tracking-widest text-text-disabled flex-shrink-0 mr-3">{label}</span>
      <span className={cn("text-right break-all", mono ? "text-xs text-text-secondary font-mono" : "text-xs text-text-secondary")}>{value}</span>
    </div>
  );
}

function DrawerSection({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="mb-5">
      <div className="text-2xs font-bold uppercase tracking-widest text-text-disabled mb-2.5 pb-1.5 border-b border-white/4">{label}</div>
      {children}
    </div>
  );
}

// ─── EvtDetailDrawer ──────────────────────────────────────────────────────────

function EvtDetailDrawer({ event, onClose, navigate }: {
  event: EventHuntResultEntry; onClose: () => void; navigate: (path: string) => void;
}) {
  const sev = severityLabel(event.severity);
  const catC = categoryColor(event.category);
  const anomalyPct = Math.round(event.anomaly_score * 100);
  return (
    <>
      <div onClick={onClose} className="fixed inset-0 z-40" />
      <div className="fixed right-0 top-0 bottom-0 w-[420px] z-41 bg-bg-surface border-l border-border flex flex-col overflow-hidden shadow-2xl">
        <div className="px-5 py-4 border-b border-border flex items-start justify-between flex-shrink-0">
          <div>
            <div className="text-sm font-bold font-display text-text-primary">Event Detail</div>
            <div className="text-2xs text-text-disabled font-mono mt-1">{event.event_id}</div>
          </div>
          <button onClick={onClose} className="flex items-center justify-center w-7 h-7 rounded-md bg-white/5 border border-border text-text-muted hover:text-text-secondary cursor-pointer">
            <X size={14} />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto px-5 py-4.5">
          <div className="flex gap-2 flex-wrap mb-5">
            <span className="px-3 py-0.5 rounded-md text-xs font-bold uppercase" style={{ background: `${catC}18`, color: catC, border: `1px solid ${catC}33` }}>{event.category}</span>
            <span className="px-3 py-0.5 rounded-md text-xs font-bold" style={{ color: sev.color }}>{sev.label}</span>
            {event.is_anomaly && (
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-xs font-bold bg-sev-medium/10 text-sev-medium border border-sev-medium/25"><AlertTriangle size={11} /> ANOMALY</span>
            )}
            {event.is_threat_ip && (
              <span className="inline-flex items-center gap-1 px-2.5 py-0.5 rounded-md text-xs font-bold bg-sev-critical/10 text-sev-critical border border-sev-critical/25"><Shield size={11} /> THREAT IP</span>
            )}
          </div>
          <DrawerSection label="Event">
            <DrawerField label="Timestamp" value={fmtTs(event.timestamp)} mono />
            <DrawerField label="Hostname"  value={event.host_name} />
            <DrawerField label="Username"  value={event.username} />
            <DrawerField label="Process"   value={event.process_name} mono />
            <DrawerField label="Source IP" value={event.source_ip} mono />
            <DrawerField label="Dest IP"   value={event.dest_ip} mono />
            <DrawerField label="Country"   value={event.geo_country} />
          </DrawerSection>
          {(event.is_anomaly || event.is_threat_ip || event.ueba_flags.length > 0) && (
            <DrawerSection label="UEBA Analysis">
              {event.anomaly_score > 0 && (
                <div className="mb-3">
                  <div className="flex justify-between mb-1.5">
                    <span className="text-2xs font-bold uppercase tracking-widest text-text-disabled">Anomaly Score</span>
                    <span className={cn("text-xs font-bold font-mono", event.is_anomaly ? "text-sev-medium" : "text-text-disabled")}>{anomalyPct}%</span>
                  </div>
                  <div className="h-1 rounded-sm bg-white/6">
                    <div className="h-full rounded-sm transition-all duration-400" style={{ width: `${Math.min(anomalyPct, 100)}%`, background: event.is_anomaly ? "#FBBF24" : "#475569" }} />
                  </div>
                </div>
              )}
              {event.ueba_flags.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {event.ueba_flags.map((flag) => (
                    <span key={flag} className="px-2 py-px rounded text-2xs font-semibold bg-indigo-500/10 text-indigo-300 border border-indigo-500/20">{flag.replace(/_/g, " ")}</span>
                  ))}
                </div>
              )}
            </DrawerSection>
          )}
          {event.tags.length > 0 && (
            <DrawerSection label="Tags">
              <div className="flex flex-wrap gap-1.5">
                {event.tags.map((tag) => <span key={tag} className="px-2 py-px rounded text-2xs font-semibold bg-purple-500/8 text-purple-300 border border-purple-500/20">{tag}</span>)}
              </div>
            </DrawerSection>
          )}
          {event.match_reasons.length > 0 && (
            <DrawerSection label="Match Reasons">
              {event.match_reasons.map((r, i) => (
                <div key={i} className="flex items-baseline gap-2 mb-1">
                  <span className="text-blue-400 text-sm leading-none flex-shrink-0">›</span>
                  <span className="text-xs text-tx-3 font-mono">{r}</span>
                </div>
              ))}
            </DrawerSection>
          )}
          {event.correlation_id && (
            <DrawerSection label="Linked Investigation">
              <button onClick={() => navigate(`/investigations/${event.correlation_id}`)}
                className="flex items-center gap-2 w-full px-3.5 py-2 rounded-lg bg-accent/8 border border-accent/20 text-blue-300 text-xs font-semibold cursor-pointer text-left">
                <ExternalLink size={13} />
                Open Investigation
                <span className="ml-auto text-2xs text-text-disabled font-mono">{event.correlation_id.slice(0, 8)}…</span>
              </button>
            </DrawerSection>
          )}
        </div>
      </div>
    </>
  );
}

// ─── InvFilterRow ─────────────────────────────────────────────────────────────

function InvFilterRow({ filter, onChange, onRemove, canRemove }: {
  filter: HuntFilter; onChange: (f: HuntFilter) => void; onRemove: () => void; canRemove: boolean;
}) {
  const field     = INV_HUNT_FIELDS.find((f) => f.value === filter.field);
  const fieldType = field?.type ?? "text";
  const operators = INV_OPS_BY_TYPE[fieldType];
  const handleFieldChange = (fv: string) => {
    const newType = INV_HUNT_FIELDS.find((f) => f.value === fv)?.type ?? "text";
    onChange({ field: fv, operator: INV_OPS_BY_TYPE[newType][0].value, value: "" });
  };
  let valueEl: ReactNode;
  if (fieldType === "status") {
    valueEl = <select className="inp flex-1" value={filter.value} onChange={(e) => onChange({ ...filter, value: e.target.value })}>
      <option value="">Select...</option>{STATUS_OPTIONS.map((v) => <option key={v} value={v}>{v.replace(/_/g, " ")}</option>)}</select>;
  } else if (fieldType === "confidence") {
    valueEl = <select className="inp flex-1" value={filter.value} onChange={(e) => onChange({ ...filter, value: e.target.value })}>
      <option value="">Select...</option>{CONFIDENCE_OPTIONS.map((v) => <option key={v} value={v}>{v}</option>)}</select>;
  } else if (fieldType === "verdict") {
    valueEl = <select className="inp flex-1" value={filter.value} onChange={(e) => onChange({ ...filter, value: e.target.value })}>
      <option value="">Select...</option>{VERDICT_OPTIONS.map((v) => <option key={v} value={v}>{v.replace(/_/g, " ")}</option>)}</select>;
  } else {
    valueEl = <input className="inp flex-1" type={fieldType === "number" ? "number" : "text"} placeholder="Value..." value={filter.value} onChange={(e) => onChange({ ...filter, value: e.target.value })} />;
  }
  return (
    <div className="flex gap-1.5 items-center">
      <select className="inp w-36 flex-shrink-0" value={filter.field} onChange={(e) => handleFieldChange(e.target.value)}>
        {INV_HUNT_FIELDS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
      </select>
      <select className="inp w-28 flex-shrink-0" value={filter.operator} onChange={(e) => onChange({ ...filter, operator: e.target.value as HuntFilter["operator"] })}>
        {operators.map((op) => <option key={op.value} value={op.value}>{op.label}</option>)}
      </select>
      {valueEl}
      <button onClick={onRemove} disabled={!canRemove} className={cn("flex items-center justify-center w-7 h-7 rounded-md flex-shrink-0 border transition-all", canRemove ? "bg-sev-critical/8 border-sev-critical/20 text-sev-critical cursor-pointer" : "bg-white/4 border-white/6 text-text-disabled cursor-default")}>
        <Trash2 size={12} />
      </button>
    </div>
  );
}

// ─── EvtFilterRow ─────────────────────────────────────────────────────────────

function EvtFilterRow({ filter, onChange, onRemove, canRemove }: {
  filter: EventHuntFilter; onChange: (f: EventHuntFilter) => void; onRemove: () => void; canRemove: boolean;
}) {
  const field     = EVT_HUNT_FIELDS.find((f) => f.value === filter.field);
  const fieldType = field?.type ?? "text";
  const operators = EVT_OPS_BY_TYPE[fieldType];
  const handleFieldChange = (fv: string) => {
    const newType = EVT_HUNT_FIELDS.find((f) => f.value === fv)?.type ?? "text";
    onChange({ field: fv, operator: EVT_OPS_BY_TYPE[newType][0].value, value: "" });
  };
  return (
    <div className="flex gap-1.5 items-center">
      <select className="inp w-36 flex-shrink-0" value={filter.field} onChange={(e) => handleFieldChange(e.target.value)}>
        {EVT_HUNT_FIELDS.map((f) => <option key={f.value} value={f.value}>{f.label}</option>)}
      </select>
      <select className="inp w-28 flex-shrink-0" value={filter.operator} onChange={(e) => onChange({ ...filter, operator: e.target.value as EventHuntFilter["operator"] })}>
        {operators.map((op) => <option key={op.value} value={op.value}>{op.label}</option>)}
      </select>
      <input className="inp flex-1" type={fieldType === "number" ? "number" : "text"} placeholder={field?.placeholder ?? "Value..."} value={filter.value} onChange={(e) => onChange({ ...filter, value: e.target.value })} />
      <button onClick={onRemove} disabled={!canRemove} className={cn("flex items-center justify-center w-7 h-7 rounded-md flex-shrink-0 border transition-all", canRemove ? "bg-sev-critical/8 border-sev-critical/20 text-sev-critical cursor-pointer" : "bg-white/4 border-white/6 text-text-disabled cursor-default")}>
        <Trash2 size={12} />
      </button>
    </div>
  );
}

// ─── InvResultRow ─────────────────────────────────────────────────────────────

function InvResultRow({ entry, onClick, isLast }: { entry: HuntResultEntry; onClick: () => void; isLast: boolean }) {
  const sc  = scoreColors(entry.threat_score);
  const stC = statusColor(entry.status);
  return (
    <div onClick={onClick} className={cn("grid items-center px-3.5 py-2.5 cursor-pointer hover:bg-white/3 transition-colors", !isLast && "border-b border-white/3")}
      style={{ gridTemplateColumns: "68px 1fr 116px 80px 180px 88px" }}>
      <div><span className="inline-block px-1.5 py-0.5 rounded text-xs font-bold font-mono" style={{ background: sc.bg, color: sc.color }}>{entry.threat_score}</span></div>
      <div className="text-xs text-text-secondary pr-3 overflow-hidden text-ellipsis whitespace-nowrap">{entry.executive_summary}</div>
      <div><span className="inline-block px-2 py-0.5 rounded text-2xs font-semibold" style={{ background: `${stC}1a`, color: stC, border: `1px solid ${stC}33` }}>{entry.status.replace(/_/g, " ")}</span></div>
      <div className="text-xs text-text-muted">{entry.confidence}</div>
      <div className="flex gap-1 flex-nowrap overflow-hidden">
        {entry.match_reasons.slice(0, 2).map((r, i) => <span key={i} className="inline-block px-1.5 py-px rounded text-2xs font-semibold whitespace-nowrap bg-indigo-500/10 text-indigo-300 border border-indigo-500/15">{r}</span>)}
        {entry.match_reasons.length > 2 && <span className="text-2xs text-text-disabled flex-shrink-0">+{entry.match_reasons.length - 2}</span>}
      </div>
      <div className="text-2xs text-text-muted text-right">{formatRelativeTime(entry.created_at)}</div>
    </div>
  );
}

// ─── EvtResultRow ─────────────────────────────────────────────────────────────

function EvtResultRow({ entry, onClick, isLast }: { entry: EventHuntResultEntry; onClick: () => void; isLast: boolean }) {
  const sev  = severityLabel(entry.severity);
  const catC = categoryColor(entry.category);
  return (
    <div onClick={onClick} className={cn("grid items-center px-3.5 py-2 cursor-pointer hover:bg-white/3 transition-colors text-xs", !isLast && "border-b border-white/3")}
      style={{ gridTemplateColumns: "148px 140px 140px 120px 80px 70px 1fr" }}>
      <div className="text-2xs font-mono text-text-muted">{fmtTs(entry.timestamp)}</div>
      <div className="text-text-secondary overflow-hidden text-ellipsis whitespace-nowrap pr-2">{entry.host_name ?? <span className="text-text-disabled">—</span>}</div>
      <div className="text-text-secondary overflow-hidden text-ellipsis whitespace-nowrap pr-2">{entry.username ?? <span className="text-text-disabled">—</span>}</div>
      <div className="text-tx-3 text-xs overflow-hidden text-ellipsis whitespace-nowrap pr-2">{entry.process_name ?? entry.source_ip ?? <span className="text-text-disabled">—</span>}</div>
      <div><span className="inline-block px-1.5 py-px rounded text-2xs font-bold uppercase" style={{ background: `${catC}18`, color: catC, border: `1px solid ${catC}33` }}>{entry.category}</span></div>
      <div><span className="text-2xs font-bold" style={{ color: sev.color }}>{sev.label}</span></div>
      <div className="flex gap-1 flex-nowrap overflow-hidden">
        {entry.is_threat_ip && <span className="inline-flex items-center gap-0.5 px-1.5 py-px rounded text-2xs font-semibold bg-sev-critical/10 text-sev-critical border border-sev-critical/20 whitespace-nowrap flex-shrink-0"><Shield size={9} /> THREAT IP</span>}
        {entry.is_anomaly && <span className="inline-flex items-center gap-0.5 px-1.5 py-px rounded text-2xs font-semibold bg-sev-medium/10 text-sev-medium border border-sev-medium/20 whitespace-nowrap flex-shrink-0"><AlertTriangle size={9} /> ANOMALY</span>}
        {entry.ueba_flags.slice(0, 1).map((flag) => <span key={flag} className="inline-block px-1.5 py-px rounded text-2xs font-semibold whitespace-nowrap flex-shrink-0 bg-indigo-500/10 text-indigo-300 border border-indigo-500/15">{flag.replace(/_/g, " ")}</span>)}
        {entry.ueba_flags.length > 1 && <span className="text-2xs text-text-disabled flex-shrink-0">+{entry.ueba_flags.length - 1}</span>}
        {!entry.is_threat_ip && !entry.is_anomaly && entry.ueba_flags.length === 0 && <span className="text-2xs text-text-disabled">—</span>}
      </div>
    </div>
  );
}

// ─── HuntPage ─────────────────────────────────────────────────────────────────

export function HuntPage() {
  const navigate = useNavigate();

  // Shared
  const [mode,        setMode]        = useState<HuntMode>("event");
  const [timeRange,   setTimeRange]   = useState("24h");
  const [filterLogic, setFilterLogic] = useState<FilterLogic>("and");
  const [savedHunts,  setSavedHunts]  = useState<SavedHunt[]>([]);
  const [showSaveModal,      setShowSaveModal]      = useState(false);
  const [confirmDeleteHunt,  setConfirmDeleteHunt]  = useState<SavedHunt | null>(null);
  const [showHistory,        setShowHistory]        = useState(true);
  const [history,            setHistory]            = useState(() => loadHuntHistory());
  const [kqlQuery,           setKqlQuery]           = useState("");
  const [selectedBucket,     setSelectedBucket]     = useState<string | undefined>();

  // Hooks
  const inv = useInvestigationHunt();
  const evt = useEventHunt();

  useEffect(() => {
    huntApi.listSaved()
      .then((data) => setSavedHunts(Array.isArray(data) ? data : []))
      .catch((e) => toastError(extractApiError(e), "Failed to load saved hunts"));
  }, []);

  const isRunning = mode === "investigation" ? inv.running : evt.running;
  const handleRun = useCallback(() => {
    if (isRunning) return;
    const p = mode === "investigation"
      ? inv.run(timeRange, filterLogic)
      : evt.run(timeRange, filterLogic);
    p.then(() => setHistory(loadHuntHistory())).catch(() => {});
  }, [isRunning, mode, inv, evt, timeRange, filterLogic]);

  // Ctrl+Enter shortcut — fires the hunt
  useKeyboard("Enter", (e) => { e.preventDefault(); handleRun(); }, { ctrl: true });

  const exportRows: Record<string, unknown>[] = mode === "event"
    ? evt.results.map((r) => ({ timestamp: r.timestamp, host: r.host_name ?? "", user: r.username ?? "", process: r.process_name ?? "", source_ip: r.source_ip ?? "", category: r.category, severity: r.severity }))
    : inv.results.map((r) => ({ id: r.investigation_id, score: r.threat_score, status: r.status, summary: r.executive_summary }));

  const handleKqlSubmit = useCallback((query: string) => {
    setKqlQuery(query);
    handleRun();
  }, [handleRun]);

  const handleTemplateSelect = useCallback((template: HuntTemplate) => {
    if (template.mode === "event" || template.mode === "investigation") {
      setMode(template.mode);
    }
    if (template.kql) {
      setKqlQuery(template.kql);
    }
    if (Array.isArray(template.filters)) {
      evt.setFilters(template.filters.map((f) => ({
        field: f.field,
        operator: "contains" as const,
        value: f.value,
      })));
    }
    if (template.tactic) {
      inv.setMitreTactics([template.tactic]);
    }
  }, [evt, inv]);

  const evtTimestamps = evt.results.map((r) => r.timestamp);

  const loadSavedHunt = (hunt: SavedHunt) => {
    type SavedQ = { mode?: HuntMode; logic?: FilterLogic; filters?: HuntFilter[]; mitre_tactics?: string[]; [k: string]: unknown };
    const q = hunt.query_params as SavedQ;
    if (q.mode === "investigation" || q.mode === "event") setMode(q.mode);
    if (q.logic === "and" || q.logic === "or") setFilterLogic(q.logic);
    if (Array.isArray(q.filters))       inv.setFilters(q.filters);
    if (Array.isArray(q.mitre_tactics)) inv.setMitreTactics(q.mitre_tactics);
    evt.loadFromSaved(q as import("./hooks/useEventHunt").SavedEvtParams);
  };

  const handleSave = async (name: string, desc: string) => {
    const query_params = {
      mode, logic: filterLogic, filters: inv.filters, mitre_tactics: inv.mitreTactics,
      evt_filters: evt.filters, evt_categories: evt.categories,
      evt_ueba_flags: evt.uebaFlags, evt_tags: evt.tags,
      evt_is_anomaly: evt.isAnomaly, evt_is_threat_ip: evt.isThreatIp,
      evt_min_severity: evt.minSeverity,
    };
    const hunt = await huntApi.saveHunt({ name, description: desc || undefined, query_params });
    setSavedHunts((prev) => [hunt, ...prev]);
  };

  const handleDeleteSavedHunt = (hunt: SavedHunt, e: React.MouseEvent) => {
    e.stopPropagation();
    setConfirmDeleteHunt(hunt);
  };
  const confirmDelete = async () => {
    if (!confirmDeleteHunt) return;
    try {
      await huntApi.deleteSavedHunt(confirmDeleteHunt.hunt_id);
      setSavedHunts((prev) => prev.filter((h) => h.hunt_id !== confirmDeleteHunt.hunt_id));
    } catch (e) { toastError(extractApiError(e), "Delete failed"); }
    finally { setConfirmDeleteHunt(null); }
  };

  const error = mode === "investigation" ? inv.error : evt.error;
  const hasRun = mode === "investigation" ? inv.hasRun : evt.hasRun;

  return (
    <div className="flex overflow-hidden bg-bg-base" style={{ height: "calc(100vh - 50px - 40px)" }}>

      {/* Saved Hunts Sidebar */}
      <div className="w-[210px] flex-shrink-0 border-r border-border bg-bg-surface flex flex-col overflow-hidden">
        <div className="px-3.5 pt-4 pb-2.5">
          <div className="text-2xs font-bold uppercase tracking-widest text-text-disabled mb-3">Saved Hunts</div>
          <button onClick={() => setShowSaveModal(true)} className="flex items-center gap-1.5 w-full px-2.5 py-1.5 bg-accent/6 border border-accent/15 rounded-lg text-xs font-semibold text-blue-300 cursor-pointer">
            <Plus size={12} /> Save Current
          </button>
        </div>
        <div className="flex-1 overflow-y-auto">
          {savedHunts.length === 0 && history.length === 0 ? (
            <div className="px-3.5 py-6 text-center text-xs text-text-disabled leading-relaxed">
              <Crosshair size={22} className="block mx-auto mb-2 opacity-20" />No saved hunts yet
            </div>
          ) : savedHunts.map((hunt) => (
            <div key={hunt.hunt_id} onClick={() => loadSavedHunt(hunt)}
              className="flex items-center gap-1.5 px-3.5 py-2 border-b border-white/3 cursor-pointer hover:bg-white/3 transition-colors group">
              <div className="flex-1 min-w-0">
                <div className="text-xs font-semibold text-text-secondary whitespace-nowrap overflow-hidden text-ellipsis">{hunt.name}</div>
                <div className="text-2xs text-text-disabled">{hunt.run_count} run{hunt.run_count !== 1 ? "s" : ""}</div>
              </div>
              <button onClick={(e) => handleDeleteSavedHunt(hunt, e)}
                aria-label={`Delete ${hunt.name}`}
                className="flex items-center justify-center w-5.5 h-5.5 rounded flex-shrink-0 opacity-0 group-hover:opacity-100 text-text-disabled hover:text-sev-critical hover:bg-sev-critical/8 border border-transparent hover:border-sev-critical/20 transition-all cursor-pointer">
                <Trash2 size={11} />
              </button>
            </div>
          ))}

          {/* Recent query history */}
          {history.length > 0 && (
            <div>
              <button
                onClick={() => setShowHistory((v) => !v)}
                className="flex items-center gap-1.5 w-full px-3.5 py-2.5 text-left border-t border-white/4 hover:bg-white/3 transition-colors"
                aria-expanded={showHistory}
              >
                <History size={11} className="text-text-disabled flex-shrink-0" />
                <span className="text-2xs font-bold uppercase tracking-widest text-text-disabled flex-1">Recent</span>
                <ChevronDown size={11} className={cn("text-text-disabled transition-transform", showHistory && "rotate-180")} />
              </button>
              {showHistory && history.slice(0, 8).map((entry) => {
                const filtersArr = (entry.filters as HuntFilter[] | undefined) ?? [];
                const timeRangeStr = (entry.timeRange as string | undefined) ?? "";
                const filterSummary = filtersArr.slice(0, 2)
                  .map((f) => `${String(f.field)} ${String(f.operator)} ${String(f.value)}`)
                  .join(", ");
                return (
                <button
                  key={entry.id}
                  onClick={() => {
                    if (entry.mode === "investigation") {
                      setMode("investigation");
                      inv.loadFromHistory(entry as unknown as import("./hooks/useInvestigationHunt").HuntHistoryEntry);
                    } else {
                      setMode("event");
                    }
                  }}
                  className="flex items-start gap-2 w-full text-left px-3.5 py-2 border-b border-white/3 hover:bg-white/3 transition-colors"
                >
                  <Clock size={10} className="text-text-disabled mt-0.5 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="text-2xs text-text-disabled capitalize">{entry.mode}</div>
                    <div className="text-2xs text-text-muted truncate">{filterSummary || "—"}</div>
                    <div className="text-2xs text-text-disabled">{timeRangeStr || "All time"}</div>
                  </div>
                </button>
                );
              })}
            </div>
          )}
        </div>

        {/* Hypothesis Templates */}
        <div className="flex-shrink-0 border-t border-border">
          <HypothesisTemplates onSelect={handleTemplateSelect} />
        </div>
      </div>

      {/* Main Panel */}
      <div className="flex-1 flex flex-col overflow-hidden">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-3.5 border-b border-border flex-shrink-0">
          <div className="flex items-center gap-5">
            <div>
              <h1 className="text-lg font-bold font-display text-text-primary m-0">Threat Hunt</h1>
              <p className="text-xs text-text-disabled m-0 mt-0.5">
                {mode === "event" ? "Hunt raw events by host, user, process, IP, UEBA flag, tag, and more" : "Query aggregated investigations by score, status, and MITRE tactic"}
              </p>
            </div>
            <div className="flex bg-white/4 border border-white/8 rounded-lg p-0.5">
              {([
                { id: "event" as HuntMode,         icon: FileSearch, label: "Event Hunt"         },
                { id: "investigation" as HuntMode,  icon: Crosshair,  label: "Investigation Hunt" },
              ] as const).map(({ id, icon: Icon, label }) => (
                <button key={id} onClick={() => setMode(id)} className={cn("flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-semibold border-none cursor-pointer transition-all", mode === id ? "bg-accent/15 text-blue-300" : "bg-transparent text-text-muted hover:text-text-secondary")}>
                  <Icon size={13} /> {label}
                </button>
              ))}
            </div>
          </div>
          <div className="flex items-center gap-2">
            <HuntExportButton
              rows={exportRows}
              filename={mode === "event" ? `hunt-events-${Date.now()}` : `hunt-investigations-${Date.now()}`}
              disabled={exportRows.length === 0}
            />
            <Button variant="primary" size="sm" disabled={isRunning} loading={isRunning} onClick={handleRun} aria-label="Run hunt query (Ctrl+Enter)">
              <Play size={13} /> {isRunning ? "Running..." : "Run Hunt"}
            </Button>
          </div>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto px-6 py-5">
          {/* Time range + logic */}
          <div className="flex gap-3 mb-4 items-end flex-wrap">
            <div>
              <label className="block text-2xs font-bold uppercase tracking-widest text-text-disabled mb-1.5">Time Range</label>
              <div className="flex gap-0.5 bg-white/3 border border-white/7 rounded-lg p-0.5">
                {TIME_RANGES.map((t) => (
                  <button
                    key={t.value}
                    onClick={() => setTimeRange(t.value)}
                    className={cn(
                      "px-3 py-1 rounded-md text-xs font-semibold transition-all cursor-pointer border-none",
                      timeRange === t.value
                        ? "bg-accent/15 text-blue-300"
                        : "bg-transparent text-text-disabled hover:text-text-muted",
                    )}
                  >
                    {t.label}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <label className="block text-2xs font-bold uppercase tracking-widest text-text-disabled mb-1.5">Filter Logic</label>
              <div className="flex gap-1 bg-white/3 border border-white/7 rounded-lg p-0.5">
                {(["and", "or"] as FilterLogic[]).map((lg) => (
                  <button key={lg} onClick={() => setFilterLogic(lg)} className={cn("px-4 py-1 rounded-md text-xs font-bold uppercase cursor-pointer border-none transition-all", filterLogic === lg ? "bg-accent/15 text-blue-300" : "bg-transparent text-text-disabled hover:text-text-muted")}>{lg}</button>
                ))}
              </div>
            </div>
          </div>

          {/* KQL Input — shown for active mode */}
          <div className="mb-4">
            <KQLQueryInput
              value={kqlQuery}
              onChange={setKqlQuery}
              onSubmit={handleKqlSubmit}
              placeholder={mode === "event"
                ? "KQL: host:DESKTOP-* AND category:process AND severity:>=3"
                : "KQL: threat_score:>=80 AND status:active"}
            />
          </div>

          {/* Event Query Builder */}
          {mode === "event" && (
            <div className="bg-white/2 border border-white/6 rounded-xl p-4 mb-4">
              <div className="text-2xs font-bold uppercase tracking-widest text-text-disabled mb-3.5">Event Query Builder</div>
              <div className="flex gap-2 flex-wrap mb-3.5">
                <BoolToggle value={evt.isAnomaly}  onChange={evt.setIsAnomaly}  label="Anomaly Only"   />
                <BoolToggle value={evt.isThreatIp} onChange={evt.setIsThreatIp} label="Threat IP Only" />
                {[1, 2, 3, 4].map((sev) => {
                  const { label, color } = severityLabel(sev);
                  const active = evt.minSeverity === sev;
                  return (
                    <button key={sev} onClick={() => evt.setMinSeverity(active ? null : sev)}
                      className={cn("px-2.5 py-1 rounded-md text-xs font-semibold cursor-pointer border transition-all", active ? "border-opacity-55" : "bg-white/4 border-white/10 text-text-disabled")}
                      style={active ? { background: `${color}18`, borderColor: `${color}55`, color } : {}}>
                      {label}+
                    </button>
                  );
                })}
              </div>
              <div className="mb-3.5">
                <div className="text-2xs font-bold uppercase tracking-widest text-text-disabled mb-2">Category</div>
                <div className="flex gap-1.5 flex-wrap">
                  {EVENT_CATEGORIES.map((cat) => {
                    const active = evt.categories.includes(cat);
                    const color  = categoryColor(cat);
                    return (
                      <button key={cat} onClick={() => evt.setCategories(active ? evt.categories.filter((c) => c !== cat) : [...evt.categories, cat])}
                        className="px-2.5 py-0.5 rounded text-xs font-semibold cursor-pointer border transition-all"
                        style={active ? { background: `${color}18`, borderColor: `${color}55`, color } : { background: "rgba(255,255,255,0.04)", borderColor: "rgba(255,255,255,0.08)", color: "#5C6373" }}>
                        {cat}
                      </button>
                    );
                  })}
                </div>
              </div>
              <div className="flex flex-col gap-2 mb-2.5">
                {evt.filters.map((filter, idx) => (
                  <EvtFilterRow key={idx} filter={filter}
                    onChange={(f) => evt.setFilters(evt.filters.map((x, j) => j === idx ? f : x))}
                    onRemove={() => evt.setFilters(evt.filters.filter((_, j) => j !== idx))}
                    canRemove={evt.filters.length > 1} />
                ))}
              </div>
              <button onClick={() => evt.setFilters([...evt.filters, { field: "host_name", operator: "contains" as const, value: "" }])}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-md mb-3.5 bg-transparent border border-dashed border-white/10 text-text-disabled text-xs font-semibold cursor-pointer hover:border-white/20 hover:text-text-muted transition-all">
                <Plus size={12} /> Add Filter
              </button>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <div className="text-2xs font-bold uppercase tracking-widest text-text-disabled mb-1.5">UEBA Flags</div>
                  <MultiSelectDropdown label="Any flag" options={UEBA_FLAG_OPTIONS} selected={evt.uebaFlags} onChange={evt.setUebaFlags} accentColor="#818CF8" />
                </div>
                <div>
                  <div className="text-2xs font-bold uppercase tracking-widest text-text-disabled mb-1.5">Tags / Rule IDs</div>
                  <TagChipInput tags={evt.tags} onChange={evt.setTags} placeholder="Type tag and press Enter..." />
                </div>
              </div>
            </div>
          )}

          {/* Investigation Query Builder */}
          {mode === "investigation" && (
            <div className="bg-white/2 border border-white/6 rounded-xl p-4 mb-4">
              <div className="text-2xs font-bold uppercase tracking-widest text-text-disabled mb-3.5">Investigation Query Builder</div>
              <div className="flex flex-col gap-2 mb-2.5">
                {inv.filters.map((filter, idx) => (
                  <div key={idx}>
                    {idx > 0 && (
                      <div className="flex items-center gap-2 mb-2">
                        <div className="flex-1 h-px bg-white/4" />
                        <span className="text-2xs font-bold text-text-disabled uppercase tracking-widest">{filterLogic}</span>
                        <div className="flex-1 h-px bg-white/4" />
                      </div>
                    )}
                    <InvFilterRow filter={filter}
                      onChange={(f) => inv.setFilters(inv.filters.map((x, j) => j === idx ? f : x))}
                      onRemove={() => inv.setFilters(inv.filters.filter((_, j) => j !== idx))}
                      canRemove={inv.filters.length > 1} />
                  </div>
                ))}
              </div>
              <button onClick={() => inv.setFilters([...inv.filters, { field: "threat_score", operator: "gte" as const, value: "" }])}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-md mb-3.5 bg-transparent border border-dashed border-white/10 text-text-disabled text-xs font-semibold cursor-pointer hover:border-white/20 hover:text-text-muted transition-all">
                <Plus size={12} /> Add Filter
              </button>
              <div>
                <label className="block text-2xs font-bold uppercase tracking-widest text-text-disabled mb-1.5">MITRE Tactic</label>
                <MitreTacticsDropdown selected={inv.mitreTactics} onChange={inv.setMitreTactics} />
              </div>
            </div>
          )}

          {/* Errors */}
          {error && (
            <div className="px-3.5 py-2.5 mb-4 rounded-lg bg-sev-critical/8 border border-sev-critical/20 text-xs text-severity-critical">{error}</div>
          )}

          {/* Pre-run empty state */}
          {!hasRun && !isRunning && (
            <div className="text-center py-16 text-text-disabled">
              <Crosshair size={36} className="block mx-auto mb-3 opacity-15" />
              <div className="text-sm text-text-muted mb-1">Configure your query and click Run Hunt</div>
              <div className="text-xs">
                {mode === "event" ? "Hunts raw events — hostname, username, process, IP, UEBA flags, tags" : "Searches aggregated investigations by score, status, MITRE tactic"}
              </div>
            </div>
          )}

          {/* Event Results */}
          {mode === "event" && evt.hasRun && (
            <div>
              {evt.summary && <SummaryBar summary={evt.summary} />}
              <HuntTimeSeriesOverlay
                timestamps={evtTimestamps}
                selectedBucket={selectedBucket}
                onBucketClick={setSelectedBucket}
              />
              <div className="flex items-center mb-3">
                <span className="text-sm font-semibold text-text-primary">Events</span>
                {evt.total !== null && <span className="text-xs text-text-muted ml-2">{evt.total} event{evt.total !== 1 ? "s" : ""}{evt.hasMore ? "+" : ""}</span>}
                <span className="text-xs text-text-disabled ml-2">— click a row to inspect</span>
              </div>
              {evt.results.length === 0 ? (
                <div className="text-center py-12 text-text-disabled text-sm">
                  <Search size={28} className="block mx-auto mb-2.5 opacity-20" />No events matched your query
                </div>
              ) : (
                <div className="bg-white/1 border border-white/6 rounded-xl overflow-hidden">
                  <div className="grid px-3.5 py-2 border-b border-white/6 bg-white/2" style={{ gridTemplateColumns: "148px 140px 140px 120px 80px 70px 1fr" }}>
                    {["Timestamp", "Hostname", "Username", "Process / Source IP", "Category", "Severity", "Flags"].map((col) => (
                      <div key={col} className="text-2xs font-bold uppercase tracking-widest text-text-disabled">{col}</div>
                    ))}
                  </div>
                  {evt.results.map((entry, idx) => (
                    <EvtResultRow key={entry.event_id} entry={entry} onClick={() => evt.setSelectedEvt(entry)} isLast={idx === evt.results.length - 1 && !evt.hasMore} />
                  ))}
                  {evt.hasMore && (
                    <div className="px-3.5 py-3 border-t border-white/4">
                      <Button variant="ghost" size="sm" className="w-full" loading={evt.loadingMore} onClick={() => evt.loadMore(timeRange, filterLogic)}>
                        {evt.loadingMore ? "Loading..." : "Load More"}
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {/* Investigation Results */}
          {mode === "investigation" && inv.hasRun && (
            <div>
              <div className="flex items-center mb-3">
                <span className="text-sm font-semibold text-text-primary">Results</span>
                {inv.total !== null && <span className="text-xs text-text-muted ml-2">{inv.total} investigation{inv.total !== 1 ? "s" : ""}</span>}
              </div>
              {inv.results.length === 0 ? (
                <div className="text-center py-12 text-text-disabled text-sm">
                  <Search size={28} className="block mx-auto mb-2.5 opacity-20" />No investigations matched your query
                </div>
              ) : (
                <div className="bg-white/1 border border-white/6 rounded-xl overflow-hidden">
                  <div className="grid px-3.5 py-2 border-b border-white/6 bg-white/2" style={{ gridTemplateColumns: "68px 1fr 116px 80px 180px 88px" }}>
                    {["Score", "Title", "Status", "Confidence", "Match Reasons", "Created"].map((col) => (
                      <div key={col} className="text-2xs font-bold uppercase tracking-widest text-text-disabled">{col}</div>
                    ))}
                  </div>
                  {inv.results.map((entry, idx) => (
                    <InvResultRow key={entry.investigation_id} entry={entry} onClick={() => navigate(`/investigations/${entry.investigation_id}`)} isLast={idx === inv.results.length - 1 && !inv.hasMore} />
                  ))}
                  {inv.hasMore && (
                    <div className="px-3.5 py-3 border-t border-white/4">
                      <Button variant="ghost" size="sm" className="w-full" loading={inv.loadingMore} onClick={() => inv.loadMore(timeRange, filterLogic)}>
                        {inv.loadingMore ? "Loading..." : "Load More"}
                      </Button>
                    </div>
                  )}
                </div>
              )}
            </div>
          )}
        </div>
      </div>

      {/* Event Detail Drawer */}
      {evt.selectedEvt && (
        <EvtDetailDrawer event={evt.selectedEvt} onClose={() => evt.setSelectedEvt(null)} navigate={navigate} />
      )}

      {/* Save Modal */}
      {showSaveModal && <SaveModal onSave={handleSave} onClose={() => setShowSaveModal(false)} />}

      {/* Delete Confirm */}
      {confirmDeleteHunt && (
        <div
          role="dialog"
          aria-modal="true"
          aria-label="Confirm delete saved hunt"
          className="fixed inset-0 z-[100] bg-black/70 flex items-center justify-center"
          onClick={() => setConfirmDeleteHunt(null)}
          onKeyDown={(e) => { if (e.key === "Escape") setConfirmDeleteHunt(null); }}
        >
          <div onClick={(e) => e.stopPropagation()} className="w-96 bg-bg-elevated border border-border rounded-xl p-6 flex flex-col gap-4">
            <div className="text-sm font-bold text-text-primary">Delete Saved Hunt</div>
            <p className="text-xs text-tx-3 m-0">Are you sure you want to delete <strong className="text-text-primary">"{confirmDeleteHunt.name}"</strong>? This cannot be undone.</p>
            <div className="flex gap-2 justify-end">
              <Button variant="ghost" size="sm" onClick={() => setConfirmDeleteHunt(null)}>Cancel</Button>
              <Button variant="danger" size="sm" onClick={confirmDelete}>Delete</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
