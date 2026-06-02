import { X } from "lucide-react";
import { cn } from "@/lib/utils";
import type { TimelineFilterState, TimelineEventType, TimelineActorType } from "../../types/timeline";

const EVENT_TYPE_LABELS: Partial<Record<TimelineEventType, string>> = {
  alert_triggered:       "Alert",
  investigation_created: "Created",
  status_changed:        "Status",
  assigned:              "Assigned",
  note_added:            "Note",
  evidence_added:        "Evidence",
  ai_analyzed:           "AI",
  verdict_updated:       "Verdict",
};

const ACTOR_TYPES: Array<{ value: "all" | TimelineActorType; label: string }> = [
  { value: "all",     label: "All" },
  { value: "system",  label: "System" },
  { value: "analyst", label: "Analyst" },
  { value: "ai",      label: "AI" },
];

interface TimelineFiltersProps {
  filters: TimelineFilterState;
  onChange: (f: TimelineFilterState) => void;
}

export function TimelineFilters({ filters, onChange }: TimelineFiltersProps) {
  const hasActive =
    filters.types.length > 0 ||
    filters.actorType !== "all" ||
    filters.search.trim() !== "";

  const toggleType = (type: TimelineEventType) => {
    const next = filters.types.includes(type)
      ? filters.types.filter((t) => t !== type)
      : [...filters.types, type];
    onChange({ ...filters, types: next });
  };

  return (
    <div className="space-y-2 px-3 pb-2 border-b border-border">
      {/* Search */}
      <input
        type="text"
        value={filters.search}
        onChange={(e) => onChange({ ...filters, search: e.target.value })}
        placeholder="Filter timeline..."
        className="w-full px-2 py-1.5 text-xs bg-bg-elevated border border-border rounded-md text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent"
      />

      {/* Actor type */}
      <div className="flex items-center gap-1">
        {ACTOR_TYPES.map((a) => (
          <button
            key={a.value}
            onClick={() => onChange({ ...filters, actorType: a.value })}
            className={cn(
              "px-2 py-0.5 text-2xs rounded-md transition-colors",
              filters.actorType === a.value
                ? "bg-accent text-white"
                : "text-text-muted hover:text-text-secondary hover:bg-bg-elevated"
            )}
          >
            {a.label}
          </button>
        ))}

        {hasActive && (
          <button
            onClick={() => onChange({ types: [], actorType: "all", search: "", severity: [] })}
            className="ml-auto flex items-center gap-0.5 text-2xs text-text-muted hover:text-severity-critical transition-colors"
          >
            <X className="w-3 h-3" />
            Clear
          </button>
        )}
      </div>

      {/* Event type chips */}
      <div className="flex flex-wrap gap-1">
        {(Object.entries(EVENT_TYPE_LABELS) as [TimelineEventType, string][]).map(([type, label]) => (
          <button
            key={type}
            onClick={() => toggleType(type)}
            className={cn(
              "px-1.5 py-0.5 text-2xs rounded border transition-colors",
              filters.types.includes(type)
                ? "bg-accent/10 text-accent border-accent/30"
                : "text-text-muted border-border hover:bg-bg-elevated"
            )}
          >
            {label}
          </button>
        ))}
      </div>
    </div>
  );
}
