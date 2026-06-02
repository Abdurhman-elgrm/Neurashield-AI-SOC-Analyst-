import { useState, useRef, useEffect } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { Clock } from "lucide-react";
import { format } from "date-fns";
import { SkeletonText } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { TimelineEventCard } from "./TimelineEventCard";
import { TimelineFilters } from "./TimelineFilters";
import { useTimeline } from "../../hooks/useTimeline";
import { DEFAULT_TIMELINE_FILTER } from "../../types/timeline";
import type { TimelineFilterState } from "../../types/timeline";

// ─── Date group header ────────────────────────────────────────────────────────

function DateHeader({ date }: { date: string }) {
  return (
    <div className="flex items-center gap-2 py-1.5 sticky top-0 bg-bg-surface z-10">
      <span className="text-2xs text-text-muted font-medium">
        {format(new Date(date), "MMM d, yyyy")}
      </span>
      <div className="flex-1 h-px bg-border" />
    </div>
  );
}

// ─── InvestigationTimeline ────────────────────────────────────────────────────

interface InvestigationTimelineProps {
  investigationId: string;
}

export function InvestigationTimeline({ investigationId }: InvestigationTimelineProps) {
  const [filters, setFilters] = useState<TimelineFilterState>(DEFAULT_TIMELINE_FILTER);
  const { filtered, isLoading } = useTimeline(investigationId, filters);
  const containerRef = useRef<HTMLDivElement>(null);

  // Scroll to bottom on new events
  const lastCountRef = useRef(0);
  useEffect(() => {
    if (filtered.length > lastCountRef.current && containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
    lastCountRef.current = filtered.length;
  }, [filtered.length]);

  // Build flat rows: interleave date headers + events
  const rows = buildRows(filtered);

  const virtualizer = useVirtualizer({
    count: rows.length,
    getScrollElement: () => containerRef.current,
    estimateSize: (i) => (rows[i].type === "date" ? 32 : 80),
    overscan: 5,
  });

  return (
    <div className="flex flex-col h-full">
      <div className="px-3 pt-3 pb-0 flex items-center gap-2 flex-shrink-0">
        <Clock className="w-3.5 h-3.5 text-accent" />
        <span className="text-xs font-semibold text-text-primary">Timeline</span>
        <span className="text-2xs text-text-muted ml-auto">{filtered.length} events</span>
      </div>

      <TimelineFilters filters={filters} onChange={setFilters} />

      {isLoading ? (
        <div className="p-3 space-y-3">
          <SkeletonText lines={6} />
        </div>
      ) : !filtered.length ? (
        <EmptyState
          icon={<Clock className="w-5 h-5" />}
          title="No events"
          description="Timeline events will appear here."
          className="py-8"
        />
      ) : (
        <div ref={containerRef} className="flex-1 overflow-y-auto px-3 pt-3">
          <div
            style={{ height: virtualizer.getTotalSize(), position: "relative" }}
          >
            {virtualizer.getVirtualItems().map((vItem) => {
              const row = rows[vItem.index];
              return (
                <div
                  key={vItem.key}
                  style={{
                    position: "absolute",
                    top: 0,
                    left: 0,
                    right: 0,
                    transform: `translateY(${vItem.start}px)`,
                  }}
                >
                  {row.type === "date" ? (
                    <DateHeader date={row.date!} />
                  ) : (
                    <TimelineEventCard
                      event={row.event!}
                      isLast={vItem.index === rows.length - 1}
                    />
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Build flat rows with date separators ─────────────────────────────────────

type Row =
  | { type: "date"; date: string; event?: undefined }
  | { type: "event"; event: NonNullable<ReturnType<typeof useTimeline>["filtered"]>[number]; date?: undefined };

function buildRows(events: ReturnType<typeof useTimeline>["filtered"]): Row[] {
  const rows: Row[] = [];
  let lastDay = "";

  for (const event of events) {
    const day = format(new Date(event.timestamp), "yyyy-MM-dd");
    if (day !== lastDay) {
      rows.push({ type: "date", date: event.timestamp });
      lastDay = day;
    }
    rows.push({ type: "event", event });
  }
  return rows;
}
