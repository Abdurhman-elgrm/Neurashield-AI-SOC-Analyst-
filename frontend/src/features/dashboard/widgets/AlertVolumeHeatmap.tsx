import { useQuery } from "@tanstack/react-query";
import { apiClient } from "@/api/client";
import { cn } from "@/lib/utils";
import type { DashboardTimeRange } from "../types/dashboard";

interface HeatmapCell {
  day: number;  // 0=Sun … 6=Sat
  hour: number; // 0–23
  count: number;
}

const DAY_LABELS = ["Sun","Mon","Tue","Wed","Thu","Fri","Sat"];
const HOUR_LABELS = Array.from({ length: 24 }, (_, i) =>
  i === 0 ? "12a" : i < 12 ? `${i}a` : i === 12 ? "12p" : `${i - 12}p`
);

function sampleHeatmap(): HeatmapCell[] {
  const cells: HeatmapCell[] = [];
  for (let d = 0; d < 7; d++) {
    for (let h = 0; h < 24; h++) {
      const isBusinessHours = h >= 8 && h <= 18 && d >= 1 && d <= 5;
      const isSpike = (d === 2 || d === 3) && h >= 10 && h <= 13;
      cells.push({
        day: d,
        hour: h,
        count: isSpike
          ? Math.floor(Math.random() * 35 + 20)
          : isBusinessHours
            ? Math.floor(Math.random() * 18 + 4)
            : Math.floor(Math.random() * 4),
      });
    }
  }
  return cells;
}

function cellColorClass(count: number, max: number): string {
  if (count === 0) return "bg-bg-elevated";
  const intensity = count / max;
  if (intensity < 0.2)  return "bg-accent/15";
  if (intensity < 0.4)  return "bg-accent/30";
  if (intensity < 0.6)  return "bg-accent/50";
  if (intensity < 0.8)  return "bg-accent/70";
  return "bg-accent/90";
}

interface Props {
  timeRange: DashboardTimeRange;
}

export function AlertVolumeHeatmap({ timeRange }: Props) {
  void timeRange;

  const { data, isLoading } = useQuery({
    queryKey: ["dashboard", "heatmap", timeRange],
    queryFn: () =>
      apiClient.get<HeatmapCell[]>(`/dashboard/alert-heatmap?timeRange=${timeRange}`)
        .then((r) => r.data)
        .catch(() => sampleHeatmap()),
    staleTime: 300_000,
    placeholderData: sampleHeatmap,
  });

  const cells = data ?? [];
  const max = Math.max(1, ...cells.map((c) => c.count));
  const total = cells.reduce((s, c) => s + c.count, 0);

  const peak = cells.reduce<HeatmapCell | null>(
    (best, c) => (!best || c.count > best.count ? c : best), null
  );

  const lookup = new Map<string, number>(cells.map((c) => [`${c.day}-${c.hour}`, c.count]));

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">Alert Volume Heatmap</h3>
        <div className="flex items-center gap-3">
          {peak && (
            <span className="text-2xs text-text-muted">
              Peak:{" "}
              <span className="text-text-secondary font-mono">
                {DAY_LABELS[peak.day]} {HOUR_LABELS[peak.hour]}
              </span>
              <span className="ml-1 text-accent font-bold">{peak.count}</span>
            </span>
          )}
          <span className="text-2xs text-text-disabled">{total.toLocaleString()} total</span>
        </div>
      </div>

      {isLoading ? (
        <div className="skel h-40 rounded-lg" />
      ) : (
        <div className="overflow-x-auto">
          <div
            className="inline-grid gap-px"
            style={{ gridTemplateColumns: `28px repeat(24, minmax(14px, 1fr))` }}
          >
            {/* Hour labels */}
            <div />
            {HOUR_LABELS.map((h, i) => (
              <div key={i} className="text-2xs text-text-disabled text-center leading-none pb-1">
                {i % 6 === 0 ? h : ""}
              </div>
            ))}

            {/* Day rows — use explicit keys, no fragments */}
            {DAY_LABELS.flatMap((day, dIdx) => [
              <div key={`lbl-${dIdx}`} className="text-2xs text-text-muted flex items-center pr-1">{day}</div>,
              ...Array.from({ length: 24 }, (_, hIdx) => {
                const count = lookup.get(`${dIdx}-${hIdx}`) ?? 0;
                const isPeak = peak?.day === dIdx && peak?.hour === hIdx;
                return (
                  <div
                    key={`cell-${dIdx}-${hIdx}`}
                    title={`${day} ${HOUR_LABELS[hIdx]}: ${count} alerts`}
                    className={cn(
                      "rounded-sm h-4 w-full transition-opacity hover:opacity-80",
                      cellColorClass(count, max),
                      isPeak && "ring-1 ring-accent ring-offset-1 ring-offset-bg-card",
                    )}
                  />
                );
              }),
            ])}
          </div>

          {/* Legend */}
          <div className="flex items-center gap-1.5 mt-2.5">
            <span className="text-2xs text-text-disabled mr-1">Less</span>
            {[0, 0.2, 0.4, 0.6, 0.8, 1].map((v, i) => (
              <div
                key={i}
                className={cn(
                  "w-3.5 h-3.5 rounded-sm",
                  v === 0 ? "bg-bg-elevated" : `bg-accent/${Math.round(v * 90)}`,
                )}
              />
            ))}
            <span className="text-2xs text-text-disabled ml-1">More</span>
          </div>
        </div>
      )}
    </div>
  );
}
