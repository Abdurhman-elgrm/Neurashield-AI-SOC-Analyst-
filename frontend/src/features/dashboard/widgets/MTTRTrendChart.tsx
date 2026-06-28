import { useQuery } from "@tanstack/react-query";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend, ReferenceLine,
} from "recharts";
import { TrendingDown, TrendingUp, Minus } from "lucide-react";
import { apiClient } from "@/api/client";
import type { DashboardTimeRange } from "../types/dashboard";

interface MTTRTrendPoint {
  week: string;
  critical_minutes: number;
  high_minutes:     number;
  medium_minutes:   number;
}


// SLA targets in minutes
const TARGETS = { critical: 60, high: 240, medium: 480 };

function fmt(v: number) {
  return v >= 60 ? `${(v / 60).toFixed(1)}h` : `${Math.round(v)}m`;
}

function KpiPill({
  label, value, target, color,
}: { label: string; value: number; target: number; color: string }) {
  const good = value <= target;
  const Icon = good ? TrendingDown : value <= target * 1.2 ? Minus : TrendingUp;
  return (
    <div
      className="flex-1 rounded-lg px-3 py-2 border"
      style={{ background: `${color}08`, borderColor: `${color}20` }}
    >
      <div className="flex items-center justify-between gap-1 mb-0.5">
        <span className="text-2xs font-bold uppercase tracking-widest" style={{ color: "#5C6373" }}>{label}</span>
        <Icon size={9} style={{ color: good ? "#10B981" : "#EF4444" }} />
      </div>
      <div className="text-sm font-extrabold font-mono leading-tight" style={{ color }}>
        {fmt(value)}
      </div>
      <div className="text-2xs mt-0.5" style={{ color: good ? "#10B981" : "#EF4444" }}>
        {good
          ? `${Math.round(((target - value) / target) * 100)}% under SLA`
          : `${Math.round(((value - target) / target) * 100)}% over SLA`}
      </div>
    </div>
  );
}

interface Props {
  timeRange: DashboardTimeRange;
}

export function MTTRTrendChart({ timeRange }: Props) {
  void timeRange;

  const { data, isLoading } = useQuery({
    queryKey: ["dashboard", "mttr-trend"],
    queryFn: () =>
      apiClient.get<{ data: MTTRTrendPoint[] }>("/dashboard/mttr-trend")
        .then((r) => r.data.data ?? [])
        .catch(() => [] as MTTRTrendPoint[]),
    staleTime: 300_000,
    placeholderData: [] as MTTRTrendPoint[],
  });

  const points = data ?? [];
  const last = points[points.length - 1];

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4 flex flex-col gap-3">
      <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">MTTR Trend</h3>

      {/* Current-week KPI strip */}
      {isLoading ? (
        <div className="flex gap-2">
          {[1,2,3].map(i => <div key={i} className="flex-1 skel h-14 rounded-lg" />)}
        </div>
      ) : last ? (
        <div className="flex gap-2">
          <KpiPill label="Critical" value={last.critical_minutes} target={TARGETS.critical} color="#EF4444" />
          <KpiPill label="High"     value={last.high_minutes}     target={TARGETS.high}     color="#F97316" />
          <KpiPill label="Medium"   value={last.medium_minutes}   target={TARGETS.medium}   color="#F59E0B" />
        </div>
      ) : null}

      {/* Trend chart */}
      {isLoading ? (
        <div className="skel h-40 rounded-lg" />
      ) : (
        <ResponsiveContainer width="100%" height={155}>
          <LineChart data={points} margin={{ top: 4, right: 8, bottom: 0, left: -10 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
            <XAxis dataKey="week" tick={{ fill: "#5C6373", fontSize: 9 }} tickFormatter={(v: string) => v.slice(5)} />
            <YAxis tick={{ fill: "#5C6373", fontSize: 9 }} tickFormatter={fmt} />
            <Tooltip
              contentStyle={{ background: "#111", border: "1px solid #1F2937", fontSize: 11 }}
              formatter={(v: number) => [fmt(v)]}
            />
            <Legend wrapperStyle={{ fontSize: 10 }} />
            <ReferenceLine y={TARGETS.critical} stroke="#EF4444" strokeDasharray="4 2" strokeOpacity={0.3}
              label={{ value: "SLA", fill: "#EF4444", fontSize: 8, opacity: 0.5 }} />
            <ReferenceLine y={TARGETS.high} stroke="#F97316" strokeDasharray="4 2" strokeOpacity={0.25} />
            <Line type="monotone" dataKey="critical_minutes" name="Critical" stroke="#EF4444" strokeWidth={1.5} dot={false} />
            <Line type="monotone" dataKey="high_minutes"     name="High"     stroke="#F97316" strokeWidth={1.5} dot={false} />
            <Line type="monotone" dataKey="medium_minutes"   name="Medium"   stroke="#F59E0B" strokeWidth={1.5} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      )}

      <p className="text-2xs text-text-disabled -mt-1">Dashed lines = SLA targets · 8-week rolling window</p>
    </div>
  );
}
