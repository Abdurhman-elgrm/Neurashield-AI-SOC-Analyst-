import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { Globe, Maximize2, TrendingUp } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { socMetricsApi } from "@/api/soc-metrics";
import type { GeoThreat } from "@/api/soc-metrics";
import type { DashboardTimeRange } from "../types/dashboard";


const SEV_COLORS: Record<string, string> = {
  critical: "#EF4444",
  high:     "#F97316",
  medium:   "#F59E0B",
  low:      "#6B7280",
};

const SEV_ORDER = ["critical", "high", "medium", "low"];

// Simplified continent polygon data — [lng, lat] pairs
const CONTINENT_POLYS: [number, number][][] = [
  // North America
  [[-140,70],[-100,77],[-55,68],[-52,47],[-65,42],[-80,25],[-90,15],[-85,8],
   [-100,18],[-118,22],[-120,35],[-135,60],[-155,58]],
  // South America
  [[-78,12],[-62,12],[-34,-5],[-38,-54],[-68,-55],[-76,-40],[-80,-5]],
  // Europe
  [[-10,36],[35,36],[42,47],[60,65],[28,72],[5,62],[-10,55]],
  // Africa
  [[-18,37],[37,37],[52,12],[44,-11],[34,-34],[18,-34],[-18,17]],
  // Asia
  [[30,70],[148,70],[148,25],[100,2],[80,8],[55,22],[38,36],[30,36]],
  // Australia
  [[114,-22],[154,-22],[154,-38],[136,-44],[114,-34]],
  // Greenland
  [[-45,83],[-12,78],[-18,72],[-50,60],[-58,76]],
];

const W = 560;
const H = 260;

function geoToSvg(lat: number, lng: number): [number, number] {
  return [
    ((lng + 180) / 360) * W,
    ((90 - lat) / 180) * H,
  ];
}

function continentPoints(coords: [number, number][]): string {
  return coords.map(([lng, lat]) => geoToSvg(lat, lng).join(",")).join(" ");
}

interface TopCountry {
  country: string;
  count: number;
  severity: string;
}

interface Props {
  timeRange: DashboardTimeRange;
}

export function GeoThreatMap({ timeRange }: Props) {
  const navigate = useNavigate();
  void timeRange;
  const [hovered, setHovered] = useState<number | null>(null);

  const { data } = useQuery({
    queryKey: ["geo-threats", timeRange],
    queryFn: () => socMetricsApi.getGeoThreats(timeRange).catch(() => [] as GeoThreat[]),
    staleTime: 120_000,
    placeholderData: [] as GeoThreat[],
  });

  const threats = data ?? [];
  const totalCount = threats.reduce((s, t) => s + t.count, 0);

  // Top 5 countries by count
  const byCountry = threats.reduce<Record<string, TopCountry>>((acc, t) => {
    if (!acc[t.country]) acc[t.country] = { country: t.country, count: 0, severity: t.severity };
    acc[t.country].count += t.count;
    if (SEV_ORDER.indexOf(t.severity) < SEV_ORDER.indexOf(acc[t.country].severity)) {
      acc[t.country].severity = t.severity;
    }
    return acc;
  }, {});
  const topCountries = Object.values(byCountry).sort((a, b) => b.count - a.count).slice(0, 5);
  const maxCount = Math.max(1, topCountries[0]?.count ?? 1);

  return (
    <div className="bg-bg-card border border-border rounded-xl p-4">
      {/* Header */}
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <Globe size={13} className="text-emerald-400" />
          <h3 className="text-xs font-bold uppercase tracking-widest text-text-muted">Geo Threat Intelligence</h3>
          <span className="ml-1 px-1.5 py-0.5 rounded text-2xs font-bold bg-red-500/10 text-red-400 border border-red-500/20">
            {totalCount} events
          </span>
        </div>
        <button
          onClick={() => navigate("/geo-map")}
          aria-label="Full screen geo map"
          className="text-text-muted hover:text-text-primary transition-colors"
        >
          <Maximize2 size={13} />
        </button>
      </div>

      <div className="flex gap-3">
        {/* SVG Map */}
        <div className="flex-1 min-w-0 rounded-lg overflow-hidden bg-[#080c14]" style={{ height: H }}>
          <svg width="100%" height="100%" viewBox={`0 0 ${W} ${H}`} preserveAspectRatio="xMidYMid meet">
            {/* Ocean */}
            <rect width={W} height={H} fill="#080c14" />

            {/* Latitude / longitude grid */}
            {[-60, -30, 0, 30, 60].map((lat) => {
              const [, y] = geoToSvg(lat, 0);
              return (
                <line key={`lat${lat}`} x1={0} y1={y} x2={W} y2={y}
                  stroke="rgba(255,255,255,0.04)" strokeWidth={0.5} strokeDasharray={lat === 0 ? "3 3" : "0"} />
              );
            })}
            {[-120, -60, 0, 60, 120].map((lng) => {
              const [x] = geoToSvg(0, lng);
              return (
                <line key={`lng${lng}`} x1={x} y1={0} x2={x} y2={H}
                  stroke="rgba(255,255,255,0.04)" strokeWidth={0.5} />
              );
            })}

            {/* Continent landmasses */}
            {CONTINENT_POLYS.map((poly, i) => (
              <polygon
                key={i}
                points={continentPoints(poly)}
                fill="rgba(100,120,160,0.12)"
                stroke="rgba(100,150,200,0.18)"
                strokeWidth={0.8}
              />
            ))}

            {/* Threat markers with pulse animation */}
            {threats.map((t, i) => {
              const [x, y] = geoToSvg(t.lat, t.lng);
              const r = Math.max(4, Math.min(14, Math.sqrt(t.count) * 2));
              const color = SEV_COLORS[t.severity] ?? SEV_COLORS.low;
              const isHov = hovered === i;
              return (
                <g
                  key={i}
                  style={{ cursor: "pointer" }}
                  onMouseEnter={() => setHovered(i)}
                  onMouseLeave={() => setHovered(null)}
                >
                  {/* Outer pulse ring */}
                  <circle cx={x} cy={y} r={r * 2} fill={color} opacity={isHov ? 0.15 : 0.08}>
                    {!isHov && (
                      <>
                        <animate attributeName="r" values={`${r};${r * 2.5};${r}`} dur="2s" repeatCount="indefinite" />
                        <animate attributeName="opacity" values="0.12;0.02;0.12" dur="2s" repeatCount="indefinite" />
                      </>
                    )}
                  </circle>
                  {/* Mid ring */}
                  <circle cx={x} cy={y} r={r} fill={color} opacity={0.2} />
                  {/* Core dot */}
                  <circle cx={x} cy={y} r={r * 0.45} fill={color} opacity={isHov ? 1 : 0.85} />
                  {/* Hover tooltip */}
                  {isHov && (
                    <foreignObject x={x + 8} y={y - 22} width={130} height={44}>
                      <div
                        style={{
                          background: "#111827", border: `1px solid ${color}40`,
                          borderRadius: 5, padding: "4px 8px", fontSize: 10, color: "#E5E7EB",
                        }}
                      >
                        <div style={{ fontWeight: 700, color }}>{t.country}</div>
                        <div style={{ color: "#9CA3AF" }}>{t.count} events · {t.severity}</div>
                      </div>
                    </foreignObject>
                  )}
                </g>
              );
            })}
          </svg>
        </div>

        {/* Country breakdown sidebar */}
        <div className="w-36 flex-shrink-0 flex flex-col gap-1.5 justify-center">
          <div className="flex items-center gap-1 mb-0.5">
            <TrendingUp size={10} className="text-text-muted" />
            <span className="text-2xs font-bold uppercase tracking-widest text-text-disabled">Top Sources</span>
          </div>
          {topCountries.map((c) => {
            const color = SEV_COLORS[c.severity] ?? SEV_COLORS.low;
            const pct = (c.count / maxCount) * 100;
            return (
              <div key={c.country}>
                <div className="flex items-center justify-between mb-0.5">
                  <span className="text-2xs text-text-secondary truncate max-w-[84px]">{c.country}</span>
                  <span className="text-2xs font-mono font-bold" style={{ color }}>{c.count}</span>
                </div>
                <div className="h-1 rounded-full bg-bg-elevated overflow-hidden">
                  <div
                    className="h-full rounded-full"
                    style={{ width: `${pct}%`, background: color, opacity: 0.8 }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {/* Legend row */}
      <div className="flex items-center gap-4 mt-2.5">
        {SEV_ORDER.map((sev) => (
          <span key={sev} className="flex items-center gap-1 text-2xs text-text-muted">
            <span className="w-2 h-2 rounded-full" style={{ background: SEV_COLORS[sev] }} />
            {sev}
          </span>
        ))}
        <span className="ml-auto text-2xs text-text-disabled">{threats.length} source regions</span>
      </div>
    </div>
  );
}
