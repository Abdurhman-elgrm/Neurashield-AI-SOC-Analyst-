import { useEffect, useState, useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import {
  LineChart, Line, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer,
} from "recharts";
import { User, AlertTriangle, MapPin, TrendingUp, Shield, Activity } from "lucide-react";
import { uebaApi } from "@/api/ueba";
import type { RiskyUser } from "@/api/ueba";
import { WidgetErrorBoundary } from "@/components/ui/WidgetErrorBoundary";

// ─── Risk tier helpers ────────────────────────────────────────────────────────

function riskTier(score: number): { label: string; color: string; bg: string } {
  if (score >= 80) return { label: "Critical", color: "#EF4444", bg: "rgba(239,68,68,0.12)"  };
  if (score >= 60) return { label: "High",     color: "#F97316", bg: "rgba(249,115,22,0.12)" };
  if (score >= 40) return { label: "Medium",   color: "#F59E0B", bg: "rgba(245,158,11,0.12)" };
  return                  { label: "Low",      color: "#10B981", bg: "rgba(16,185,129,0.1)"  };
}

// ─── KPI strip ────────────────────────────────────────────────────────────────

function UEBAKPIStrip({ users }: { users: RiskyUser[] }) {
  const critical  = users.filter(u => u.ueba_score >= 80).length;
  const high      = users.filter(u => u.ueba_score >= 60 && u.ueba_score < 80).length;
  const flagged   = users.filter(u => u.last_anomaly_at).length;
  const avgScore  = users.length > 0
    ? Math.round(users.reduce((s, u) => s + u.ueba_score, 0) / users.length)
    : 0;

  const kpis = [
    { label: "Monitored Users",   value: users.length, color: "#8B95A7", icon: User,         sublabel: "active profiles" },
    { label: "Critical Risk",     value: critical,     color: "#EF4444", icon: AlertTriangle, sublabel: "score ≥ 80"     },
    { label: "High Risk",         value: high,         color: "#F97316", icon: TrendingUp,    sublabel: "score 60–79"    },
    { label: "Flagged Today",     value: flagged,      color: "#F59E0B", icon: Activity,      sublabel: "recent anomaly" },
    { label: "Avg Risk Score",    value: avgScore,     color: avgScore >= 60 ? "#EF4444" : avgScore >= 40 ? "#F59E0B" : "#10B981",
      icon: Shield, sublabel: "across all users" },
  ];

  return (
    <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 8, marginBottom: 16 }}>
      {kpis.map(({ label, value, color, icon: Icon, sublabel }) => (
        <div key={label} style={{
          background: "#0D0D0D",
          border: `1px solid ${value > 0 && color !== "#8B95A7" && color !== "#10B981" ? `${color}20` : "rgba(255,255,255,0.06)"}`,
          borderLeft: `3px solid ${color}`,
          borderRadius: 8, padding: "12px 14px",
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, marginBottom: 6 }}>
            <Icon size={11} style={{ color, flexShrink: 0 }} />
            <span style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1.2px", color: "#5C6373" }}>
              {label}
            </span>
          </div>
          <div style={{ fontSize: 24, fontWeight: 800, color, fontFamily: "'JetBrains Mono', monospace", lineHeight: 1 }}>
            {value}
          </div>
          <div style={{ fontSize: 10, color: "#3A4150", marginTop: 4 }}>{sublabel}</div>
        </div>
      ))}
    </div>
  );
}

// ─── Risk score bar ───────────────────────────────────────────────────────────

function RiskBar({ score }: { score: number }) {
  const { color } = riskTier(score);
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 6, width: 80, flexShrink: 0 }}>
      <div style={{ flex: 1, height: 4, background: "rgba(255,255,255,0.06)", borderRadius: 2 }}>
        <div style={{
          height: "100%", width: `${score}%`, background: color,
          borderRadius: 2, transition: "width 400ms ease",
        }} />
      </div>
      <span style={{ fontSize: 11, fontWeight: 700, color, fontFamily: "'JetBrains Mono', monospace", width: 24, textAlign: "right" }}>
        {score}
      </span>
    </div>
  );
}

// ─── User Timeline ────────────────────────────────────────────────────────────

function UserTimeline({ userId }: { userId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ["ueba", "timeline", userId],
    queryFn: () => uebaApi.getUserTimeline(userId, "30d"),
    staleTime: 60_000,
    enabled: !!userId,
  });

  if (isLoading) return <div className="skel h-32 rounded-lg" />;

  return (
    <ResponsiveContainer width="100%" height={130}>
      <LineChart data={data ?? []} margin={{ top: 4, right: 8, bottom: 0, left: -20 }}>
        <defs>
          <linearGradient id="riskGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="5%" stopColor="#3B82F6" stopOpacity={0.15} />
            <stop offset="95%" stopColor="#3B82F6" stopOpacity={0} />
          </linearGradient>
        </defs>
        <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" />
        <XAxis dataKey="date" tick={{ fill: "#5C6373", fontSize: 9 }} tickFormatter={(v: string) => v.slice(5)} />
        <YAxis tick={{ fill: "#5C6373", fontSize: 9 }} domain={[0, 100]} />
        <Tooltip
          contentStyle={{ background: "#111", border: "1px solid #1F2937", fontSize: 11 }}
          formatter={(v: number) => [`${v}`, "Risk Score"]}
        />
        <Line type="monotone" dataKey="score" stroke="#3B82F6" strokeWidth={2} dot={false} name="UEBA Score" />
      </LineChart>
    </ResponsiveContainer>
  );
}

// ─── Flag Distribution ────────────────────────────────────────────────────────

function FlagDistribution() {
  const { data, isLoading } = useQuery({
    queryKey: ["ueba", "flag-distribution"],
    queryFn: uebaApi.getFlagDistribution,
    staleTime: 300_000,
  });

  return (
    <div style={{ background: "#0D0D0D", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 12, padding: 16 }}>
      <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1.5px", color: "#5C6373", marginBottom: 12 }}>
        UEBA Flag Distribution
      </div>
      {isLoading ? <div className="skel h-40 rounded-lg" /> : (
        <ResponsiveContainer width="100%" height={160}>
          <BarChart data={data ?? []} layout="vertical" margin={{ top: 0, right: 8, bottom: 0, left: 90 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.04)" horizontal={false} />
            <XAxis type="number" tick={{ fill: "#5C6373", fontSize: 9 }} />
            <YAxis type="category" dataKey="flag" tick={{ fill: "#8B95A7", fontSize: 9 }} width={90} />
            <Tooltip contentStyle={{ background: "#111", border: "1px solid #1F2937", fontSize: 11 }} />
            <Bar dataKey="count" fill="#3B82F6" opacity={0.8} radius={[0, 4, 4, 0]} />
          </BarChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}

// ─── Impossible Travel ────────────────────────────────────────────────────────

function ImpossibleTravel() {
  const { data, isLoading } = useQuery({
    queryKey: ["ueba", "impossible-travel"],
    queryFn: uebaApi.getImpossibleTravel,
    staleTime: 120_000,
  });

  return (
    <div style={{ background: "#0D0D0D", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 12, padding: 16 }}>
      <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: 12 }}>
        <MapPin size={12} style={{ color: "#EF4444" }} />
        <span style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1.5px", color: "#5C6373" }}>
          Impossible Travel Alerts
        </span>
        {(data ?? []).length > 0 && (
          <span style={{
            marginLeft: "auto", fontSize: 9, fontWeight: 700, padding: "1px 6px", borderRadius: 10,
            background: "rgba(239,68,68,0.1)", color: "#EF4444", border: "1px solid rgba(239,68,68,0.2)",
          }}>
            {data?.length}
          </span>
        )}
      </div>
      {isLoading ? <div className="skel h-32 rounded-lg" /> : (
        (data ?? []).length === 0 ? (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "24px 0", gap: 6 }}>
            <MapPin size={20} style={{ color: "#3A4150" }} />
            <span style={{ fontSize: 12, color: "#3A4150" }}>No impossible travel detected.</span>
          </div>
        ) : (
          <table style={{ width: "100%", borderCollapse: "collapse" }}>
            <thead>
              <tr>
                {["User", "Location 1", "Location 2", "Δ Time"].map(h => (
                  <th key={h} style={{
                    textAlign: h === "Δ Time" ? "right" : "left", paddingBottom: 8,
                    fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px",
                    color: "#3A4150", borderBottom: "1px solid rgba(255,255,255,0.06)",
                  }}>{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((e, i) => (
                <tr key={i} style={{ borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                  <td style={{ padding: "8px 0", fontSize: 11, fontWeight: 600, color: "#F5F7FA" }}>{e.username}</td>
                  <td style={{ padding: "8px 0", fontSize: 11, color: "#8B95A7" }}>{e.location_1}</td>
                  <td style={{ padding: "8px 0", fontSize: 11, color: "#8B95A7" }}>{e.location_2}</td>
                  <td style={{ padding: "8px 0", textAlign: "right", fontSize: 11, fontWeight: 700, color: "#F97316", fontFamily: "'JetBrains Mono', monospace" }}>
                    {e.time_delta_minutes < 60 ? `${e.time_delta_minutes}m` : `${(e.time_delta_minutes / 60).toFixed(1)}h`}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )
      )}
    </div>
  );
}

// ─── UEBADashboard ────────────────────────────────────────────────────────────

type RiskFilter = "all" | "critical" | "high" | "medium";

export function UEBADashboard() {
  useEffect(() => { document.title = "UEBA Dashboard — NEURASHIELD"; }, []);

  const [selectedUser, setSelectedUser] = useState<RiskyUser | null>(null);
  const [riskFilter,   setRiskFilter]   = useState<RiskFilter>("all");

  const { data: users = [], isLoading } = useQuery({
    queryKey: ["ueba", "top-users"],
    queryFn: () => uebaApi.getTopUsers(50),
    staleTime: 120_000,
  });

  const filteredUsers = useMemo(() => {
    if (riskFilter === "critical") return users.filter(u => u.ueba_score >= 80);
    if (riskFilter === "high")     return users.filter(u => u.ueba_score >= 60 && u.ueba_score < 80);
    if (riskFilter === "medium")   return users.filter(u => u.ueba_score >= 40 && u.ueba_score < 60);
    return users;
  }, [users, riskFilter]);

  const RISK_CHIPS: Array<{ value: RiskFilter; label: string; color: string; count: number }> = [
    { value: "all",      label: "All",      color: "#8B95A7", count: users.length                              },
    { value: "critical", label: "Critical", color: "#EF4444", count: users.filter(u => u.ueba_score >= 80).length },
    { value: "high",     label: "High",     color: "#F97316", count: users.filter(u => u.ueba_score >= 60 && u.ueba_score < 80).length },
    { value: "medium",   label: "Medium",   color: "#F59E0B", count: users.filter(u => u.ueba_score >= 40 && u.ueba_score < 60).length },
  ];

  return (
    <div className="pb-6">
      {/* Page header */}
      <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between", marginBottom: 16 }}>
        <div>
          <h1 style={{ fontSize: 20, fontWeight: 800, fontFamily: "'Space Grotesk', sans-serif", color: "#F5F7FA", margin: 0 }}>
            User Behavior Analytics
          </h1>
          <p style={{ fontSize: 12, color: "#5C6373", margin: "3px 0 0" }}>
            UEBA scoring, anomaly detection, and insider threat monitoring
          </p>
        </div>
      </div>

      {/* KPI strip */}
      {!isLoading && <UEBAKPIStrip users={users} />}
      {isLoading && (
        <div style={{ display: "grid", gridTemplateColumns: "repeat(5, 1fr)", gap: 8, marginBottom: 16 }}>
          {Array.from({ length: 5 }, (_, i) => <div key={i} className="skel h-20 rounded-lg" />)}
        </div>
      )}

      <div style={{ display: "grid", gridTemplateColumns: "2fr 1fr", gap: 12, marginBottom: 12 }}>
        {/* Risky users list */}
        <div style={{ background: "#0D0D0D", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 12, overflow: "hidden" }}>
          {/* List header + filter */}
          <div style={{
            display: "flex", alignItems: "center", justifyContent: "space-between",
            padding: "12px 14px", borderBottom: "1px solid rgba(255,255,255,0.06)",
          }}>
            <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <User size={13} style={{ color: "#3B82F6" }} />
              <span style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1.5px", color: "#5C6373" }}>
                Risky Users
              </span>
            </div>
            {/* Risk filter chips */}
            <div style={{
              display: "flex", gap: 2,
              background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)",
              borderRadius: 6, padding: 2,
            }}>
              {RISK_CHIPS.map(chip => (
                <button key={chip.value} onClick={() => setRiskFilter(chip.value)} style={{
                  display: "flex", alignItems: "center", gap: 4,
                  padding: "3px 8px", borderRadius: 4, border: "none", cursor: "pointer",
                  fontSize: 10, fontWeight: 600, transition: "all 100ms",
                  background: riskFilter === chip.value ? `${chip.color}18` : "transparent",
                  color: riskFilter === chip.value ? chip.color : "#5C6373",
                }}>
                  {chip.label}
                  <span style={{
                    fontSize: 9, fontWeight: 800, padding: "0 4px", borderRadius: 8,
                    background: riskFilter === chip.value ? `${chip.color}25` : "rgba(255,255,255,0.06)",
                    color: riskFilter === chip.value ? chip.color : "#3A4150",
                  }}>
                    {chip.count}
                  </span>
                </button>
              ))}
            </div>
          </div>

          {/* User rows */}
          <div style={{ overflowY: "auto", maxHeight: 380 }}>
            {isLoading ? (
              Array.from({ length: 6 }, (_, i) => (
                <div key={i} style={{ display: "flex", alignItems: "center", gap: 10, padding: "10px 14px", borderBottom: "1px solid rgba(255,255,255,0.04)" }}>
                  <div className="skel" style={{ width: 28, height: 28, borderRadius: "50%" }} />
                  <div className="skel" style={{ flex: 1, height: 14, borderRadius: 4 }} />
                  <div className="skel" style={{ width: 80, height: 8, borderRadius: 4 }} />
                </div>
              ))
            ) : filteredUsers.length === 0 ? (
              <div style={{ display: "flex", flexDirection: "column", alignItems: "center", padding: "40px 0", gap: 8 }}>
                <Shield size={24} style={{ color: "#3A4150" }} />
                <span style={{ fontSize: 12, color: "#3A4150" }}>No users in this risk tier.</span>
              </div>
            ) : filteredUsers.map((u) => {
              const tier = riskTier(u.ueba_score);
              const isSelected = selectedUser?.user_id === u.user_id;
              return (
                <button
                  key={u.user_id}
                  onClick={() => setSelectedUser(isSelected ? null : u)}
                  style={{
                    display: "flex", alignItems: "center", gap: 10, width: "100%",
                    padding: "10px 14px", borderBottom: "1px solid rgba(255,255,255,0.04)",
                    textAlign: "left", border: "none", cursor: "pointer",
                    background: isSelected ? `${tier.color}08` : "transparent",
                    borderLeft: `2px solid ${isSelected ? tier.color : "transparent"}`,
                    transition: "all 100ms",
                  }}
                >
                  {/* Avatar */}
                  <div style={{
                    width: 28, height: 28, borderRadius: "50%", flexShrink: 0,
                    background: `${tier.color}20`,
                    display: "flex", alignItems: "center", justifyContent: "center",
                    fontSize: 11, fontWeight: 700, color: tier.color,
                  }}>
                    {(u.username[0] ?? "?").toUpperCase()}
                  </div>

                  {/* Name + flags */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 12, fontWeight: 600, color: "#F5F7FA", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                      {u.username}
                    </div>
                    {u.top_flags.length > 0 && (
                      <div style={{ fontSize: 9, color: "#5C6373", marginTop: 2, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                        {u.top_flags.slice(0, 2).join(" · ")}
                      </div>
                    )}
                  </div>

                  {/* Score bar */}
                  <RiskBar score={u.ueba_score} />

                  {/* Anomaly indicator */}
                  {u.last_anomaly_at && (
                    <AlertTriangle size={10} style={{ color: "#F97316", flexShrink: 0 }} />
                  )}
                </button>
              );
            })}
          </div>
        </div>

        {/* Selected user detail */}
        <div style={{ background: "#0D0D0D", border: "1px solid rgba(255,255,255,0.06)", borderRadius: 12, padding: 16 }}>
          {selectedUser ? (
            <>
              <div style={{ display: "flex", alignItems: "flex-start", gap: 10, marginBottom: 14 }}>
                {/* Avatar */}
                <div style={{
                  width: 36, height: 36, borderRadius: "50%", flexShrink: 0,
                  background: `${riskTier(selectedUser.ueba_score).color}20`,
                  display: "flex", alignItems: "center", justifyContent: "center",
                  fontSize: 14, fontWeight: 800, color: riskTier(selectedUser.ueba_score).color,
                }}>
                  {(selectedUser.username[0] ?? "?").toUpperCase()}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 14, fontWeight: 700, color: "#F5F7FA" }}>{selectedUser.username}</div>
                  <div style={{ display: "flex", alignItems: "center", gap: 6, marginTop: 3 }}>
                    <span style={{
                      fontSize: 9, fontWeight: 700, padding: "2px 6px", borderRadius: 4,
                      background: riskTier(selectedUser.ueba_score).bg,
                      color: riskTier(selectedUser.ueba_score).color,
                      textTransform: "uppercase", letterSpacing: "0.5px",
                    }}>
                      {riskTier(selectedUser.ueba_score).label} Risk
                    </span>
                    <span style={{ fontSize: 18, fontWeight: 800, color: riskTier(selectedUser.ueba_score).color, fontFamily: "'JetBrains Mono', monospace" }}>
                      {selectedUser.ueba_score}
                    </span>
                  </div>
                </div>
              </div>

              <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1.2px", color: "#5C6373", marginBottom: 6 }}>
                30-day Risk Trend
              </div>
              <UserTimeline userId={selectedUser.user_id} />

              {selectedUser.top_flags.length > 0 && (
                <div style={{ marginTop: 12 }}>
                  <div style={{ fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1.2px", color: "#5C6373", marginBottom: 6 }}>
                    Active Flags
                  </div>
                  <div style={{ display: "flex", flexWrap: "wrap", gap: 4 }}>
                    {selectedUser.top_flags.map((f) => (
                      <span key={f} style={{
                        padding: "2px 8px", borderRadius: 4, fontSize: 10, fontWeight: 600,
                        background: "rgba(249,115,22,0.1)", color: "#F97316",
                        border: "1px solid rgba(249,115,22,0.2)",
                      }}>
                        {f}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {selectedUser.last_anomaly_at && (
                <div style={{
                  marginTop: 12, padding: "8px 10px", borderRadius: 6,
                  background: "rgba(249,115,22,0.06)", border: "1px solid rgba(249,115,22,0.15)",
                  display: "flex", alignItems: "center", gap: 6,
                }}>
                  <AlertTriangle size={11} style={{ color: "#F97316", flexShrink: 0 }} />
                  <span style={{ fontSize: 10, color: "#F97316" }}>
                    Last anomaly: {new Date(selectedUser.last_anomaly_at).toLocaleString([], { dateStyle: "short", timeStyle: "short" })}
                  </span>
                </div>
              )}
            </>
          ) : (
            <div style={{
              height: "100%", minHeight: 200,
              display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: 8,
            }}>
              <User size={28} style={{ color: "#3A4150" }} />
              <span style={{ fontSize: 12, color: "#3A4150", textAlign: "center" }}>
                Select a user to view<br />their risk timeline
              </span>
            </div>
          )}
        </div>
      </div>

      <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
        <WidgetErrorBoundary title="Flag Distribution"><FlagDistribution /></WidgetErrorBoundary>
        <WidgetErrorBoundary title="Impossible Travel"><ImpossibleTravel /></WidgetErrorBoundary>
      </div>
    </div>
  );
}
