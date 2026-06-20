import { useState, useEffect } from "react";
import { NavLink, useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  Bell,
  FolderSearch,
  Activity,
  Crosshair,
  Shield,
  Sparkles,
  Monitor,
  Settings,
  LogOut,
  BookOpen,
  FileBarChart,
  Download,
} from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
import { useTenantStore } from "@/stores/tenantStore";
import { LogoCompact } from "@/components/ui/Logo";
import { getAlerts } from "@/services/alertsApi";
import { agentsApi } from "@/api/agents";
import { useQuery } from "@tanstack/react-query";

// ─── Live badge counts ────────────────────────────────────────────────────────

function useOpenAlertCount() {
  const { data } = useQuery({
    queryKey: ["sidebar", "alerts-open"],
    queryFn: () => getAlerts({ status: ["open"], pageSize: 1, page: 1 }),
    staleTime: 60_000,
    refetchInterval: 60_000,
    retry: false,
  });
  return data?.total ?? 0;
}

function useOnlineAgentCount() {
  const { data } = useQuery({
    queryKey: ["sidebar", "agents-online"],
    queryFn: async () => {
      const resp = await agentsApi.list({ status: "online", limit: 1 });
      return resp.data.pagination.total;
    },
    staleTime: 30_000,
    refetchInterval: 30_000,
    retry: false,
  });
  return data ?? 0;
}

// ─── NavItem ─────────────────────────────────────────────────────────────────

interface NavItemProps {
  to: string;
  icon: React.ElementType;
  label: string;
  badge?: string | number;
  badgeColor?: "red" | "green" | "blue";
}

function NavItem({ to, icon: Icon, label, badge, badgeColor = "blue" }: NavItemProps) {
  const badgeBg =
    badgeColor === "red"   ? "rgba(239,68,68,0.15)"  :
    badgeColor === "green" ? "rgba(16,185,129,0.15)" :
                             "rgba(59,130,246,0.15)";
  const badgeFg =
    badgeColor === "red"   ? "#FCA5A5" :
    badgeColor === "green" ? "#6EE7B7" :
                             "#93C5FD";

  const displayBadge = typeof badge === "number" ? (badge > 999 ? "999+" : badge > 0 ? badge : null) : badge;

  return (
    <NavLink
      to={to}
      style={({ isActive }) => ({
        display: "flex",
        alignItems: "center",
        gap: 9,
        padding: "7px 14px",
        fontSize: 13,
        fontWeight: isActive ? 500 : 400,
        color: isActive ? "#93C5FD" : "#8B95A7",
        background: isActive ? "rgba(59,130,246,0.08)" : "transparent",
        borderLeft: `2px solid ${isActive ? "#3B82F6" : "transparent"}`,
        transition: "all 120ms",
        textDecoration: "none",
      })}
    >
      {({ isActive }) => (
        <>
          <Icon
            size={14}
            style={{
              opacity: isActive ? 0.9 : 0.45,
              color: isActive ? "#60A5FA" : "inherit",
              flexShrink: 0,
            }}
          />
          <span style={{ flex: 1 }}>{label}</span>
          {displayBadge != null && (
            <span style={{
              padding: "1px 6px",
              borderRadius: 9999,
              fontSize: 9,
              fontWeight: 700,
              fontFamily: "'JetBrains Mono', monospace",
              background: badgeBg,
              color: badgeFg,
            }}>
              {displayBadge}
            </span>
          )}
        </>
      )}
    </NavLink>
  );
}

// ─── Sidebar ─────────────────────────────────────────────────────────────────

export function Sidebar() {
  const user       = useAuthStore((s) => s.user);
  const clearAuth  = useAuthStore((s) => s.clearAuth);
  const tenant     = useTenantStore((s) => s.activeTenant);
  const memberRole = useTenantStore((s) => s.memberRole);
  const hasRole    = useTenantStore((s) => s.hasRole);
  const navigate   = useNavigate();
  const alertCount = useOpenAlertCount();
  const onlineAgentCount = useOnlineAgentCount();

  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 30_000);
    return () => clearInterval(t);
  }, []);
  void now;

  const tenantName = tenant?.name ?? "NEURASHIELD";
  const userRole   = memberRole ?? user?.roles?.[0] ?? "analyst";

  const handleLogout = () => {
    clearAuth();
    navigate("/login");
  };

  return (
    <aside style={{
      width: "220px",
      minWidth: "220px",
      background: "#050505",
      borderRight: "1px solid rgba(255,255,255,0.06)",
      display: "flex",
      flexDirection: "column",
      height: "100vh",
      position: "fixed",
      top: 0,
      left: 0,
      zIndex: 40,
    }}>

      {/* Logo */}
      <NavLink to="/dashboard" style={{ display: "block", textDecoration: "none", padding: "12px 14px", borderBottom: "1px solid rgba(255,255,255,0.04)", cursor: "pointer" }}>
        <LogoCompact />
      </NavLink>

      {/* Nav */}
      <nav style={{ flex: 1, overflowY: "auto", padding: "8px 0" }}>
        <div className="sec-label">Operations</div>
        <NavItem to="/dashboard" icon={LayoutDashboard} label="Overview" />
        <NavItem to="/alerts"    icon={Bell}            label="Alerts" badge={alertCount} badgeColor="red" />
        {hasRole('analyst') && (
          <NavItem to="/investigations" icon={FolderSearch} label="Investigations" />
        )}

        <div className="sec-label">Investigate</div>
        <NavItem to="/events" icon={Activity} label="Events" />
        {hasRole('analyst') && (
          <NavItem to="/hunt"  icon={Crosshair} label="Threat Hunt" />
        )}
        <NavItem to="/rules" icon={Shield} label="Detection Rules" />

        <div className="sec-label">AI &amp; Response</div>
        {hasRole('analyst') && (
          <NavItem to="/copilot"   icon={Sparkles}     label="AI Copilot" badge="BETA" badgeColor="blue" />
        )}
        {hasRole('analyst') && (
          <NavItem to="/playbooks" icon={BookOpen}      label="Playbooks" />
        )}

        <div className="sec-label">Reporting</div>
        {hasRole('analyst') && (
          <NavItem to="/reports"   icon={FileBarChart}  label="Reports" />
        )}

        <div className="sec-label">Platform</div>
        <NavItem to="/agents"    icon={Monitor}   label="Agents" badge={onlineAgentCount || undefined} badgeColor="green" />
        <NavItem to="/installer" icon={Download}  label="Device Enrollment" />
        <NavItem to="/settings"  icon={Settings}  label="Settings" />
      </nav>

      {/* Footer */}
      <div style={{ borderTop: "1px solid rgba(255,255,255,0.05)", padding: "12px 14px" }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: "#F5F7FA", marginBottom: 2 }}>
          {tenantName}
        </div>
        <div style={{
          fontSize: 9,
          textTransform: "uppercase",
          letterSpacing: "1px",
          color: "#5C6373",
          marginBottom: 8,
          fontFamily: "'JetBrains Mono', monospace",
        }}>
          {String(userRole).toUpperCase()}
        </div>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 10 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span className="dot-live" />
            <span style={{
              fontSize: 9,
              fontWeight: 700,
              textTransform: "uppercase",
              letterSpacing: "1px",
              color: "#10B981",
            }}>LIVE</span>
          </div>
          <div style={{
            display: "flex",
            alignItems: "center",
            gap: 4,
            fontSize: 11,
            color: "#5C6373",
            fontFamily: "'JetBrains Mono', monospace",
          }}>
            <Monitor size={11} />
            <span>{alertCount > 0 ? alertCount : "—"}</span>
          </div>
        </div>
        <button
          onClick={handleLogout}
          style={{
            width: "100%",
            padding: "6px",
            borderRadius: 6,
            fontSize: 11,
            color: "#5C6373",
            background: "transparent",
            border: "1px solid rgba(255,255,255,0.05)",
            cursor: "pointer",
            transition: "all 120ms",
            textAlign: "left",
            display: "flex",
            alignItems: "center",
            gap: 6,
          }}
          onMouseOver={(e) => {
            (e.currentTarget as HTMLButtonElement).style.color = "#F5F7FA";
            (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(255,255,255,0.12)";
          }}
          onMouseOut={(e) => {
            (e.currentTarget as HTMLButtonElement).style.color = "#5C6373";
            (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(255,255,255,0.05)";
          }}
        >
          <LogOut size={11} />
          Sign out
        </button>
      </div>
    </aside>
  );
}
