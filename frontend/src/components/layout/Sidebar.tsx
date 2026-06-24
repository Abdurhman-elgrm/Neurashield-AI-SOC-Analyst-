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
  Upload,
  Network,
  BarChart3,
  Server,
  UserSearch,
  ScrollText,
  EyeOff,
  Globe,
  Swords,
  Building2,
  Wifi,
  FileCheck,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
import { useTenantStore } from "@/stores/tenantStore";
import { useUIStore } from "@/stores/uiStore";
import { LogoCompact } from "@/components/ui/Logo";
import { getAlerts } from "@/services/alertsApi";
import { agentsApi } from "@/api/agents";
import { useQuery } from "@tanstack/react-query";
import { useMyAlertCount } from "@/hooks/useMyAlertCount";

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
      return resp.pagination.total;
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
  collapsed?: boolean;
}

function NavItem({ to, icon: Icon, label, badge, badgeColor = "blue", collapsed = false }: NavItemProps) {
  const badgeBg =
    badgeColor === "red"   ? "rgba(239,68,68,0.15)"  :
    badgeColor === "green" ? "rgba(16,185,129,0.15)" :
                             "rgba(59,130,246,0.15)";
  const badgeFg =
    badgeColor === "red"   ? "#FCA5A5" :
    badgeColor === "green" ? "#6EE7B7" :
                             "#93C5FD";

  const displayBadge = typeof badge === "number"
    ? (badge > 999 ? "999+" : badge > 0 ? badge : null)
    : badge;

  return (
    <NavLink
      to={to}
      title={collapsed ? label : undefined}
      style={({ isActive }) => ({
        display: "flex",
        alignItems: "center",
        gap: collapsed ? 0 : 9,
        padding: collapsed ? "8px 0" : "7px 14px",
        justifyContent: collapsed ? "center" : "flex-start",
        fontSize: 13,
        fontWeight: isActive ? 500 : 400,
        color: isActive ? "#93C5FD" : "#8B95A7",
        background: isActive ? "rgba(59,130,246,0.08)" : "transparent",
        borderLeft: collapsed ? "none" : `2px solid ${isActive ? "#3B82F6" : "transparent"}`,
        borderRight: collapsed ? `2px solid ${isActive ? "#3B82F6" : "transparent"}` : "none",
        transition: "all 120ms",
        textDecoration: "none",
        position: "relative",
      })}
    >
      {({ isActive }) => (
        <>
          <Icon
            size={collapsed ? 16 : 14}
            style={{
              opacity: isActive ? 0.9 : collapsed ? 0.6 : 0.45,
              color: isActive ? "#60A5FA" : "inherit",
              flexShrink: 0,
            }}
          />
          {!collapsed && (
            <span style={{ flex: 1 }}>{label}</span>
          )}
          {!collapsed && displayBadge != null && (
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
          {/* Collapsed badge dot */}
          {collapsed && displayBadge != null && (
            <span style={{
              position: "absolute",
              top: 6,
              right: 8,
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: badgeColor === "red" ? "#EF4444" : badgeColor === "green" ? "#10B981" : "#3B82F6",
            }} />
          )}
        </>
      )}
    </NavLink>
  );
}

// ─── Section label ────────────────────────────────────────────────────────────

function SectionLabel({ label, collapsed }: { label: string; collapsed: boolean }) {
  if (collapsed) {
    return <div style={{ height: 1, background: "rgba(255,255,255,0.05)", margin: "8px 10px" }} />;
  }
  return (
    <div className="sec-label">{label}</div>
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

  const collapsed        = useUIStore((s) => s.sidebarCollapsed);
  const toggleSidebar    = useUIStore((s) => s.toggleSidebar);

  const alertCount       = useOpenAlertCount();
  const onlineAgentCount = useOnlineAgentCount();
  const { data: myAlertCount = 0 } = useMyAlertCount();

  const [now, setNow] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setNow(new Date()), 30_000);
    return () => clearInterval(t);
  }, []);
  void now;

  const tenantName = tenant?.name ?? "NEURASHIELD";
  const userRole   = memberRole ?? user?.roles?.[0] ?? "analyst";
  const sidebarW   = collapsed ? 48 : 220;

  const handleLogout = () => {
    clearAuth();
    navigate("/login");
  };

  return (
    <aside
      style={{
        width: sidebarW,
        minWidth: sidebarW,
        background: "#050505",
        borderRight: "1px solid rgba(255,255,255,0.06)",
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        position: "fixed",
        top: 0,
        left: 0,
        zIndex: 40,
        transition: "width 200ms cubic-bezier(0.4,0,0.2,1)",
        overflow: "hidden",
      }}
    >
      {/* Logo + collapse toggle */}
      <div style={{
        display: "flex",
        alignItems: "center",
        justifyContent: collapsed ? "center" : "space-between",
        padding: collapsed ? "12px 0" : "12px 10px 12px 14px",
        borderBottom: "1px solid rgba(255,255,255,0.04)",
        flexShrink: 0,
      }}>
        {!collapsed && (
          <NavLink to="/dashboard" style={{ textDecoration: "none", cursor: "pointer", flex: 1 }}>
            <LogoCompact />
          </NavLink>
        )}
        {collapsed && (
          <NavLink to="/dashboard" style={{ textDecoration: "none", cursor: "pointer" }}>
            <LogoCompact compact />
          </NavLink>
        )}
        <button
          onClick={toggleSidebar}
          title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            width: 22,
            height: 22,
            borderRadius: 5,
            background: "transparent",
            border: "1px solid rgba(255,255,255,0.06)",
            color: "#5C6373",
            cursor: "pointer",
            flexShrink: 0,
            transition: "all 120ms",
          }}
          onMouseOver={(e) => { (e.currentTarget as HTMLButtonElement).style.color = "#F5F7FA"; }}
          onMouseOut={(e)  => { (e.currentTarget as HTMLButtonElement).style.color = "#5C6373"; }}
        >
          {collapsed ? <ChevronRight size={11} /> : <ChevronLeft size={11} />}
        </button>
      </div>

      {/* Nav */}
      <nav style={{ flex: 1, overflowY: "auto", overflowX: "hidden", padding: "8px 0" }}>
        <SectionLabel label="Operations" collapsed={collapsed} />
        <NavItem to="/dashboard"      icon={LayoutDashboard} label="Overview"      collapsed={collapsed} />
        <NavItem to="/alerts"         icon={Bell}            label="Alerts"        badge={alertCount} badgeColor="red" collapsed={collapsed} />

        {!collapsed && myAlertCount > 0 && (
          <NavLink
            to="/alerts?assignedTo=me"
            style={{ display: "flex", alignItems: "center", gap: 6, padding: "3px 14px 5px 36px", textDecoration: "none" }}
          >
            <span style={{ fontSize: 10, color: "#5C6373" }}>
              {myAlertCount} assigned to me
            </span>
          </NavLink>
        )}

        {hasRole("analyst") && (
          <NavItem to="/investigations" icon={FolderSearch} label="Investigations" collapsed={collapsed} />
        )}

        <SectionLabel label="Investigate" collapsed={collapsed} />
        <NavItem to="/events" icon={Activity} label="Events"          collapsed={collapsed} />
        {hasRole("analyst") && (
          <NavItem to="/hunt"  icon={Crosshair} label="Threat Hunt"   collapsed={collapsed} />
        )}
        <NavItem to="/rules" icon={Shield} label="Detection Rules"    collapsed={collapsed} />
        {hasRole("analyst") && (
          <NavItem to="/graph" icon={Network} label="Attack Graph"    collapsed={collapsed} />
        )}

        <SectionLabel label="AI & Response" collapsed={collapsed} />
        {hasRole("analyst") && (
          <NavItem to="/copilot"   icon={Sparkles}  label="AI Copilot" badge="BETA" badgeColor="blue" collapsed={collapsed} />
        )}
        {hasRole("analyst") && (
          <NavItem to="/playbooks" icon={BookOpen}  label="Playbooks"  collapsed={collapsed} />
        )}

        <SectionLabel label="Reporting" collapsed={collapsed} />
        {hasRole("analyst") && (
          <NavItem to="/reports"            icon={FileBarChart} label="Reports"       collapsed={collapsed} />
        )}
        {hasRole("analyst") && (
          <NavItem to="/compliance-reports" icon={FileCheck}    label="Compliance"    collapsed={collapsed} />
        )}
        {hasRole("analyst") && (
          <NavItem to="/soc-metrics"        icon={BarChart3}    label="SOC Metrics"   collapsed={collapsed} />
        )}
        {hasRole("analyst") && (
          <NavItem to="/mitre"              icon={Swords}       label="MITRE ATT&CK"  collapsed={collapsed} />
        )}

        <SectionLabel label="Intelligence" collapsed={collapsed} />
        {hasRole("analyst") && (
          <NavItem to="/threat-intel"       icon={Globe}       label="Threat Intel"   collapsed={collapsed} />
        )}
        {hasRole("analyst") && (
          <NavItem to="/ueba"               icon={UserSearch}  label="UEBA"           collapsed={collapsed} />
        )}
        {hasRole("analyst") && (
          <NavItem to="/assets"             icon={Server}      label="Assets"         collapsed={collapsed} />
        )}
        {hasRole("analyst") && (
          <NavItem to="/rules/suppression"  icon={EyeOff}      label="Suppressions"   collapsed={collapsed} />
        )}

        <SectionLabel label="Platform" collapsed={collapsed} />
        <NavItem to="/agents"    icon={Monitor}   label="Agents"           badge={onlineAgentCount || undefined} badgeColor="green" collapsed={collapsed} />
        <NavItem to="/installer" icon={Download}  label="Device Enrollment" collapsed={collapsed} />
        {hasRole("admin") && (
          <NavItem to="/fleet"   icon={Wifi}      label="Fleet"            collapsed={collapsed} />
        )}
        {hasRole("admin") && (
          <NavItem to="/import"  icon={Upload}    label="Log Import"       collapsed={collapsed} />
        )}
        {hasRole("admin") && (
          <NavItem to="/audit-log" icon={ScrollText} label="Audit Log"     collapsed={collapsed} />
        )}
        {hasRole("admin") && (
          <NavItem to="/mssp"    icon={Building2} label="MSSP Portal"      collapsed={collapsed} />
        )}
        <NavItem to="/settings"  icon={Settings}  label="Settings"         collapsed={collapsed} />
      </nav>

      {/* Footer */}
      <div style={{
        borderTop: "1px solid rgba(255,255,255,0.05)",
        padding: collapsed ? "12px 0" : "12px 14px",
        flexShrink: 0,
      }}>
        {!collapsed && (
          <>
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
          </>
        )}
        <div style={{
          display: "flex",
          alignItems: "center",
          justifyContent: collapsed ? "center" : "space-between",
          marginBottom: 10,
        }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6 }}>
            <span className="dot-live" />
            {!collapsed && (
              <span style={{
                fontSize: 9, fontWeight: 700, textTransform: "uppercase",
                letterSpacing: "1px", color: "#10B981",
              }}>LIVE</span>
            )}
          </div>
          {!collapsed && (
            <div style={{
              display: "flex", alignItems: "center", gap: 4,
              fontSize: 11, color: "#5C6373", fontFamily: "'JetBrains Mono', monospace",
            }}>
              <Monitor size={11} />
              <span>{alertCount > 0 ? alertCount : "—"}</span>
            </div>
          )}
        </div>
        <button
          onClick={handleLogout}
          title="Sign out"
          style={{
            width: "100%",
            padding: collapsed ? "6px" : "6px",
            borderRadius: 6,
            fontSize: 11,
            color: "#5C6373",
            background: "transparent",
            border: "1px solid rgba(255,255,255,0.05)",
            cursor: "pointer",
            transition: "all 120ms",
            textAlign: collapsed ? "center" : "left",
            display: "flex",
            alignItems: "center",
            justifyContent: collapsed ? "center" : "flex-start",
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
          {!collapsed && "Sign out"}
        </button>
      </div>
    </aside>
  );
}
