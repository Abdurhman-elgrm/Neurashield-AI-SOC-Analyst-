import { useState } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import {
  LayoutDashboard, Bell, FolderSearch, Activity, Crosshair, Shield,
  Sparkles, Monitor, Settings, LogOut, BookOpen, FileBarChart, Download,
  BarChart3, Server, UserSearch,
  Globe, Swords, Building2,
  ChevronLeft, ChevronRight,
} from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
import { useTenantStore } from "@/stores/tenantStore";
import { useUIStore } from "@/stores/uiStore";
import { LogoCompact } from "@/components/ui/Logo";
import { getAlertsSummary } from "@/services/alertsApi";
import { agentsApi } from "@/api/agents";
import { useQuery } from "@tanstack/react-query";
import { useMyAlertCount } from "@/hooks/useMyAlertCount";

// ─── Live badge counts ────────────────────────────────────────────────────────

function useOpenAlertCount() {
  const { data } = useQuery({
    queryKey: ["sidebar", "alerts-open"],
    queryFn: () => getAlertsSummary(),
    staleTime: 60_000, refetchInterval: 60_000, retry: false,
  });
  return data?.open ?? 0;
}

function useOnlineAgentCount() {
  const { data } = useQuery({
    queryKey: ["sidebar", "agents-online"],
    queryFn: async () => {
      const resp = await agentsApi.list({ status: "online", limit: 1 });
      return resp.pagination.total;
    },
    staleTime: 30_000, refetchInterval: 30_000, retry: false,
  });
  return data ?? 0;
}

// ─── Dimensions ───────────────────────────────────────────────────────────────

export const SIDEBAR_OPEN_W   = 230;
export const SIDEBAR_CLOSED_W = 56;

// ─── Types ────────────────────────────────────────────────────────────────────

interface NavItemDef {
  to: string;
  icon: React.ElementType;
  label: string;
  badge?: number | string | null;
  badgeColor?: "red" | "green" | "blue";
  tabParam?: string;
}

interface SectionDef {
  label: string;
  items: NavItemDef[];
}

// ─── Settings tab → active check ─────────────────────────────────────────────

function useSettingsTab() {
  const location = useLocation();
  return new URLSearchParams(location.search).get("tab") || "profile";
}

// ─── Single nav item ──────────────────────────────────────────────────────────

function NavItem({
  to, icon: Icon, label, badge, badgeColor = "red", collapsed, tabParam,
}: NavItemDef & { collapsed: boolean }) {
  const location    = useLocation();
  const navigate    = useNavigate();
  const settingsTab = useSettingsTab();
  const [hov, setHov] = useState(false);

  const badgeBg =
    badgeColor === "red"   ? "rgba(239,68,68,0.18)"  :
    badgeColor === "green" ? "rgba(16,185,129,0.18)" :
                             "rgba(59,130,246,0.18)";
  const badgeFg =
    badgeColor === "red"   ? "#FCA5A5" :
    badgeColor === "green" ? "#6EE7B7" :
                             "#93C5FD";

  const displayBadge =
    typeof badge === "number"
      ? badge > 999 ? "999+" : badge > 0 ? String(badge) : null
      : badge ?? null;

  // For settings items: active by ?tab= param; otherwise by pathname
  const isActive = tabParam !== undefined
    ? location.pathname === "/settings" && settingsTab === tabParam
    : location.pathname === to || location.pathname.startsWith(to + "/");

  if (tabParam !== undefined) {
    // Render as button (same URL, different query param)
    return (
      <button
        onClick={() => navigate(to)}
        title={collapsed ? label : undefined}
        onMouseEnter={() => setHov(true)}
        onMouseLeave={() => setHov(false)}
        style={{
          display: "flex",
          alignItems: "center",
          gap: 10,
          width: "100%",
          padding: collapsed ? "8px 0" : "7px 12px",
          justifyContent: collapsed ? "center" : "flex-start",
          fontSize: 13,
          fontWeight: isActive ? 500 : 400,
          color: isActive ? "#E2E8F0" : hov ? "#C1C9D6" : "#6B7280",
          background: isActive ? "rgba(59,130,246,0.10)" : hov ? "rgba(255,255,255,0.03)" : "transparent",
          borderLeft: collapsed ? "none" : `2px solid ${isActive ? "#3B82F6" : "transparent"}`,
          borderRight: collapsed ? `2px solid ${isActive ? "#3B82F6" : "transparent"}` : "none",
          border: "none",
          transition: "all 100ms",
          cursor: "pointer",
          textAlign: "left" as const,
          flexShrink: 0,
        }}
      >
        <Icon
          size={15}
          style={{
            color: isActive ? "#60A5FA" : hov ? "#9CA3AF" : "#4B5563",
            transition: "color 100ms",
            flexShrink: 0,
          }}
        />
        {!collapsed && <span style={{ flex: 1 }}>{label}</span>}
        {!collapsed && displayBadge && (
          <span style={{
            padding: "1px 6px", borderRadius: 9999,
            fontSize: 9, fontWeight: 700,
            fontFamily: "'JetBrains Mono', monospace",
            background: badgeBg, color: badgeFg,
          }}>
            {displayBadge}
          </span>
        )}
        {collapsed && displayBadge && (
          <span style={{
            position: "absolute" as const, top: 5, right: 5,
            width: 5, height: 5, borderRadius: "50%",
            background: badgeColor === "red" ? "#EF4444" : badgeColor === "green" ? "#10B981" : "#3B82F6",
          }} />
        )}
      </button>
    );
  }

  return (
    <NavLink
      to={to}
      title={collapsed ? label : undefined}
      end={to === "/settings" || to === "/dashboard"}
      style={() => ({
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: collapsed ? "8px 0" : "7px 12px",
        justifyContent: collapsed ? "center" : "flex-start",
        fontSize: 13,
        fontWeight: isActive ? 500 : 400,
        color: isActive ? "#E2E8F0" : hov ? "#C1C9D6" : "#6B7280",
        background: isActive ? "rgba(59,130,246,0.10)" : hov ? "rgba(255,255,255,0.03)" : "transparent",
        borderLeft: collapsed ? "none" : `2px solid ${isActive ? "#3B82F6" : "transparent"}`,
        borderRight: collapsed ? `2px solid ${isActive ? "#3B82F6" : "transparent"}` : "none",
        transition: "all 100ms",
        textDecoration: "none",
        position: "relative" as const,
      })}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
    >
      <Icon
        size={15}
        style={{
          color: isActive ? "#60A5FA" : hov ? "#9CA3AF" : "#4B5563",
          transition: "color 100ms",
          flexShrink: 0,
        }}
      />
      {!collapsed && <span style={{ flex: 1 }}>{label}</span>}
      {!collapsed && displayBadge && (
        <span style={{
          padding: "1px 6px", borderRadius: 9999,
          fontSize: 9, fontWeight: 700,
          fontFamily: "'JetBrains Mono', monospace",
          background: badgeBg, color: badgeFg,
        }}>
          {displayBadge}
        </span>
      )}
      {collapsed && displayBadge && (
        <span style={{
          position: "absolute", top: 5, right: 5,
          width: 5, height: 5, borderRadius: "50%",
          background: badgeColor === "red" ? "#EF4444" : badgeColor === "green" ? "#10B981" : "#3B82F6",
        }} />
      )}
    </NavLink>
  );
}

// ─── Section header ───────────────────────────────────────────────────────────

function SectionLabel({ label, collapsed }: { label: string; collapsed: boolean }) {
  if (collapsed) {
    return <div style={{ height: 1, background: "rgba(255,255,255,0.05)", margin: "6px 10px" }} />;
  }
  return (
    <div style={{
      padding: "10px 14px 3px",
      fontSize: 9,
      fontWeight: 700,
      letterSpacing: "1.2px",
      textTransform: "uppercase" as const,
      color: "#374151",
      fontFamily: "'JetBrains Mono', monospace",
    }}>
      {label}
    </div>
  );
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────

export function Sidebar() {
  const user       = useAuthStore((s) => s.user);
  const clearAuth  = useAuthStore((s) => s.clearAuth);
  const tenant     = useTenantStore((s) => s.activeTenant);
  const memberRole = useTenantStore((s) => s.memberRole);
  const hasRole    = useTenantStore((s) => s.hasRole);
  const navigate   = useNavigate();

  const collapsed     = useUIStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);

  const alertCount       = useOpenAlertCount();
  const onlineAgentCount = useOnlineAgentCount();
  const { data: _mc = 0 } = useMyAlertCount();
  void _mc;

  const tenantName = tenant?.name ?? "NEURASHIELD";
  const userRole   = memberRole ?? user?.roles?.[0] ?? "analyst";

  const SECTIONS: SectionDef[] = [
    {
      label: "",
      items: [
        { to: "/dashboard", icon: LayoutDashboard, label: "Overview" },
      ],
    },
    {
      label: "Detect",
      items: [
        { to: "/alerts",         icon: Bell,        label: "Alerts",         badge: alertCount || null, badgeColor: "red" as const   },
        ...(hasRole("analyst") ? [{ to: "/investigations", icon: FolderSearch, label: "Investigations" }] : []),
      ],
    },
    {
      label: "Analyze",
      items: [
        { to: "/events", icon: Activity,  label: "Events"          },
        ...(hasRole("analyst") ? [{ to: "/hunt",  icon: Crosshair, label: "Threat Hunt"    }] : []),
        { to: "/rules",  icon: Shield,    label: "Detection Rules" },
      ],
    },
    {
      label: "Respond",
      items: [
        ...(hasRole("analyst") ? [{ to: "/copilot",   icon: Sparkles,  label: "AI Copilot", badge: "BETA" as const, badgeColor: "blue" as const }] : []),
        ...(hasRole("analyst") ? [{ to: "/playbooks", icon: BookOpen,  label: "Playbooks"                                                         }] : []),
      ],
    },
    {
      label: "Report",
      items: [
        ...(hasRole("analyst") ? [{ to: "/reports",     icon: FileBarChart, label: "Reports"      }] : []),
        ...(hasRole("analyst") ? [{ to: "/soc-metrics", icon: BarChart3,    label: "SOC Metrics"  }] : []),
        ...(hasRole("analyst") ? [{ to: "/mitre",       icon: Swords,       label: "MITRE ATT&CK" }] : []),
      ],
    },
    {
      label: "Intelligence",
      items: [
        ...(hasRole("analyst") ? [{ to: "/threat-intel", icon: Globe,      label: "Threat Intel" }] : []),
        ...(hasRole("analyst") ? [{ to: "/ueba",        icon: UserSearch, label: "UEBA"         }] : []),
        ...(hasRole("analyst") ? [{ to: "/assets",      icon: Server,     label: "Assets"       }] : []),
      ],
    },
    {
      label: "Platform",
      items: [
        { to: "/agents",    icon: Monitor,  label: "Agents",       badge: onlineAgentCount || null, badgeColor: "green" as const },
        { to: "/installer", icon: Download, label: "Device Enroll"                                                      },
        ...(hasRole("admin") ? [{ to: "/mssp", icon: Building2, label: "MSSP Portal" }] : []),
      ],
    },
    {
      label: "Settings",
      items: [
        { to: "/settings", icon: Settings, label: "Settings" },
      ],
    },
  ].filter((s) => s.items.length > 0);

  const handleLogout = () => { clearAuth(); navigate("/login"); };

  const sidebarW = collapsed ? SIDEBAR_CLOSED_W : SIDEBAR_OPEN_W;

  return (
    <aside
      style={{
        width: sidebarW,
        minWidth: sidebarW,
        background: "#050505",
        borderRight: "1px solid rgba(255,255,255,0.055)",
        display: "flex",
        flexDirection: "column",
        height: "100vh",
        position: "fixed",
        top: 0,
        left: 0,
        zIndex: 40,
        transition: "width 200ms cubic-bezier(0.4,0,0.2,1), min-width 200ms cubic-bezier(0.4,0,0.2,1)",
        overflow: "hidden",
      }}
    >
      {/* Logo row */}
      <div style={{
        height: 48,
        display: "flex",
        alignItems: "center",
        justifyContent: collapsed ? "center" : "space-between",
        padding: collapsed ? "0" : "0 10px 0 14px",
        borderBottom: "1px solid rgba(255,255,255,0.05)",
        flexShrink: 0,
      }}>
        <NavLink to="/dashboard" style={{ textDecoration: "none", display: "flex", alignItems: "center" }}>
          <LogoCompact compact={collapsed} />
        </NavLink>
        {!collapsed && (
          <button
            onClick={toggleSidebar}
            title="Collapse sidebar"
            style={{
              display: "flex", alignItems: "center", justifyContent: "center",
              width: 24, height: 24, borderRadius: 4,
              background: "transparent",
              border: "1px solid rgba(255,255,255,0.07)",
              color: "#374151", cursor: "pointer", transition: "all 120ms", flexShrink: 0,
            }}
            onMouseOver={(e) => { (e.currentTarget as HTMLButtonElement).style.color = "#9CA3AF"; }}
            onMouseOut={(e)  => { (e.currentTarget as HTMLButtonElement).style.color = "#374151"; }}
          >
            <ChevronLeft size={12} />
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav style={{ flex: 1, overflowY: "auto", overflowX: "hidden", padding: "6px 0" }}>
        {SECTIONS.map((section, si) => (
          <div key={si}>
            {section.label && <SectionLabel label={section.label} collapsed={collapsed} />}
            {section.items.map((item) => (
              <NavItem
                key={item.to + (item.tabParam ?? "")}
                {...item}
                collapsed={collapsed}
              />
            ))}
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div style={{
        borderTop: "1px solid rgba(255,255,255,0.05)",
        padding: collapsed ? "10px 0" : "10px 12px",
        display: "flex",
        alignItems: "center",
        justifyContent: collapsed ? "center" : "space-between",
        gap: 8,
        flexShrink: 0,
      }}>
        {collapsed ? (
          <div style={{ display: "flex", flexDirection: "column", alignItems: "center", gap: 8 }}>
            <span className="dot-live" title="Live" />
            <button
              onClick={toggleSidebar}
              title="Expand sidebar"
              style={{
                display: "flex", alignItems: "center", justifyContent: "center",
                width: 24, height: 24, borderRadius: 4,
                background: "transparent",
                border: "1px solid rgba(255,255,255,0.07)",
                color: "#374151", cursor: "pointer", transition: "all 120ms",
              }}
              onMouseOver={(e) => { (e.currentTarget as HTMLButtonElement).style.color = "#9CA3AF"; }}
              onMouseOut={(e)  => { (e.currentTarget as HTMLButtonElement).style.color = "#374151"; }}
            >
              <ChevronRight size={12} />
            </button>
            <button
              onClick={handleLogout}
              title="Sign out"
              style={{
                display: "flex", alignItems: "center", justifyContent: "center",
                width: 24, height: 24, borderRadius: 4,
                background: "transparent",
                border: "1px solid rgba(255,255,255,0.07)",
                color: "#374151", cursor: "pointer", transition: "all 120ms",
              }}
              onMouseOver={(e) => { (e.currentTarget as HTMLButtonElement).style.color = "#F87171"; }}
              onMouseOut={(e)  => { (e.currentTarget as HTMLButtonElement).style.color = "#374151"; }}
            >
              <LogOut size={12} />
            </button>
          </div>
        ) : (
          <>
            <div style={{ minWidth: 0 }}>
              <div style={{
                fontSize: 11.5, fontWeight: 600, color: "#D1D5DB",
                whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
                marginBottom: 1,
              }}>
                {tenantName}
              </div>
              <div style={{ display: "flex", alignItems: "center", gap: 5 }}>
                <span className="dot-live" title="Live" />
                <span style={{
                  fontSize: 8.5, textTransform: "uppercase", letterSpacing: "0.8px",
                  color: "#374151", fontFamily: "'JetBrains Mono', monospace",
                }}>
                  {String(userRole).toUpperCase()}
                </span>
              </div>
            </div>
            <button
              onClick={handleLogout}
              title="Sign out"
              style={{
                display: "flex", alignItems: "center", justifyContent: "center",
                width: 28, height: 28, borderRadius: 5,
                background: "transparent",
                border: "1px solid rgba(255,255,255,0.07)",
                color: "#374151", cursor: "pointer", transition: "all 120ms", flexShrink: 0,
              }}
              onMouseOver={(e) => { (e.currentTarget as HTMLButtonElement).style.color = "#F87171"; (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(248,113,113,0.3)"; }}
              onMouseOut={(e)  => { (e.currentTarget as HTMLButtonElement).style.color = "#374151"; (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(255,255,255,0.07)"; }}
            >
              <LogOut size={13} />
            </button>
          </>
        )}
      </div>
    </aside>
  );
}
