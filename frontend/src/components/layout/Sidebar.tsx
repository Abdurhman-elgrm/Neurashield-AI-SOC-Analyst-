import { useState, useEffect } from "react";
import { NavLink, useLocation, useNavigate } from "react-router-dom";
import {
  LayoutDashboard, Bell, FolderSearch, Activity, Crosshair, Shield,
  Sparkles, Monitor, Settings, LogOut, BookOpen, FileBarChart, Download,
  Upload, Network, BarChart3, Server, UserSearch, ScrollText, EyeOff,
  Globe, Swords, Building2, Wifi, FileCheck, PanelLeftOpen, PanelLeftClose,
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
    staleTime: 60_000, refetchInterval: 60_000, retry: false,
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
    staleTime: 30_000, refetchInterval: 30_000, retry: false,
  });
  return data ?? 0;
}

// ─── Types ────────────────────────────────────────────────────────────────────

interface NavItemDef {
  to: string;
  icon: React.ElementType;
  label: string;
  badge?: string | number | null;
  badgeColor?: "red" | "green" | "blue";
}

interface CategoryDef {
  id: string;
  icon: React.ElementType;
  label: string;
  direct?: string;
  items?: NavItemDef[];
}

// ─── Route to category mapping ───────────────────────────────────────────────

const ROUTE_CATS: [string, string][] = [
  ["/dashboard", "overview"],
  ["/alerts", "detect"],
  ["/investigations", "detect"],
  ["/events", "analyze"],
  ["/hunt", "analyze"],
  ["/rules/suppression", "intel"],
  ["/rules", "analyze"],
  ["/graph", "analyze"],
  ["/copilot", "respond"],
  ["/playbooks", "respond"],
  ["/compliance-reports", "report"],
  ["/reports", "report"],
  ["/soc-metrics", "report"],
  ["/mitre", "report"],
  ["/threat-intel", "intel"],
  ["/ueba", "intel"],
  ["/assets", "intel"],
  ["/agents", "platform"],
  ["/installer", "platform"],
  ["/fleet", "platform"],
  ["/import", "platform"],
  ["/audit-log", "platform"],
  ["/mssp", "platform"],
  ["/settings", "settings"],
];

function pathToCategory(pathname: string): string {
  for (const [route, cat] of ROUTE_CATS) {
    if (
      pathname === route ||
      pathname.startsWith(route + "/") ||
      pathname.startsWith(route + "?")
    ) {
      return cat;
    }
  }
  return "overview";
}

// ─── Dimensions ───────────────────────────────────────────────────────────────

export const RAIL_W           = 56;
export const PANEL_W          = 180;
export const SIDEBAR_OPEN_W   = RAIL_W + PANEL_W;
export const SIDEBAR_CLOSED_W = RAIL_W;

// ─── Rail category button ────────────────────────────────────────────────────

function RailItem({
  id, icon: Icon, label, isActive, hasDot, onClick,
}: {
  id: string;
  icon: React.ElementType;
  label: string;
  isActive: boolean;
  hasDot?: boolean;
  onClick: (id: string) => void;
}) {
  const [hov, setHov] = useState(false);

  return (
    <button
      onClick={() => onClick(id)}
      title={label}
      onMouseEnter={() => setHov(true)}
      onMouseLeave={() => setHov(false)}
      style={{
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
        gap: 3,
        width: "100%",
        padding: "10px 0 9px",
        background: isActive ? "rgba(59,130,246,0.09)" : hov ? "rgba(255,255,255,0.025)" : "transparent",
        border: "none",
        borderRight: `2px solid ${isActive ? "#3B82F6" : "transparent"}`,
        cursor: "pointer",
        position: "relative",
        transition: "background 100ms, border-color 100ms",
        flexShrink: 0,
      }}
    >
      <Icon
        size={15}
        style={{
          color: isActive ? "#60A5FA" : hov ? "#9CA3AF" : "#4B5563",
          transition: "color 100ms",
        }}
      />
      <span style={{
        fontSize: 7.5,
        fontWeight: 700,
        letterSpacing: "0.5px",
        textTransform: "uppercase" as const,
        color: isActive ? "#60A5FA" : hov ? "#6B7280" : "#374151",
        fontFamily: "'JetBrains Mono', monospace",
        lineHeight: 1,
        transition: "color 100ms",
      }}>
        {label}
      </span>
      {hasDot && (
        <span style={{
          position: "absolute", top: 7, right: 9,
          width: 5, height: 5, borderRadius: "50%",
          background: "#EF4444",
          boxShadow: "0 0 4px rgba(239,68,68,0.6)",
        }} />
      )}
    </button>
  );
}

// ─── Panel nav item ───────────────────────────────────────────────────────────

function PanelItem({ to, icon: Icon, label, badge, badgeColor = "blue" }: NavItemDef) {
  const badgeBg =
    badgeColor === "red"   ? "rgba(239,68,68,0.15)"  :
    badgeColor === "green" ? "rgba(16,185,129,0.15)" :
                             "rgba(59,130,246,0.15)";
  const badgeFg =
    badgeColor === "red"   ? "#FCA5A5" :
    badgeColor === "green" ? "#6EE7B7" :
                             "#93C5FD";

  const displayBadge =
    typeof badge === "number"
      ? badge > 999 ? "999+" : badge > 0 ? badge : null
      : badge;

  return (
    <NavLink
      to={to}
      style={({ isActive }) => ({
        display: "flex",
        alignItems: "center",
        gap: 8,
        padding: "6px 12px 6px 14px",
        margin: "1px 6px 1px 0",
        fontSize: 12.5,
        fontWeight: isActive ? 500 : 400,
        color: isActive ? "#E2E8F0" : "#6B7280",
        background: isActive ? "rgba(59,130,246,0.08)" : "transparent",
        borderLeft: `2px solid ${isActive ? "#3B82F6" : "transparent"}`,
        transition: "all 100ms",
        textDecoration: "none",
        borderRadius: "0 4px 4px 0",
      })}
    >
      {({ isActive }) => (
        <>
          <Icon size={13} style={{ opacity: isActive ? 0.85 : 0.38, color: isActive ? "#60A5FA" : "inherit", flexShrink: 0 }} />
          <span style={{ flex: 1 }}>{label}</span>
          {displayBadge != null && (
            <span style={{
              padding: "1px 5px", borderRadius: 9999, fontSize: 9, fontWeight: 700,
              fontFamily: "'JetBrains Mono', monospace", background: badgeBg, color: badgeFg,
            }}>
              {displayBadge}
            </span>
          )}
        </>
      )}
    </NavLink>
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
  const location   = useLocation();

  const collapsed     = useUIStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);

  const alertCount       = useOpenAlertCount();
  const onlineAgentCount = useOnlineAgentCount();
  const { data: _mc = 0 } = useMyAlertCount();
  void _mc;

  const tenantName = tenant?.name ?? "NEURASHIELD";
  const userRole   = memberRole ?? user?.roles?.[0] ?? "analyst";

  const currentCategory = pathToCategory(location.pathname);
  const [activeCategory, setActiveCategory] = useState(currentCategory);

  useEffect(() => {
    setActiveCategory(currentCategory);
  }, [currentCategory]);

  const CATEGORIES: CategoryDef[] = [
    { id: "overview", icon: LayoutDashboard, label: "Overview", direct: "/dashboard" },
    {
      id: "detect", icon: Bell, label: "Detect",
      items: [
        { to: "/alerts",         icon: Bell,        label: "Alerts",         badge: alertCount || null, badgeColor: "red" },
        ...(hasRole("analyst") ? [{ to: "/investigations", icon: FolderSearch, label: "Investigations" }] : []),
      ],
    },
    {
      id: "analyze", icon: Crosshair, label: "Analyze",
      items: [
        { to: "/events", icon: Activity, label: "Events" },
        ...(hasRole("analyst") ? [{ to: "/hunt",  icon: Crosshair, label: "Threat Hunt"    }] : []),
        { to: "/rules",          icon: Shield,    label: "Detection Rules" },
        ...(hasRole("analyst") ? [{ to: "/graph", icon: Network,   label: "Attack Graph"   }] : []),
      ],
    },
    {
      id: "respond", icon: Sparkles, label: "Respond",
      items: [
        ...(hasRole("analyst") ? [{ to: "/copilot",   icon: Sparkles, label: "AI Copilot", badge: "BETA" as const, badgeColor: "blue" as const }] : []),
        ...(hasRole("analyst") ? [{ to: "/playbooks", icon: BookOpen, label: "Playbooks"                                                         }] : []),
      ],
    },
    {
      id: "report", icon: FileBarChart, label: "Report",
      items: [
        ...(hasRole("analyst") ? [{ to: "/reports",            icon: FileBarChart, label: "Reports"      }] : []),
        ...(hasRole("analyst") ? [{ to: "/compliance-reports", icon: FileCheck,    label: "Compliance"   }] : []),
        ...(hasRole("analyst") ? [{ to: "/soc-metrics",        icon: BarChart3,    label: "SOC Metrics"  }] : []),
        ...(hasRole("analyst") ? [{ to: "/mitre",              icon: Swords,       label: "MITRE ATT&CK" }] : []),
      ],
    },
    {
      id: "intel", icon: Globe, label: "Intel",
      items: [
        ...(hasRole("analyst") ? [{ to: "/threat-intel",      icon: Globe,      label: "Threat Intel" }] : []),
        ...(hasRole("analyst") ? [{ to: "/ueba",              icon: UserSearch, label: "UEBA"         }] : []),
        ...(hasRole("analyst") ? [{ to: "/assets",            icon: Server,     label: "Assets"       }] : []),
        ...(hasRole("analyst") ? [{ to: "/rules/suppression", icon: EyeOff,     label: "Suppressions" }] : []),
      ],
    },
    {
      id: "platform", icon: Monitor, label: "Platform",
      items: [
        { to: "/agents",    icon: Monitor,   label: "Agents",       badge: onlineAgentCount || null, badgeColor: "green" },
        { to: "/installer", icon: Download,  label: "Device Enroll"                                                      },
        ...(hasRole("admin") ? [{ to: "/fleet",     icon: Wifi,       label: "Fleet"       }] : []),
        ...(hasRole("admin") ? [{ to: "/import",    icon: Upload,     label: "Log Import"  }] : []),
        ...(hasRole("admin") ? [{ to: "/audit-log", icon: ScrollText, label: "Audit Log"   }] : []),
        ...(hasRole("admin") ? [{ to: "/mssp",      icon: Building2,  label: "MSSP Portal" }] : []),
      ],
    },
    { id: "settings", icon: Settings, label: "Settings", direct: "/settings" },
  ];

  const activeDef = CATEGORIES.find((c) => c.id === activeCategory);

  const handleRailClick = (id: string) => {
    const cat = CATEGORIES.find((c) => c.id === id)!;
    if (cat.direct) {
      navigate(cat.direct);
      setActiveCategory(id);
      return;
    }
    if (cat.items && cat.items.length > 0) {
      if (collapsed) {
        toggleSidebar();
        setActiveCategory(id);
      } else if (id === activeCategory) {
        toggleSidebar();
      } else {
        setActiveCategory(id);
      }
    }
  };

  const handleLogout = () => { clearAuth(); navigate("/login"); };

  return (
    <aside style={{
      width: collapsed ? SIDEBAR_CLOSED_W : SIDEBAR_OPEN_W,
      minWidth: collapsed ? SIDEBAR_CLOSED_W : SIDEBAR_OPEN_W,
      background: "#050505",
      display: "flex",
      height: "100vh",
      position: "fixed",
      top: 0, left: 0,
      zIndex: 40,
      transition: "width 200ms cubic-bezier(0.4,0,0.2,1), min-width 200ms cubic-bezier(0.4,0,0.2,1)",
      overflow: "hidden",
      borderRight: "1px solid rgba(255,255,255,0.055)",
    }}>

      {/* ── Icon Rail ──────────────────────────────────────────────────── */}
      <div style={{
        width: RAIL_W, minWidth: RAIL_W,
        display: "flex", flexDirection: "column", height: "100%",
        borderRight: collapsed ? "none" : "1px solid rgba(255,255,255,0.04)",
        flexShrink: 0,
      }}>
        {/* Logo */}
        <div style={{
          height: 48, display: "flex", alignItems: "center", justifyContent: "center",
          borderBottom: "1px solid rgba(255,255,255,0.04)", flexShrink: 0,
        }}>
          <NavLink to="/dashboard" style={{ textDecoration: "none", display: "flex" }}>
            <LogoCompact compact />
          </NavLink>
        </div>

        {/* Category buttons */}
        <nav style={{ flex: 1, overflowY: "auto", overflowX: "hidden", padding: "6px 0" }}>
          {CATEGORIES.map((cat) => (
            <RailItem
              key={cat.id}
              id={cat.id}
              icon={cat.icon}
              label={cat.label}
              isActive={activeCategory === cat.id}
              hasDot={cat.id === "detect" && alertCount > 0}
              onClick={handleRailClick}
            />
          ))}
        </nav>

        {/* Rail footer: live dot + toggle + logout */}
        <div style={{
          borderTop: "1px solid rgba(255,255,255,0.04)",
          padding: "10px 0",
          display: "flex", flexDirection: "column", alignItems: "center", gap: 7,
          flexShrink: 0,
        }}>
          <span className="dot-live" title="Live" />
          <button
            onClick={toggleSidebar}
            title={collapsed ? "Expand navigation" : "Collapse navigation"}
            style={{
              display: "flex", alignItems: "center", justifyContent: "center",
              width: 26, height: 26, borderRadius: 5,
              background: "transparent", border: "1px solid rgba(255,255,255,0.06)",
              color: "#374151", cursor: "pointer", transition: "all 120ms",
            }}
            onMouseOver={(e) => { (e.currentTarget as HTMLButtonElement).style.color = "#D1D5DB"; }}
            onMouseOut={(e)  => { (e.currentTarget as HTMLButtonElement).style.color = "#374151"; }}
          >
            {collapsed ? <PanelLeftOpen size={12} /> : <PanelLeftClose size={12} />}
          </button>
          <button
            onClick={handleLogout}
            title="Sign out"
            style={{
              display: "flex", alignItems: "center", justifyContent: "center",
              width: 26, height: 26, borderRadius: 5,
              background: "transparent", border: "1px solid rgba(255,255,255,0.06)",
              color: "#374151", cursor: "pointer", transition: "all 120ms",
            }}
            onMouseOver={(e) => { (e.currentTarget as HTMLButtonElement).style.color = "#F87171"; }}
            onMouseOut={(e)  => { (e.currentTarget as HTMLButtonElement).style.color = "#374151"; }}
          >
            <LogOut size={12} />
          </button>
        </div>
      </div>

      {/* ── Secondary Panel ────────────────────────────────────────────── */}
      <div style={{
        width: PANEL_W, minWidth: PANEL_W,
        display: "flex", flexDirection: "column", height: "100%",
        background: "#060606",
        opacity: collapsed ? 0 : 1,
        pointerEvents: collapsed ? "none" : "auto",
        transition: "opacity 150ms",
        flexShrink: 0,
      }}>
        {/* Panel header */}
        <div style={{
          height: 48, display: "flex", alignItems: "center",
          padding: "0 14px", gap: 8,
          borderBottom: "1px solid rgba(255,255,255,0.04)", flexShrink: 0,
        }}>
          {activeDef && (
            <>
              <activeDef.icon size={13} style={{ color: "#374151", flexShrink: 0 }} />
              <span style={{
                fontSize: 9, fontWeight: 700, letterSpacing: "1.5px",
                textTransform: "uppercase", color: "#374151",
                fontFamily: "'JetBrains Mono', monospace",
              }}>
                {activeDef.label}
              </span>
            </>
          )}
        </div>

        {/* Panel items */}
        <nav style={{ flex: 1, overflowY: "auto", overflowX: "hidden", padding: "10px 0" }}>
          {activeDef?.direct ? (
            <PanelItem to={activeDef.direct} icon={activeDef.icon} label={activeDef.label} />
          ) : (
            activeDef?.items?.map((item) => (
              <PanelItem key={item.to} {...item} />
            ))
          )}
        </nav>

        {/* Tenant + role */}
        <div style={{
          borderTop: "1px solid rgba(255,255,255,0.04)",
          padding: "12px 14px", flexShrink: 0,
        }}>
          <div style={{
            fontSize: 11.5, fontWeight: 600, color: "#D1D5DB", marginBottom: 3,
            whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis",
          }}>
            {tenantName}
          </div>
          <div style={{
            fontSize: 8.5, textTransform: "uppercase", letterSpacing: "1px",
            color: "#374151", fontFamily: "'JetBrains Mono', monospace",
          }}>
            {String(userRole).toUpperCase()}
          </div>
        </div>
      </div>
    </aside>
  );
}
