import { useState, useEffect } from "react";
import { ChevronDown, Search, LogOut, Settings, Plus, Loader, ClipboardList, ChevronRight, Home } from "lucide-react";
import { useNavigate, useLocation, Link } from "react-router-dom";
import { useQueryClient } from "@tanstack/react-query";
import { useAuthStore } from "@/stores/authStore";
import { useTenantStore } from "@/stores/tenantStore";
import { useUIStore } from "@/stores/uiStore";
import { useRealtimeStore } from "@/stores/realtimeStore";
import { NotificationBell } from "@/components/notifications/NotificationCenter";
import { ShiftHandoffModal } from "@/components/ui/ShiftHandoffModal";
import { fetchMyTenants, createTenant } from "@/api/tenants";
import type { Tenant, MemberRole } from "@/types/tenant";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "@/components/ui/Dropdown";

// ─── Route → breadcrumb label map ─────────────────────────────────────────────

const ROUTE_LABELS: Record<string, string> = {
  dashboard:         "Overview",
  alerts:            "Alert Triage",
  investigations:    "Investigations",
  events:            "Event Explorer",
  hunt:              "Threat Hunt",
  rules:             "Detection Rules",
  graph:             "Attack Graph",
  copilot:           "AI Copilot",
  playbooks:         "Playbooks",
  reports:           "Reports",
  "compliance-reports": "Compliance",
  "soc-metrics":     "SOC Metrics",
  sla:               "SLA Dashboard",
  mitre:             "MITRE ATT&CK",
  "threat-intel":    "Threat Intel",
  ueba:              "UEBA",
  assets:            "Assets",
  suppression:       "Suppressions",
  agents:            "Agents",
  installer:         "Device Enrollment",
  fleet:             "Fleet",
  import:            "Log Import",
  "audit-log":       "Audit Log",
  mssp:              "MSSP Portal",
  settings:          "Settings",
};

function useBreadcrumbs() {
  const location = useLocation();
  const segments = location.pathname.split("/").filter(Boolean);
  return segments.map((seg, idx) => ({
    label: ROUTE_LABELS[seg] ?? seg,
    path:  "/" + segments.slice(0, idx + 1).join("/"),
    isLast: idx === segments.length - 1,
  }));
}

// ─── Breadcrumb ───────────────────────────────────────────────────────────────

function Breadcrumb() {
  const crumbs = useBreadcrumbs();
  if (crumbs.length === 0) return null;

  return (
    <nav aria-label="Breadcrumb" style={{ display: "flex", alignItems: "center", gap: 4 }}>
      <Link to="/dashboard" style={{ color: "#5C6373", textDecoration: "none", display: "flex", alignItems: "center" }}>
        <Home size={11} />
      </Link>
      {crumbs.map((crumb) => (
        <span key={crumb.path} style={{ display: "flex", alignItems: "center", gap: 4 }}>
          <ChevronRight size={10} style={{ color: "#3A4150", flexShrink: 0 }} />
          {crumb.isLast ? (
            <span style={{
              fontSize: 12,
              fontWeight: 600,
              color: "#F5F7FA",
              whiteSpace: "nowrap",
            }}>
              {crumb.label}
            </span>
          ) : (
            <Link
              to={crumb.path}
              style={{
                fontSize: 12,
                color: "#5C6373",
                textDecoration: "none",
                whiteSpace: "nowrap",
                transition: "color 120ms",
              }}
              onMouseOver={(e) => ((e.target as HTMLElement).style.color = "#B8C0CC")}
              onMouseOut={(e)  => ((e.target as HTMLElement).style.color = "#5C6373")}
            >
              {crumb.label}
            </Link>
          )}
        </span>
      ))}
    </nav>
  );
}

// ─── Clock ────────────────────────────────────────────────────────────────────

function Clock() {
  const [time, setTime] = useState(new Date());
  useEffect(() => {
    const t = setInterval(() => setTime(new Date()), 1000);
    return () => clearInterval(t);
  }, []);
  return (
    <span style={{
      fontFamily: "'JetBrains Mono', monospace",
      fontSize: 11,
      color: "#5C6373",
      letterSpacing: "0.05em",
    }}>
      {time.toLocaleTimeString("en-GB")}
    </span>
  );
}

// ─── Connection status ────────────────────────────────────────────────────────

function ConnectionStatus() {
  const state = useRealtimeStore((s) => s.connectionState);
  const isLive       = state === "connected";
  const isConnecting = state === "connecting" || state === "reconnecting";
  const color = isLive ? "#10B981" : isConnecting ? "#F59E0B" : "#5C6373";
  const label = isLive ? "Live" : isConnecting ? "…" : "Offline";

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color }}>
      {isLive ? (
        <span className="dot-live" />
      ) : (
        <span style={{ width: 6, height: 6, borderRadius: "50%", background: color, display: "inline-block" }} />
      )}
      <span style={{ fontFamily: "'JetBrains Mono', monospace", fontSize: 10 }}>{label}</span>
    </div>
  );
}

// ─── User menu ────────────────────────────────────────────────────────────────

function UserMenu() {
  const user      = useAuthStore((s) => s.user);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const navigate  = useNavigate();

  const initial     = user?.full_name?.[0]?.toUpperCase() ?? user?.email?.[0]?.toUpperCase() ?? "U";
  const displayName = user?.full_name || user?.email || "User";

  const handleLogout = () => { clearAuth(); navigate("/login"); };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button style={{
          display: "flex",
          alignItems: "center",
          gap: 6,
          fontSize: 12,
          color: "#8B95A7",
          background: "none",
          border: "none",
          cursor: "pointer",
          borderRadius: 6,
          padding: "3px 6px",
          transition: "all 120ms",
        }}>
          <div style={{
            width: 26,
            height: 26,
            borderRadius: "50%",
            position: "relative",
            overflow: "hidden",
            flexShrink: 0,
            background: "linear-gradient(135deg, #2563EB, #38BDF8)",
          }}>
            <div style={{
              position: "absolute", inset: 0,
              display: "flex", alignItems: "center", justifyContent: "center",
              color: "#fff", fontSize: 10, fontWeight: 700,
            }}>
              {initial}
            </div>
            {user?.avatar_url && (
              <img
                src={user.avatar_url}
                alt=""
                style={{ position: "absolute", inset: 0, width: "100%", height: "100%", objectFit: "cover" }}
                onError={(e) => { (e.target as HTMLImageElement).style.display = "none" }}
              />
            )}
          </div>
          <span style={{ maxWidth: 100, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
            {displayName}
          </span>
          <ChevronDown size={12} style={{ opacity: 0.5 }} />
        </button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="w-[200px]">
        <div className="px-2 py-2 border-b border-border mb-1">
          <p className="text-sm font-medium text-text-primary truncate">{displayName}</p>
          {user?.email && (
            <p className="text-xs text-text-muted truncate">{user.email}</p>
          )}
        </div>
        <DropdownMenuItem onSelect={() => navigate("/settings")}>
          <Settings className="w-3.5 h-3.5" />
          Settings &amp; Profile
        </DropdownMenuItem>
        <DropdownMenuSeparator />
        <DropdownMenuItem
          onSelect={handleLogout}
          className="text-severity-critical focus:text-severity-critical focus:bg-severity-critical/10"
        >
          <LogOut className="w-3.5 h-3.5" />
          Sign out
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  );
}

// ─── Tenant selector ──────────────────────────────────────────────────────────

function TenantSelector() {
  const navigate       = useNavigate();
  const activeTenant   = useTenantStore((s) => s.activeTenant);
  const setStoreTenant = useTenantStore((s) => s.setActiveTenant);
  const setAuthTenant  = useAuthStore((s) => s.setActiveTenant);
  const queryClient    = useQueryClient();

  const [open,        setOpen]        = useState(false);
  const [tenants,     setTenants]     = useState<Tenant[]>([]);
  const [loading,     setLoading]     = useState(false);
  const [creating,    setCreating]    = useState(false);
  const [newName,     setNewName]     = useState("");
  const [createError, setCreateError] = useState<string | null>(null);

  const openDropdown = async () => {
    setOpen(true);
    setLoading(true);
    try {
      const list = await fetchMyTenants();
      setTenants(list);
    } catch {
      setTenants([]);
    } finally {
      setLoading(false);
    }
  };

  const selectTenant = (t: Tenant) => {
    const role: MemberRole = t.member_role ?? "owner";
    setStoreTenant(t, role);
    setAuthTenant(t.id);
    setOpen(false);
    queryClient.clear();
  };

  const handleCreate = async () => {
    if (!newName.trim()) return;
    setCreating(true);
    setCreateError(null);
    try {
      const tenant = await createTenant(newName.trim());
      selectTenant(tenant);
      setNewName("");
      navigate("/dashboard");
    } catch {
      setCreateError("Failed to create workspace. Try again.");
    } finally {
      setCreating(false);
    }
  };

  return (
    <div style={{ position: "relative" }}>
      <button
        onClick={openDropdown}
        style={{
          display: "flex", alignItems: "center", gap: 5,
          fontSize: 12, fontWeight: activeTenant ? 600 : 400,
          color: activeTenant ? "#B8C0CC" : "#F59E0B",
          background: activeTenant ? "rgba(255,255,255,0.03)" : "rgba(245,158,11,0.08)",
          border: activeTenant ? "1px solid rgba(255,255,255,0.07)" : "1px solid rgba(245,158,11,0.2)",
          borderRadius: 6, padding: "3px 8px",
          cursor: "pointer",
          maxWidth: 160,
          overflow: "hidden",
          textOverflow: "ellipsis",
          whiteSpace: "nowrap",
          transition: "all 120ms",
        }}
      >
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
          {activeTenant ? activeTenant.name : "No workspace"}
        </span>
        <ChevronDown size={11} style={{ color: "#5C6373", flexShrink: 0 }} />
      </button>

      {open && (
        <>
          <div onClick={() => setOpen(false)} style={{ position: "fixed", inset: 0, zIndex: 99 }} />
          <div style={{
            position: "absolute", top: "calc(100% + 6px)", left: 0,
            background: "#111111", border: "1px solid rgba(255,255,255,0.1)",
            borderRadius: 8, zIndex: 100, minWidth: 220, overflow: "hidden",
            boxShadow: "0 8px 32px rgba(0,0,0,0.6)",
          }}>
            {loading && (
              <div style={{ padding: "12px 14px", display: "flex", alignItems: "center", gap: 8, color: "#5C6373", fontSize: 12 }}>
                <Loader size={12} className="animate-spin" /> Loading…
              </div>
            )}

            {!loading && tenants.length > 0 && (
              <>
                <div style={{ padding: "6px 10px 4px", fontSize: 9, fontWeight: 700, textTransform: "uppercase", letterSpacing: "1px", color: "#5C6373" }}>
                  Your workspaces
                </div>
                {tenants.map((t) => (
                  <button
                    key={t.id}
                    onClick={() => selectTenant(t)}
                    style={{
                      display: "flex", alignItems: "center", width: "100%",
                      padding: "8px 14px", background: activeTenant?.id === t.id ? "rgba(59,130,246,0.1)" : "transparent",
                      border: "none", color: activeTenant?.id === t.id ? "#93C5FD" : "#F5F7FA",
                      fontSize: 13, cursor: "pointer", textAlign: "left",
                      transition: "background 120ms",
                    }}
                  >
                    <span style={{ flex: 1 }}>{t.name}</span>
                    {activeTenant?.id === t.id && (
                      <span style={{ fontSize: 9, color: "#60A5FA", fontFamily: "monospace" }}>ACTIVE</span>
                    )}
                  </button>
                ))}
                <div style={{ borderTop: "1px solid rgba(255,255,255,0.06)", margin: "4px 0" }} />
              </>
            )}

            {!loading && (
              <div style={{ padding: "8px 10px" }}>
                {!creating ? (
                  <button
                    onClick={() => setCreating(true)}
                    style={{
                      display: "flex", alignItems: "center", gap: 6, width: "100%",
                      padding: "7px 8px", background: "transparent", border: "none",
                      color: "#8B95A7", fontSize: 12, cursor: "pointer",
                      borderRadius: 5, transition: "background 120ms",
                    }}
                  >
                    <Plus size={12} /> New workspace
                  </button>
                ) : (
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    <div style={{ display: "flex", gap: 6 }}>
                      <input
                        autoFocus
                        className="inp"
                        style={{ flex: 1, fontSize: 12, height: 30, padding: "0 8px" }}
                        placeholder="Workspace name"
                        value={newName}
                        onChange={(e) => { setNewName(e.target.value); setCreateError(null); }}
                        onKeyDown={(e) => { if (e.key === "Enter") handleCreate(); if (e.key === "Escape") setCreating(false); }}
                      />
                      <button
                        onClick={handleCreate}
                        disabled={!newName.trim()}
                        style={{
                          padding: "0 10px", height: 30, borderRadius: 5, fontSize: 11,
                          background: "rgba(59,130,246,0.15)", border: "1px solid rgba(59,130,246,0.3)",
                          color: "#93C5FD", cursor: "pointer",
                        }}
                      >
                        Create
                      </button>
                    </div>
                    {createError && (
                      <p style={{ margin: 0, fontSize: 11, color: "#F87171" }}>{createError}</p>
                    )}
                  </div>
                )}
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}

// ─── Divider ──────────────────────────────────────────────────────────────────

function Divider() {
  return <div style={{ width: 1, height: 16, background: "rgba(255,255,255,0.06)", flexShrink: 0 }} />;
}

// ─── TopBar ───────────────────────────────────────────────────────────────────

export function TopBar() {
  const openCommandPalette = useUIStore((s) => s.openCommandPalette);
  const hasRole = useTenantStore((s) => s.hasRole);
  const [handoffOpen, setHandoffOpen] = useState(false);

  return (
    <>
      <header style={{
        height: 50,
        background: "#0A0A0A",
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        display: "flex",
        alignItems: "center",
        padding: "0 20px",
        gap: 12,
        flexShrink: 0,
      }}>

        {/* Left: Tenant selector + breadcrumb */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, flex: 1, minWidth: 0 }}>
          <TenantSelector />
          <Divider />
          <Breadcrumb />
        </div>

        {/* Right: actions */}
        <div style={{ display: "flex", alignItems: "center", gap: 10, flexShrink: 0 }}>

          {/* Clock */}
          <Clock />

          <Divider />

          {/* Search / Command Palette trigger */}
          <button
            onClick={openCommandPalette}
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "5px 10px",
              borderRadius: 6,
              background: "rgba(255,255,255,0.04)",
              border: "1px solid rgba(255,255,255,0.09)",
              color: "#8B95A7",
              fontSize: 12,
              cursor: "pointer",
              transition: "all 120ms",
              minWidth: 160,
            }}
            aria-label="Open command palette (⌘K)"
            onMouseOver={(e) => {
              (e.currentTarget as HTMLButtonElement).style.background = "rgba(255,255,255,0.07)";
              (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(255,255,255,0.14)";
              (e.currentTarget as HTMLButtonElement).style.color = "#F5F7FA";
            }}
            onMouseOut={(e) => {
              (e.currentTarget as HTMLButtonElement).style.background = "rgba(255,255,255,0.04)";
              (e.currentTarget as HTMLButtonElement).style.borderColor = "rgba(255,255,255,0.09)";
              (e.currentTarget as HTMLButtonElement).style.color = "#8B95A7";
            }}
          >
            <Search size={12} style={{ flexShrink: 0 }} />
            <span style={{ flex: 1, textAlign: "left" }}>Search…</span>
            <kbd style={{
              fontSize: 9, color: "#5C6373", fontFamily: "monospace",
              background: "rgba(255,255,255,0.06)",
              border: "1px solid rgba(255,255,255,0.1)",
              borderRadius: 3,
              padding: "1px 4px",
            }}>⌘K</kbd>
          </button>

          <Divider />

          {/* Shift handoff */}
          {hasRole("analyst") && (
            <>
              <button
                onClick={() => setHandoffOpen(true)}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: 5,
                  padding: "4px 9px",
                  borderRadius: 5,
                  background: "rgba(255,255,255,0.03)",
                  border: "1px solid rgba(255,255,255,0.07)",
                  color: "#5C6373",
                  fontSize: 11,
                  cursor: "pointer",
                  transition: "all 120ms",
                }}
                aria-label="Open shift handoff"
              >
                <ClipboardList size={11} />
                <span>Handoff</span>
              </button>
              <Divider />
            </>
          )}

          {/* Connection status */}
          <ConnectionStatus />

          <Divider />

          {/* Notification bell */}
          <NotificationBell />

          <Divider />

          {/* User menu */}
          <UserMenu />
        </div>
      </header>

      <ShiftHandoffModal open={handoffOpen} onClose={() => setHandoffOpen(false)} />
    </>
  );
}
