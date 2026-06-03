import { useState, useEffect } from "react";
import { ChevronDown, Search, LogOut, User, Settings } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "@/stores/authStore";
import { useTenantStore } from "@/stores/tenantStore";
import { useUIStore } from "@/stores/uiStore";
import { useRealtimeStore } from "@/stores/realtimeStore";
import { NotificationBell } from "@/components/notifications/NotificationCenter";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "@/components/ui/Dropdown";

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
      fontSize: 12,
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
  const isLive = state === "connected";
  const isConnecting = state === "connecting" || state === "reconnecting";
  const color = isLive ? "#10B981" : isConnecting ? "#F59E0B" : "#5C6373";

  return (
    <div style={{ display: "flex", alignItems: "center", gap: 5, fontSize: 11, color }}>
      {isLive ? (
        <span className="dot-live" />
      ) : (
        <span style={{ width: 6, height: 6, borderRadius: "50%", background: color, display: "inline-block" }} />
      )}
      <span>{isLive ? "Live" : isConnecting ? "Connecting…" : "Offline"}</span>
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
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            background: "linear-gradient(135deg, #2563EB, #38BDF8)",
            color: "#fff",
            fontSize: 10,
            fontWeight: 700,
            flexShrink: 0,
          }}>
            {initial}
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
        <DropdownMenuItem onSelect={() => navigate("/profile")}>
          <User className="w-3.5 h-3.5" />
          Profile
        </DropdownMenuItem>
        <DropdownMenuItem onSelect={() => navigate("/settings")}>
          <Settings className="w-3.5 h-3.5" />
          Settings
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
  const activeTenant = useTenantStore((s) => s.activeTenant);
  if (!activeTenant) return <span style={{ fontSize: 12, color: "#5C6373" }}>No tenant</span>;
  return (
    <button style={{
      display: "flex",
      alignItems: "center",
      gap: 5,
      fontSize: 13,
      fontWeight: 600,
      color: "#F5F7FA",
      background: "none",
      border: "none",
      cursor: "pointer",
      padding: 0,
    }}>
      {activeTenant.name}
      <ChevronDown size={12} style={{ color: "#5C6373" }} />
    </button>
  );
}

// ─── TopBar ───────────────────────────────────────────────────────────────────

export function TopBar() {
  const openCommandPalette = useUIStore((s) => s.openCommandPalette);

  return (
    <header style={{
      height: 50,
      background: "#0A0A0A",
      borderBottom: "1px solid rgba(255,255,255,0.06)",
      display: "flex",
      alignItems: "center",
      padding: "0 20px",
      gap: 16,
      flexShrink: 0,
    }}>
      {/* Tenant selector */}
      <TenantSelector />

      {/* Right side */}
      <div style={{ marginLeft: "auto", display: "flex", alignItems: "center", gap: 14 }}>

        {/* Clock */}
        <Clock />

        {/* Divider */}
        <div style={{ width: 1, height: 16, background: "rgba(255,255,255,0.06)" }} />

        {/* Command palette trigger */}
        <button
          onClick={openCommandPalette}
          style={{
            display: "flex",
            alignItems: "center",
            gap: 5,
            padding: "3px 8px",
            borderRadius: 5,
            background: "rgba(255,255,255,0.03)",
            border: "1px solid rgba(255,255,255,0.07)",
            color: "#5C6373",
            fontSize: 11,
            cursor: "pointer",
            transition: "all 120ms",
          }}
          aria-label="Open command palette"
        >
          <Search size={11} />
          <span>Search</span>
          <kbd style={{ fontSize: 9, opacity: 0.6, fontFamily: "monospace" }}>⌘K</kbd>
        </button>

        {/* Divider */}
        <div style={{ width: 1, height: 16, background: "rgba(255,255,255,0.06)" }} />

        {/* Connection status */}
        <ConnectionStatus />

        {/* Divider */}
        <div style={{ width: 1, height: 16, background: "rgba(255,255,255,0.06)" }} />

        {/* Notification bell */}
        <NotificationBell />

        {/* Divider */}
        <div style={{ width: 1, height: 16, background: "rgba(255,255,255,0.06)" }} />

        {/* User menu */}
        <UserMenu />
      </div>
    </header>
  );
}
