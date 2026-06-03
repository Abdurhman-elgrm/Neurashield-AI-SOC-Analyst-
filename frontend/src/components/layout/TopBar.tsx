import { ChevronDown, Command, Wifi, WifiOff, LogOut, User, Settings } from "lucide-react";
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
import { cn } from "@/lib/utils";

// ─── ConnectionStatus ─────────────────────────────────────────────────────────

function ConnectionStatus() {
  const state = useRealtimeStore((s) => s.connectionState);

  const isLive = state === "connected";
  const isConnecting = state === "connecting" || state === "reconnecting";

  return (
    <div
      className={cn(
        "flex items-center gap-1.5 text-xs",
        isLive ? "text-status-online" : isConnecting ? "text-severity-medium" : "text-text-muted"
      )}
    >
      {isLive ? (
        <Wifi className="w-3.5 h-3.5" />
      ) : (
        <WifiOff className="w-3.5 h-3.5" />
      )}
      <span className="hidden sm:inline">
        {isLive ? "Live" : isConnecting ? "Connecting…" : "Offline"}
      </span>
    </div>
  );
}

// ─── UserMenu ─────────────────────────────────────────────────────────────────

function UserMenu() {
  const user = useAuthStore((s) => s.user);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const navigate = useNavigate();

  const initial = user?.full_name?.[0]?.toUpperCase() ?? user?.email?.[0]?.toUpperCase() ?? "U";
  const displayName = user?.full_name || user?.email || "User";

  const handleLogout = () => {
    clearAuth();
    navigate("/login");
  };

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <button className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary transition-colors rounded px-1.5 py-1 hover:bg-bg-subtle">
          <div
            className="w-7 h-7 rounded-full flex items-center justify-center flex-shrink-0 text-xs font-semibold text-white"
            style={{ background: "linear-gradient(135deg, #2563EB, #38BDF8)" }}
          >
            {initial}
          </div>
          <span className="hidden md:inline max-w-[120px] truncate">{displayName}</span>
          <ChevronDown className="w-3.5 h-3.5 text-text-muted" />
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

// ─── TopBar ───────────────────────────────────────────────────────────────────

export function TopBar() {
  const activeTenant = useTenantStore((s) => s.activeTenant);
  const openCommandPalette = useUIStore((s) => s.openCommandPalette);

  return (
    <header className="h-14 flex items-center justify-between px-6 border-b border-border bg-bg-surface flex-shrink-0">
      {/* Left: tenant context */}
      <div className="flex items-center gap-3">
        {activeTenant ? (
          <button className="flex items-center gap-2 text-sm text-text-secondary hover:text-text-primary transition-colors">
            <span className="font-medium text-text-primary">{activeTenant.name}</span>
            <ChevronDown className="w-3.5 h-3.5" />
          </button>
        ) : (
          <span className="text-sm text-text-muted">No tenant selected</span>
        )}
      </div>

      {/* Right: command trigger + status + notifications + user */}
      <div className="flex items-center gap-2">
        {/* Cmd+K trigger */}
        <button
          onClick={openCommandPalette}
          className="hidden sm:flex items-center gap-1.5 px-2.5 py-1.5 rounded border border-border text-xs text-text-muted hover:text-text-primary hover:bg-bg-subtle transition-colors"
          aria-label="Open command palette"
        >
          <Command className="w-3 h-3" />
          <span>Search</span>
          <kbd className="ml-1 px-1 py-0.5 rounded bg-bg-subtle border border-border font-mono text-2xs">
            ⌘K
          </kbd>
        </button>

        <div className="w-px h-5 bg-border" />
        <ConnectionStatus />
        <div className="w-px h-5 bg-border" />
        <NotificationBell />
        <div className="w-px h-5 bg-border" />
        <UserMenu />
      </div>
    </header>
  );
}
