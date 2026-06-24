import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { CommandPalette } from "@/components/command/CommandPalette";
import { Toaster } from "@/components/ui/Toaster";
import { ShortcutsModal } from "@/components/ui/ShortcutsModal";
import { KeyboardShortcuts } from "@/hooks/useKeyboard";
import { useTenantInit } from "@/hooks/useTenantInit";
import { useTenantCacheReset } from "@/hooks/useTenantCacheReset";
import { useUIStore } from "@/stores/uiStore";

export function AppShell() {
  useTenantInit();
  useTenantCacheReset();

  const collapsed = useUIStore((s) => s.sidebarCollapsed);
  const sidebarW  = collapsed ? 48 : 220;

  return (
    <div style={{ display: "flex", height: "100vh", background: "#000000", overflow: "hidden" }}>
      {/* Skip navigation — visible on focus for keyboard users */}
      <a
        href="#main-content"
        className="sr-only focus:not-sr-only focus:fixed focus:top-2 focus:left-2 focus:z-[200] focus:px-4 focus:py-2 focus:text-xs focus:font-semibold focus:text-text-primary focus:bg-bg-elevated focus:border focus:border-accent focus:rounded-lg"
      >
        Skip to main content
      </a>

      {/* Fixed sidebar */}
      <Sidebar />

      {/* Main column — offset by sidebar width (animated) */}
      <div style={{
        flex: 1,
        marginLeft: sidebarW,
        display: "flex",
        flexDirection: "column",
        minWidth: 0,
        overflow: "hidden",
        transition: "margin-left 200ms cubic-bezier(0.4,0,0.2,1)",
      }}>
        {/* Fixed-height topbar */}
        <TopBar />

        {/* Scrollable page area */}
        <main
          id="main-content"
          tabIndex={-1}
          className="page-in"
          style={{
            flex: 1,
            overflowY: "auto",
            padding: "20px 24px",
          }}
        >
          <Outlet />
        </main>
      </div>

      {/* Global overlays */}
      <CommandPalette />
      <Toaster />
      <ShortcutsModal />
      <KeyboardShortcuts />
    </div>
  );
}
