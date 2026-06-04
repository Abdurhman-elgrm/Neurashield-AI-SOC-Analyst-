import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { CommandPalette } from "@/components/command/CommandPalette";
import { Toaster } from "@/components/ui/Toaster";
import { KeyboardShortcuts } from "@/hooks/useKeyboard";
import { useTenantInit } from "@/hooks/useTenantInit";

export function AppShell() {
  useTenantInit();
  return (
    <div style={{ display: "flex", height: "100vh", background: "#000000", overflow: "hidden" }}>
      {/* Fixed sidebar */}
      <Sidebar />

      {/* Main column — offset by sidebar width */}
      <div style={{
        flex: 1,
        marginLeft: 220,
        display: "flex",
        flexDirection: "column",
        minWidth: 0,
        overflow: "hidden",
      }}>
        {/* Fixed-height topbar */}
        <TopBar />

        {/* Scrollable page area */}
        <main
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
      <KeyboardShortcuts />
    </div>
  );
}
