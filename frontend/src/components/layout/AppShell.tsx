import { Outlet } from "react-router-dom";
import { Sidebar } from "./Sidebar";
import { TopBar } from "./TopBar";
import { CommandPalette } from "@/components/command/CommandPalette";
import { Toaster } from "@/components/ui/Toaster";
import { KeyboardShortcuts } from "@/hooks/useKeyboard";

export function AppShell() {
  return (
    <div className="flex h-screen bg-bg-base overflow-hidden">
      <Sidebar />

      <div className="flex flex-col flex-1 min-w-0 overflow-hidden">
        <TopBar />

        <main className="flex-1 overflow-y-auto p-6">
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
