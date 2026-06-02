import { Command } from "cmdk";
import { useNavigate } from "react-router-dom";
import {
  LayoutDashboard,
  AlertTriangle,
  Search,
  Server,
  Settings,
  ShieldCheck,
  FileSearch,
  Network,
  Brain,
  KeyRound,
  LogOut,
  X,
} from "lucide-react";
import { motion, AnimatePresence } from "framer-motion";
import { useUIStore } from "@/stores/uiStore";
import { useAuthStore } from "@/stores/authStore";
import { cn } from "@/lib/utils";

// ─── Command definitions ──────────────────────────────────────────────────────

interface CommandItem {
  id: string;
  label: string;
  description?: string;
  icon: React.ReactNode;
  group: string;
  action: () => void;
  keywords?: string[];
}

function useCommandItems(): CommandItem[] {
  const navigate = useNavigate();
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const close = useUIStore((s) => s.closeCommandPalette);

  const nav = (to: string) => () => { navigate(to); close(); };

  return [
    // Navigation
    { id: "dashboard",      label: "Overview",      description: "Security operations summary", icon: <LayoutDashboard className="w-4 h-4" />, group: "Navigate", action: nav("/dashboard") },
    { id: "alerts",         label: "Alerts",         description: "Active security alerts",      icon: <AlertTriangle className="w-4 h-4" />,   group: "Navigate", action: nav("/alerts") },
    { id: "investigations", label: "Investigations", description: "Open investigations",         icon: <ShieldCheck className="w-4 h-4" />,     group: "Navigate", action: nav("/investigations") },
    { id: "events",         label: "Log Explorer",   description: "Search raw events",           icon: <FileSearch className="w-4 h-4" />,      group: "Navigate", action: nav("/events") },
    { id: "hunt",           label: "Threat Hunt",    description: "Hunt for threats",            icon: <Search className="w-4 h-4" />,          group: "Navigate", action: nav("/hunt") },
    { id: "graph",          label: "Graph Analysis", description: "Attack graph visualization", icon: <Network className="w-4 h-4" />,         group: "Navigate", action: nav("/graph") },
    { id: "agents",         label: "Agents",         description: "Deployed agents",             icon: <Server className="w-4 h-4" />,          group: "Navigate", action: nav("/agents") },
    { id: "copilot",        label: "AI Copilot",     description: "AI-powered investigation",    icon: <Brain className="w-4 h-4" />,           group: "Navigate", action: nav("/copilot") },
    { id: "settings",       label: "Settings",       description: "Platform settings",           icon: <Settings className="w-4 h-4" />,        group: "Navigate", action: nav("/settings") },
    { id: "installer",      label: "Installer",      description: "Agent installer tokens",      icon: <KeyRound className="w-4 h-4" />,        group: "Navigate", action: nav("/installer") },
    // Actions
    {
      id: "logout",
      label: "Sign out",
      icon: <LogOut className="w-4 h-4" />,
      group: "Actions",
      action: () => { clearAuth(); navigate("/login"); close(); },
    },
  ];
}

// ─── CommandPalette ───────────────────────────────────────────────────────────

export function CommandPalette() {
  const open = useUIStore((s) => s.commandPaletteOpen);
  const { closeCommandPalette } = useUIStore();
  const commands = useCommandItems();

  // Group commands
  const groups = commands.reduce<Record<string, CommandItem[]>>((acc, cmd) => {
    if (!acc[cmd.group]) acc[cmd.group] = [];
    acc[cmd.group].push(cmd);
    return acc;
  }, {});

  return (
    <AnimatePresence>
      {open && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="fixed inset-0 z-50 bg-black/60 backdrop-blur-sm"
            onClick={closeCommandPalette}
          />

          {/* Palette */}
          <motion.div
            initial={{ opacity: 0, scale: 0.96, y: -8 }}
            animate={{ opacity: 1, scale: 1, y: 0 }}
            exit={{ opacity: 0, scale: 0.96, y: -8 }}
            transition={{ duration: 0.15, ease: "easeOut" }}
            className="fixed left-1/2 top-[20vh] z-50 -translate-x-1/2 w-full max-w-[560px]"
          >
            <Command
              className="rounded-xl border border-border bg-bg-elevated shadow-panel overflow-hidden"
              loop
            >
              <div className="flex items-center gap-2 px-3 border-b border-border">
                <Search className="w-4 h-4 text-text-muted flex-shrink-0" />
                <Command.Input
                  className="flex-1 py-3.5 bg-transparent text-sm text-text-primary placeholder:text-text-muted outline-none"
                  placeholder="Search commands, navigate pages…"
                  autoFocus
                />
                <button
                  onClick={closeCommandPalette}
                  className="text-text-muted hover:text-text-primary transition-colors"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <Command.List className="max-h-[400px] overflow-y-auto py-2">
                <Command.Empty className="px-4 py-8 text-center text-sm text-text-muted">
                  No commands found
                </Command.Empty>

                {Object.entries(groups).map(([group, items]) => (
                  <Command.Group key={group} heading={group}>
                    <div className="px-2 py-1">
                      <p className="px-2 py-1 text-2xs font-semibold uppercase tracking-wider text-text-muted">
                        {group}
                      </p>
                      {items.map((cmd) => (
                        <Command.Item
                          key={cmd.id}
                          value={`${cmd.label} ${cmd.description ?? ""} ${cmd.keywords?.join(" ") ?? ""}`}
                          onSelect={cmd.action}
                          className={cn(
                            "flex items-center gap-3 px-3 py-2 rounded-md cursor-pointer",
                            "text-sm text-text-secondary",
                            "data-[selected=true]:bg-bg-subtle data-[selected=true]:text-text-primary",
                            "transition-colors duration-100"
                          )}
                        >
                          <span className="text-text-muted flex-shrink-0">{cmd.icon}</span>
                          <span className="flex-1">
                            <span className="font-medium text-text-primary">{cmd.label}</span>
                            {cmd.description && (
                              <span className="ml-2 text-xs text-text-muted">{cmd.description}</span>
                            )}
                          </span>
                        </Command.Item>
                      ))}
                    </div>
                  </Command.Group>
                ))}
              </Command.List>

              <div className="border-t border-border px-3 py-2 flex items-center gap-3 text-2xs text-text-muted">
                <span><kbd className="px-1 py-0.5 rounded bg-bg-subtle border border-border font-mono">↑↓</kbd> Navigate</span>
                <span><kbd className="px-1 py-0.5 rounded bg-bg-subtle border border-border font-mono">↵</kbd> Select</span>
                <span><kbd className="px-1 py-0.5 rounded bg-bg-subtle border border-border font-mono">Esc</kbd> Close</span>
              </div>
            </Command>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
