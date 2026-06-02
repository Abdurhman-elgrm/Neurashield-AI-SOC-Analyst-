import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  AlertTriangle,
  Search,
  Server,
  Settings,
  Users,
  ShieldCheck,
  Activity,
  FileSearch,
  KeyRound,
  Network,
  Brain,
  ChevronLeft,
  ChevronRight,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useUIStore } from "@/stores/uiStore";
import { Tooltip } from "@/components/ui/Tooltip";

interface NavItem {
  label: string;
  icon: React.ElementType;
  to: string;
}

interface NavSection {
  title: string;
  items: NavItem[];
}

const NAV_SECTIONS: NavSection[] = [
  {
    title: "Operations",
    items: [
      { label: "Overview",      icon: LayoutDashboard, to: "/dashboard" },
      { label: "Alerts",        icon: AlertTriangle,   to: "/alerts" },
      { label: "Investigations",icon: ShieldCheck,     to: "/investigations" },
    ],
  },
  {
    title: "Investigate",
    items: [
      { label: "Log Explorer",  icon: FileSearch, to: "/events" },
      { label: "Threat Hunt",   icon: Search,     to: "/hunt" },
      { label: "Graph Analysis",icon: Network,    to: "/graph" },
    ],
  },
  {
    title: "AI",
    items: [
      { label: "AI Copilot",    icon: Brain,  to: "/copilot" },
    ],
  },
  {
    title: "Response",
    items: [
      { label: "Agents",        icon: Server,   to: "/agents" },
      { label: "Installer",     icon: KeyRound, to: "/installer" },
    ],
  },
  {
    title: "Platform",
    items: [
      { label: "Team",          icon: Users,    to: "/team" },
      { label: "Settings",      icon: Settings, to: "/settings" },
    ],
  },
];

export function Sidebar() {
  const collapsed = useUIStore((s) => s.sidebarCollapsed);
  const toggleSidebar = useUIStore((s) => s.toggleSidebar);

  return (
    <aside
      className={cn(
        "flex-shrink-0 flex flex-col h-full bg-bg-surface border-r border-border transition-all duration-200",
        collapsed ? "w-[56px]" : "w-[220px]"
      )}
    >
      {/* Logo + collapse toggle */}
      <div className="flex items-center h-14 border-b border-border px-3 flex-shrink-0">
        <div
          className={cn(
            "flex items-center gap-2.5 flex-1 min-w-0",
            collapsed && "justify-center"
          )}
        >
          <div className="w-7 h-7 rounded-md bg-accent/10 border border-accent/30 flex items-center justify-center flex-shrink-0">
            <Activity className="w-4 h-4 text-accent" />
          </div>
          {!collapsed && (
            <span className="text-sm font-semibold text-text-primary truncate">
              SOC Platform
            </span>
          )}
        </div>
        {!collapsed && (
          <button
            onClick={toggleSidebar}
            className="ml-auto p-1 rounded text-text-muted hover:text-text-primary hover:bg-bg-subtle transition-colors flex-shrink-0"
            aria-label="Collapse sidebar"
          >
            <ChevronLeft className="w-4 h-4" />
          </button>
        )}
      </div>

      {/* Navigation */}
      <nav className="flex-1 overflow-y-auto py-3 px-2">
        {NAV_SECTIONS.map((section) => (
          <div key={section.title} className={cn("mb-4", collapsed && "mb-2")}>
            {!collapsed && (
              <p className="px-3 mb-1 text-2xs font-semibold uppercase tracking-wider text-text-muted">
                {section.title}
              </p>
            )}
            {collapsed && <div className="my-1 h-px bg-border mx-1" />}
            <ul className="space-y-0.5">
              {section.items.map((item) => (
                <li key={item.to}>
                  {collapsed ? (
                    <Tooltip content={item.label} side="right">
                      <NavLink
                        to={item.to}
                        className={({ isActive }) =>
                          cn(
                            "flex items-center justify-center w-9 h-9 mx-auto rounded transition-colors",
                            isActive
                              ? "bg-bg-subtle text-accent"
                              : "text-text-muted hover:text-text-primary hover:bg-bg-subtle"
                          )
                        }
                        aria-label={item.label}
                      >
                        <item.icon className="w-4 h-4 flex-shrink-0" />
                      </NavLink>
                    </Tooltip>
                  ) : (
                    <NavLink
                      to={item.to}
                      className={({ isActive }) =>
                        cn(
                          "sidebar-item",
                          isActive && "sidebar-item-active text-text-primary bg-bg-subtle"
                        )
                      }
                    >
                      <item.icon className="w-4 h-4 flex-shrink-0" />
                      <span>{item.label}</span>
                    </NavLink>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      {/* Footer */}
      <div className="p-2 border-t border-border flex-shrink-0">
        {collapsed ? (
          <button
            onClick={toggleSidebar}
            className="flex items-center justify-center w-9 h-9 mx-auto rounded text-text-muted hover:text-text-primary hover:bg-bg-subtle transition-colors"
            aria-label="Expand sidebar"
          >
            <ChevronRight className="w-4 h-4" />
          </button>
        ) : (
          <div className="flex items-center gap-2 px-2 py-1.5">
            <div className="w-6 h-6 rounded-full bg-accent/20 flex items-center justify-center flex-shrink-0">
              <span className="text-xs font-medium text-accent">U</span>
            </div>
            <div className="min-w-0">
              <p className="text-xs font-medium text-text-primary truncate">User</p>
              <p className="text-2xs text-text-muted truncate">Analyst</p>
            </div>
          </div>
        )}
      </div>
    </aside>
  );
}
