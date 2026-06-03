import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  AlertTriangle,
  ShieldCheck,
  Database,
  Crosshair,
  BookOpen,
  Server,
  Brain,
  Settings,
  ChevronLeft,
  ChevronRight,
  LogOut,
} from "lucide-react";
import { cn } from "@/lib/utils";
import { useUIStore } from "@/stores/uiStore";
import { useAuthStore } from "@/stores/authStore";
import { Tooltip } from "@/components/ui/Tooltip";
import { LogoFull, LogoIcon } from "@/components/ui/Logo";

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
      { label: "Dashboard",       icon: LayoutDashboard, to: "/dashboard" },
      { label: "Alerts",          icon: AlertTriangle,   to: "/alerts" },
      { label: "Investigations",  icon: ShieldCheck,     to: "/investigations" },
    ],
  },
  {
    title: "Investigate",
    items: [
      { label: "Events",          icon: Database,  to: "/events" },
      { label: "Threat Hunt",     icon: Crosshair, to: "/hunt" },
      { label: "Detection Rules", icon: BookOpen,  to: "/rules" },
    ],
  },
  {
    title: "AI & Response",
    items: [
      { label: "AI Copilot", icon: Brain,  to: "/copilot" },
      { label: "Agents",     icon: Server, to: "/agents" },
    ],
  },
  {
    title: "Platform",
    items: [
      { label: "Settings", icon: Settings, to: "/settings" },
    ],
  },
];

export function Sidebar() {
  const collapsed = useUIStore((s) => s.sidebarCollapsed);
  const toggle    = useUIStore((s) => s.toggleSidebar);
  const user      = useAuthStore((s) => s.user);
  const clearAuth = useAuthStore((s) => s.clearAuth);

  const initials = user?.full_name
    ? user.full_name.split(" ").map((n) => n[0]).join("").slice(0, 2).toUpperCase()
    : (user?.email?.[0] ?? "U").toUpperCase();

  return (
    <aside
      className={cn(
        "relative flex-shrink-0 flex flex-col h-full border-r transition-all duration-200",
        collapsed ? "w-16" : "w-60"
      )}
      style={{ background: "#050505", borderColor: "#1C1C1C" }}
    >
      {/* Logo */}
      <div
        className="flex items-center h-14 px-3 flex-shrink-0 border-b"
        style={{ borderColor: "#1C1C1C" }}
      >
        {collapsed ? (
          <div className="flex items-center justify-center w-full">
            <LogoIcon size={30} />
          </div>
        ) : (
          <div className="flex items-center justify-between w-full">
            <LogoFull size={30} />
            <button
              onClick={toggle}
              className="p-1 rounded text-text-muted hover:text-text-primary transition-colors"
              aria-label="Collapse sidebar"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
          </div>
        )}
      </div>

      {/* Nav */}
      <nav className="flex-1 overflow-y-auto py-3 px-2 space-y-4">
        {NAV_SECTIONS.map((section) => (
          <div key={section.title}>
            {!collapsed && (
              <p
                className="px-3 mb-1.5 text-2xs font-semibold uppercase tracking-widest"
                style={{ color: "rgba(96,165,250,0.4)" }}
              >
                {section.title}
              </p>
            )}
            {collapsed && (
              <div className="my-2 h-px mx-2" style={{ background: "#1C1C1C" }} />
            )}
            <ul className="space-y-0.5">
              {section.items.map((item) => (
                <li key={item.to}>
                  {collapsed ? (
                    <Tooltip content={item.label} side="right">
                      <NavLink
                        to={item.to}
                        className={({ isActive }) =>
                          cn(
                            "flex items-center justify-center w-10 h-10 mx-auto rounded-lg transition-all duration-150",
                            isActive
                              ? "bg-primary-600/20 text-primary-400"
                              : "text-text-muted hover:text-text-primary hover:bg-white/[0.04]"
                          )
                        }
                        aria-label={item.label}
                      >
                        {({ isActive }) => (
                          <item.icon
                            className={cn(
                              "w-[18px] h-[18px] flex-shrink-0",
                              isActive && "drop-shadow-[0_0_6px_rgba(59,130,246,0.7)]"
                            )}
                          />
                        )}
                      </NavLink>
                    </Tooltip>
                  ) : (
                    <NavLink
                      to={item.to}
                      className={({ isActive }) =>
                        cn(
                          "flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm font-medium transition-all duration-150",
                          "border-l-2",
                          isActive
                            ? "bg-primary-600/15 border-primary-500 text-primary-400"
                            : "border-transparent text-text-muted hover:text-text-primary hover:bg-white/[0.03]"
                        )
                      }
                    >
                      {({ isActive }) => (
                        <>
                          <item.icon
                            className={cn(
                              "w-4 h-4 flex-shrink-0",
                              isActive && "drop-shadow-[0_0_6px_rgba(59,130,246,0.7)]"
                            )}
                          />
                          <span>{item.label}</span>
                        </>
                      )}
                    </NavLink>
                  )}
                </li>
              ))}
            </ul>
          </div>
        ))}
      </nav>

      {/* Footer — user info + logout */}
      <div
        className="p-2 border-t flex-shrink-0"
        style={{ borderColor: "#1C1C1C" }}
      >
        {collapsed ? (
          <div className="flex flex-col items-center gap-2">
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold flex-shrink-0"
              style={{ background: "linear-gradient(135deg, #2563EB, #38BDF8)", color: "white" }}
            >
              {initials}
            </div>
            <button
              onClick={toggle}
              className="flex items-center justify-center w-8 h-8 rounded text-text-muted hover:text-text-primary hover:bg-white/[0.04] transition-colors"
              aria-label="Expand sidebar"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        ) : (
          <div className="flex items-center gap-2.5 px-2 py-2 rounded-lg hover:bg-white/[0.03] group transition-colors">
            <div
              className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold flex-shrink-0"
              style={{ background: "linear-gradient(135deg, #2563EB, #38BDF8)", color: "white" }}
            >
              {initials}
            </div>
            <div className="min-w-0 flex-1">
              <p className="text-xs font-medium text-text-primary truncate">
                {user?.full_name ?? user?.email ?? "User"}
              </p>
              <p className="text-2xs text-text-muted truncate capitalize">
                {user?.roles?.[0] ?? "analyst"}
              </p>
            </div>
            <button
              onClick={clearAuth}
              className="opacity-0 group-hover:opacity-100 p-1 rounded text-text-muted hover:text-critical transition-all"
              title="Sign out"
            >
              <LogOut className="w-3.5 h-3.5" />
            </button>
          </div>
        )}
      </div>
    </aside>
  );
}
