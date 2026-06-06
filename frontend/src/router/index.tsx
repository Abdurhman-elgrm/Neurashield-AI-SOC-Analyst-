import { lazy, Suspense, Component } from "react";
import type { ReactNode, ErrorInfo } from "react";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { AuthGuard } from "@/features/auth/AuthGuard";
import { LoginPage } from "@/features/auth/LoginPage";
import { RegisterPage } from "@/features/auth/RegisterPage";
import { NotFound } from "@/pages/NotFound";
import { Unauthorized } from "@/pages/Unauthorized";

// ─── Chunk-load error boundary ────────────────────────────────────────────────
// After a new deployment the old hashed chunk URLs 404. Catch that error
// and do a hard reload so the browser fetches the fresh index.html + new chunks.

const RELOAD_KEY = "__chunk_reload";

class ChunkErrorBoundary extends Component<
  { children: ReactNode },
  { errored: boolean }
> {
  state = { errored: false };

  componentDidCatch(error: Error, _info: ErrorInfo) {
    const isChunkError =
      error.message.includes("Failed to fetch dynamically imported module") ||
      error.message.includes("Importing a module script failed") ||
      error.name === "ChunkLoadError";

    if (isChunkError) {
      // Guard against reload loops: only reload once per session
      const alreadyReloaded = sessionStorage.getItem(RELOAD_KEY);
      if (!alreadyReloaded) {
        sessionStorage.setItem(RELOAD_KEY, "1");
        window.location.reload();
        return;
      }
    }
    this.setState({ errored: true });
  }

  static getDerivedStateFromError() {
    return { errored: true };
  }

  render() {
    if (this.state.errored) {
      return (
        <div style={{
          display: "flex", flexDirection: "column",
          alignItems: "center", justifyContent: "center",
          minHeight: "100vh", background: "#000",
          color: "#8B95A7", fontSize: 13, gap: 12,
        }}>
          <div style={{ fontSize: 14, color: "#F5F7FA", fontWeight: 600 }}>
            Something went wrong
          </div>
          <button
            onClick={() => {
              sessionStorage.removeItem(RELOAD_KEY);
              window.location.reload();
            }}
            style={{
              padding: "6px 16px", borderRadius: 6, fontSize: 12,
              background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.3)",
              color: "#93C5FD", cursor: "pointer",
            }}
          >
            Reload page
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

// ─── Lazy loader with auto-retry on chunk error ───────────────────────────────

function lazyPage<T extends React.ComponentType<unknown>>(
  factory: () => Promise<{ default: T }>
): React.LazyExoticComponent<T> {
  return lazy(() =>
    factory().catch((err: Error) => {
      const isChunkError =
        err.message.includes("Failed to fetch dynamically imported module") ||
        err.message.includes("Importing a module script failed") ||
        err.name === "ChunkLoadError";

      if (isChunkError && !sessionStorage.getItem(RELOAD_KEY)) {
        sessionStorage.setItem(RELOAD_KEY, "1");
        window.location.reload();
      }
      throw err;
    })
  );
}

// ─── Lazy-loaded shell ────────────────────────────────────────────────────────

const AppShell = lazyPage(() =>
  import("@/components/layout/AppShell").then((m) => ({ default: m.AppShell }))
);

// ─── Lazy-loaded pages ────────────────────────────────────────────────────────

const DashboardPage = lazyPage(() =>
  import("@/features/dashboard/DashboardPage").then((m) => ({ default: m.DashboardPage }))
);
const AlertsPage = lazyPage(() =>
  import("@/features/alerts/AlertsPage").then((m) => ({ default: m.AlertsPage }))
);
const InvestigationsPage = lazyPage(() =>
  import("@/features/investigations/InvestigationsPage").then((m) => ({ default: m.InvestigationsPage }))
);
const InvestigationDetailPage = lazyPage(() =>
  import("@/features/investigations/InvestigationDetailPage").then((m) => ({ default: m.InvestigationDetailPage }))
);
const EventsPage = lazyPage(() =>
  import("@/features/events/EventsPage").then((m) => ({ default: m.EventsPage }))
);
const HuntPage = lazyPage(() =>
  import("@/features/hunt/HuntPage").then((m) => ({ default: m.HuntPage }))
);
const GraphPage = lazyPage(() =>
  import("@/features/graph/GraphPage").then((m) => ({ default: m.GraphPage }))
);
const AgentsPage = lazyPage(() =>
  import("@/features/agents/AgentsPage").then((m) => ({ default: m.AgentsPage }))
);
const CopilotPage = lazyPage(() =>
  import("@/features/copilot/CopilotPage").then((m) => ({ default: m.CopilotPage }))
);
const InstallerPage = lazyPage(() =>
  import("@/features/installer/InstallerPage").then((m) => ({ default: m.InstallerPage }))
);
const SettingsPage = lazyPage(() =>
  import("@/features/settings/SettingsPage").then((m) => ({ default: m.SettingsPage }))
);
const RulesPage = lazyPage(() =>
  import("@/features/rules/RulesPage").then((m) => ({ default: m.RulesPage }))
);

// ─── Loading fallback ─────────────────────────────────────────────────────────

function PageLoader() {
  return (
    <div className="min-h-screen bg-bg-base flex items-center justify-center">
      <div className="w-6 h-6 border-2 border-border-strong border-t-accent rounded-full animate-spin" />
    </div>
  );
}

function S({ children }: { children: React.ReactNode }) {
  return <Suspense fallback={<PageLoader />}>{children}</Suspense>;
}

// ─── Router ───────────────────────────────────────────────────────────────────

const router = createBrowserRouter([
  // Public routes
  { path: "/login",        element: <LoginPage /> },
  { path: "/register",     element: <RegisterPage /> },
  { path: "/unauthorized", element: <Unauthorized /> },

  // Protected routes — wrapped in AppShell
  {
    path: "/",
    element: (
      <AuthGuard>
        <S><AppShell /></S>
      </AuthGuard>
    ),
    children: [
      { index: true,                    element: <S><DashboardPage /></S> },
      { path: "dashboard",              element: <S><DashboardPage /></S> },
      { path: "alerts",                 element: <S><AlertsPage /></S> },
      { path: "investigations",         element: <S><InvestigationsPage /></S> },
      { path: "investigations/:id",     element: <S><InvestigationDetailPage /></S> },
      { path: "events",                 element: <S><EventsPage /></S> },
      { path: "hunt",                   element: <S><HuntPage /></S> },
      { path: "rules",                  element: <S><RulesPage /></S> },
      { path: "graph",                  element: <S><GraphPage /></S> },
      { path: "agents",                 element: <S><AgentsPage /></S> },
      { path: "copilot",                element: <S><CopilotPage /></S> },
      { path: "installer",              element: <S><InstallerPage /></S> },
      { path: "settings",               element: <S><SettingsPage /></S> },
    ],
  },

  // 404
  { path: "*", element: <NotFound /> },
]);

export function AppRouter() {
  return (
    <ChunkErrorBoundary>
      <RouterProvider router={router} />
    </ChunkErrorBoundary>
  );
}
