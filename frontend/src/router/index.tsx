import { lazy, Suspense } from "react";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { AuthGuard } from "@/features/auth/AuthGuard";
import { LoginPage } from "@/features/auth/LoginPage";
import { RegisterPage } from "@/features/auth/RegisterPage";
import { NotFound } from "@/pages/NotFound";
import { Unauthorized } from "@/pages/Unauthorized";

// ─── Lazy-loaded shell ────────────────────────────────────────────────────────

const AppShell = lazy(() =>
  import("@/components/layout/AppShell").then((m) => ({ default: m.AppShell }))
);

// ─── Lazy-loaded pages ────────────────────────────────────────────────────────

const DashboardPage = lazy(() =>
  import("@/features/dashboard/DashboardPage").then((m) => ({ default: m.DashboardPage }))
);
const AlertsPage = lazy(() =>
  import("@/features/alerts/AlertsPage").then((m) => ({ default: m.AlertsPage }))
);
const InvestigationsPage = lazy(() =>
  import("@/features/investigations/InvestigationsPage").then((m) => ({ default: m.InvestigationsPage }))
);
const InvestigationDetailPage = lazy(() =>
  import("@/features/investigations/InvestigationDetailPage").then((m) => ({ default: m.InvestigationDetailPage }))
);
const EventsPage = lazy(() =>
  import("@/features/events/EventsPage").then((m) => ({ default: m.EventsPage }))
);
const HuntPage = lazy(() =>
  import("@/features/hunt/HuntPage").then((m) => ({ default: m.HuntPage }))
);
const GraphPage = lazy(() =>
  import("@/features/graph/GraphPage").then((m) => ({ default: m.GraphPage }))
);
const AgentsPage = lazy(() =>
  import("@/features/agents/AgentsPage").then((m) => ({ default: m.AgentsPage }))
);
const CopilotPage = lazy(() =>
  import("@/features/copilot/CopilotPage").then((m) => ({ default: m.CopilotPage }))
);
const InstallerPage = lazy(() =>
  import("@/features/installer/InstallerPage").then((m) => ({ default: m.InstallerPage }))
);
const SettingsPage = lazy(() =>
  import("@/features/settings/SettingsPage").then((m) => ({ default: m.SettingsPage }))
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
  { path: "/login",    element: <LoginPage /> },
  { path: "/register", element: <RegisterPage /> },
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
      { index: true,              element: <S><DashboardPage /></S> },
      { path: "dashboard",        element: <S><DashboardPage /></S> },
      { path: "alerts",           element: <S><AlertsPage /></S> },
      { path: "investigations",          element: <S><InvestigationsPage /></S> },
      { path: "investigations/:id",     element: <S><InvestigationDetailPage /></S> },
      { path: "events",           element: <S><EventsPage /></S> },
      { path: "hunt",             element: <S><HuntPage /></S> },
      { path: "graph",            element: <S><GraphPage /></S> },
      { path: "agents",           element: <S><AgentsPage /></S> },
      { path: "copilot",          element: <S><CopilotPage /></S> },
      { path: "installer",        element: <S><InstallerPage /></S> },
      { path: "settings",         element: <S><SettingsPage /></S> },
    ],
  },

  // 404
  { path: "*", element: <NotFound /> },
]);

export function AppRouter() {
  return <RouterProvider router={router} />;
}
