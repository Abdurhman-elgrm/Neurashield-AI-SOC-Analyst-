import { lazy, Suspense, Component } from "react";
import type { ReactNode, ErrorInfo } from "react";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { AuthGuard } from "@/features/auth/AuthGuard";
import { RequireRole } from "@/components/auth/RequireRole";
import { LoginPage } from "@/features/auth/LoginPage";
import { RegisterPage } from "@/features/auth/RegisterPage";
import { MFALoginPromptPage } from "@/features/auth/MFALoginPromptPage";
import { NotFound } from "@/pages/NotFound";
import { Unauthorized } from "@/pages/Unauthorized";
import { LandingPage } from "@/pages/LandingPage";
import { DocsPage } from "@/pages/DocsPage";

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
const SetupPage = lazyPage(() =>
  import("@/features/setup/SetupPage").then((m) => ({ default: m.SetupPage }))
);
const AcceptInvitePage = lazyPage(() =>
  import("@/features/auth/AcceptInvitePage").then((m) => ({ default: m.AcceptInvitePage }))
);
const ForgotPasswordPage = lazyPage(() =>
  import("@/features/auth/ForgotPasswordPage").then((m) => ({ default: m.ForgotPasswordPage }))
);
const ResetPasswordPage = lazyPage(() =>
  import("@/features/auth/ResetPasswordPage").then((m) => ({ default: m.ResetPasswordPage }))
);
const VerifyEmailPage = lazyPage(() =>
  import("@/features/auth/VerifyEmailPage").then((m) => ({ default: m.VerifyEmailPage }))
);
const MFASetupPage = lazyPage(() =>
  import("@/features/auth/MFASetupPage").then((m) => ({ default: m.MFASetupPage }))
);
const PlaybooksPage = lazyPage(() =>
  import("@/features/playbooks/PlaybooksPage").then((m) => ({ default: m.PlaybooksPage }))
);
const PlaybookDetailPage = lazyPage(() =>
  import("@/features/playbooks/PlaybookDetailPage").then((m) => ({ default: m.PlaybookDetailPage }))
);
const ReportsPage = lazyPage(() =>
  import("@/features/reports/ReportsPage").then((m) => ({ default: m.ReportsPage }))
);
const ImportPage = lazyPage(() =>
  import("@/features/import/ImportPage").then((m) => ({ default: m.ImportPage as React.ComponentType<unknown> }))
);
const SocMetricsPage = lazyPage(() =>
  import("@/features/soc-metrics/SocMetricsPage").then((m) => ({ default: m.SocMetricsPage }))
);
const AssetsPage = lazyPage(() =>
  import("@/features/assets/AssetsPage").then((m) => ({ default: m.AssetsPage }))
);
const UEBADashboard = lazyPage(() =>
  import("@/features/ueba/UEBADashboard").then((m) => ({ default: m.UEBADashboard }))
);
const AuditLogPage = lazyPage(() =>
  import("@/features/audit-log/AuditLogPage").then((m) => ({ default: m.AuditLogPage }))
);
const SuppressionRulesPage = lazyPage(() =>
  import("@/features/rules/suppression/SuppressionRulesPage").then((m) => ({ default: m.SuppressionRulesPage }))
);
const ThreatIntelPage = lazyPage(() =>
  import("@/features/threat-intel/ThreatIntelPage").then((m) => ({ default: m.ThreatIntelPage }))
);
const MitreNavigatorPage = lazyPage(() =>
  import("@/features/mitre/MitreNavigatorPage").then((m) => ({ default: m.MitreNavigatorPage }))
);
const MSSPOverviewPage = lazyPage(() =>
  import("@/features/mssp/MSSPOverviewPage").then((m) => ({ default: m.MSSPOverviewPage }))
);
const FleetDashboardPage = lazyPage(() =>
  import("@/features/fleet/FleetDashboardPage").then((m) => ({ default: m.FleetDashboardPage }))
);
const ComplianceSchedulerPage = lazyPage(() =>
  import("@/features/reports/ComplianceSchedulerPage").then((m) => ({ default: m.ComplianceSchedulerPage }))
);
const SLADashboard = lazyPage(() =>
  import("@/features/soc-metrics/SLADashboard").then((m) => ({ default: m.SLADashboard }))
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
  // ── Public marketing / docs pages (no AppShell, no auth) ──────────────────
  { path: "/",     element: <LandingPage /> },
  { path: "/docs", element: <DocsPage /> },

  // ── Auth pages ─────────────────────────────────────────────────────────────
  { path: "/login",            element: <LoginPage /> },
  { path: "/register",         element: <RegisterPage /> },
  { path: "/unauthorized",     element: <Unauthorized /> },
  { path: "/mfa-login",        element: <MFALoginPromptPage /> },
  { path: "/mfa-setup",        element: <S><MFASetupPage /></S> },
  { path: "/accept-invite",    element: <S><AcceptInvitePage /></S> },
  { path: "/forgot-password",  element: <S><ForgotPasswordPage /></S> },
  { path: "/reset-password",   element: <S><ResetPasswordPage /></S> },
  { path: "/verify-email",     element: <S><VerifyEmailPage /></S> },

  // ── Setup — authenticated but no tenant needed ─────────────────────────────
  {
    path: "/setup",
    element: (
      <AuthGuard>
        <S><SetupPage /></S>
      </AuthGuard>
    ),
  },

  // ── Protected app routes (pathless layout — all paths stay unchanged) ──────
  // Using a pathless route element means every child path is an absolute path,
  // so /dashboard, /alerts, etc. remain exactly as they were.
  {
    element: (
      <AuthGuard>
        <S><AppShell /></S>
      </AuthGuard>
    ),
    children: [
      { path: "dashboard",          element: <S><DashboardPage /></S> },
      { path: "alerts",             element: <S><AlertsPage /></S> },
      { path: "events",             element: <S><EventsPage /></S> },
      { path: "agents",             element: <S><AgentsPage /></S> },
      { path: "installer",          element: <S><InstallerPage /></S> },
      { path: "settings",           element: <S><SettingsPage /></S> },
      // analyst+ only
      { path: "investigations",     element: <S><RequireRole min="analyst"><InvestigationsPage /></RequireRole></S> },
      { path: "investigations/:id", element: <S><RequireRole min="analyst"><InvestigationDetailPage /></RequireRole></S> },
      { path: "hunt",               element: <S><RequireRole min="analyst"><HuntPage /></RequireRole></S> },
      { path: "copilot",            element: <S><RequireRole min="analyst"><CopilotPage /></RequireRole></S> },
      // analyst+ only
      { path: "rules",              element: <S><RequireRole min="analyst"><RulesPage /></RequireRole></S> },
      { path: "graph",              element: <S><RequireRole min="analyst"><GraphPage /></RequireRole></S> },
      // playbooks
      { path: "playbooks",          element: <S><RequireRole min="analyst"><PlaybooksPage /></RequireRole></S> },
      { path: "playbooks/:id",      element: <S><RequireRole min="analyst"><PlaybookDetailPage /></RequireRole></S> },
      // reports
      { path: "reports",            element: <S><RequireRole min="analyst"><ReportsPage /></RequireRole></S> },
      // log import
      { path: "import",             element: <S><RequireRole min="admin"><ImportPage /></RequireRole></S> },
      // SOC Operations
      { path: "soc-metrics",        element: <S><RequireRole min="analyst"><SocMetricsPage /></RequireRole></S> },
      { path: "soc-metrics/sla",    element: <S><RequireRole min="analyst"><SLADashboard /></RequireRole></S> },
      { path: "assets",             element: <S><RequireRole min="analyst"><AssetsPage /></RequireRole></S> },
      { path: "ueba",               element: <S><RequireRole min="analyst"><UEBADashboard /></RequireRole></S> },
      { path: "audit-log",          element: <S><RequireRole min="admin"><AuditLogPage /></RequireRole></S> },
      { path: "rules/suppression",  element: <S><RequireRole min="analyst"><SuppressionRulesPage /></RequireRole></S> },
      { path: "threat-intel",       element: <S><RequireRole min="analyst"><ThreatIntelPage /></RequireRole></S> },
      { path: "mitre",              element: <S><RequireRole min="analyst"><MitreNavigatorPage /></RequireRole></S> },
      { path: "compliance-reports", element: <S><RequireRole min="analyst"><ComplianceSchedulerPage /></RequireRole></S> },
      // Admin / MSSP
      { path: "fleet",              element: <S><RequireRole min="admin"><FleetDashboardPage /></RequireRole></S> },
      { path: "mssp",               element: <S><RequireRole min="admin"><MSSPOverviewPage /></RequireRole></S> },
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
