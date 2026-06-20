import { useState, FormEvent } from "react";
import { Link, useNavigate, useLocation, useSearchParams } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import { Eye, EyeOff, AlertCircle, MailCheck, RefreshCw, CheckCircle2 } from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
import { useTenantStore } from "@/stores/tenantStore";
import { authApi } from "@/api/auth";
import { isApiError } from "@/api/client";
import { fetchMyTenants } from "@/api/tenants";
import { cn, extractApiError } from "@/lib/utils";
import { LogoFull } from "@/components/ui/Logo";
import type { MemberRole } from "@/types/tenant";

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const [searchParams] = useSearchParams();

  const setAuth        = useAuthStore((s) => s.setAuth);
  const setAuthTenant  = useAuthStore((s) => s.setActiveTenant);
  const setStoreTenant = useTenantStore((s) => s.setActiveTenant);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Email-not-verified state
  const [unverifiedEmail, setUnverifiedEmail] = useState<string | null>(null);
  const [resendLoading, setResendLoading] = useState(false);
  const [resendSent,    setResendSent]    = useState(false);
  const [resendError,   setResendError]   = useState<string | null>(null);

  const from = (location.state as { from?: Location })?.from?.pathname ?? "/dashboard";

  // Banner shown after RegisterPage redirects here post-registration
  const justRegistered = searchParams.get("registered") === "1";

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setUnverifiedEmail(null);
    setResendSent(false);
    setIsLoading(true);
    try {
      const tokens = await authApi.login({ email, password });
      setAuth(
        { id: "", email, full_name: "", is_active: true, created_at: "" },
        tokens.access_token,
        tokens.refresh_token,
      );

      try {
        const tenants = await fetchMyTenants();
        if (tenants.length > 0) {
          const tenant = tenants[0];
          const role: MemberRole = "owner";
          setStoreTenant(tenant, role);
          setAuthTenant(tenant.id);
          navigate(from, { replace: true });
        } else {
          navigate("/setup", { replace: true, state: { from: from } });
        }
      } catch {
        navigate(from, { replace: true });
      }
    } catch (err) {
      if (
        isApiError(err) &&
        err.code === "FORBIDDEN" &&
        (err.details as Record<string, unknown>)?.code === "EMAIL_NOT_VERIFIED"
      ) {
        setUnverifiedEmail(email);
      } else {
        setError(extractApiError(err));
      }
    } finally {
      setIsLoading(false);
    }
  }

  async function handleResend() {
    if (!unverifiedEmail || resendLoading || resendSent) return;
    setResendLoading(true);
    setResendError(null);
    try {
      await authApi.resendVerification(unverifiedEmail);
      setResendSent(true);
    } catch (err) {
      setResendError(extractApiError(err));
    } finally {
      setResendLoading(false);
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4 bg-grid"
      style={{ background: "#000000" }}
    >
      <div
        className="fixed top-0 left-1/4 w-[500px] h-[500px] rounded-full pointer-events-none"
        style={{
          background: "radial-gradient(circle, rgba(59,130,246,0.08) 0%, transparent 70%)",
          filter: "blur(40px)",
        }}
      />
      <div
        className="fixed bottom-0 right-1/4 w-[400px] h-[400px] rounded-full pointer-events-none"
        style={{
          background: "radial-gradient(circle, rgba(6,182,212,0.06) 0%, transparent 70%)",
          filter: "blur(40px)",
        }}
      />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25, ease: "easeOut" }}
        className="relative w-full max-w-[400px]"
      >
        <div className="flex justify-center mb-8">
          <LogoFull size={40} showSubtitle />
        </div>

        <div
          className="rounded-2xl p-7 border"
          style={{
            background: "rgba(13,13,13,0.9)",
            borderColor: "rgba(59,130,246,0.2)",
            boxShadow: "0 0 40px rgba(59,130,246,0.1), inset 0 1px 0 rgba(255,255,255,0.04)",
            backdropFilter: "blur(12px)",
          }}
        >
          <div className="mb-6">
            <h1 className="font-display text-xl font-bold text-text-primary mb-1">Welcome back</h1>
            <p className="text-sm text-text-muted">Sign in to your NEURASHIELD console</p>
          </div>

          <AnimatePresence mode="wait">
            {/* ── Just-registered banner ── */}
            {justRegistered && !unverifiedEmail && !error && (
              <motion.div
                key="registered"
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="flex items-start gap-2.5 p-3 mb-4 rounded-lg"
                style={{
                  background: "rgba(16,185,129,0.07)",
                  border: "1px solid rgba(16,185,129,0.22)",
                }}
              >
                <MailCheck className="w-4 h-4 mt-0.5 flex-shrink-0" style={{ color: "#10B981" }} />
                <p className="text-sm" style={{ color: "#6EE7B7", lineHeight: 1.5 }}>
                  Account created! Check your inbox (or <strong>Spam / Junk folder</strong>) for the verification email.
                </p>
              </motion.div>
            )}

            {/* ── Generic error banner ── */}
            {error && !unverifiedEmail && (
              <motion.div
                key="error"
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="flex items-start gap-2.5 p-3 mb-4 rounded-lg"
                style={{
                  background: "rgba(248,113,113,0.08)",
                  border: "1px solid rgba(248,113,113,0.25)",
                }}
              >
                <AlertCircle className="w-4 h-4 text-severity-critical mt-0.5 flex-shrink-0" />
                <p className="text-sm text-severity-critical">{error}</p>
              </motion.div>
            )}

            {/* ── Email not verified banner ── */}
            {unverifiedEmail && (
              <motion.div
                key="unverified"
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="mb-4 rounded-lg overflow-hidden"
                style={{
                  background: "rgba(245,158,11,0.07)",
                  border: "1px solid rgba(245,158,11,0.28)",
                }}
              >
                <div className="flex items-start gap-2.5 p-3">
                  <MailCheck className="w-4 h-4 mt-0.5 flex-shrink-0" style={{ color: "#F59E0B" }} />
                  <div style={{ flex: 1 }}>
                    <p className="text-sm font-medium mb-0.5" style={{ color: "#FCD34D" }}>
                      Email not verified
                    </p>
                    <p className="text-xs" style={{ color: "#A78A4F", lineHeight: 1.5 }}>
                      A verification link was sent to{" "}
                      <span style={{ color: "#FCD34D", fontWeight: 600 }}>{unverifiedEmail}</span>.
                      Check your <strong style={{ color: "#FCD34D" }}>inbox and Spam / Junk folder</strong> for the verification link.
                    </p>
                  </div>
                </div>

                <div
                  className="px-3 pb-3"
                  style={{ borderTop: "1px solid rgba(245,158,11,0.15)", paddingTop: 8 }}
                >
                  {resendSent ? (
                    <div className="flex items-center gap-2" style={{ color: "#10B981", fontSize: 12 }}>
                      <CheckCircle2 size={13} />
                      Sent — check your inbox and Spam / Junk folder.
                    </div>
                  ) : (
                    <button
                      onClick={handleResend}
                      disabled={resendLoading}
                      style={{
                        display: "flex", alignItems: "center", gap: 6,
                        fontSize: 12, fontWeight: 600, color: "#F59E0B",
                        background: "none", border: "none", cursor: resendLoading ? "default" : "pointer",
                        padding: 0, opacity: resendLoading ? 0.6 : 1,
                      }}
                    >
                      <RefreshCw size={12} style={{ animation: resendLoading ? "spin 1s linear infinite" : "none" }} />
                      {resendLoading ? "Sending…" : "Resend verification email"}
                    </button>
                  )}
                  {resendError && (
                    <p style={{ color: "#FCA5A5", fontSize: 11, marginTop: 4 }}>{resendError}</p>
                  )}
                </div>
              </motion.div>
            )}
          </AnimatePresence>

          <form onSubmit={handleSubmit} className="space-y-4">
            <div>
              <label htmlFor="email" className="block text-xs font-medium text-text-secondary mb-1.5">
                Email address
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => { setEmail(e.target.value); setUnverifiedEmail(null); setError(null); setResendSent(false); }}
                className="input-base"
                placeholder="analyst@company.com"
                required
                disabled={isLoading}
              />
            </div>

            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label htmlFor="password" className="block text-xs font-medium text-text-secondary">
                  Password
                </label>
                <Link
                  to="/forgot-password"
                  className="text-xs transition-colors"
                  style={{ color: "#60A5FA" }}
                >
                  Forgot password?
                </Link>
              </div>
              <div className="relative">
                <input
                  id="password"
                  type={showPassword ? "text" : "password"}
                  autoComplete="current-password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className="input-base pr-10"
                  placeholder="••••••••"
                  required
                  disabled={isLoading}
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary transition-colors"
                  tabIndex={-1}
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              className={cn("btn-primary w-full mt-2", isLoading && "opacity-70 cursor-not-allowed")}
              disabled={isLoading}
            >
              {isLoading ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Authenticating…
                </>
              ) : (
                "Sign in"
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-sm text-text-muted mt-5">
          Don&apos;t have an account?{" "}
          <Link to="/register" className="text-primary-400 hover:text-primary-500 transition-colors font-medium">
            Create one
          </Link>
        </p>
      </motion.div>
    </div>
  );
}
