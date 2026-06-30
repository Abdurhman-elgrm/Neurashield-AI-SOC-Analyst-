import { useState, FormEvent, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldCheck, AlertCircle } from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
import { useTenantStore } from "@/stores/tenantStore";
import { authApi } from "@/api/auth";
import { isApiError } from "@/api/client";
import { extractApiError } from "@/lib/utils";
import { fetchMyTenants } from "@/api/tenants";
import type { MemberRole } from "@/types/tenant";

export function MFALoginPromptPage() {
  const navigate = useNavigate();

  const mfaPending     = useAuthStore((s) => s.mfaPending);
  const setAuth        = useAuthStore((s) => s.setAuth);
  const setUser        = useAuthStore((s) => s.setUser);
  const setMFAPending  = useAuthStore((s) => s.setMFAPending);
  const setAuthTenant  = useAuthStore((s) => s.setActiveTenant);
  const setStoreTenant = useTenantStore((s) => s.setActiveTenant);

  const [code, setCode]         = useState("");
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError]       = useState<string | null>(null);

  // If there is no pending MFA challenge (e.g. direct navigation), send back to login.
  useEffect(() => {
    if (!mfaPending) {
      navigate("/login", { replace: true });
    }
  }, [mfaPending, navigate]);

  if (!mfaPending) return null;

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!mfaPending) return;
    setError(null);
    setIsLoading(true);
    try {
      const tokens = await authApi.login({
        email: mfaPending.email,
        password: mfaPending.password,
        mfa_code: code.trim(),
      });
      setAuth(
        { id: "", email: mfaPending.email, full_name: "", is_active: true, created_at: "" },
        tokens.access_token,
      );
      setMFAPending(null);
      try {
        const [me, tenants] = await Promise.all([authApi.me(), fetchMyTenants()]);
        setUser(me);
        if (tenants.length > 0) {
          const tenant = tenants[0];
          const role: MemberRole = "owner";
          setStoreTenant(tenant, role);
          setAuthTenant(tenant.id);
          navigate("/dashboard", { replace: true });
        } else {
          navigate("/setup", { replace: true });
        }
      } catch {
        navigate("/dashboard", { replace: true });
      }
    } catch (err) {
      if (isApiError(err)) {
        setError(err.message || "Invalid MFA code");
      } else {
        setError(extractApiError(err));
      }
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4"
      style={{ background: "#000000" }}
    >
      <div
        className="fixed top-0 left-1/4 w-[500px] h-[500px] rounded-full pointer-events-none"
        style={{
          background: "radial-gradient(circle, rgba(59,130,246,0.08) 0%, transparent 70%)",
          filter: "blur(40px)",
        }}
      />

      <motion.div
        initial={{ opacity: 0, y: 20 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.25, ease: "easeOut" }}
        className="w-full max-w-sm"
      >
        <div
          className="rounded-2xl p-8 shadow-2xl"
          style={{
            background: "rgba(15, 17, 21, 0.95)",
            border: "1px solid rgba(255, 255, 255, 0.08)",
          }}
        >
          <div className="flex flex-col items-center mb-8">
            <div
              className="w-12 h-12 rounded-xl flex items-center justify-center mb-4"
              style={{ background: "rgba(59,130,246,0.15)", border: "1px solid rgba(59,130,246,0.3)" }}
            >
              <ShieldCheck className="w-6 h-6 text-blue-400" />
            </div>
            <h1 className="text-xl font-semibold text-white">Two-factor authentication</h1>
            <p className="text-sm mt-1" style={{ color: "#8B95A7" }}>
              Enter the 6-digit code from your authenticator app
            </p>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="block text-sm font-medium mb-1.5" style={{ color: "#CBD5E1" }}>
                Authentication code
              </label>
              <input
                type="text"
                inputMode="numeric"
                pattern="[0-9]*"
                maxLength={8}
                value={code}
                onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))}
                placeholder="000000"
                autoFocus
                className="w-full px-4 py-2.5 rounded-xl text-center text-2xl tracking-[0.5em] font-mono transition-all outline-none"
                style={{
                  background: "rgba(255,255,255,0.04)",
                  border: "1px solid rgba(255,255,255,0.12)",
                  color: "#F5F7FA",
                }}
                disabled={isLoading}
              />
            </div>

            {error && (
              <motion.div
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                className="flex items-start gap-2 text-sm rounded-xl px-3 py-2.5"
                style={{
                  background: "rgba(239,68,68,0.1)",
                  border: "1px solid rgba(239,68,68,0.3)",
                  color: "#FCA5A5",
                }}
              >
                <AlertCircle className="w-4 h-4 mt-0.5 shrink-0" />
                <span>{error}</span>
              </motion.div>
            )}

            <button
              type="submit"
              disabled={isLoading || code.length < 6}
              className="w-full py-2.5 rounded-xl text-sm font-semibold transition-all"
              style={{
                background: isLoading || code.length < 6
                  ? "rgba(59,130,246,0.3)"
                  : "rgba(59,130,246,0.8)",
                color: "#fff",
                cursor: isLoading || code.length < 6 ? "not-allowed" : "pointer",
              }}
            >
              {isLoading ? "Verifying…" : "Verify"}
            </button>

            <button
              type="button"
              onClick={() => { setMFAPending(null); navigate("/login"); }}
              className="w-full text-sm text-center"
              style={{ color: "#8B95A7" }}
            >
              ← Back to login
            </button>
          </form>
        </div>
      </motion.div>
    </div>
  );
}
