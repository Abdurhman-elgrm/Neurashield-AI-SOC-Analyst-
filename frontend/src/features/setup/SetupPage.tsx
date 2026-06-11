import { useState, FormEvent } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { LogoFull } from "@/components/ui/Logo";
import { useAuthStore } from "@/stores/authStore";
import { useTenantStore } from "@/stores/tenantStore";
import { createTenant } from "@/api/tenants";
import type { MemberRole } from "@/types/tenant";

export function SetupPage() {
  const navigate      = useNavigate();
  const location      = useLocation();
  const from          = (location.state as { from?: string } | null)?.from ?? "/dashboard";
  const setAuthTenant  = useAuthStore((s) => s.setActiveTenant);
  const setStoreTenant = useTenantStore((s) => s.setActiveTenant);

  const [name,      setName]      = useState("");
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    setError(null);
    setLoading(true);
    try {
      const tenant = await createTenant(name.trim());
      const role: MemberRole = "owner";
      setStoreTenant(tenant, role);
      setAuthTenant(tenant.id);
      navigate(from, { replace: true });
    } catch {
      setError("Failed to create workspace. Please try again.");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div style={{
      minHeight: "100vh",
      background: "#000000",
      display: "flex",
      flexDirection: "column",
      alignItems: "center",
      justifyContent: "center",
      padding: 24,
    }}>
      {/* Ambient glow */}
      <div style={{
        position: "fixed", top: 0, left: "25%",
        width: 500, height: 500, borderRadius: "50%",
        background: "radial-gradient(circle, rgba(59,130,246,0.08) 0%, transparent 70%)",
        filter: "blur(40px)", pointerEvents: "none",
      }} />

      <div style={{ width: "100%", maxWidth: 420 }}>
        {/* Logo */}
        <div style={{ display: "flex", justifyContent: "center", marginBottom: 40 }}>
          <LogoFull />
        </div>

        {/* Card */}
        <div style={{
          background: "rgba(255,255,255,0.03)",
          border: "1px solid rgba(255,255,255,0.08)",
          borderRadius: 12,
          padding: 32,
        }}>
          <h1 style={{ fontSize: 20, fontWeight: 700, color: "#F5F7FA", marginBottom: 6 }}>
            Create your workspace
          </h1>
          <p style={{ fontSize: 13, color: "#5C6373", marginBottom: 24 }}>
            Give your workspace a name to get started.
          </p>

          <form onSubmit={handleSubmit} style={{ display: "flex", flexDirection: "column", gap: 16 }}>
            <div>
              <label style={{ display: "block", fontSize: 12, color: "#8B95A7", marginBottom: 6 }}>
                Workspace name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Acme Security SOC"
                autoFocus
                style={{
                  width: "100%",
                  padding: "10px 12px",
                  background: "rgba(255,255,255,0.04)",
                  border: "1px solid rgba(255,255,255,0.1)",
                  borderRadius: 8,
                  color: "#F5F7FA",
                  fontSize: 14,
                  outline: "none",
                  boxSizing: "border-box",
                }}
              />
            </div>

            {error && (
              <p style={{ fontSize: 12, color: "#F87171", margin: 0 }}>{error}</p>
            )}

            <button
              type="submit"
              disabled={!name.trim() || loading}
              style={{
                padding: "10px 0",
                borderRadius: 8,
                fontSize: 14,
                fontWeight: 600,
                color: "#fff",
                background: !name.trim() || loading
                  ? "rgba(59,130,246,0.3)"
                  : "rgba(59,130,246,0.9)",
                border: "none",
                cursor: !name.trim() || loading ? "not-allowed" : "pointer",
                transition: "background 0.15s",
              }}
            >
              {loading ? "Creating…" : "Create workspace →"}
            </button>
          </form>
        </div>
      </div>
    </div>
  );
}
