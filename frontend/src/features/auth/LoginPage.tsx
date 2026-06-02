import { useState, FormEvent } from "react";
import { Link, useNavigate, useLocation } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldCheck, Eye, EyeOff, AlertCircle } from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
import { authApi } from "@/api/auth";
import { cn, extractApiError } from "@/lib/utils";

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const setAuth = useAuthStore((s) => s.setAuth);

  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const from = (location.state as { from?: Location })?.from?.pathname ?? "/dashboard";

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setIsLoading(true);

    try {
      const tokens = await authApi.login({ email, password });
      // Minimal user object until profile is fetched
      setAuth(
        { id: "", email, full_name: "", is_active: true, created_at: "" },
        tokens.access_token,
        tokens.refresh_token,
      );
      navigate(from, { replace: true });
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div className="min-h-screen bg-bg-base flex items-center justify-center p-4">
      <motion.div
        initial={{ opacity: 0, y: 16 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.2, ease: "easeOut" }}
        className="w-full max-w-[400px]"
      >
        {/* Logo */}
        <div className="flex items-center gap-3 mb-8">
          <div className="w-9 h-9 rounded-lg bg-accent/10 border border-accent/30 flex items-center justify-center">
            <ShieldCheck className="w-5 h-5 text-accent" />
          </div>
          <span className="text-lg font-semibold text-text-primary">SOC Platform</span>
        </div>

        {/* Card */}
        <div className="card p-6">
          <div className="mb-6">
            <h1 className="text-xl font-semibold text-text-primary mb-1">Sign in</h1>
            <p className="text-sm text-text-secondary">Enter your credentials to access the platform</p>
          </div>

          {error && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
              className="flex items-start gap-2.5 p-3 mb-4 rounded bg-severity-critical/10 border border-severity-critical/20"
            >
              <AlertCircle className="w-4 h-4 text-severity-critical mt-0.5 flex-shrink-0" />
              <p className="text-sm text-severity-critical">{error}</p>
            </motion.div>
          )}

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
                onChange={(e) => setEmail(e.target.value)}
                className="input-base"
                placeholder="analyst@company.com"
                required
                disabled={isLoading}
              />
            </div>

            <div>
              <label htmlFor="password" className="block text-xs font-medium text-text-secondary mb-1.5">
                Password
              </label>
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
              className={cn("btn-primary w-full justify-center", isLoading && "opacity-70 cursor-not-allowed")}
              disabled={isLoading}
            >
              {isLoading ? (
                <span className="flex items-center gap-2">
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Signing in…
                </span>
              ) : (
                "Sign in"
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-sm text-text-muted mt-4">
          Don&apos;t have an account?{" "}
          <Link to="/register" className="text-accent hover:text-accent-hover transition-colors">
            Create one
          </Link>
        </p>
      </motion.div>
    </div>
  );
}
