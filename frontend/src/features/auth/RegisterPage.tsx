import { useState, FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { ShieldCheck, Eye, EyeOff, AlertCircle, CheckCircle2 } from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
import { authApi } from "@/api/auth";
import { cn, extractApiError } from "@/lib/utils";

function PasswordRule({ met, label }: { met: boolean; label: string }) {
  return (
    <div className={cn("flex items-center gap-1.5 text-xs", met ? "text-status-online" : "text-text-muted")}>
      <CheckCircle2 className="w-3 h-3" />
      {label}
    </div>
  );
}

export function RegisterPage() {
  const navigate = useNavigate();
  const setAuth = useAuthStore((s) => s.setAuth);

  const [fullName, setFullName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const rules = {
    length: password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    digit: /\d/.test(password),
  };
  const allRulesMet = Object.values(rules).every(Boolean);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (!allRulesMet) return;
    setError(null);
    setIsLoading(true);

    try {
      const tokens = await authApi.register({ email, password, full_name: fullName });
      setAuth(
        { id: "", email, full_name: fullName, is_active: true, created_at: "" },
        tokens.access_token,
        tokens.refresh_token,
      );
      navigate("/onboarding", { replace: true });
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
            <h1 className="text-xl font-semibold text-text-primary mb-1">Create account</h1>
            <p className="text-sm text-text-secondary">Start monitoring your security operations</p>
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
              <label htmlFor="full-name" className="block text-xs font-medium text-text-secondary mb-1.5">
                Full name
              </label>
              <input
                id="full-name"
                type="text"
                autoComplete="name"
                value={fullName}
                onChange={(e) => setFullName(e.target.value)}
                className="input-base"
                placeholder="Jane Smith"
                required
                minLength={1}
                disabled={isLoading}
              />
            </div>

            <div>
              <label htmlFor="email" className="block text-xs font-medium text-text-secondary mb-1.5">
                Work email
              </label>
              <input
                id="email"
                type="email"
                autoComplete="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                className="input-base"
                placeholder="jane@company.com"
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
                  autoComplete="new-password"
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

              {password && (
                <div className="mt-2 grid grid-cols-2 gap-1">
                  <PasswordRule met={rules.length} label="8+ characters" />
                  <PasswordRule met={rules.uppercase} label="Uppercase letter" />
                  <PasswordRule met={rules.lowercase} label="Lowercase letter" />
                  <PasswordRule met={rules.digit} label="Number" />
                </div>
              )}
            </div>

            <button
              type="submit"
              className={cn("btn-primary w-full justify-center", (isLoading || !allRulesMet) && "opacity-70 cursor-not-allowed")}
              disabled={isLoading || !allRulesMet}
            >
              {isLoading ? (
                <span className="flex items-center gap-2">
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Creating account…
                </span>
              ) : (
                "Create account"
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-sm text-text-muted mt-4">
          Already have an account?{" "}
          <Link to="/login" className="text-accent hover:text-accent-hover transition-colors">
            Sign in
          </Link>
        </p>
      </motion.div>
    </div>
  );
}
