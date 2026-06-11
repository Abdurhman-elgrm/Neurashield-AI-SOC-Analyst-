import { useState, FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Eye, EyeOff, AlertCircle, CheckCircle2, Circle } from "lucide-react";
import { useAuthStore } from "@/stores/authStore";
import { authApi } from "@/api/auth";
import { cn, extractApiError } from "@/lib/utils";
import { LogoFull } from "@/components/ui/Logo";

function PasswordRule({ met, label }: { met: boolean; label: string }) {
  return (
    <div className={cn("flex items-center gap-1.5 text-xs transition-colors", met ? "text-cyber-400" : "text-text-muted")}>
      {met
        ? <CheckCircle2 className="w-3 h-3 flex-shrink-0" />
        : <Circle className="w-3 h-3 flex-shrink-0" />}
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
    length:    password.length >= 8,
    uppercase: /[A-Z]/.test(password),
    lowercase: /[a-z]/.test(password),
    digit:     /\d/.test(password),
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
      navigate("/setup", { replace: true });
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <div
      className="min-h-screen flex items-center justify-center p-4 bg-grid"
      style={{ background: "#000000" }}
    >
      {/* Ambient glow blobs */}
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
        {/* Logo */}
        <div className="flex justify-center mb-8">
          <LogoFull size={40} showSubtitle />
        </div>

        {/* Card */}
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
            <h1 className="font-display text-xl font-bold text-text-primary mb-1">Create account</h1>
            <p className="text-sm text-text-muted">Deploy your AI-powered SOC in minutes</p>
          </div>

          {error && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: "auto" }}
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
                <div className="mt-2.5 grid grid-cols-2 gap-1.5">
                  <PasswordRule met={rules.length}    label="8+ characters" />
                  <PasswordRule met={rules.uppercase} label="Uppercase letter" />
                  <PasswordRule met={rules.lowercase} label="Lowercase letter" />
                  <PasswordRule met={rules.digit}     label="Number" />
                </div>
              )}
            </div>

            <button
              type="submit"
              className={cn("btn-primary w-full mt-2", (isLoading || !allRulesMet) && "opacity-60 cursor-not-allowed")}
              disabled={isLoading || !allRulesMet}
            >
              {isLoading ? (
                <>
                  <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                  Creating account…
                </>
              ) : (
                "Create account"
              )}
            </button>
          </form>
        </div>

        <p className="text-center text-sm text-text-muted mt-5">
          Already have an account?{" "}
          <Link to="/login" className="text-primary-400 hover:text-primary-500 transition-colors font-medium">
            Sign in
          </Link>
        </p>
      </motion.div>
    </div>
  );
}
