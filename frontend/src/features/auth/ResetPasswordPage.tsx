import { useState, FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { AlertCircle, CheckCircle, Eye, EyeOff, ArrowLeft } from "lucide-react";
import { authApi } from "@/api/auth";
import { extractApiError } from "@/lib/utils";
import { LogoFull } from "@/components/ui/Logo";

export function ResetPasswordPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
  const token = searchParams.get("token") ?? "";

  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [done, setDone] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    if (password !== confirm) {
      setError("Passwords do not match");
      return;
    }
    setError(null);
    setIsLoading(true);
    try {
      await authApi.resetPassword(token, password);
      setDone(true);
      setTimeout(() => navigate("/login"), 3000);
    } catch (err) {
      setError(extractApiError(err));
    } finally {
      setIsLoading(false);
    }
  }

  if (!token) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4" style={{ background: "#000000" }}>
        <div className="text-center">
          <p className="text-sm mb-4" style={{ color: "#8B95A7" }}>Invalid reset link.</p>
          <Link to="/forgot-password" className="text-sm" style={{ color: "#60A5FA" }}>
            Request a new one →
          </Link>
        </div>
      </div>
    );
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
          {done ? (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="text-center py-4"
            >
              <div
                className="w-12 h-12 rounded-full flex items-center justify-center mx-auto mb-4"
                style={{ background: "rgba(16,185,129,0.12)", border: "1px solid rgba(16,185,129,0.25)" }}
              >
                <CheckCircle className="w-6 h-6" style={{ color: "#10B981" }} />
              </div>
              <h2 className="font-display font-bold mb-2" style={{ fontSize: 16, color: "#F5F7FA" }}>
                Password updated
              </h2>
              <p className="text-sm" style={{ color: "#8B95A7" }}>
                Your password has been changed. Redirecting to sign in…
              </p>
            </motion.div>
          ) : (
            <>
              <div className="mb-6">
                <h1 className="font-display text-xl font-bold mb-1" style={{ color: "#F5F7FA" }}>
                  Set new password
                </h1>
                <p className="text-sm" style={{ color: "#8B95A7" }}>
                  Choose a strong password for your account.
                </p>
              </div>

              {error && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  className="flex items-start gap-2.5 p-3 mb-4 rounded-lg"
                  style={{ background: "rgba(248,113,113,0.08)", border: "1px solid rgba(248,113,113,0.25)" }}
                >
                  <AlertCircle className="w-4 h-4 mt-0.5 flex-shrink-0" style={{ color: "#F87171" }} />
                  <p className="text-sm" style={{ color: "#F87171" }}>{error}</p>
                </motion.div>
              )}

              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: "#8B95A7" }}>
                    New password
                  </label>
                  <div className="relative">
                    <input
                      type={showPassword ? "text" : "password"}
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="input-base pr-10"
                      placeholder="Minimum 8 characters"
                      minLength={8}
                      required
                      disabled={isLoading}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2"
                      style={{ color: "#5C6373", background: "none", border: "none", cursor: "pointer" }}
                      tabIndex={-1}
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                <div>
                  <label className="block text-xs font-medium mb-1.5" style={{ color: "#8B95A7" }}>
                    Confirm new password
                  </label>
                  <input
                    type={showPassword ? "text" : "password"}
                    value={confirm}
                    onChange={(e) => setConfirm(e.target.value)}
                    className="input-base"
                    placeholder="Repeat your password"
                    required
                    disabled={isLoading}
                    style={{
                      borderColor: confirm && confirm !== password
                        ? "rgba(248,113,113,0.5)"
                        : undefined,
                    }}
                  />
                </div>

                <button
                  type="submit"
                  className="btn-primary w-full mt-2"
                  disabled={isLoading}
                  style={{ opacity: isLoading ? 0.7 : 1, cursor: isLoading ? "not-allowed" : "pointer" }}
                >
                  {isLoading ? (
                    <>
                      <span className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                      Updating password…
                    </>
                  ) : (
                    "Set New Password"
                  )}
                </button>
              </form>
            </>
          )}
        </div>

        <div className="flex justify-center mt-5">
          <Link
            to="/login"
            className="flex items-center gap-1.5 text-sm"
            style={{ color: "#5C6373", textDecoration: "none" }}
          >
            <ArrowLeft className="w-4 h-4" />
            Back to sign in
          </Link>
        </div>
      </motion.div>
    </div>
  );
}
