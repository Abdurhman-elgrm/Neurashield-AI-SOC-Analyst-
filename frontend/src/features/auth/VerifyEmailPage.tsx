import { useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { motion } from "framer-motion";
import { CheckCircle, XCircle, Loader2 } from "lucide-react";
import { authApi } from "@/api/auth";
import { extractApiError } from "@/lib/utils";
import { LogoFull } from "@/components/ui/Logo";

type State = "loading" | "success" | "error";

export function VerifyEmailPage() {
  const [searchParams] = useSearchParams();
  const token = searchParams.get("token") ?? "";
  const [state, setState] = useState<State>("loading");
  const [errorMsg, setErrorMsg] = useState<string | null>(null);

  useEffect(() => {
    if (!token) {
      setState("error");
      setErrorMsg("No verification token provided.");
      return;
    }

    authApi.verifyEmail(token)
      .then(() => setState("success"))
      .catch((err) => {
        setState("error");
        setErrorMsg(extractApiError(err));
      });
  }, [token]);

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
          className="rounded-2xl p-8 border text-center"
          style={{
            background: "rgba(13,13,13,0.9)",
            borderColor: "rgba(59,130,246,0.2)",
            boxShadow: "0 0 40px rgba(59,130,246,0.1), inset 0 1px 0 rgba(255,255,255,0.04)",
            backdropFilter: "blur(12px)",
          }}
        >
          {state === "loading" && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex flex-col items-center gap-4 py-4"
            >
              <Loader2 className="w-10 h-10 animate-spin" style={{ color: "#3B82F6" }} />
              <p className="text-sm" style={{ color: "#8B95A7" }}>Verifying your email address…</p>
            </motion.div>
          )}

          {state === "success" && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="flex flex-col items-center gap-4 py-4"
            >
              <div
                className="w-14 h-14 rounded-full flex items-center justify-center"
                style={{ background: "rgba(16,185,129,0.12)", border: "1px solid rgba(16,185,129,0.25)" }}
              >
                <CheckCircle className="w-7 h-7" style={{ color: "#10B981" }} />
              </div>
              <div>
                <h2 className="font-display font-bold mb-2" style={{ fontSize: 18, color: "#F5F7FA" }}>
                  Email verified!
                </h2>
                <p className="text-sm mb-6" style={{ color: "#8B95A7", lineHeight: 1.6 }}>
                  Your email address has been confirmed. You can now sign in to your account.
                </p>
              </div>
              <Link
                to="/login"
                className="btn-primary"
                style={{
                  display: "inline-flex", alignItems: "center", justifyContent: "center",
                  padding: "8px 24px", borderRadius: 8, fontSize: 13, fontWeight: 600,
                  background: "#3B82F6", color: "#ffffff", textDecoration: "none",
                }}
              >
                Sign in
              </Link>
            </motion.div>
          )}

          {state === "error" && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              className="flex flex-col items-center gap-4 py-4"
            >
              <div
                className="w-14 h-14 rounded-full flex items-center justify-center"
                style={{ background: "rgba(239,68,68,0.1)", border: "1px solid rgba(239,68,68,0.25)" }}
              >
                <XCircle className="w-7 h-7" style={{ color: "#EF4444" }} />
              </div>
              <div>
                <h2 className="font-display font-bold mb-2" style={{ fontSize: 18, color: "#F5F7FA" }}>
                  Verification failed
                </h2>
                <p className="text-sm mb-2" style={{ color: "#8B95A7", lineHeight: 1.6 }}>
                  {errorMsg ?? "The verification link is invalid or has expired."}
                </p>
              </div>
              <div className="flex flex-col items-center gap-2 w-full">
                <Link
                  to="/login"
                  style={{
                    display: "inline-flex", alignItems: "center", justifyContent: "center",
                    width: "100%", padding: "8px 24px", borderRadius: 8, fontSize: 13,
                    fontWeight: 600, background: "#3B82F6", color: "#ffffff",
                    textDecoration: "none",
                  }}
                >
                  Go to sign in
                </Link>
              </div>
            </motion.div>
          )}
        </div>
      </motion.div>
    </div>
  );
}
