import { useNavigate } from "react-router-dom";
import { ShieldOff } from "lucide-react";
import { Button } from "@/components/ui/Button";

export function Unauthorized() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-bg-base flex items-center justify-center">
      <div className="text-center space-y-4 max-w-md px-4">
        <div className="flex justify-center">
          <ShieldOff className="w-12 h-12 text-severity-critical" />
        </div>
        <h1 className="text-xl font-semibold text-text-primary">Access denied</h1>
        <p className="text-sm text-text-muted">
          You don't have permission to view this page. Contact your administrator if you believe this is an error.
        </p>
        <div className="flex items-center justify-center gap-3 pt-2">
          <Button variant="secondary" onClick={() => navigate(-1)}>
            Go back
          </Button>
          <Button onClick={() => navigate("/dashboard")}>
            Dashboard
          </Button>
        </div>
      </div>
    </div>
  );
}
