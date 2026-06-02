import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/Button";

export function NotFound() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-bg-base flex items-center justify-center">
      <div className="text-center space-y-4 max-w-md px-4">
        <p className="text-6xl font-bold text-text-muted select-none">404</p>
        <h1 className="text-xl font-semibold text-text-primary">Page not found</h1>
        <p className="text-sm text-text-muted">
          The page you're looking for doesn't exist or has been moved.
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
