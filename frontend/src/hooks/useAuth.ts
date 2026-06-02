import { useNavigate } from "react-router-dom";
import { useAuthStore } from "@/stores/authStore";
import { useTenantStore } from "@/stores/tenantStore";

export function useAuth() {
  const navigate = useNavigate();
  const user = useAuthStore((s) => s.user);
  const accessToken = useAuthStore((s) => s.accessToken);
  const activeTenantId = useAuthStore((s) => s.activeTenantId);
  const clearAuth = useAuthStore((s) => s.clearAuth);
  const activeTenant = useTenantStore((s) => s.activeTenant);

  const isAuthenticated = !!accessToken;

  const logout = () => {
    clearAuth();
    navigate("/login");
  };

  const hasRole = (role: string): boolean => {
    return user?.roles?.includes(role) ?? false;
  };

  const isAdmin = hasRole("admin") || hasRole("super_admin");
  const isAnalyst = hasRole("analyst") || isAdmin;

  return {
    user,
    accessToken,
    activeTenantId,
    activeTenant,
    isAuthenticated,
    isAdmin,
    isAnalyst,
    logout,
    hasRole,
  };
}
