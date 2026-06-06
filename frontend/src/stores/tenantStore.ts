import { create } from "zustand";
import type { Tenant, MemberRole } from "@/types/tenant";

interface TenantState {
  activeTenant: Tenant | null;
  memberRole: MemberRole | null;
  tenants: Tenant[];

  setActiveTenant: (tenant: Tenant, role: MemberRole) => void;
  setTenants: (tenants: Tenant[]) => void;
  clearTenant: () => void;

  // Permission helpers — pass any role string; uses hierarchy owner>admin>analyst>viewer
  hasRole: (minimum: string) => boolean;
}

const ROLE_HIERARCHY: Record<MemberRole, number> = {
  viewer: 0,
  analyst: 1,
  admin: 2,
  owner: 3,
};

export const useTenantStore = create<TenantState>()((set, get) => ({
  activeTenant: null,
  memberRole: null,
  tenants: [],

  setActiveTenant: (tenant, role) =>
    set({ activeTenant: tenant, memberRole: role }),

  setTenants: (tenants) => set({ tenants }),

  clearTenant: () => set({ activeTenant: null, memberRole: null }),

  hasRole: (minimum) => {
    const { memberRole } = get();
    if (!memberRole) return false;
    const minKey = minimum as MemberRole;
    // Unknown role strings are treated as maximum privilege so UI stays accessible
    // while the backend enforces real RBAC on every request.
    if (!(minKey in ROLE_HIERARCHY)) return true;
    return ROLE_HIERARCHY[memberRole] >= ROLE_HIERARCHY[minKey];
  },
}));
