export interface Tenant {
  id: string;
  name: string;
  slug: string;
  is_active: boolean;
  created_at: string;
}

export interface TenantMember {
  id: string;
  tenant_id: string;
  user_id: string;
  role: MemberRole;
  joined_at: string | null;
  created_at: string;
  email?: string;
  full_name?: string;
}

export type MemberRole = "owner" | "admin" | "analyst" | "viewer";

export interface TenantCreateRequest {
  name: string;
  slug?: string;
}

export interface TenantUpdateRequest {
  name?: string;
}
