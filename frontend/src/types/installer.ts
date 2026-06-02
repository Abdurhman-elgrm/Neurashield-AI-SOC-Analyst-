export type InstallerTokenStatus =
  | "pending"
  | "installing"
  | "active"
  | "expired"
  | "revoked"
  | "failed";

export interface InstallerToken {
  id: string;
  tenant_id: string;
  token_preview: string;
  organization: string;
  machine_name: string;
  status: InstallerTokenStatus;
  expires_at: string;
  used_at: string | null;
  installed_at: string | null;
  revoked_at: string | null;
  device_id: string | null;
  metadata: Record<string, unknown>;
  created_by_id: string | null;
  created_at: string;
  updated_at: string;
}

export interface InstallerTokenGenerateResponse extends InstallerToken {
  raw_token: string;
}

export interface GenerateTokenRequest {
  organization: string;
  machine_name: string;
  metadata?: Record<string, unknown>;
}

export interface RevokeTokenRequest {
  reason?: string;
}

export interface InstallerTokensPage {
  data: InstallerToken[];
  pagination: {
    page: number;
    limit: number;
    total: number;
    pages: number;
  };
  meta: {
    request_id: string;
    timestamp: string;
  };
}
