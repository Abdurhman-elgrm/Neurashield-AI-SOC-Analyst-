import { apiPost, apiGet } from "@/api/client";
import type { LoginRequest, RegisterRequest, TokenPair, User } from "@/types/auth";

export interface MFASetupResponse {
  provisioning_uri: string;
  encrypted_secret: string;
}

export interface MFABackupCodesResponse {
  backup_codes: string[];
}

export const authApi = {
  register: (data: RegisterRequest): Promise<TokenPair> =>
    apiPost<TokenPair>("/auth/register", data),

  login: (data: LoginRequest): Promise<TokenPair> =>
    apiPost<TokenPair>("/auth/login", data),

  refresh: (refreshToken: string): Promise<TokenPair> =>
    apiPost<TokenPair>("/auth/refresh", { refresh_token: refreshToken }),

  logout: (refreshToken: string): Promise<void> =>
    apiPost<void>("/auth/logout", { refresh_token: refreshToken }),

  me: (): Promise<User> =>
    apiGet<User>("/auth/me"),

  forgotPassword: (email: string): Promise<void> =>
    apiPost<void>("/auth/forgot-password", { email }),

  resetPassword: (token: string, new_password: string): Promise<void> =>
    apiPost<void>("/auth/reset-password", { token, new_password }),

  changePassword: (current_password: string, new_password: string): Promise<void> =>
    apiPost<void>("/auth/change-password", { current_password, new_password }),

  resendVerification: (email: string): Promise<void> =>
    apiPost<void>("/auth/resend-verification", { email }),

  verifyEmail: (token: string): Promise<void> =>
    apiGet<void>('/auth/verify-email', { token }),

  demoLogin: (): Promise<TokenPair> =>
    apiPost<TokenPair>("/auth/demo"),

  // MFA endpoints
  mfaSetup: (): Promise<MFASetupResponse> =>
    apiPost<MFASetupResponse>("/auth/mfa/setup"),

  mfaVerify: (encrypted_secret: string, code: string): Promise<MFABackupCodesResponse> =>
    apiPost<MFABackupCodesResponse>("/auth/mfa/verify", { encrypted_secret, code }),

  mfaDisable: (password: string, code: string): Promise<void> =>
    apiPost<void>("/auth/mfa/disable", { password, code }),
};
