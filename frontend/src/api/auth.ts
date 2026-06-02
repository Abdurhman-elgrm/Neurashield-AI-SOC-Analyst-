import { apiPost } from "@/api/client";
import type { LoginRequest, RegisterRequest, TokenPair, User } from "@/types/auth";

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
    apiPost<User>("/auth/me"),
};
