import { apiPost, apiGet, apiClient } from "@/api/client";
import type {
  InstallerToken,
  InstallerTokenGenerateResponse,
  InstallerTokensPage,
  GenerateTokenRequest,
  RevokeTokenRequest,
} from "@/types/installer";

export const installerApi = {
  generate: (data: GenerateTokenRequest) =>
    apiPost<InstallerTokenGenerateResponse>("/installer/generate-token", data),

  list: async (params?: {
    page?: number;
    limit?: number;
    status?: string;
  }): Promise<InstallerTokensPage> => {
    const resp = await apiClient.get<InstallerTokensPage>("/installer/tokens", {
      params,
    });
    return resp.data;
  },

  getStatus: (id: string) =>
    apiGet<InstallerToken>(`/installer/token/${id}/status`),

  revoke: (id: string, data: RevokeTokenRequest = {}) =>
    apiPost<InstallerToken>(`/installer/revoke/${id}`, data),
};
