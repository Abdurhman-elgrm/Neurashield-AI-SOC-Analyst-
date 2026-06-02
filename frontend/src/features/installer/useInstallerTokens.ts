import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { installerApi } from "@/api/installer";
import type {
  InstallerTokenStatus,
  GenerateTokenRequest,
  RevokeTokenRequest,
} from "@/types/installer";

const QUERY_KEY = "installer-tokens";

export function useInstallerTokens(
  page: number,
  limit: number,
  statusFilter: InstallerTokenStatus | "all",
) {
  return useQuery({
    queryKey: [QUERY_KEY, page, limit, statusFilter],
    queryFn: () =>
      installerApi.list({
        page,
        limit,
        status: statusFilter === "all" ? undefined : statusFilter,
      }),
  });
}

export function useGenerateToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (data: GenerateTokenRequest) => installerApi.generate(data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [QUERY_KEY] });
    },
  });
}

export function useRevokeToken() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: ({ id, data }: { id: string; data: RevokeTokenRequest }) =>
      installerApi.revoke(id, data),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: [QUERY_KEY] });
    },
  });
}
