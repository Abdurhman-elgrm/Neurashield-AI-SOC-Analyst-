import { useQuery } from "@tanstack/react-query";
import { apiClient } from "@/api/client";
import { ProcessTree } from "../process/ProcessTree";
import type { ProcessNode } from "../process/ProcessTree";

// GET /investigations/:id/process-tree — returns process tree roots
interface ProcessTreeResponse {
  roots: ProcessNode[];
}


interface Props {
  id: string;
  isActive: boolean;
}

export function ProcessTreeTab({ id, isActive }: Props) {
  const { data, isLoading } = useQuery({
    queryKey: ["inv-process-tree", id],
    queryFn: () =>
      apiClient
        .get<{ data: ProcessTreeResponse }>(`/investigations/${id}/process-tree`)
         
        .then((r) => (r.data as any).data ?? r.data)
        .catch(() => ({ roots: [] as ProcessNode[] })),
    enabled: isActive,
    staleTime: 120_000,
  });

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-sm font-bold text-text-primary">Process Tree</h3>
          <p className="text-xs text-text-muted mt-0.5">
            Reconstructed process execution chain from correlated events.
          </p>
        </div>
        {data && data.roots.length > 0 && (
          <div className="flex items-center gap-2 text-2xs text-text-muted">
            <span className="w-2 h-2 rounded-sm bg-severity-high/60 border border-severity-high/40" />
            Suspicious
          </div>
        )}
      </div>

      <div className="rounded-xl border border-border bg-bg-card p-3">
        <ProcessTree roots={data?.roots ?? []} isLoading={isLoading} />
      </div>
    </div>
  );
}
