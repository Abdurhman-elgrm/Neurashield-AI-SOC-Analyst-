import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import {
  getInvestigationEvidence,
  uploadEvidence,
  PLACEHOLDER_EVIDENCE,
} from "../api/investigationsApi";
import { investigationKeys } from "./useInvestigation";
import type { EvidenceItem, EvidenceUploadProgress } from "../types/evidence";

// ─── Evidence list ────────────────────────────────────────────────────────────

export function useEvidence(investigationId: string) {
  return useQuery({
    queryKey: investigationKeys.evidence(investigationId),
    queryFn: () => getInvestigationEvidence(investigationId),
    placeholderData: PLACEHOLDER_EVIDENCE,
    staleTime: 30_000,
    enabled: !!investigationId,
  });
}

// ─── Evidence upload ──────────────────────────────────────────────────────────

export function useEvidenceUpload(investigationId: string) {
  const qc = useQueryClient();
  const [uploads, setUploads] = useState<EvidenceUploadProgress[]>([]);

  const updateUpload = (fileId: string, patch: Partial<EvidenceUploadProgress>) =>
    setUploads((prev) => prev.map((u) => (u.fileId === fileId ? { ...u, ...patch } : u)));

  const uploadFile = async (
    file: File,
    meta: { title: string; type: string; description?: string; tags?: string[] }
  ): Promise<EvidenceItem | null> => {
    const fileId = `${file.name}-${Date.now()}`;

    setUploads((prev) => [
      ...prev,
      { fileId, fileName: file.name, progress: 0, status: "uploading" },
    ]);

    try {
      const result = await uploadEvidence(investigationId, file, meta, (pct) => {
        updateUpload(fileId, { progress: pct });
      });
      updateUpload(fileId, { progress: 100, status: "complete" });
      void qc.invalidateQueries({ queryKey: investigationKeys.evidence(investigationId) });

      setTimeout(() => {
        setUploads((prev) => prev.filter((u) => u.fileId !== fileId));
      }, 2000);

      return result;
    } catch (err) {
      updateUpload(fileId, {
        status: "error",
        error: err instanceof Error ? err.message : "Upload failed",
      });
      return null;
    }
  };

  const removeUpload = (fileId: string) =>
    setUploads((prev) => prev.filter((u) => u.fileId !== fileId));

  return { uploads, uploadFile, removeUpload };
}

// ─── Delete evidence ──────────────────────────────────────────────────────────

export function useDeleteEvidence(investigationId: string) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (evidenceId: string) => {
      // Optimistically remove from cache
      qc.setQueryData<EvidenceItem[]>(
        investigationKeys.evidence(investigationId),
        (prev) => prev?.filter((e) => e.id !== evidenceId) ?? prev
      );
    },
    onSettled: () => {
      void qc.invalidateQueries({ queryKey: investigationKeys.evidence(investigationId) });
    },
  });
}
