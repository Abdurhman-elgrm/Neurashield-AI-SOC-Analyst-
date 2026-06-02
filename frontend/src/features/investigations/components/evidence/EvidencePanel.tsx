import { FileText } from "lucide-react";
import { SkeletonText } from "@/components/ui/Skeleton";
import { EmptyState } from "@/components/ui/EmptyState";
import { EvidenceList } from "./EvidenceList";
import { EvidenceUploader } from "./EvidenceUploader";
import { useEvidence, useEvidenceUpload, useDeleteEvidence } from "../../hooks/useEvidence";

interface EvidencePanelProps {
  investigationId: string;
}

export function EvidencePanel({ investigationId }: EvidencePanelProps) {
  const { data: items, isLoading } = useEvidence(investigationId);
  const { uploads, uploadFile, removeUpload } = useEvidenceUpload(investigationId);
  const { mutate: deleteItem } = useDeleteEvidence(investigationId);

  return (
    <div className="space-y-6">
      <section>
        <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">
          Upload Evidence
        </h3>
        <EvidenceUploader
          uploads={uploads}
          onUpload={uploadFile}
          onRemoveUpload={removeUpload}
        />
      </section>

      <section>
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
            Evidence ({items?.length ?? 0})
          </h3>
        </div>

        {isLoading ? (
          <SkeletonText lines={4} />
        ) : !items?.length ? (
          <EmptyState
            icon={<FileText className="w-5 h-5" />}
            title="No evidence yet"
            description="Upload screenshots, logs, or files to document this investigation."
            className="py-6"
          />
        ) : (
          <EvidenceList items={items} onDelete={(id) => deleteItem(id)} />
        )}
      </section>
    </div>
  );
}
