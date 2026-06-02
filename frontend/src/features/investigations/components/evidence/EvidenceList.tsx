import { memo } from "react";
import { formatDistanceToNowStrict } from "date-fns";
import { FileText, Image, Code, FileJson, Trash2, Download } from "lucide-react";
import { EVIDENCE_TYPE_LABELS } from "../../types/evidence";
import type { EvidenceItem, EvidenceType } from "../../types/evidence";

const TYPE_ICON: Record<EvidenceType, React.ReactNode> = {
  screenshot:   <Image className="w-4 h-4" />,
  log:          <FileText className="w-4 h-4" />,
  json_payload: <FileJson className="w-4 h-4" />,
  note:         <FileText className="w-4 h-4" />,
  file:         <FileText className="w-4 h-4" />,
  pcap:         <Code className="w-4 h-4" />,
  memory_dump:  <Code className="w-4 h-4" />,
};

function formatFileSize(bytes?: number): string {
  if (!bytes) return "";
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)}MB`;
}

const EvidenceCard = memo(function EvidenceCard({
  item,
  onDelete,
}: {
  item: EvidenceItem;
  onDelete: (id: string) => void;
}) {
  return (
    <div className="border border-border rounded-lg bg-bg-subtle overflow-hidden">
      {/* Screenshot preview */}
      {item.type === "screenshot" && item.url && (
        <div className="aspect-video bg-bg-elevated overflow-hidden">
          <img src={item.url} alt={item.title} className="w-full h-full object-cover" />
        </div>
      )}

      <div className="p-3">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2 flex-1 min-w-0">
            <span className="text-text-muted flex-shrink-0">{TYPE_ICON[item.type]}</span>
            <div className="min-w-0">
              <p className="text-xs font-medium text-text-primary truncate">{item.title}</p>
              <p className="text-2xs text-text-muted">
                {EVIDENCE_TYPE_LABELS[item.type]}
                {item.fileSize && ` · ${formatFileSize(item.fileSize)}`}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-1 flex-shrink-0">
            {item.url && (
              <a
                href={item.url}
                target="_blank"
                rel="noopener noreferrer"
                className="p-1 text-text-muted hover:text-accent transition-colors rounded"
              >
                <Download className="w-3.5 h-3.5" />
              </a>
            )}
            <button
              onClick={() => onDelete(item.id)}
              className="p-1 text-text-muted hover:text-severity-critical transition-colors rounded"
            >
              <Trash2 className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>

        {/* Note content inline */}
        {item.type === "note" && item.content && (
          <p className="mt-2 text-xs text-text-secondary bg-bg-elevated rounded p-2 border border-border">
            {item.content}
          </p>
        )}

        {/* Tags */}
        {item.tags.length > 0 && (
          <div className="flex flex-wrap gap-1 mt-2">
            {item.tags.map((tag) => (
              <span
                key={tag}
                className="px-1.5 py-0.5 text-2xs bg-bg-elevated text-text-muted border border-border rounded"
              >
                {tag}
              </span>
            ))}
          </div>
        )}

        <p className="text-2xs text-text-muted mt-2">
          {item.uploaderName} · {formatDistanceToNowStrict(new Date(item.createdAt), { addSuffix: true })}
        </p>
      </div>
    </div>
  );
});

interface EvidenceListProps {
  items: EvidenceItem[];
  onDelete: (id: string) => void;
}

export function EvidenceList({ items, onDelete }: EvidenceListProps) {
  if (!items.length) return null;

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
      {items.map((item) => (
        <EvidenceCard key={item.id} item={item} onDelete={onDelete} />
      ))}
    </div>
  );
}
