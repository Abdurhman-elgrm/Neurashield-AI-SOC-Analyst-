import { useState, useRef, useCallback } from "react";
import { Upload, X, CheckCircle, AlertCircle, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import type { EvidenceUploadProgress, EvidenceType } from "../../types/evidence";

const EVIDENCE_TYPES: Array<{ value: EvidenceType; label: string }> = [
  { value: "screenshot",   label: "Screenshot" },
  { value: "log",          label: "Log" },
  { value: "json_payload", label: "JSON" },
  { value: "file",         label: "File" },
  { value: "pcap",         label: "PCAP" },
];

interface EvidenceUploaderProps {
  uploads: EvidenceUploadProgress[];
  onUpload: (
    file: File,
    meta: { title: string; type: string; description?: string; tags?: string[] }
  ) => Promise<unknown>;
  onRemoveUpload: (fileId: string) => void;
}

export function EvidenceUploader({ uploads, onUpload, onRemoveUpload }: EvidenceUploaderProps) {
  const [dragging, setDragging] = useState(false);
  const [title, setTitle] = useState("");
  const [type, setType] = useState<EvidenceType>("file");
  const [tags, setTags] = useState("");
  const [pending, setPending] = useState<File[]>([]);
  const inputRef = useRef<HTMLInputElement>(null);

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    setDragging(false);
    const files = Array.from(e.dataTransfer.files);
    if (files.length) setPending((prev) => [...prev, ...files]);
  }, []);

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = Array.from(e.target.files ?? []);
    if (files.length) setPending((prev) => [...prev, ...files]);
    e.target.value = "";
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    for (const file of pending) {
      await onUpload(file, {
        title: title || file.name,
        type,
        tags: tags.split(",").map((t) => t.trim()).filter(Boolean),
      });
    }
    setPending([]);
    setTitle("");
    setTags("");
  };

  return (
    <div className="space-y-3">
      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragging(true); }}
        onDragLeave={() => setDragging(false)}
        onDrop={handleDrop}
        onClick={() => inputRef.current?.click()}
        className={cn(
          "border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition-colors",
          dragging
            ? "border-accent bg-accent/5"
            : "border-border hover:border-accent/50 hover:bg-bg-subtle"
        )}
      >
        <Upload className="w-6 h-6 text-text-muted mx-auto mb-2" />
        <p className="text-sm text-text-muted">
          Drop files here or <span className="text-accent">browse</span>
        </p>
        <p className="text-2xs text-text-muted/60 mt-1">Screenshots, logs, JSON, PCAPs</p>
        <input
          ref={inputRef}
          type="file"
          multiple
          className="hidden"
          onChange={handleFileInput}
        />
      </div>

      {/* Pending files */}
      {pending.length > 0 && (
        <form onSubmit={(e) => void handleSubmit(e)} className="space-y-2">
          <div className="flex flex-wrap gap-2">
            {pending.map((f, i) => (
              <div
                key={i}
                className="flex items-center gap-1.5 px-2 py-1 bg-bg-elevated border border-border rounded text-xs text-text-secondary"
              >
                {f.name}
                <button
                  type="button"
                  onClick={() => setPending((prev) => prev.filter((_, j) => j !== i))}
                  className="text-text-muted hover:text-severity-critical"
                >
                  <X className="w-3 h-3" />
                </button>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-2 gap-2">
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              placeholder="Title (optional)"
              className="col-span-2 px-2 py-1.5 text-xs bg-bg-elevated border border-border rounded-md text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent"
            />
            <select
              value={type}
              onChange={(e) => setType(e.target.value as EvidenceType)}
              className="px-2 py-1.5 text-xs bg-bg-elevated border border-border rounded-md text-text-primary focus:outline-none focus:border-accent"
            >
              {EVIDENCE_TYPES.map((t) => (
                <option key={t.value} value={t.value}>{t.label}</option>
              ))}
            </select>
            <input
              type="text"
              value={tags}
              onChange={(e) => setTags(e.target.value)}
              placeholder="Tags (comma-separated)"
              className="px-2 py-1.5 text-xs bg-bg-elevated border border-border rounded-md text-text-primary placeholder:text-text-muted focus:outline-none focus:border-accent"
            />
          </div>

          <button
            type="submit"
            className="w-full py-1.5 text-xs font-medium bg-accent text-white rounded-md hover:bg-accent/90 transition-colors"
          >
            Upload {pending.length} file{pending.length !== 1 ? "s" : ""}
          </button>
        </form>
      )}

      {/* Upload progress */}
      {uploads.map((u) => (
        <div
          key={u.fileId}
          className="flex items-center gap-2 text-xs bg-bg-subtle border border-border rounded-md px-3 py-2"
        >
          {u.status === "uploading" && <Loader2 className="w-3.5 h-3.5 text-accent animate-spin" />}
          {u.status === "complete"  && <CheckCircle className="w-3.5 h-3.5 text-status-online" />}
          {u.status === "error"     && <AlertCircle className="w-3.5 h-3.5 text-severity-critical" />}
          <span className="flex-1 text-text-secondary truncate">{u.fileName}</span>
          {u.status === "uploading" && (
            <span className="text-text-muted tabular-nums">{u.progress}%</span>
          )}
          {u.status === "error" && (
            <span className="text-severity-critical">{u.error}</span>
          )}
          <button
            onClick={() => onRemoveUpload(u.fileId)}
            className="text-text-muted hover:text-text-primary"
          >
            <X className="w-3 h-3" />
          </button>
        </div>
      ))}
    </div>
  );
}
