export type EvidenceType =
  | "screenshot"
  | "log"
  | "json_payload"
  | "note"
  | "file"
  | "pcap"
  | "memory_dump";

export interface EvidenceItem {
  id: string;
  investigationId: string;
  tenantId: string;
  type: EvidenceType;
  title: string;
  description?: string;
  tags: string[];
  uploadedBy: string;
  uploaderName: string;
  fileSize?: number;
  mimeType?: string;
  url?: string;
  content?: string;
  metadata: Record<string, unknown>;
  createdAt: string;
}

export interface EvidenceUploadProgress {
  fileId: string;
  fileName: string;
  progress: number;   // 0-100
  status: "pending" | "uploading" | "complete" | "error";
  error?: string;
}

export const EVIDENCE_TYPE_LABELS: Record<EvidenceType, string> = {
  screenshot:   "Screenshot",
  log:          "Log File",
  json_payload: "JSON Payload",
  note:         "Note",
  file:         "File",
  pcap:         "PCAP",
  memory_dump:  "Memory Dump",
};

export const EVIDENCE_ACCEPT_MAP: Record<EvidenceType, string> = {
  screenshot:   "image/*",
  log:          "text/plain,.log",
  json_payload: "application/json,.json",
  note:         "*",
  file:         "*",
  pcap:         ".pcap,.pcapng",
  memory_dump:  ".dmp,.mem",
};
