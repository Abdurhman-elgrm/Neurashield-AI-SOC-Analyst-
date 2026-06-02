import type { FilterFieldDef } from "@/components/filters/types";

export const ALERT_FILTER_FIELDS: FilterFieldDef[] = [
  {
    key: "severity",
    label: "Severity",
    type: "enum",
    options: [
      { value: "critical", label: "Critical" },
      { value: "high", label: "High" },
      { value: "medium", label: "Medium" },
      { value: "low", label: "Low" },
      { value: "info", label: "Info" },
    ],
  },
  {
    key: "status",
    label: "Status",
    type: "enum",
    options: [
      { value: "open", label: "Open" },
      { value: "in_progress", label: "In Progress" },
      { value: "closed", label: "Closed" },
      { value: "suppressed", label: "Suppressed" },
    ],
  },
  {
    key: "hostname",
    label: "Hostname",
    type: "string",
    placeholder: "Filter by hostname...",
  },
  {
    key: "username",
    label: "Username",
    type: "string",
    placeholder: "Filter by user...",
  },
  {
    key: "source_ip",
    label: "Source IP",
    type: "string",
    placeholder: "e.g. 192.168.1.0",
  },
  {
    key: "mitre_technique",
    label: "MITRE Technique",
    type: "string",
    placeholder: "e.g. T1059",
  },
  {
    key: "ai_verdict",
    label: "AI Verdict",
    type: "enum",
    options: [
      { value: "true_positive", label: "True Positive" },
      { value: "false_positive", label: "False Positive" },
      { value: "benign", label: "Benign" },
      { value: "pending", label: "Pending" },
    ],
  },
  {
    key: "assigned_to",
    label: "Assigned To",
    type: "string",
    placeholder: "Filter by analyst...",
  },
];
