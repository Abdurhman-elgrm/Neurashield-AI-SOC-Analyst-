from __future__ import annotations

# Sigma field name → our NormalizedEvent dot-path
SIGMA_FIELD_TO_NORMALIZED: dict[str, str] = {
    # ── Process ──────────────────────────────────────────────────────────────────
    "Image":               "process.executable",
    "OriginalFileName":    "process.name",
    "CommandLine":         "process.command_line",
    "ParentImage":         "raw.parent_image",
    "ParentCommandLine":   "raw.parent_command_line",
    "ParentProcessName":   "raw.parent_process_name",
    "ProcessName":         "process.name",
    "IntegrityLevel":      "raw.integrity_level",
    # ── User ─────────────────────────────────────────────────────────────────────
    "User":                "user.name",
    "SubjectUserName":     "user.name",
    "TargetUserName":      "user.name",
    "AccountName":         "user.name",
    "LogonUserName":       "user.name",
    "SubjectDomainName":   "user.domain",
    "TargetDomainName":    "user.domain",
    # ── Network ──────────────────────────────────────────────────────────────────
    "DestinationIp":       "network.dst_ip",
    "DestinationPort":     "network.dst_port",
    "DestinationHostname": "network.dst_ip",
    "SourceIp":            "network.src_ip",
    "SourcePort":          "network.src_port",
    "IpAddress":           "network.src_ip",
    "IpPort":              "network.src_port",
    # ── File ─────────────────────────────────────────────────────────────────────
    "TargetFilename":      "file.path",
    "FileName":            "file.name",
    "FilePath":            "file.path",
    # ── Registry ─────────────────────────────────────────────────────────────────
    "TargetObject":        "registry.key",
    "Details":             "registry.value",
    "NewName":             "registry.key",
    # ── DNS ──────────────────────────────────────────────────────────────────────
    "QueryName":           "raw.query_name",
    "QueryType":           "raw.query_type",
    # ── Hashes ───────────────────────────────────────────────────────────────────
    "Hashes":              "raw.hashes",
    "md5":                 "process.hash_md5",
    "sha256":              "process.hash_sha256",
    # ── Windows events ────────────────────────────────────────────────────────────
    "EventID":             "raw.windows_event_id",
    "Channel":             "raw.channel",
    "Provider_Name":       "raw.source_name",
    "Computer":            "hostname",
    "LogonType":           "raw.logon_type",
    "WorkstationName":     "raw.workstation_name",
    "EventType":           "raw.event_type",
    # ── Service ──────────────────────────────────────────────────────────────────
    "ServiceName":         "raw.service_name",
    "ImagePath":           "process.executable",
    # ── Generic ──────────────────────────────────────────────────────────────────
    "Category":            "category",
    "Hostname":            "hostname",
}

# Sigma logsource.category → our event category
SIGMA_LOGSOURCE_TO_CATEGORY: dict[str, str] = {
    "process_creation":      "process",
    "network_connection":    "network",
    "network_traffic":       "network",
    "dns_query":             "dns",
    "dns":                   "dns",
    "file_event":            "file",
    "file_change":           "file",
    "file_rename":           "file",
    "file_delete":           "file",
    "registry_event":        "registry",
    "registry_add":          "registry",
    "registry_set":          "registry",
    "registry_delete":       "registry",
    "registry_rename":       "registry",
    "authentication":        "auth",
    "failed_authentication": "auth",
    "logon":                 "auth",
    "system":                "system",
}

# Sigma logsource.product → our os_type
SIGMA_PRODUCT_TO_OS: dict[str, str] = {
    "windows": "windows",
    "linux":   "linux",
    "macos":   "macos",
}

# Sigma level → our RuleSeverity
SIGMA_LEVEL_TO_SEVERITY: dict[str, str] = {
    "informational": "low",
    "low":           "low",
    "medium":        "medium",
    "high":          "high",
    "critical":      "critical",
}

# Sigma field modifiers → our condition op
SIGMA_MODIFIER_TO_OP: dict[str, str] = {
    "contains":   "contains",
    "startswith": "startswith",
    "endswith":   "endswith",
    "re":         "regex",
    "lt":         "lt",
    "lte":        "lte",
    "gt":         "gt",
    "gte":        "gte",
}
