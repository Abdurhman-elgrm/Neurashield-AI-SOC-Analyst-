import type { MitreTactic } from "@/features/dashboard/types/mitre";

// ─── MITRE ATT&CK Enterprise (v15) — curated subset ──────────────────────────
// Full reference: https://attack.mitre.org/matrices/enterprise/

export const MITRE_TACTICS: MitreTactic[] = [
  {
    id: "TA0043", name: "Reconnaissance", shortName: "Recon",
    techniques: [
      { id: "T1595", name: "Active Scanning",               tacticId: "TA0043" },
      { id: "T1592", name: "Gather Victim Host Info",        tacticId: "TA0043" },
      { id: "T1589", name: "Gather Victim Identity Info",    tacticId: "TA0043" },
      { id: "T1590", name: "Gather Victim Network Info",     tacticId: "TA0043" },
      { id: "T1591", name: "Gather Victim Org Info",         tacticId: "TA0043" },
      { id: "T1598", name: "Phishing for Information",       tacticId: "TA0043" },
    ],
  },
  {
    id: "TA0042", name: "Resource Development", shortName: "Resource Dev",
    techniques: [
      { id: "T1583", name: "Acquire Infrastructure",         tacticId: "TA0042" },
      { id: "T1584", name: "Compromise Infrastructure",      tacticId: "TA0042" },
      { id: "T1585", name: "Establish Accounts",             tacticId: "TA0042" },
      { id: "T1586", name: "Compromise Accounts",            tacticId: "TA0042" },
      { id: "T1587", name: "Develop Capabilities",           tacticId: "TA0042" },
      { id: "T1588", name: "Obtain Capabilities",            tacticId: "TA0042" },
    ],
  },
  {
    id: "TA0001", name: "Initial Access", shortName: "Init Access",
    techniques: [
      { id: "T1566", name: "Phishing",                       tacticId: "TA0001" },
      { id: "T1190", name: "Exploit Public-Facing App",      tacticId: "TA0001" },
      { id: "T1133", name: "External Remote Services",       tacticId: "TA0001" },
      { id: "T1078", name: "Valid Accounts",                 tacticId: "TA0001" },
      { id: "T1091", name: "Removable Media",                tacticId: "TA0001" },
      { id: "T1195", name: "Supply Chain Compromise",        tacticId: "TA0001" },
    ],
  },
  {
    id: "TA0002", name: "Execution", shortName: "Execution",
    techniques: [
      { id: "T1059", name: "Command/Script Interpreter",     tacticId: "TA0002" },
      { id: "T1053", name: "Scheduled Task/Job",             tacticId: "TA0002" },
      { id: "T1047", name: "Windows Mgmt Instrumentation",   tacticId: "TA0002" },
      { id: "T1569", name: "System Services",                tacticId: "TA0002" },
      { id: "T1204", name: "User Execution",                 tacticId: "TA0002" },
      { id: "T1106", name: "Native API",                     tacticId: "TA0002" },
    ],
  },
  {
    id: "TA0003", name: "Persistence", shortName: "Persistence",
    techniques: [
      { id: "T1543", name: "Create/Modify System Process",   tacticId: "TA0003" },
      { id: "T1547", name: "Boot/Logon Autostart Execution", tacticId: "TA0003" },
      { id: "T1136", name: "Create Account",                 tacticId: "TA0003" },
      { id: "T1505", name: "Server Software Component",      tacticId: "TA0003" },
      { id: "T1546", name: "Event Triggered Execution",      tacticId: "TA0003" },
      { id: "T1053", name: "Scheduled Task/Job",             tacticId: "TA0003" },
    ],
  },
  {
    id: "TA0004", name: "Privilege Escalation", shortName: "Priv Esc",
    techniques: [
      { id: "T1055", name: "Process Injection",              tacticId: "TA0004" },
      { id: "T1068", name: "Exploitation for Priv Esc",      tacticId: "TA0004" },
      { id: "T1134", name: "Access Token Manipulation",      tacticId: "TA0004" },
      { id: "T1484", name: "Domain Policy Modification",     tacticId: "TA0004" },
      { id: "T1548", name: "Abuse Elevation Control Mech",   tacticId: "TA0004" },
      { id: "T1611", name: "Escape to Host",                 tacticId: "TA0004" },
    ],
  },
  {
    id: "TA0005", name: "Defense Evasion", shortName: "Def Evasion",
    techniques: [
      { id: "T1027", name: "Obfuscated Files/Info",          tacticId: "TA0005" },
      { id: "T1562", name: "Impair Defenses",                tacticId: "TA0005" },
      { id: "T1070", name: "Indicator Removal",              tacticId: "TA0005" },
      { id: "T1036", name: "Masquerading",                   tacticId: "TA0005" },
      { id: "T1055", name: "Process Injection",              tacticId: "TA0005" },
      { id: "T1112", name: "Modify Registry",                tacticId: "TA0005" },
    ],
  },
  {
    id: "TA0006", name: "Credential Access", shortName: "Cred Access",
    techniques: [
      { id: "T1003", name: "OS Credential Dumping",          tacticId: "TA0006" },
      { id: "T1110", name: "Brute Force",                    tacticId: "TA0006" },
      { id: "T1558", name: "Steal or Forge Kerberos Tickets",tacticId: "TA0006" },
      { id: "T1555", name: "Creds from Password Stores",     tacticId: "TA0006" },
      { id: "T1552", name: "Unsecured Credentials",          tacticId: "TA0006" },
      { id: "T1056", name: "Input Capture",                  tacticId: "TA0006" },
    ],
  },
  {
    id: "TA0007", name: "Discovery", shortName: "Discovery",
    techniques: [
      { id: "T1083", name: "File and Directory Discovery",   tacticId: "TA0007" },
      { id: "T1082", name: "System Information Discovery",   tacticId: "TA0007" },
      { id: "T1016", name: "System Network Config Disc.",     tacticId: "TA0007" },
      { id: "T1057", name: "Process Discovery",              tacticId: "TA0007" },
      { id: "T1087", name: "Account Discovery",              tacticId: "TA0007" },
      { id: "T1135", name: "Network Share Discovery",        tacticId: "TA0007" },
    ],
  },
  {
    id: "TA0008", name: "Lateral Movement", shortName: "Lateral Mov",
    techniques: [
      { id: "T1021", name: "Remote Services",                tacticId: "TA0008" },
      { id: "T1550", name: "Use Alt Auth Material",          tacticId: "TA0008" },
      { id: "T1534", name: "Internal Spearphishing",         tacticId: "TA0008" },
      { id: "T1080", name: "Taint Shared Content",           tacticId: "TA0008" },
      { id: "T1563", name: "Remote Service Session Hijacking",tacticId: "TA0008" },
      { id: "T1570", name: "Lateral Tool Transfer",          tacticId: "TA0008" },
    ],
  },
  {
    id: "TA0009", name: "Collection", shortName: "Collection",
    techniques: [
      { id: "T1074", name: "Data Staged",                    tacticId: "TA0009" },
      { id: "T1114", name: "Email Collection",               tacticId: "TA0009" },
      { id: "T1560", name: "Archive Collected Data",         tacticId: "TA0009" },
      { id: "T1056", name: "Input Capture",                  tacticId: "TA0009" },
      { id: "T1530", name: "Data from Cloud Storage",        tacticId: "TA0009" },
      { id: "T1213", name: "Data from Info Repositories",    tacticId: "TA0009" },
    ],
  },
  {
    id: "TA0011", name: "Command and Control", shortName: "C2",
    techniques: [
      { id: "T1071", name: "Application Layer Protocol",     tacticId: "TA0011" },
      { id: "T1573", name: "Encrypted Channel",              tacticId: "TA0011" },
      { id: "T1105", name: "Ingress Tool Transfer",          tacticId: "TA0011" },
      { id: "T1132", name: "Data Encoding",                  tacticId: "TA0011" },
      { id: "T1008", name: "Fallback Channels",              tacticId: "TA0011" },
      { id: "T1572", name: "Protocol Tunneling",             tacticId: "TA0011" },
    ],
  },
  {
    id: "TA0010", name: "Exfiltration", shortName: "Exfiltration",
    techniques: [
      { id: "T1041", name: "Exfil Over C2 Channel",          tacticId: "TA0010" },
      { id: "T1048", name: "Exfil Over Alt Protocol",        tacticId: "TA0010" },
      { id: "T1567", name: "Exfil Over Web Service",         tacticId: "TA0010" },
      { id: "T1030", name: "Data Transfer Size Limits",      tacticId: "TA0010" },
      { id: "T1052", name: "Exfil Over Physical Medium",     tacticId: "TA0010" },
      { id: "T1020", name: "Automated Exfiltration",         tacticId: "TA0010" },
    ],
  },
  {
    id: "TA0040", name: "Impact", shortName: "Impact",
    techniques: [
      { id: "T1485", name: "Data Destruction",               tacticId: "TA0040" },
      { id: "T1486", name: "Data Encrypted for Impact",      tacticId: "TA0040" },
      { id: "T1490", name: "Inhibit System Recovery",        tacticId: "TA0040" },
      { id: "T1489", name: "Service Stop",                   tacticId: "TA0040" },
      { id: "T1499", name: "Endpoint Denial of Service",     tacticId: "TA0040" },
      { id: "T1496", name: "Resource Hijacking",             tacticId: "TA0040" },
    ],
  },
];

export const MITRE_TECHNIQUE_INDEX: Record<string, string> = Object.fromEntries(
  MITRE_TACTICS.flatMap((t) => t.techniques.map((tech) => [tech.id, tech.name]))
);
