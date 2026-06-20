import { useState, useEffect, useRef, useCallback } from 'react'
import { Link } from 'react-router-dom'
import {
  ChevronRight, ChevronDown, Terminal, Shield, Bell, Search,
  GitMerge, Globe, UserCheck, Brain, FileText, BarChart3,
  Users, Settings, Network, AlertTriangle, Eye,
  BookOpen, ArrowLeft, Copy, Check, Menu, X,
} from 'lucide-react'
import { LogoFull } from '@/components/ui/Logo'

// ─── Types ────────────────────────────────────────────────────────────────────

interface DocSection {
  id: string
  label: string
  icon: React.ElementType
  children?: { id: string; label: string }[]
}

// ─── Sidebar structure ────────────────────────────────────────────────────────

const NAV: DocSection[] = [
  {
    id: 'overview', label: 'Overview', icon: BookOpen,
  },
  {
    id: 'quickstart', label: 'Quick Start', icon: Terminal,
    children: [
      { id: 'qs-requirements', label: 'Requirements' },
      { id: 'qs-account',      label: 'Create Account' },
      { id: 'qs-agent',        label: 'Install Agent' },
      { id: 'qs-verify',       label: 'Verify Detection' },
    ],
  },
  {
    id: 'dashboard', label: 'Dashboard', icon: BarChart3,
  },
  {
    id: 'alerts', label: 'Alerts', icon: Bell,
    children: [
      { id: 'alerts-lifecycle', label: 'Alert Lifecycle' },
      { id: 'alerts-severity',  label: 'Severity Levels' },
      { id: 'alerts-triage',    label: 'Triage & Actions' },
    ],
  },
  {
    id: 'detection', label: 'Detection Rules', icon: Shield,
    children: [
      { id: 'det-native',  label: 'Native Rules' },
      { id: 'det-sigma',   label: 'Sigma Rules' },
      { id: 'det-ueba',    label: 'UEBA Rules' },
      { id: 'det-ai',      label: 'AI Rule Generator' },
      { id: 'det-custom',  label: 'Custom Rules' },
    ],
  },
  {
    id: 'attack-chain', label: 'Attack Chain Correlator', icon: GitMerge,
  },
  {
    id: 'threat-intel', label: 'Threat Intelligence', icon: Globe,
  },
  {
    id: 'ueba', label: 'UEBA Analytics', icon: UserCheck,
  },
  {
    id: 'investigations', label: 'Investigations', icon: Search,
  },
  {
    id: 'hunting', label: 'Threat Hunting', icon: Eye,
  },
  {
    id: 'graph', label: 'Attack Graph', icon: Network,
  },
  {
    id: 'copilot', label: 'AI Copilot', icon: Brain,
  },
  {
    id: 'playbooks', label: 'IR Playbooks', icon: FileText,
  },
  {
    id: 'notifications', label: 'Notifications', icon: Bell,
  },
  {
    id: 'reports', label: 'Reports', icon: BarChart3,
  },
  {
    id: 'agents', label: 'Agent Management', icon: Terminal,
  },
  {
    id: 'team', label: 'Team & Roles', icon: Users,
  },
  {
    id: 'settings', label: 'Settings', icon: Settings,
  },
]

// ─── Reusable doc components ──────────────────────────────────────────────────

function Callout({ type = 'info', children }: { type?: 'info' | 'warn' | 'tip'; children: React.ReactNode }) {
  const styles = {
    info: 'border-blue-500/30 bg-blue-500/5 text-blue-300',
    warn: 'border-amber-500/30 bg-amber-500/5 text-amber-300',
    tip:  'border-green-500/30 bg-green-500/5 text-green-300',
  }
  const icons = {
    info: <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />,
    warn: <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />,
    tip:  <Check className="w-4 h-4 shrink-0 mt-0.5" />,
  }
  return (
    <div className={`flex gap-3 px-4 py-3 rounded-lg border text-sm leading-relaxed my-4 ${styles[type]}`}>
      {icons[type]}
      <div>{children}</div>
    </div>
  )
}

function CodeBlock({ children, lang = 'bash' }: { children: string; lang?: string }) {
  const [copied, setCopied] = useState(false)
  const copy = () => {
    navigator.clipboard.writeText(children)
    setCopied(true)
    setTimeout(() => setCopied(false), 1800)
  }
  return (
    <div className="relative my-4 rounded-xl border border-border-strong bg-bg-elevated overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 border-b border-border bg-bg-surface">
        <span className="text-xs text-tx-4 font-mono">{lang}</span>
        <button
          onClick={copy}
          className="flex items-center gap-1.5 text-xs text-tx-4 hover:text-tx-2 transition-colors"
        >
          {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
          {copied ? 'Copied' : 'Copy'}
        </button>
      </div>
      <pre className="p-4 text-xs font-mono text-tx-2 overflow-x-auto leading-relaxed whitespace-pre-wrap">
        {children}
      </pre>
    </div>
  )
}

function Table({ headers, rows }: { headers: string[]; rows: (string | React.ReactNode)[][] }) {
  return (
    <div className="my-4 overflow-x-auto rounded-xl border border-border">
      <table className="w-full text-sm">
        <thead>
          <tr className="border-b border-border bg-bg-elevated">
            {headers.map((h) => (
              <th key={h} className="text-left px-4 py-2.5 text-xs font-semibold text-tx-3 uppercase tracking-wider">{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((row, i) => (
            <tr key={i} className="border-b border-border last:border-0 hover:bg-bg-hover transition-colors">
              {row.map((cell, j) => (
                <td key={j} className="px-4 py-3 text-tx-2">{cell}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function DocH2({ id, children }: { id: string; children: React.ReactNode }) {
  return (
    <h2 id={id} className="text-2xl font-bold text-tx-1 mt-12 mb-4 scroll-mt-24" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
      {children}
    </h2>
  )
}

function DocH3({ id, children }: { id?: string; children: React.ReactNode }) {
  return (
    <h3 id={id} className="text-lg font-semibold text-tx-1 mt-8 mb-3 scroll-mt-24">
      {children}
    </h3>
  )
}

function DocP({ children }: { children: React.ReactNode }) {
  return <p className="text-sm text-tx-2 leading-relaxed mb-3">{children}</p>
}

function Badge({ color, children }: { color: string; children: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${color}`}>
      {children}
    </span>
  )
}

// ─── All documentation content ────────────────────────────────────────────────

function DocContent() {
  return (
    <div className="max-w-3xl">

      {/* ── Overview ──────────────────────────────────────────────────────── */}
      <DocH2 id="overview">Overview</DocH2>
      <DocP>
        <strong className="text-tx-1">NEURASHIELD</strong> is an enterprise-grade AI Security Operations Center (SOC) platform.
        It combines a lightweight endpoint agent, a real-time event processing pipeline, and an AI-powered
        detection and response layer — giving your team full threat visibility from the moment the agent is deployed.
      </DocP>
      <DocP>
        Unlike traditional SIEMs that require months of rule tuning and manual investigation, NEURASHIELD works
        automatically from day one: 80+ detection rules fire, threat intelligence enriches every event, behavioral
        baselines self-calibrate, and attack chains correlate across multiple alerts — all without configuration.
      </DocP>

      <DocH3>Core capabilities</DocH3>
      <Table
        headers={['Capability', 'Description']}
        rows={[
          ['AI Detection Engine', '80+ native rules + Sigma YAML + UEBA, real-time evaluation'],
          ['Attack Chain Correlator', '12 multi-stage attack patterns detected automatically'],
          ['Threat Intelligence', 'Live AbuseIPDB (IP) + MalwareBazaar (hash) enrichment'],
          ['UEBA Analytics', 'Per-user behavioral baselines, anomaly scoring'],
          ['AI Copilot', 'Natural-language investigation assistant'],
          ['Auto IR Playbooks', 'AI-generated response playbooks on every HIGH/CRITICAL alert'],
          ['Real-time Notifications', 'Slack, Teams, PagerDuty, Email, Webhooks'],
          ['Reports', 'Executive and operational security reports'],
        ]}
      />

      {/* ── Quick Start ───────────────────────────────────────────────────── */}
      <DocH2 id="quickstart">Quick Start</DocH2>
      <DocP>Get NEURASHIELD running in under 5 minutes.</DocP>

      <DocH3 id="qs-requirements">System Requirements</DocH3>
      <Table
        headers={['Component', 'Requirement']}
        rows={[
          ['Windows Agent', 'Windows 10 / Server 2016 or later, Python 3.8+'],
          ['Linux Agent',   'Ubuntu 20.04+, Debian 10+, RHEL 8+, Python 3.8+'],
          ['Sysmon (optional)', 'Sysmon v15+ for process creation and network event enrichment'],
          ['Backend',       'No local server required — cloud-hosted on Railway'],
          ['Browser',       'Chrome, Firefox, Edge (modern versions)'],
        ]}
      />
      <Callout type="tip">
        Install Sysmon on Windows endpoints for richer process telemetry (parent process, command-line args,
        network connections). Without Sysmon, basic Windows Event Log data is still collected and many rules still fire.
      </Callout>

      <DocH3 id="qs-account">Step 1 — Create Your Account</DocH3>
      <DocP>
        Navigate to the NEURASHIELD platform and click <strong className="text-tx-1">Create Account</strong>.
        Fill in your name, email address, and password. You will receive an email verification link — click it
        before signing in.
      </DocP>
      <DocP>
        After email verification, sign in and complete the Organization Setup wizard. Enter your organization
        name — this creates your isolated tenant where all agents, alerts, and data are stored.
      </DocP>

      <DocH3 id="qs-agent">Step 2 — Install the Agent</DocH3>
      <DocP>
        Navigate to <strong className="text-tx-1">Agents → Install Agent</strong> in the sidebar. The page
        generates a one-line installer command pre-populated with your tenant credentials.
      </DocP>
      <CodeBlock lang="powershell">{`# Windows — run as Administrator in PowerShell
Invoke-WebRequest -Uri "https://your-platform/api/agents/installer/download" \`
  -Headers @{ "X-Tenant-ID" = "your-tenant-id" } \`
  -OutFile "neurashield-setup.exe"
.\\neurashield-setup.exe`}</CodeBlock>
      <CodeBlock lang="bash">{`# Linux — run as root
curl -sSL https://your-platform/api/agents/installer/download \\
  -H "X-Tenant-ID: your-tenant-id" | sudo bash`}</CodeBlock>
      <DocP>
        The installer copies the agent to <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">C:\ProgramData\SOCAnalyst\</code> on
        Windows or <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">/opt/soc-analyst/</code> on Linux,
        stores your encrypted credentials, and registers the agent as a system service that starts automatically.
      </DocP>

      <DocH3 id="qs-verify">Step 3 — Verify Detection</DocH3>
      <DocP>
        Go to <strong className="text-tx-1">Agents</strong> in the sidebar. Within 60 seconds of installation,
        your endpoint should appear with status <Badge color="text-green-400 bg-green-500/10">Online</Badge>.
        Within a few minutes, events begin streaming and the dashboard populates with activity.
      </DocP>
      <Callout type="info">
        The first alert you see is usually a baseline "Anomalous Login Hour" or threat-intel enrichment alert.
        This is expected — NEURASHIELD is actively analyzing from the first event.
      </Callout>

      {/* ── Dashboard ─────────────────────────────────────────────────────── */}
      <DocH2 id="dashboard">Dashboard</DocH2>
      <DocP>
        The Dashboard is your real-time security operations center view. It refreshes automatically via
        WebSocket — no manual reload needed.
      </DocP>
      <Table
        headers={['Widget', 'Description']}
        rows={[
          ['Alert Summary', 'Open alert count by severity (Critical, High, Medium, Low)'],
          ['Agent Status', 'Online / Offline agents with last-seen timestamp'],
          ['Recent Alerts', 'Last 10 alerts across all agents with one-click triage'],
          ['UEBA Insights', 'Anomaly counts and top flagged users for the last 24h'],
          ['Event Throughput', 'Events per minute across all agents'],
          ['Top Attack Techniques', 'MITRE ATT&CK techniques seen most in the last 7 days'],
        ]}
      />

      {/* ── Alerts ────────────────────────────────────────────────────────── */}
      <DocH2 id="alerts">Alerts</DocH2>
      <DocP>
        Alerts are the core output of the detection engine. Every time a rule fires, an alert is created
        with a severity, evidence, MITRE mapping, and the full event context.
      </DocP>

      <DocH3 id="alerts-lifecycle">Alert Lifecycle</DocH3>
      <Table
        headers={['Status', 'Meaning']}
        rows={[
          [<Badge color="text-red-400 bg-red-500/10">Open</Badge>,        'New alert, not yet reviewed'],
          [<Badge color="text-amber-400 bg-amber-500/10">In Progress</Badge>, 'Analyst is actively investigating'],
          [<Badge color="text-green-400 bg-green-500/10">Resolved</Badge>, 'Investigation complete, threat addressed'],
          [<Badge color="text-tx-3 bg-bg-elevated">False Positive</Badge>, 'Confirmed as not a real threat'],
        ]}
      />

      <DocH3 id="alerts-severity">Severity Levels</DocH3>
      <Table
        headers={['Severity', 'Meaning', 'Examples']}
        rows={[
          [<Badge color="text-red-400 bg-red-500/10">Critical</Badge>, 'Active attack in progress', 'Mimikatz, Ransomware, confirmed malware hash'],
          [<Badge color="text-orange-400 bg-orange-500/10">High</Badge>, 'Strong indicator of compromise', 'AMSI bypass, LSASS dump attempt, PsExec lateral'],
          [<Badge color="text-amber-400 bg-amber-500/10">Medium</Badge>, 'Suspicious behavior requiring review', 'Encoded PowerShell, new scheduled task, BITS transfer'],
          [<Badge color="text-blue-400 bg-blue-500/10">Low</Badge>,  'Informational / weak indicator', 'New local user, off-hours login, high port outbound'],
        ]}
      />
      <Callout type="info">
        UEBA context and threat intelligence can auto-escalate alert severity. A Medium rule that fires
        on a known threat IP may be elevated to Critical automatically.
      </Callout>

      <DocH3 id="alerts-triage">Triage & Actions</DocH3>
      <DocP>
        Click any alert to open the detail panel. From here you can:
      </DocP>
      <ul className="space-y-2 mb-4">
        {[
          'Change the alert status (Open → In Progress → Resolved)',
          'View the full evidence dict: event fields, matched rule, MITRE techniques',
          'Read the AI analysis summary generated automatically on alert creation',
          'Link the alert to an existing Investigation or create a new one',
          'Download the AI-generated IR Playbook for this alert',
          'Suppress future alerts from the same rule + host for a configurable window',
        ].map((item) => (
          <li key={item} className="flex items-start gap-2 text-sm text-tx-2">
            <ChevronRight className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            {item}
          </li>
        ))}
      </ul>

      {/* ── Detection Rules ───────────────────────────────────────────────── */}
      <DocH2 id="detection">Detection Rules</DocH2>
      <DocP>
        NEURASHIELD ships with 80 rules across four types. All rules are enabled by default for every new tenant.
        Navigate to <strong className="text-tx-1">Rules</strong> in the sidebar to manage them.
      </DocP>
      <Table
        headers={['Type', 'Count', 'How it works']}
        rows={[
          ['Native Pattern', '74', 'Field-level conditions evaluated against every normalized event'],
          ['Sigma YAML', '24', 'Open-standard Sigma rules compiled into condition trees'],
          ['UEBA', '6', 'Statistical anomaly rules against per-user behavioral baselines'],
          ['Threshold', '6', 'Count-based rules: X events within Y seconds triggers an alert'],
        ]}
      />

      <DocH3 id="det-native">Native Pattern Rules</DocH3>
      <DocP>
        Native rules are JSON condition trees evaluated in-memory by the detection engine on every event.
        They support operators: <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">eq</code>,&nbsp;
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">contains</code>,&nbsp;
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">regex</code>,&nbsp;
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">gt/lt</code>,&nbsp;
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">in</code>,&nbsp;
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">list_contains</code>,&nbsp;
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">any_of</code>,&nbsp;
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">none_of</code>,&nbsp;
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">any_of_groups</code>.
      </DocP>
      <DocP>
        Rules are grouped by MITRE tactic: Execution, Persistence, Privilege Escalation, Defense Evasion,
        Credential Access, Discovery, Lateral Movement, Command & Control, Exfiltration, Impact, and more.
      </DocP>

      <DocH3 id="det-sigma">Sigma Rules</DocH3>
      <DocP>
        Sigma is an open standard for writing detection rules that are portable across SIEM platforms.
        NEURASHIELD includes 24 built-in Sigma rules and can import additional community rules.
        Rules are compiled into the same condition tree format as native rules.
      </DocP>
      <CodeBlock lang="yaml">{`title: AMSI Bypass Attempt via Reflection
status: experimental
description: Detects PowerShell attempting to bypass AMSI via reflection techniques
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\\powershell.exe'
    CommandLine|contains:
      - 'AmsiUtils'
      - 'amsiInitFailed'
      - 'AmsiScanBuffer'
  condition: selection
level: high
tags:
  - attack.defense_evasion
  - attack.t1562.001`}</CodeBlock>

      <DocH3 id="det-ueba">UEBA Rules</DocH3>
      <DocP>
        UEBA rules fire when the UEBA engine flags a behavioral anomaly. The engine builds per-user baselines
        over a 14-day rolling window and scores deviations.
      </DocP>
      <Table
        headers={['UEBA Rule', 'Trigger']}
        rows={[
          ['Impossible Travel',        'Login from two locations impossible within the time gap'],
          ['Off-Hours Login',          'Login significantly outside the user\'s normal hours'],
          ['New Country Login',        'First login ever from a new country for this user'],
          ['High Volume Data Access',  'File/DB reads > 3× the user\'s 14-day average'],
          ['Privilege Spike',          'Sudden use of admin privileges not seen in baseline'],
          ['Anomaly Score Threshold',  'UEBA composite score exceeds the configured threshold'],
        ]}
      />

      <DocH3 id="det-ai">AI Rule Generator</DocH3>
      <DocP>
        Navigate to <strong className="text-tx-1">Rules → AI Rule Generator</strong>. Describe the threat you
        want to detect in plain English, and the AI generates a complete detection rule with conditions, severity,
        MITRE mapping, and suppression window.
      </DocP>
      <Callout type="tip">
        Example prompt: "Detect when PowerShell downloads a file using Invoke-WebRequest or wget and immediately
        executes it — common in fileless malware dropper chains." The AI produces a precise
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs ml-1">any_of_groups</code> rule
        covering both command-line patterns.
      </Callout>

      <DocH3 id="det-custom">Custom Rules</DocH3>
      <DocP>
        Click <strong className="text-tx-1">Rules → New Rule</strong> to write a custom rule manually.
        You can also edit any built-in rule or clone it as a starting point.
        Custom rules support all the same operators as native rules and can be assigned any severity and MITRE mapping.
      </DocP>
      <Callout type="warn">
        Disabling built-in rules reduces your detection coverage. Only disable rules that generate persistent
        false positives in your environment, and consider adding a suppression instead.
      </Callout>

      {/* ── Attack Chain ──────────────────────────────────────────────────── */}
      <DocH2 id="attack-chain">Attack Chain Correlator</DocH2>
      <DocP>
        The Attack Chain Correlator automatically detects multi-stage attacks by correlating individual alerts
        on the same host within configurable time windows. When a chain fires, a single consolidated
        <Badge color="text-red-400 bg-red-500/10 mx-1">Critical</Badge> chain alert is created summarising
        all contributing alerts and the attack path.
      </DocP>
      <DocP>
        Chain alerts have the prefix <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">[Attack Chain]</code> in
        their title and include a full evidence dict listing all contributing alert IDs, matched stages, and the time window.
      </DocP>

      <DocH3>Built-in Attack Chains</DocH3>
      <Table
        headers={['Chain Name', 'Window', 'Min Stages']}
        rows={[
          ['Brute Force → Account Compromise', '30 min', '2'],
          ['Credential Dump → Lateral Movement', '1 hour', '2'],
          ['Discovery → Privilege Escalation', '2 hours', '2'],
          ['Defense Evasion → Execution', '30 min', '2'],
          ['Process Injection → C2 Beacon', '15 min', '2'],
          ['Ransomware Multi-Stage Attack', '10 min', '2'],
          ['Initial Access → Malicious Execution', '30 min', '2'],
          ['Persistence → C2 Communication', '1 hour', '2'],
          ['Credential Dump → Exfiltration', '2 hours', '2'],
          ['Known Malware → Lateral Movement', '1 hour', '2'],
          ['Full Kill Chain: Recon → Cred Dump → Lateral', '3 hours', '3'],
          ['Defense Evasion → Cred Dump → Persistence', '3 hours', '3'],
        ]}
      />
      <Callout type="info">
        A Redis dedup key prevents the same chain from firing more than once within its time window,
        even if new matching alerts appear. Chain alerts themselves are never used as input to other chains —
        preventing cascade loops.
      </Callout>

      {/* ── Threat Intel ──────────────────────────────────────────────────── */}
      <DocH2 id="threat-intel">Threat Intelligence</DocH2>
      <DocP>
        Every event is automatically enriched with live threat intelligence before hitting the detection engine.
        No API keys are required — NEURASHIELD uses free-tier APIs with built-in circuit breakers and Redis caching.
      </DocP>
      <Table
        headers={['Source', 'What it checks', 'Cache TTL']}
        rows={[
          ['AbuseIPDB',     'IP reputation score (0–100) for all source/destination IPs', '24 hours positive, 1 hour negative'],
          ['MalwareBazaar', 'SHA-256 hash of files detected by FIM or Sysmon event 11',  '24 hours positive, 1 hour negative'],
        ]}
      />
      <DocP>
        When a threat is detected, the following flags are added to <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">threat_intel_flags</code>:
      </DocP>
      <CodeBlock lang="json">{`// AbuseIPDB hit
{ "is_threat_ip": true, "abuse_confidence": 98, "threat_intel_flags": ["abuseipdb_threat"] }

// MalwareBazaar hit
{ "is_threat_ip": true, "threat_intel_flags": ["hash_ioc_match", "malwarebazaar:Emotet"] }`}</CodeBlock>
      <DocP>
        These flags are available in detection rules via the <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">list_contains</code> operator,
        and they auto-escalate the severity of matching alerts.
      </DocP>

      {/* ── UEBA ──────────────────────────────────────────────────────────── */}
      <DocH2 id="ueba">UEBA Analytics</DocH2>
      <DocP>
        User and Entity Behavior Analytics (UEBA) builds statistical baselines for each user over a
        14-day rolling window. Deviations from baseline are scored and can fire UEBA alerts.
      </DocP>
      <DocH3>What is tracked</DocH3>
      <ul className="space-y-2 mb-4">
        {[
          'Login hours distribution (mean, std dev)',
          'Login source countries and IP ranges',
          'Authentication failure rate',
          'Data volume accessed per session',
          'Privilege usage patterns',
          'Geographic location of logins (IP geolocation)',
        ].map((item) => (
          <li key={item} className="flex items-start gap-2 text-sm text-tx-2">
            <ChevronRight className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            {item}
          </li>
        ))}
      </ul>
      <DocP>
        A composite UEBA score (0–100) is assigned to each event. The score and individual flag names
        (<code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">impossible_travel</code>,&nbsp;
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">off_hours_login</code>, etc.)
        are available to detection rules for context-aware severity escalation.
      </DocP>

      {/* ── Investigations ────────────────────────────────────────────────── */}
      <DocH2 id="investigations">Investigations</DocH2>
      <DocP>
        Investigations are workspaces for tracking security incidents. Create one manually or link alerts to
        an existing investigation during triage.
      </DocP>
      <Table
        headers={['Field', 'Description']}
        rows={[
          ['Title',     'Short description of the incident (e.g., "Suspected ransomware on WORKSTATION-01")'],
          ['Status',    'Open / In Progress / Closed'],
          ['Severity',  'Overall incident severity — independent of individual alert severities'],
          ['Alerts',    'All alerts linked to this investigation'],
          ['Timeline',  'Chronological view of all linked alerts and analyst notes'],
          ['Notes',     'Free-form markdown notes for the investigating analyst'],
          ['Assignee',  'The analyst responsible for the investigation'],
        ]}
      />

      {/* ── Threat Hunting ────────────────────────────────────────────────── */}
      <DocH2 id="hunting">Threat Hunting</DocH2>
      <DocP>
        The Threat Hunt page lets you write and run structured queries against raw events stored in your
        tenant database. Use it to proactively search for indicators that haven't triggered alerts.
      </DocP>
      <DocP>
        Hunts are saved and can be run on a schedule. Each hunt returns a table of matching events with
        full evidence, and matching events can be linked directly to an investigation.
      </DocP>
      <Callout type="tip">
        Start with a built-in hunt template (available from the Hunt dropdown) to search for common
        living-off-the-land (LOLBAS) patterns, new processes, or unusual network connections.
      </Callout>

      {/* ── Attack Graph ──────────────────────────────────────────────────── */}
      <DocH2 id="graph">Attack Graph</DocH2>
      <DocP>
        The Attack Graph visualizes relationships between alerts, hosts, users, processes, and network connections
        as an interactive node graph. Use it to understand lateral movement paths and the blast radius of an incident.
      </DocP>
      <Table
        headers={['Node type', 'Color', 'Represents']}
        rows={[
          ['Host',    '🟦 Blue',   'An endpoint with the agent installed'],
          ['Alert',   '🔴 Red',    'A fired alert (size = severity)'],
          ['User',    '🟡 Yellow', 'An identity involved in events'],
          ['Process', '🟢 Green',  'A process seen in events'],
          ['IP',      '🟣 Purple', 'A network endpoint (external or internal)'],
        ]}
      />

      {/* ── AI Copilot ────────────────────────────────────────────────────── */}
      <DocH2 id="copilot">AI Copilot</DocH2>
      <DocP>
        The AI Copilot is a security-specialized assistant with full awareness of your tenant's alerts,
        agents, events, and detections. Accessible from the sidebar, it accepts natural language questions
        and returns structured, actionable answers.
      </DocP>
      <DocH3>Example queries</DocH3>
      <ul className="space-y-2 mb-4">
        {[
          '"Summarize all critical alerts from the last 24 hours on WORKSTATION-01"',
          '"What MITRE techniques have been seen most this week?"',
          '"Explain what T1059.001 means and how our rules detect it"',
          '"Is the IP 185.220.101.50 malicious?"',
          '"Draft a remediation checklist for a credential dump incident"',
          '"Which users triggered UEBA anomalies this week?"',
        ].map((q) => (
          <li key={q} className="flex items-start gap-2 text-sm text-tx-2">
            <ChevronRight className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            <span className="italic">{q}</span>
          </li>
        ))}
      </ul>

      {/* ── Playbooks ─────────────────────────────────────────────────────── */}
      <DocH2 id="playbooks">IR Playbooks</DocH2>
      <DocP>
        Incident Response Playbooks are generated automatically by AI for every HIGH and CRITICAL alert.
        Each playbook is tailored to the specific alert: its severity, MITRE techniques, affected host, and evidence.
      </DocP>
      <DocH3>Playbook structure</DocH3>
      <Table
        headers={['Section', 'Content']}
        rows={[
          ['Executive Summary', 'One-paragraph non-technical summary of the incident'],
          ['Incident Details',  'Alert metadata, affected host, detection rule, MITRE mapping'],
          ['Severity Assessment', 'Justification for the assigned severity'],
          ['Response Steps',   'Numbered step-by-step actions for the analyst'],
          ['Containment',      'Immediate isolation and containment recommendations'],
          ['Eradication',      'Steps to remove the threat completely'],
          ['Recovery',         'System restoration and verification checklist'],
          ['Lessons Learned',  'Post-incident improvement recommendations'],
        ]}
      />
      <DocP>
        Playbooks can also be generated from templates for common scenarios (Ransomware, Data Breach,
        Insider Threat, etc.) via the Playbooks page.
      </DocP>

      {/* ── Notifications ─────────────────────────────────────────────────── */}
      <DocH2 id="notifications">Notifications</DocH2>
      <DocP>
        NEURASHIELD sends real-time notifications on HIGH and CRITICAL alerts through all configured channels.
        Configure integrations in <strong className="text-tx-1">Settings → Notifications</strong>.
      </DocP>
      <Table
        headers={['Channel', 'Configuration']}
        rows={[
          ['Slack',           'Paste your Slack Incoming Webhook URL'],
          ['Microsoft Teams', 'Paste your Teams Incoming Webhook URL'],
          ['PagerDuty',       'Enter your PagerDuty Integration Key (Events API v2)'],
          ['Email',           'Enter comma-separated recipient addresses'],
          ['Webhook',         'Generic HTTP POST webhook with JSON payload'],
        ]}
      />
      <Callout type="tip">
        You can configure multiple channels simultaneously. All enabled channels receive notifications
        for the same alert in parallel.
      </Callout>

      {/* ── Reports ───────────────────────────────────────────────────────── */}
      <DocH2 id="reports">Reports</DocH2>
      <DocP>
        The Reports page generates security reports for your tenant. Reports are available in PDF and JSON formats.
      </DocP>
      <Table
        headers={['Report type', 'Description']}
        rows={[
          ['Executive Summary',    'High-level overview of security posture for leadership'],
          ['Alert Report',         'Full list of alerts with evidence for a time range'],
          ['MITRE Coverage',       'Which ATT&CK techniques were detected and rule coverage'],
          ['Agent Health',         'Agent uptime, event throughput, and missed collection windows'],
          ['UEBA Report',          'Behavioral anomalies and top flagged users'],
          ['Investigation Report', 'Detailed report for a specific investigation'],
        ]}
      />

      {/* ── Agent Management ──────────────────────────────────────────────── */}
      <DocH2 id="agents">Agent Management</DocH2>
      <DocP>
        Navigate to <strong className="text-tx-1">Agents</strong> in the sidebar to see all registered
        endpoints, their health status, last-seen time, operating system, and event throughput.
      </DocP>
      <DocH3>Agent health states</DocH3>
      <Table
        headers={['State', 'Meaning']}
        rows={[
          [<Badge color="text-green-400 bg-green-500/10">Online</Badge>,  'Agent checked in within the last 5 minutes'],
          [<Badge color="text-amber-400 bg-amber-500/10">Degraded</Badge>,'Agent checked in within the last 30 minutes but is delayed'],
          [<Badge color="text-tx-3 bg-bg-elevated">Offline</Badge>,       'Agent has not checked in for more than 30 minutes'],
        ]}
      />

      <DocH3>File Integrity Monitoring (FIM)</DocH3>
      <DocP>
        The agent monitors critical system file hashes on every collection cycle. If a system binary's
        SHA-256 hash changes, an alert fires immediately and the new hash is checked against MalwareBazaar.
      </DocP>
      <DocP>
        Default FIM targets on Windows include: <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">winlogon.exe</code>,&nbsp;
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">lsass.exe</code>,&nbsp;
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">cmd.exe</code>,&nbsp;
        <code className="text-blue-400 bg-blue-500/10 px-1.5 py-0.5 rounded text-xs">powershell.exe</code>, and more.
      </DocP>

      <DocH3>Uninstalling the Agent</DocH3>
      <CodeBlock lang="powershell">{`# Windows — run as Administrator
sc stop SOCAnalystAgent
sc delete SOCAnalystAgent
Remove-Item -Recurse -Force "C:\\ProgramData\\SOCAnalyst"`}</CodeBlock>
      <CodeBlock lang="bash">{`# Linux
sudo systemctl stop soc-analyst
sudo systemctl disable soc-analyst
sudo rm -rf /opt/soc-analyst /etc/systemd/system/soc-analyst.service
sudo systemctl daemon-reload`}</CodeBlock>

      {/* ── Team & Roles ──────────────────────────────────────────────────── */}
      <DocH2 id="team">Team & Roles</DocH2>
      <DocP>
        Invite team members from <strong className="text-tx-1">Settings → Team</strong>. Each member
        is assigned a role that controls what they can view and modify.
      </DocP>
      <Table
        headers={['Role', 'Capabilities']}
        rows={[
          ['Admin',   'Full access: manage team, rules, integrations, and all SOC features'],
          ['Analyst', 'All SOC features: alerts, investigations, hunting, copilot, playbooks, reports'],
          ['Viewer',  'Read-only: view alerts, dashboard, and reports — no triage or rule editing'],
        ]}
      />
      <Callout type="info">
        Invitations are sent by email and expire after 48 hours. Invited users must have a NEURASHIELD account
        (or create one via the invite link) before they can join your tenant.
      </Callout>

      {/* ── Settings ──────────────────────────────────────────────────────── */}
      <DocH2 id="settings">Settings</DocH2>
      <Table
        headers={['Section', 'What you can configure']}
        rows={[
          ['Organization',   'Company name, timezone, logo'],
          ['Notifications',  'Slack, Teams, PagerDuty, Email, Webhook integrations'],
          ['Detection',      'Global alert rate limits, suppression defaults, max alerts per event'],
          ['UEBA',           'Anomaly score threshold, baseline window (days), enabled anomaly types'],
          ['Team',           'Invite members, change roles, remove members'],
          ['API Keys',       'Generate API keys for programmatic access to the REST API'],
          ['Danger Zone',    'Delete tenant (permanent, all data removed)'],
        ]}
      />
    </div>
  )
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────

function Sidebar({
  activeId,
  onSelect,
}: {
  activeId: string
  onSelect: (id: string) => void
}) {
  const [expanded, setExpanded] = useState<Set<string>>(new Set(['quickstart', 'alerts', 'detection']))

  const toggleExpand = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  return (
    <nav className="py-6 pr-4">
      <div className="space-y-0.5">
        {NAV.map((section) => {
          const Icon = section.icon
          const isActive = activeId === section.id || section.children?.some((c) => c.id === activeId)
          const isExpanded = expanded.has(section.id)
          return (
            <div key={section.id}>
              <button
                onClick={() => {
                  if (section.children) {
                    toggleExpand(section.id)
                  }
                  onSelect(section.id)
                }}
                className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-sm transition-colors duration-100 text-left ${
                  isActive
                    ? 'bg-blue-500/10 text-blue-400'
                    : 'text-tx-3 hover:text-tx-1 hover:bg-bg-hover'
                }`}
              >
                <Icon className="w-4 h-4 shrink-0" />
                <span className="flex-1">{section.label}</span>
                {section.children && (
                  <ChevronDown
                    className={`w-3.5 h-3.5 transition-transform duration-200 ${isExpanded ? 'rotate-180' : ''}`}
                  />
                )}
              </button>
              {section.children && isExpanded && (
                <div className="ml-6 mt-0.5 space-y-0.5 border-l border-border pl-3">
                  {section.children.map((child) => (
                    <button
                      key={child.id}
                      onClick={() => onSelect(child.id)}
                      className={`w-full text-left px-2 py-1.5 rounded text-xs transition-colors ${
                        activeId === child.id
                          ? 'text-blue-400'
                          : 'text-tx-4 hover:text-tx-2'
                      }`}
                    >
                      {child.label}
                    </button>
                  ))}
                </div>
              )}
            </div>
          )
        })}
      </div>
    </nav>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export function DocsPage() {
  const [activeId, setActiveId] = useState('overview')
  const [mobileOpen, setMobileOpen] = useState(false)
  const contentRef = useRef<HTMLDivElement>(null)

  const scrollToId = useCallback((id: string) => {
    setActiveId(id)
    setMobileOpen(false)
    const el = document.getElementById(id)
    if (el) {
      el.scrollIntoView({ behavior: 'smooth', block: 'start' })
    }
  }, [])

  // Update active section on scroll
  useEffect(() => {
    const allIds: string[] = NAV.flatMap((s) => [s.id, ...(s.children?.map((c) => c.id) ?? [])])
    const observer = new IntersectionObserver(
      (entries) => {
        const visible = entries.filter((e) => e.isIntersecting)
        if (visible.length > 0) {
          setActiveId(visible[0].target.id)
        }
      },
      { rootMargin: '-80px 0px -60% 0px', threshold: 0 }
    )
    allIds.forEach((id) => {
      const el = document.getElementById(id)
      if (el) observer.observe(el)
    })
    return () => observer.disconnect()
  }, [])

  return (
    <div className="min-h-screen bg-bg-base text-tx-1 antialiased">
      {/* Top nav */}
      <header className="fixed top-0 left-0 right-0 z-50 h-14 border-b border-border bg-bg-base/90 backdrop-blur-xl flex items-center px-6 gap-4">
        <Link to="/" className="flex items-center gap-2 text-tx-3 hover:text-tx-1 transition-colors text-sm">
          <ArrowLeft className="w-4 h-4" />
          <span className="hidden sm:inline">Back</span>
        </Link>
        <div className="w-px h-5 bg-border" />
        <LogoFull size={26} />
        <div className="hidden sm:flex items-center gap-1.5 text-sm text-tx-3">
          <ChevronRight className="w-3.5 h-3.5" />
          <span className="text-tx-1">Documentation</span>
        </div>
        <div className="flex-1" />
        <Link
          to="/register"
          className="text-sm font-medium bg-blue-500 hover:bg-blue-600 text-white px-4 py-1.5 rounded-lg transition-colors"
        >
          Get Started
        </Link>
        <button
          className="md:hidden p-2 text-tx-3 hover:text-tx-1 transition-colors"
          onClick={() => setMobileOpen((v) => !v)}
        >
          {mobileOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
        </button>
      </header>

      <div className="flex pt-14 min-h-screen">
        {/* Desktop sidebar */}
        <aside className="hidden md:block w-64 shrink-0 sticky top-14 h-[calc(100vh-56px)] overflow-y-auto border-r border-border bg-bg-surface/30 px-2">
          <Sidebar activeId={activeId} onSelect={scrollToId} />
        </aside>

        {/* Mobile sidebar drawer */}
        {mobileOpen && (
          <div className="fixed inset-0 z-40 flex md:hidden pt-14">
            <div
              className="absolute inset-0 bg-bg-base/80 backdrop-blur-sm"
              onClick={() => setMobileOpen(false)}
            />
            <aside className="relative z-10 w-72 bg-bg-surface border-r border-border h-full overflow-y-auto px-2">
              <Sidebar activeId={activeId} onSelect={scrollToId} />
            </aside>
          </div>
        )}

        {/* Main content */}
        <main
          ref={contentRef}
          className="flex-1 min-w-0 px-6 md:px-12 py-10 max-w-4xl mx-auto"
        >
          {/* Page header */}
          <div className="mb-10 pb-8 border-b border-border">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full border border-border bg-bg-surface text-xs text-tx-3 mb-4">
              <BookOpen className="w-3.5 h-3.5" />
              NEURASHIELD Platform Documentation
            </div>
            <h1
              className="text-4xl font-bold text-tx-1 mb-3"
              style={{ fontFamily: "'Space Grotesk', sans-serif" }}
            >
              Documentation
            </h1>
            <p className="text-tx-3 text-base max-w-xl">
              Complete guide to deploying, configuring, and operating NEURASHIELD —
              from agent installation to advanced threat hunting.
            </p>
          </div>

          <DocContent />

          {/* Footer */}
          <div className="mt-16 pt-8 border-t border-border flex items-center justify-between">
            <Link
              to="/"
              className="flex items-center gap-2 text-sm text-tx-3 hover:text-tx-1 transition-colors"
            >
              <ArrowLeft className="w-4 h-4" />
              Back to homepage
            </Link>
            <Link
              to="/register"
              className="flex items-center gap-2 text-sm font-medium bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg transition-colors"
            >
              Get Started
              <ChevronRight className="w-4 h-4" />
            </Link>
          </div>
        </main>
      </div>
    </div>
  )
}
