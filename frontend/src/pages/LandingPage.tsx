import { useEffect, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { motion, useInView, useMotionValue, useSpring } from 'framer-motion'
import {
  Shield, Zap, Brain, GitMerge, Globe, UserCheck,
  FileText, ChevronRight, ArrowRight,
  Terminal, Bell, BarChart3, Search, Lock, Check,
  Network, Eye, AlertTriangle, Layers,
} from 'lucide-react'
import { LogoFull } from '@/components/ui/Logo'

// ─── Animation variants ───────────────────────────────────────────────────────

const fadeUp = {
  initial: { opacity: 0, y: 28 },
  animate: { opacity: 1, y: 0, transition: { duration: 0.55, ease: [0.22, 1, 0.36, 1] } },
}

const stagger = (delay = 0.07) => ({
  animate: { transition: { staggerChildren: delay } },
})

// ─── Animated counter ─────────────────────────────────────────────────────────

function Counter({ to, suffix = '' }: { to: number; suffix?: string }) {
  const ref = useRef<HTMLSpanElement>(null)
  const inView = useInView(ref, { once: true })
  const val = useMotionValue(0)
  const spring = useSpring(val, { stiffness: 60, damping: 20 })
  const [display, setDisplay] = useState('0')

  useEffect(() => {
    if (inView) val.set(to)
  }, [inView, to, val])

  useEffect(() => spring.on('change', (v) => setDisplay(Math.round(v).toString())), [spring])

  return <span ref={ref}>{display}{suffix}</span>
}

// ─── Shared section wrapper ───────────────────────────────────────────────────

function Section({
  children,
  className = '',
  id,
}: {
  children: React.ReactNode
  className?: string
  id?: string
}) {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-80px' })
  return (
    <motion.section
      id={id}
      ref={ref}
      initial="initial"
      animate={inView ? 'animate' : 'initial'}
      className={className}
    >
      {children}
    </motion.section>
  )
}

// ─── NavBar ───────────────────────────────────────────────────────────────────

function NavBar() {
  const [scrolled, setScrolled] = useState(false)
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 20)
    window.addEventListener('scroll', onScroll)
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  return (
    <motion.nav
      initial={{ y: -64, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
      className={`fixed top-0 left-0 right-0 z-50 transition-all duration-300 ${
        scrolled
          ? 'border-b border-border bg-bg-base/90 backdrop-blur-xl'
          : 'bg-transparent'
      }`}
    >
      <div className="max-w-7xl mx-auto px-6 h-16 flex items-center justify-between">
        <LogoFull size={32} />

        <div className="hidden md:flex items-center gap-8">
          {[
            { label: 'Documentation', href: '/docs' },
            { label: 'Features', href: '#features' },
            { label: 'How it works', href: '#how-it-works' },
          ].map((item) => (
            <a
              key={item.label}
              href={item.href}
              className="text-sm text-tx-3 hover:text-tx-1 transition-colors duration-150"
            >
              {item.label}
            </a>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/login"
            className="text-sm text-tx-2 hover:text-tx-1 transition-colors duration-150 px-4 py-2"
          >
            Sign In
          </Link>
          <Link
            to="/register"
            className="text-sm font-medium bg-blue-500 hover:bg-blue-600 text-white px-4 py-2 rounded-lg transition-colors duration-150 flex items-center gap-1.5"
          >
            Get Started
            <ArrowRight className="w-3.5 h-3.5" />
          </Link>
        </div>
      </div>
    </motion.nav>
  )
}

// ─── Hero ─────────────────────────────────────────────────────────────────────

function HeroSection() {
  return (
    <div className="relative min-h-screen flex flex-col items-center justify-center overflow-hidden pt-16">
      {/* Background grid */}
      <div
        className="absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage: `linear-gradient(rgba(59,130,246,0.8) 1px, transparent 1px),
            linear-gradient(90deg, rgba(59,130,246,0.8) 1px, transparent 1px)`,
          backgroundSize: '60px 60px',
        }}
      />

      {/* Radial glow orbs */}
      <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[800px] h-[500px] rounded-full blur-[120px] opacity-[0.12] bg-blue-500 pointer-events-none" />
      <div className="absolute top-1/3 left-1/3 w-[400px] h-[400px] rounded-full blur-[100px] opacity-[0.06] bg-purple-500 pointer-events-none" />
      <div className="absolute top-1/3 right-1/3 w-[400px] h-[400px] rounded-full blur-[100px] opacity-[0.06] bg-cyan-500 pointer-events-none" />

      <div className="relative z-10 max-w-5xl mx-auto px-6 text-center">
        {/* Badge */}
        <motion.div
          initial={{ opacity: 0, scale: 0.9 }}
          animate={{ opacity: 1, scale: 1 }}
          transition={{ duration: 0.4, delay: 0.1 }}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/8 mb-8"
        >
          <div className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-pulse-dot" />
          <span className="text-xs font-medium text-blue-400 tracking-wider uppercase">
            Enterprise Security Operations
          </span>
        </motion.div>

        {/* Headline */}
        <motion.h1
          initial={{ opacity: 0, y: 32 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.65, delay: 0.2, ease: [0.22, 1, 0.36, 1] }}
          className="text-5xl md:text-7xl font-bold tracking-tight text-tx-1 mb-6 leading-[1.08]"
          style={{ fontFamily: "'Space Grotesk', sans-serif" }}
        >
          AI-Powered{' '}
          <span
            className="relative"
            style={{
              background: 'linear-gradient(135deg, #60A5FA 0%, #3B82F6 50%, #06B6D4 100%)',
              WebkitBackgroundClip: 'text',
              WebkitTextFillColor: 'transparent',
            }}
          >
            Security Operations
          </span>
          <br />
          at Machine Speed
        </motion.h1>

        {/* Subline */}
        <motion.p
          initial={{ opacity: 0, y: 24 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.55, delay: 0.35, ease: [0.22, 1, 0.36, 1] }}
          className="text-lg md:text-xl text-tx-3 max-w-2xl mx-auto mb-10 leading-relaxed"
        >
          NEURASHIELD delivers enterprise-grade threat detection, attack chain correlation,
          and AI-driven incident response — automatically, from the moment your agent is deployed.
        </motion.p>

        {/* CTAs */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.45 }}
          className="flex flex-col sm:flex-row items-center justify-center gap-4 mb-16"
        >
          <Link
            to="/register"
            className="group flex items-center gap-2 px-7 py-3.5 rounded-xl bg-blue-500 hover:bg-blue-600 text-white font-medium text-base transition-all duration-150 shadow-glow-blue hover:shadow-glow"
          >
            Start Free Trial
            <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
          </Link>
          <a
            href="/docs"
            className="flex items-center gap-2 px-7 py-3.5 rounded-xl border border-border-strong text-tx-2 hover:text-tx-1 hover:border-border-active font-medium text-base transition-all duration-150"
          >
            <FileText className="w-4 h-4" />
            View Documentation
          </a>
        </motion.div>

        {/* Terminal preview */}
        <motion.div
          initial={{ opacity: 0, y: 40, scale: 0.97 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          transition={{ duration: 0.7, delay: 0.55, ease: [0.22, 1, 0.36, 1] }}
          className="relative mx-auto max-w-3xl rounded-2xl border border-border-strong bg-bg-surface overflow-hidden shadow-panel"
        >
          {/* Window chrome */}
          <div className="flex items-center gap-2 px-4 py-3 border-b border-border bg-bg-elevated">
            <div className="w-3 h-3 rounded-full bg-red-500/60" />
            <div className="w-3 h-3 rounded-full bg-amber-500/60" />
            <div className="w-3 h-3 rounded-full bg-green-500/60" />
            <span className="ml-3 text-xs text-tx-4 font-mono">NEURASHIELD — Real-time Detection Pipeline</span>
          </div>
          <div className="p-5 font-mono text-xs text-left space-y-1.5">
            {[
              { color: 'text-tx-4',    text: '# Agent installed on WORKSTATION-01' },
              { color: 'text-green-400', text: '[10:42:13] INFO  agent started  host=WORKSTATION-01  os=Windows 11' },
              { color: 'text-tx-3',    text: '[10:42:14] INFO  events streaming  channel=Security,System,Sysmon' },
              { color: 'text-amber-400', text: '[10:43:01] WARN  threat_ip_detected  src=185.220.101.50  score=98  rule="AbuseIPDB Threat IP"' },
              { color: 'text-red-400',   text: '[10:43:02] CRIT  alert_fired  rule="Credential Dump via Mimikatz"  severity=critical' },
              { color: 'text-red-400',   text: '[10:43:03] CRIT  alert_fired  rule="Lateral Movement - PsExec"  severity=critical' },
              { color: 'text-purple-400',text: '[10:43:03] CRIT  attack_chain_fired  chain="Credential Dump → Lateral Movement"  host=WORKSTATION-01' },
              { color: 'text-blue-400',  text: '[10:43:03] INFO  playbook_generated  title="IR: Credential Access Incident"  steps=12' },
              { color: 'text-blue-400',  text: '[10:43:03] INFO  notification_sent  channels=slack,pagerduty,email' },
            ].map((line, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: 0.8 + i * 0.08, duration: 0.3 }}
                className={`${line.color}`}
              >
                {line.text}
              </motion.div>
            ))}
            <div className="flex items-center gap-1 text-blue-400 mt-2">
              <span>$</span>
              <span className="w-2 h-4 bg-blue-400 animate-pulse inline-block" />
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  )
}

// ─── Stats bar ────────────────────────────────────────────────────────────────

const STATS = [
  { value: 80, suffix: '+', label: 'Detection Rules' },
  { value: 12, suffix: '',  label: 'Attack Chain Patterns' },
  { value: 100, suffix: '%', label: 'MITRE ATT&CK Mapped' },
  { value: 0, suffix: '',   label: 'Manual Config Required' },
]

function StatsBar() {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true })
  return (
    <div ref={ref} className="border-y border-border bg-bg-surface/50">
      <div className="max-w-7xl mx-auto px-6 py-10">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
          {STATS.map((s, i) => (
            <motion.div
              key={s.label}
              initial={{ opacity: 0, y: 16 }}
              animate={inView ? { opacity: 1, y: 0 } : {}}
              transition={{ delay: i * 0.1, duration: 0.45 }}
              className="text-center"
            >
              <div
                className="text-4xl font-bold text-tx-1 mb-1 tabular-nums"
                style={{ fontFamily: "'Space Grotesk', sans-serif" }}
              >
                {inView ? <Counter to={s.value} suffix={s.suffix} /> : `0${s.suffix}`}
              </div>
              <div className="text-sm text-tx-3">{s.label}</div>
            </motion.div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Features ─────────────────────────────────────────────────────────────────

const FEATURES = [
  {
    icon: Shield,
    color: 'text-blue-400',
    glow: 'rgba(59,130,246,0.15)',
    title: 'AI Detection Engine',
    description:
      '80+ native pattern rules, 24 Sigma YAML rules, and 6 UEBA behavioral rules evaluate every event in real-time against MITRE ATT&CK techniques.',
  },
  {
    icon: GitMerge,
    color: 'text-purple-400',
    glow: 'rgba(168,85,247,0.15)',
    title: 'Attack Chain Correlator',
    description:
      'Automatically correlates individual alerts into multi-stage attack sequences using 12 built-in kill-chain patterns — no manual pivoting required.',
  },
  {
    icon: Globe,
    color: 'text-cyan-400',
    glow: 'rgba(6,182,212,0.15)',
    title: 'Live Threat Intelligence',
    description:
      'Every event is enriched in real-time via AbuseIPDB (IP reputation) and MalwareBazaar (file hash IOC) — flagging threats before rules even need to fire.',
  },
  {
    icon: UserCheck,
    color: 'text-amber-400',
    glow: 'rgba(245,158,11,0.15)',
    title: 'UEBA Analytics',
    description:
      'Per-user behavioral baselines detect anomalies like impossible travel, off-hours logins, privilege spikes, and high-volume data access automatically.',
  },
  {
    icon: Brain,
    color: 'text-green-400',
    glow: 'rgba(16,185,129,0.15)',
    title: 'AI Copilot',
    description:
      'A natural-language security assistant with full awareness of your environment — ask about alerts, hunt for threats, explain IOCs, or draft incident reports.',
  },
  {
    icon: FileText,
    color: 'text-orange-400',
    glow: 'rgba(249,115,22,0.15)',
    title: 'Auto IR Playbooks',
    description:
      'AI-generated incident response playbooks trigger automatically on every HIGH/CRITICAL alert — specific steps, MITRE mapping, and evidence included.',
  },
]

function FeaturesSection() {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })
  return (
    <Section id="features" className="py-28 px-6">
      <div className="max-w-7xl mx-auto">
        <motion.div variants={stagger()} className="text-center mb-16">
          <motion.div variants={fadeUp} className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-border-strong bg-bg-surface mb-5">
            <Layers className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-xs text-tx-3 uppercase tracking-wider">Platform Capabilities</span>
          </motion.div>
          <motion.h2 variants={fadeUp} className="text-4xl font-bold text-tx-1 mb-4" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
            Everything your SOC needs,<br />built in from day one
          </motion.h2>
          <motion.p variants={fadeUp} className="text-tx-3 text-lg max-w-xl mx-auto">
            No plugins, no configuration, no manual rule writing. Deploy the agent and every capability activates automatically.
          </motion.p>
        </motion.div>

        <div ref={ref} className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
          {FEATURES.map((feat, i) => {
            const Icon = feat.icon
            return (
              <motion.div
                key={feat.title}
                initial={{ opacity: 0, y: 24 }}
                animate={inView ? { opacity: 1, y: 0 } : {}}
                transition={{ delay: i * 0.08, duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
                className="group relative p-6 rounded-2xl border border-border-card bg-bg-surface hover:border-border-strong transition-all duration-200 cursor-default"
                style={{ '--glow': feat.glow } as React.CSSProperties}
              >
                <div
                  className="w-10 h-10 rounded-xl flex items-center justify-center mb-4"
                  style={{ background: feat.glow }}
                >
                  <Icon className={`w-5 h-5 ${feat.color}`} />
                </div>
                <h3 className="text-base font-semibold text-tx-1 mb-2">{feat.title}</h3>
                <p className="text-sm text-tx-3 leading-relaxed">{feat.description}</p>
              </motion.div>
            )
          })}
        </div>
      </div>
    </Section>
  )
}

// ─── How it works ─────────────────────────────────────────────────────────────

const STEPS = [
  {
    num: '01',
    icon: Terminal,
    title: 'Deploy the Agent',
    subtitle: '~ 30 seconds',
    description:
      'Run a single installer script on any Windows or Linux endpoint. The lightweight Python agent reads event logs, monitors file integrity, and watches network activity — no reboot, no kernel module.',
    bullets: ['Windows Event Log + Sysmon support', 'Linux syslog + auditd', 'File integrity monitoring', 'Auto-registers with your tenant'],
  },
  {
    num: '02',
    icon: Zap,
    title: 'Events Normalize & Enrich',
    subtitle: 'Real-time pipeline',
    description:
      'Every event flows through a Redis-backed pipeline: normalized into a unified schema, enriched with live threat intel (IP reputation + hash IOC), and scored by UEBA behavioral models.',
    bullets: ['AbuseIPDB IP enrichment', 'MalwareBazaar hash IOC lookup', 'UEBA anomaly scoring per user', 'Structured fields for precise detection'],
  },
  {
    num: '03',
    icon: Bell,
    title: 'AI Alerts & Responds',
    subtitle: 'Instant notification',
    description:
      'The detection engine fires alerts against 80+ rules. Attack chains correlate multi-stage sequences. AI generates IR playbooks and notifies your team via Slack, Teams, PagerDuty, or email.',
    bullets: ['Real-time dashboard alerts', 'Attack chain correlation', 'AI-generated IR playbooks', 'Slack / Teams / PagerDuty / Email'],
  },
]

function HowItWorksSection() {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })
  return (
    <Section id="how-it-works" className="py-28 px-6 bg-bg-surface/30">
      <div className="max-w-6xl mx-auto">
        <motion.div variants={stagger()} className="text-center mb-20">
          <motion.div variants={fadeUp} className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-border-strong bg-bg-surface mb-5">
            <Network className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-xs text-tx-3 uppercase tracking-wider">How it works</span>
          </motion.div>
          <motion.h2 variants={fadeUp} className="text-4xl font-bold text-tx-1 mb-4" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
            Zero configuration. Full coverage.
          </motion.h2>
          <motion.p variants={fadeUp} className="text-tx-3 text-lg max-w-xl mx-auto">
            Three steps from deployment to enterprise-grade security operations.
          </motion.p>
        </motion.div>

        <div ref={ref} className="grid grid-cols-1 lg:grid-cols-3 gap-8 relative">
          {/* Connecting line (desktop) */}
          <div className="hidden lg:block absolute top-[52px] left-[calc(16.67%+40px)] right-[calc(16.67%+40px)] h-px bg-gradient-to-r from-blue-500/40 via-purple-500/40 to-cyan-500/40" />

          {STEPS.map((step, i) => {
            const Icon = step.icon
            return (
              <motion.div
                key={step.num}
                initial={{ opacity: 0, y: 28 }}
                animate={inView ? { opacity: 1, y: 0 } : {}}
                transition={{ delay: i * 0.15, duration: 0.55, ease: [0.22, 1, 0.36, 1] }}
                className="relative"
              >
                {/* Step number + icon */}
                <div className="flex items-center gap-4 mb-5">
                  <div className="relative z-10 w-[88px] h-[88px] rounded-2xl border border-blue-500/30 bg-blue-500/8 flex flex-col items-center justify-center shrink-0">
                    <span className="text-[10px] font-mono text-blue-500/70 mb-1">{step.num}</span>
                    <Icon className="w-7 h-7 text-blue-400" />
                  </div>
                  <div>
                    <div className="text-xs text-blue-400/80 font-mono mb-0.5">{step.subtitle}</div>
                    <h3 className="text-lg font-semibold text-tx-1">{step.title}</h3>
                  </div>
                </div>
                <p className="text-sm text-tx-3 leading-relaxed mb-4">{step.description}</p>
                <ul className="space-y-2">
                  {step.bullets.map((b) => (
                    <li key={b} className="flex items-center gap-2 text-sm text-tx-3">
                      <Check className="w-3.5 h-3.5 text-green-400 shrink-0" />
                      {b}
                    </li>
                  ))}
                </ul>
              </motion.div>
            )
          })}
        </div>
      </div>
    </Section>
  )
}

// ─── MITRE coverage ───────────────────────────────────────────────────────────

const TACTICS = [
  { name: 'Initial Access',      count: 8  },
  { name: 'Execution',           count: 14 },
  { name: 'Persistence',         count: 9  },
  { name: 'Privilege Escalation',count: 7  },
  { name: 'Defense Evasion',     count: 12 },
  { name: 'Credential Access',   count: 10 },
  { name: 'Discovery',           count: 6  },
  { name: 'Lateral Movement',    count: 8  },
  { name: 'Collection',          count: 4  },
  { name: 'Command & Control',   count: 7  },
  { name: 'Exfiltration',        count: 5  },
  { name: 'Impact',              count: 10 },
]

function MitreCoverageSection() {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })
  return (
    <Section className="py-28 px-6">
      <div className="max-w-5xl mx-auto">
        <motion.div variants={stagger()} className="text-center mb-14">
          <motion.div variants={fadeUp} className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-border-strong bg-bg-surface mb-5">
            <Lock className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-xs text-tx-3 uppercase tracking-wider">MITRE ATT&CK Coverage</span>
          </motion.div>
          <motion.h2 variants={fadeUp} className="text-4xl font-bold text-tx-1 mb-4" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
            Full kill-chain visibility
          </motion.h2>
          <motion.p variants={fadeUp} className="text-tx-3 text-lg max-w-xl mx-auto">
            Every detection rule maps to MITRE ATT&CK techniques across all 12 tactics — from initial access to impact.
          </motion.p>
        </motion.div>

        <div ref={ref} className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
          {TACTICS.map((tactic, i) => (
            <motion.div
              key={tactic.name}
              initial={{ opacity: 0, scale: 0.92 }}
              animate={inView ? { opacity: 1, scale: 1 } : {}}
              transition={{ delay: i * 0.05, duration: 0.4 }}
              className="flex items-center justify-between px-4 py-3 rounded-xl border border-border-card bg-bg-surface hover:border-border-strong transition-colors duration-150"
            >
              <span className="text-sm text-tx-2">{tactic.name}</span>
              <span className="text-xs font-mono text-blue-400 bg-blue-500/10 px-2 py-0.5 rounded-full">
                {tactic.count}
              </span>
            </motion.div>
          ))}
        </div>
      </div>
    </Section>
  )
}

// ─── Architecture section ─────────────────────────────────────────────────────

const ARCH_NODES = [
  {
    icon: Terminal,
    label: 'Agent',
    desc: 'Windows / Linux\nEvent logs, FIM, Network',
    color: 'border-green-500/30 bg-green-500/5 text-green-400',
  },
  {
    icon: Zap,
    label: 'Pipeline',
    desc: 'Redis Streams\nNormalize → Enrich → Detect',
    color: 'border-amber-500/30 bg-amber-500/5 text-amber-400',
  },
  {
    icon: Brain,
    label: 'AI Engine',
    desc: 'Detection + UEBA\nAttack Chains + Copilot',
    color: 'border-blue-500/30 bg-blue-500/5 text-blue-400',
  },
  {
    icon: BarChart3,
    label: 'SOC Dashboard',
    desc: 'Alerts, Investigations\nPlaybooks, Reports',
    color: 'border-purple-500/30 bg-purple-500/5 text-purple-400',
  },
]

function ArchitectureSection() {
  const ref = useRef(null)
  const inView = useInView(ref, { once: true, margin: '-60px' })
  return (
    <Section className="py-28 px-6 bg-bg-surface/30">
      <div className="max-w-5xl mx-auto">
        <motion.div variants={stagger()} className="text-center mb-16">
          <motion.div variants={fadeUp} className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-border-strong bg-bg-surface mb-5">
            <Eye className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-xs text-tx-3 uppercase tracking-wider">Architecture</span>
          </motion.div>
          <motion.h2 variants={fadeUp} className="text-4xl font-bold text-tx-1 mb-4" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
            Built for enterprise scale
          </motion.h2>
          <motion.p variants={fadeUp} className="text-tx-3 text-lg max-w-xl mx-auto">
            A real-time event pipeline powers every detection — from raw endpoint telemetry to actionable security intelligence.
          </motion.p>
        </motion.div>

        <div ref={ref} className="flex flex-col md:flex-row items-center justify-center gap-3 md:gap-0">
          {ARCH_NODES.map((node, i) => {
            const Icon = node.icon
            return (
              <div key={node.label} className="flex flex-col md:flex-row items-center">
                <motion.div
                  initial={{ opacity: 0, scale: 0.88 }}
                  animate={inView ? { opacity: 1, scale: 1 } : {}}
                  transition={{ delay: i * 0.12, duration: 0.5, ease: [0.22, 1, 0.36, 1] }}
                  className={`flex flex-col items-center p-6 rounded-2xl border ${node.color} w-48 text-center`}
                >
                  <Icon className="w-8 h-8 mb-3" />
                  <div className="font-semibold text-tx-1 text-sm mb-1">{node.label}</div>
                  <div className="text-xs text-tx-4 whitespace-pre-line leading-relaxed">{node.desc}</div>
                </motion.div>
                {i < ARCH_NODES.length - 1 && (
                  <motion.div
                    initial={{ opacity: 0 }}
                    animate={inView ? { opacity: 1 } : {}}
                    transition={{ delay: i * 0.12 + 0.25 }}
                    className="flex items-center justify-center w-10 md:w-12 text-tx-5 my-2 md:my-0"
                  >
                    <ChevronRight className="w-5 h-5 hidden md:block" />
                    <div className="block md:hidden w-0.5 h-6 bg-border-strong" />
                  </motion.div>
                )}
              </div>
            )
          })}
        </div>

        {/* Supporting integrations */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={inView ? { opacity: 1, y: 0 } : {}}
          transition={{ delay: 0.6, duration: 0.4 }}
          className="mt-12 flex flex-wrap items-center justify-center gap-3"
        >
          {['Slack', 'Microsoft Teams', 'PagerDuty', 'Email', 'Webhooks', 'AbuseIPDB', 'MalwareBazaar'].map((int) => (
            <span
              key={int}
              className="px-3 py-1.5 rounded-lg border border-border text-xs text-tx-4 bg-bg-elevated"
            >
              {int}
            </span>
          ))}
        </motion.div>
      </div>
    </Section>
  )
}

// ─── CTA section ─────────────────────────────────────────────────────────────

function CtaSection() {
  return (
    <Section className="py-28 px-6">
      <div className="max-w-3xl mx-auto text-center relative">
        {/* Glow */}
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-48 rounded-full blur-[80px] opacity-10 bg-blue-500 pointer-events-none" />

        <motion.div variants={stagger()} className="relative z-10">
          <motion.div variants={fadeUp} className="inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-blue-500/30 bg-blue-500/8 mb-6">
            <AlertTriangle className="w-3.5 h-3.5 text-blue-400" />
            <span className="text-xs text-blue-400 uppercase tracking-wider font-medium">Start protecting your organization</span>
          </motion.div>

          <motion.h2 variants={fadeUp} className="text-4xl md:text-5xl font-bold text-tx-1 mb-5" style={{ fontFamily: "'Space Grotesk', sans-serif" }}>
            Secure your infrastructure<br />in under 5 minutes
          </motion.h2>

          <motion.p variants={fadeUp} className="text-lg text-tx-3 mb-10 max-w-lg mx-auto">
            Create your account, install the agent, and your SOC operations go live instantly —
            no configuration required.
          </motion.p>

          <motion.div variants={fadeUp} className="flex flex-col sm:flex-row items-center justify-center gap-4">
            <Link
              to="/register"
              className="group flex items-center gap-2 px-8 py-4 rounded-xl bg-blue-500 hover:bg-blue-600 text-white font-semibold text-base transition-all duration-150 shadow-glow-blue"
            >
              Create Free Account
              <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
            </Link>
            <Link
              to="/docs"
              className="flex items-center gap-2 px-8 py-4 rounded-xl border border-border-strong text-tx-2 hover:text-tx-1 hover:border-border-active font-medium text-base transition-all duration-150"
            >
              <Search className="w-4 h-4" />
              Read the Docs
            </Link>
          </motion.div>
        </motion.div>
      </div>
    </Section>
  )
}

// ─── Footer ───────────────────────────────────────────────────────────────────

function Footer() {
  return (
    <footer className="border-t border-border bg-bg-surface/30 py-12 px-6">
      <div className="max-w-7xl mx-auto">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-8">
          <div>
            <LogoFull size={28} />
            <p className="text-sm text-tx-4 mt-3 max-w-xs">
              Enterprise AI Security Operations Platform.
              Detect, correlate, and respond at machine speed.
            </p>
          </div>
          <div className="flex flex-wrap gap-x-10 gap-y-4">
            {[
              { label: 'Documentation', href: '/docs' },
              { label: 'Sign In', href: '/login' },
              { label: 'Create Account', href: '/register' },
              { label: 'Features', href: '#features' },
              { label: 'How it works', href: '#how-it-works' },
            ].map((link) => (
              <a
                key={link.label}
                href={link.href}
                className="text-sm text-tx-4 hover:text-tx-2 transition-colors"
              >
                {link.label}
              </a>
            ))}
          </div>
        </div>
        <div className="mt-10 pt-6 border-t border-border flex items-center justify-between">
          <p className="text-xs text-tx-5">© {new Date().getFullYear()} NEURASHIELD. All rights reserved.</p>
          <div className="flex items-center gap-1.5 text-xs text-tx-5">
            <div className="w-1.5 h-1.5 rounded-full bg-green-500 animate-pulse-dot" />
            All systems operational
          </div>
        </div>
      </div>
    </footer>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export function LandingPage() {
  return (
    <div className="min-h-screen bg-bg-base text-tx-1 antialiased">
      <NavBar />
      <HeroSection />
      <StatsBar />
      <FeaturesSection />
      <HowItWorksSection />
      <MitreCoverageSection />
      <ArchitectureSection />
      <CtaSection />
      <Footer />
    </div>
  )
}
