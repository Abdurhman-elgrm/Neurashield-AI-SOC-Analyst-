import { Shield, Bell, Users, Key, Database } from "lucide-react";

const SETTINGS_SECTIONS = [
  { icon: Shield, title: "Security", desc: "Authentication, MFA, and session policies." },
  { icon: Bell, title: "Notifications", desc: "Alert delivery, email digests, and webhook integrations." },
  { icon: Users, title: "Team & Roles", desc: "Manage members, invite users, and assign roles." },
  { icon: Key, title: "API Keys", desc: "Generate and revoke API keys for integrations." },
  { icon: Database, title: "Data Retention", desc: "Configure event storage TTL and purge policies." },
];

export function SettingsPage() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="page-title">Settings</h1>
        <p className="text-sm text-text-muted mt-1">Platform and tenant configuration</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {SETTINGS_SECTIONS.map((s) => (
          <button
            key={s.title}
            className="card-glow rounded-xl p-5 text-left transition-all"
          >
            <div
              className="w-10 h-10 rounded-lg flex items-center justify-center mb-3"
              style={{ background: "rgba(59,130,246,0.1)", border: "1px solid rgba(59,130,246,0.2)" }}
            >
              <s.icon className="w-5 h-5 text-primary-400" />
            </div>
            <p className="font-display font-semibold text-text-primary mb-1">{s.title}</p>
            <p className="text-xs text-text-muted leading-relaxed">{s.desc}</p>
          </button>
        ))}
      </div>
    </div>
  );
}
