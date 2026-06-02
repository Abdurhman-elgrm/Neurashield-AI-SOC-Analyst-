import type { Config } from "tailwindcss";

const config: Config = {
  darkMode: ["class"],
  content: [
    "./index.html",
    "./src/**/*.{ts,tsx}",
  ],
  theme: {
    extend: {
      // ─── Design tokens mapped to CSS variables ───────────────────────────
      colors: {
        // Base backgrounds
        "bg-base": "var(--bg-base)",
        "bg-surface": "var(--bg-surface)",
        "bg-elevated": "var(--bg-elevated)",
        "bg-subtle": "var(--bg-subtle)",

        // Borders
        border: "var(--border)",
        "border-strong": "var(--border-strong)",

        // Text
        "text-primary": "var(--text-primary)",
        "text-secondary": "var(--text-secondary)",
        "text-muted": "var(--text-muted)",

        // Accent
        accent: "var(--accent)",
        "accent-hover": "var(--accent-hover)",

        // Severity semantic colors
        severity: {
          critical: "var(--severity-critical)",
          high: "var(--severity-high)",
          medium: "var(--severity-medium)",
          low: "var(--severity-low)",
          info: "var(--severity-info)",
        },

        // Status colors
        status: {
          online: "var(--status-online)",
          offline: "var(--status-offline)",
          degraded: "var(--status-degraded)",
          unknown: "var(--status-unknown)",
        },
      },

      fontFamily: {
        sans: ["Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["JetBrains Mono", "ui-monospace", "SFMono-Regular", "monospace"],
      },

      fontSize: {
        // Dense UI — SOC tools are information-rich
        "2xs": ["0.625rem", { lineHeight: "0.875rem" }],
        xs: ["0.75rem", { lineHeight: "1rem" }],
        sm: ["0.8125rem", { lineHeight: "1.25rem" }],
        base: ["0.875rem", { lineHeight: "1.375rem" }],
        lg: ["1rem", { lineHeight: "1.5rem" }],
        xl: ["1.125rem", { lineHeight: "1.625rem" }],
        "2xl": ["1.25rem", { lineHeight: "1.75rem" }],
        "3xl": ["1.5rem", { lineHeight: "2rem" }],
      },

      borderRadius: {
        sm: "0.25rem",
        DEFAULT: "0.375rem",
        md: "0.375rem",
        lg: "0.5rem",
        xl: "0.75rem",
      },

      animation: {
        "fade-in": "fadeIn 0.15s ease-out",
        "slide-in-right": "slideInRight 0.2s ease-out",
        "slide-out-right": "slideOutRight 0.2s ease-in",
        "pulse-subtle": "pulseSubtle 2s ease-in-out infinite",
      },

      keyframes: {
        fadeIn: {
          from: { opacity: "0" },
          to: { opacity: "1" },
        },
        slideInRight: {
          from: { transform: "translateX(100%)", opacity: "0" },
          to: { transform: "translateX(0)", opacity: "1" },
        },
        slideOutRight: {
          from: { transform: "translateX(0)", opacity: "1" },
          to: { transform: "translateX(100%)", opacity: "0" },
        },
        pulseSubtle: {
          "0%, 100%": { opacity: "1" },
          "50%": { opacity: "0.6" },
        },
      },

      boxShadow: {
        "card": "0 1px 3px 0 rgba(0, 0, 0, 0.4), 0 1px 2px -1px rgba(0, 0, 0, 0.4)",
        "elevated": "0 4px 12px 0 rgba(0, 0, 0, 0.5)",
        "panel": "0 8px 32px 0 rgba(0, 0, 0, 0.6)",
        "glow-accent": "0 0 12px rgba(59, 130, 246, 0.2)",
        "glow-critical": "0 0 12px rgba(239, 68, 68, 0.2)",
      },
    },
  },
  plugins: [],
};

export default config;
