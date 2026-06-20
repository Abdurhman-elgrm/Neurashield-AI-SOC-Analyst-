from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import structlog

from app.ai.llm_manager import get_llm_manager
from .parser import SigmaParseResult, parse_sigma_yaml

logger = structlog.get_logger(__name__)

# ─── Prompt injection guard ────────────────────────────────────────────────────

_INJECTION_RE = re.compile(
    r"ignore\s+previous|system\s*:|<\s*system\s*>|you\s+are\s+now|"
    r"forget\s+everything|new\s+instructions?|##\s*system",
    re.IGNORECASE,
)

# ─── System prompt ─────────────────────────────────────────────────────────────
# Teaches the LLM: Sigma format, our supported fields, modifiers, examples.
# Deliberately concise — avoids token waste while covering 95% of real rules.

_SYSTEM_PROMPT = """\
You are a senior cybersecurity detection engineer specializing in Sigma rules.
Your only job is to generate a single valid Sigma YAML detection rule.

OUTPUT RULES (CRITICAL):
- Output ONLY raw YAML. No markdown code fences. No explanation. No comments outside YAML.
- Start your output with "title:" and end at the last YAML field.
- If the description is in Arabic or any other language, write the rule title and description in English.

SIGMA YAML STRUCTURE:
title: <concise rule name, e.g. "Suspicious PowerShell Encoded Command">
description: <one sentence: what this detects and why it matters>
status: experimental
logsource:
  category: <CHOOSE ONE: process_creation | network_connection | dns_query | file_event | registry_set | authentication>
  product: <windows | linux | macos>  # omit if cross-platform or unknown
detection:
  selection:
    FieldName|modifier: value         # single value
    FieldName|modifier:              # multiple values = OR logic
      - value1
      - value2
  selection_alt:                     # optional second selection block
    FieldName|modifier: value
  filter:                            # optional exclusion block
    FieldName: benign_value
  condition: selection               # see CONDITION EXPRESSIONS below
level: <informational | low | medium | high | critical>
tags:
  - attack.t<id>       # MITRE technique, e.g. attack.t1059
  - attack.<tactic>    # MITRE tactic, e.g. attack.execution

CONDITION EXPRESSIONS:
  selection                         → use selection block
  selection and not filter          → selection minus exclusions
  1 of selection*                   → OR across selection blocks (selection, selection_alt, etc.)
  all of them                       → AND of all selection blocks
  selection and selection_alt       → explicit AND

SUPPORTED FIELDS (use EXACT names, case-sensitive):
  Process:   Image, CommandLine, ParentImage, ParentCommandLine, OriginalFileName, User, IntegrityLevel
  Network:   DestinationIp, DestinationPort, SourceIp, SourcePort, DestinationHostname
  File:      TargetFilename, FileName
  Registry:  TargetObject, Details
  DNS:       QueryName, QueryType
  Windows:   EventID, LogonType, Provider_Name, ServiceName
  Generic:   Computer

FIELD MODIFIERS:
  |contains     substring match
  |startswith   prefix match
  |endswith     suffix match (use for executable paths: '\\cmd.exe')
  |re           regular expression
  |contains|all ALL listed values must appear (AND within one field)
  (none)        exact match

SEVERITY GUIDE:
  critical  → confirmed attack tools (mimikatz, ransomware), account compromise chains
  high      → LOLBin abuse, lateral movement, reverse shells, persistence via scripts
  medium    → reconnaissance, enumeration, suspicious but low-confidence
  low       → informational, noisy indicators

EXAMPLE 1 — Process creation (Windows):
title: Suspicious PowerShell Download Cradle
description: Detects PowerShell downloading and executing code from the internet — common malware staging
status: experimental
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith:
      - '\\powershell.exe'
      - '\\pwsh.exe'
    CommandLine|contains:
      - 'DownloadString'
      - 'DownloadFile'
      - 'WebClient'
      - 'Invoke-WebRequest'
  filter_updates:
    CommandLine|contains: 'WindowsUpdate'
  condition: selection and not filter_updates
level: high
tags:
  - attack.t1059.001
  - attack.execution

EXAMPLE 2 — Registry persistence:
title: Script Interpreter Added to Autorun Registry Key
description: Detects script interpreters writing to registry autorun keys — persistence mechanism
status: experimental
logsource:
  category: registry_set
  product: windows
detection:
  selection:
    TargetObject|contains:
      - '\\CurrentVersion\\Run'
      - '\\CurrentVersion\\RunOnce'
    Details|contains:
      - 'wscript'
      - 'cscript'
      - 'powershell'
      - 'mshta'
  condition: selection
level: high
tags:
  - attack.t1547.001
  - attack.persistence

EXAMPLE 3 — Linux reverse shell:
title: Linux Bash Reverse Shell via TCP Device File
description: Detects bash reverse shell using /dev/tcp — common post-exploitation technique on Linux
status: experimental
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains:
      - '/dev/tcp/'
      - 'bash -i'
  condition: selection
level: critical
tags:
  - attack.t1059.004
  - attack.execution

Generate a Sigma rule for the following description. Output ONLY the YAML:\
"""

# ─── Result type ───────────────────────────────────────────────────────────────

@dataclass
class GeneratorResult:
    yaml_text: str
    parsed: SigmaParseResult
    attempts: int
    error: str | None = None

    @property
    def success(self) -> bool:
        return self.error is None and bool(self.parsed.conditions)


# ─── YAML extraction ───────────────────────────────────────────────────────────

def _extract_yaml(raw: str) -> str:
    """
    Strip markdown fences and any preamble text.
    AI often wraps output in ```yaml ... ``` even when told not to.
    """
    # Remove ```yaml ... ``` or ``` ... ``` fences
    raw = re.sub(r"```(?:yaml|yml)?\s*", "", raw)
    raw = re.sub(r"```\s*$", "", raw, flags=re.MULTILINE)

    # Find first "title:" line — everything from there is the YAML
    match = re.search(r"^title\s*:", raw, re.MULTILINE)
    if match:
        return raw[match.start():].strip()

    return raw.strip()


# ─── Core generator ────────────────────────────────────────────────────────────

async def generate_sigma_rule(
    description: str,
    category_hint: str | None = None,
    severity_hint: str | None = None,
) -> GeneratorResult:
    """
    Generate a Sigma detection rule from a natural language description.

    Strategy:
    1. Build user prompt from description + optional hints
    2. Call LLM (Groq → Gemini fallback)
    3. Extract YAML from response
    4. Validate through Sigma parser
    5. If invalid, retry once with error context
    """
    if _INJECTION_RE.search(description):
        err = "Description contains disallowed patterns."
        return GeneratorResult(
            yaml_text="", parsed=_empty_parse(err), attempts=0, error=err
        )

    description = description.strip()[:1000]  # cap input length

    llm = get_llm_manager()
    attempts = 0

    # Build initial user prompt
    hint_lines: list[str] = []
    if category_hint:
        hint_lines.append(f"Hint — event category: {category_hint}")
    if severity_hint:
        hint_lines.append(f"Hint — severity level: {severity_hint}")

    user_prompt = description
    if hint_lines:
        user_prompt = "\n".join(hint_lines) + "\n\n" + description

    for attempt in range(2):
        attempts += 1
        try:
            raw = await llm.generate(
                prompt=user_prompt,
                system_prompt=_SYSTEM_PROMPT,
                max_tokens=800,
            )
        except Exception as exc:
            logger.warning("sigma_generator_llm_error", attempt=attempt, error=str(exc))
            return GeneratorResult(
                yaml_text="", parsed=_empty_parse(str(exc)),
                attempts=attempts, error=f"LLM error: {exc}",
            )

        yaml_text = _extract_yaml(raw)
        parsed = parse_sigma_yaml(yaml_text)

        logger.info(
            "sigma_generator_attempt",
            attempt=attempt + 1,
            title=parsed.title,
            conditions=len(parsed.conditions),
            parse_error=parsed.error,
        )

        if parsed.error is None and parsed.conditions:
            return GeneratorResult(yaml_text=yaml_text, parsed=parsed, attempts=attempts)

        # Retry: inject error context so the model understands what went wrong
        error_ctx = parsed.error or "No usable conditions were generated."
        user_prompt = (
            f"{description}\n\n"
            f"Previous attempt failed: {error_ctx}\n"
            f"Please fix the rule and output only valid YAML starting with 'title:'"
        )

    # Both attempts failed
    final_error = parsed.error or "Rule produced no usable detection conditions."
    return GeneratorResult(
        yaml_text=yaml_text,
        parsed=parsed,
        attempts=attempts,
        error=final_error,
    )


def _empty_parse(error: str) -> SigmaParseResult:
    return SigmaParseResult(
        title="", description="", severity="medium",
        category=None, mitre_techniques=[], mitre_tactics=[],
        conditions=[], error=error,
    )
