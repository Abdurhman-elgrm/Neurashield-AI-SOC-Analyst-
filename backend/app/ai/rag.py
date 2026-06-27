"""
RAG service — ingest knowledge sources into PostgreSQL and retrieve
relevant chunks using pgvector cosine similarity with FTS fallback.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any

import httpx
import structlog
from sqlalchemy import func, select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.rag_chunk import RAGChunk

log = structlog.get_logger(__name__)

# ─── Embedding generation ─────────────────────────────────────────────────────


async def _get_embedding(text_input: str) -> list[float] | None:
    """
    Generate a 1536-dimensional embedding using Google Gemini.
    Returns None when GEMINI_API_KEY is not configured or the call fails,
    allowing graceful fallback to FTS retrieval.
    """
    from app.core.config import settings

    if not settings.GEMINI_API_KEY:
        return None
    try:
        from google import genai
        from google.genai import types as genai_types

        client = genai.Client(api_key=settings.GEMINI_API_KEY)
        # text-embedding-004 supports variable output dimensionality via newer models.
        # We request 1536 to match the Vector(1536) column.
        response = await client.aio.models.embed_content(
            model="gemini-embedding-exp-03-07",
            contents=text_input[:8000],  # cap token count
            config=genai_types.EmbedContentConfig(output_dimensionality=1536),
        )
        return list(response.embeddings[0].values)
    except Exception as exc:
        log.debug("rag_embedding_failed", error=str(exc)[:120])
        return None


# ─── Static knowledge: Threat Actors ─────────────────────────────────────────

THREAT_ACTORS = [
    {
        "name": "APT29",
        "aliases": ["Cozy Bear", "The Dukes", "Midnight Blizzard"],
        "origin": "Russia (SVR)",
        "targets": "Government, think tanks, healthcare, technology",
        "ttps": ["T1566.001", "T1059.001", "T1078", "T1021.002", "T1003.001", "T1550.001"],
        "tools": ["Cobalt Strike", "Mimikatz", "PowerShell Empire", "SUNBURST", "TEARDROP"],
        "description": (
            "Russian state-sponsored group targeting Western governments and organizations. "
            "Known for SolarWinds SUNBURST supply-chain compromise and long-dwell-time espionage. "
            "Frequently uses valid accounts, obfuscated malware loaders, and HTTPS C2. "
            "Detection: DCSync events (4662), Golden SAML tokens, SUNBURST DGA domain patterns."
        ),
    },
    {
        "name": "APT41",
        "aliases": ["Double Dragon", "Winnti", "BARIUM"],
        "origin": "China (MSS)",
        "targets": "Healthcare, telecom, technology, video games, financial",
        "ttps": ["T1190", "T1059.003", "T1055", "T1078", "T1005", "T1195.002"],
        "tools": ["Cobalt Strike", "PlugX", "ShadowPad", "Winnti rootkit"],
        "description": (
            "Chinese state-sponsored group conducting both espionage and financial crime. "
            "Known for supply-chain attacks via trusted software vendors and exploitation of "
            "public-facing applications (Citrix, ManageEngine, Log4j). "
            "Detection: software update processes spawning shells, rootkit driver loading, "
            "unusual outbound from production servers at off-hours."
        ),
    },
    {
        "name": "Lazarus Group",
        "aliases": ["Hidden Cobra", "APT38", "Zinc", "Sapphire Sleet"],
        "origin": "North Korea (RGB)",
        "targets": "Financial institutions, cryptocurrency, defense, healthcare",
        "ttps": ["T1566.001", "T1059.001", "T1003", "T1041", "T1486", "T1021.002"],
        "tools": ["BLINDINGCAN", "Cobalt Strike", "Maui ransomware", "AppleJeus", "DTrack"],
        "description": (
            "North Korean state-sponsored group focused on financial theft and espionage. "
            "Responsible for WannaCry ransomware, SWIFT banking heists, and crypto exchange attacks. "
            "Uses job-offer-themed spearphishing and custom malware loaders. "
            "Detection: financial system access by unusual accounts, cryptocurrency wallet processes, "
            "macOS staged payloads from job-themed documents."
        ),
    },
    {
        "name": "LockBit 3.0",
        "aliases": ["LockBit Black"],
        "origin": "Criminal group (Russia-linked)",
        "targets": "All sectors — opportunistic ransomware-as-a-service",
        "ttps": ["T1486", "T1490", "T1059.001", "T1003.001", "T1021.002", "T1083", "T1562.001"],
        "tools": ["LockBit ransomware", "Cobalt Strike", "Mimikatz", "AV termination scripts"],
        "description": (
            "Ransomware-as-a-Service group responsible for attacks on Royal Mail, ICBC, and Boeing. "
            "Double-extortion: data theft before encryption. Terminates AV/EDR before payload. "
            "Detection: batch process termination (taskkill /IM *), vssadmin delete shadows, "
            "rapid file encryption (many FileCreate events per second), wevtutil cl (log clearing)."
        ),
    },
    {
        "name": "REvil",
        "aliases": ["Sodinokibi", "GOLD SOUTHFIELD"],
        "origin": "Criminal group (Russia-linked)",
        "targets": "Manufacturing, legal, financial, RaaS — Kaseya, JBS, Acer",
        "ttps": ["T1486", "T1490", "T1059.001", "T1078", "T1566.001", "T1562.001", "T1041"],
        "tools": ["REvil ransomware", "Cobalt Strike", "packed loaders"],
        "description": (
            "Ransomware group responsible for Kaseya VSA supply-chain attack (2021) and JBS attack. "
            "Exploits internet-facing services and purchased IAB credentials. "
            "Disables AV/EDR before encryption phase. "
            "Detection: vssadmin delete shadows, bcdedit recovery disabled, mass file rename, "
            "large outbound transfers before encryption."
        ),
    },
]

# ─── Static knowledge: Windows Event IDs ─────────────────────────────────────

WINDOWS_EVENTS = {
    "4624": (
        "Successful Logon",
        "An account was successfully logged on. Monitor for unusual logon types (Type 3=Network, Type 10=RemoteInteractive). Investigate off-hours or unusual source IPs.",
        ["T1078", "T1021"],
    ),
    "4625": (
        "Failed Logon",
        "An account failed to log on. Multiple failures indicate brute force (T1110). Check source IP and username patterns for credential stuffing.",
        ["T1110"],
    ),
    "4648": (
        "Logon with Explicit Credentials",
        "A logon was attempted using explicit credentials. Classic lateral movement indicator — common in Pass-the-Hash and runas attacks.",
        ["T1550.002", "T1021"],
    ),
    "4688": (
        "Process Creation",
        "A new process was created. Critical for detecting malicious execution. Check parent process and command line for encoded commands, LOLBins, Office spawning shells.",
        ["T1059", "T1055"],
    ),
    "4698": (
        "Scheduled Task Created",
        "A scheduled task was created. APT groups use schtasks.exe for persistence. Check task name, command, and creating process.",
        ["T1053.005"],
    ),
    "4702": (
        "Scheduled Task Updated",
        "Existing scheduled task was modified. Attackers update legitimate tasks to add malicious commands.",
        ["T1053.005"],
    ),
    "4719": (
        "Audit Policy Changed",
        "System audit policy was changed. Almost always malicious — attacker disabling logging to cover tracks.",
        ["T1562.002"],
    ),
    "4720": (
        "User Account Created",
        "New user account created. Attackers create backdoor accounts. Suspicious if outside IT hours.",
        ["T1136.001"],
    ),
    "4728": (
        "Member Added to Security Group",
        "User added to privileged security group. Check if target group has admin rights.",
        ["T1098"],
    ),
    "4768": (
        "Kerberos TGT Request",
        "Kerberos authentication ticket requested. Golden ticket attacks show unusual patterns (non-existent users, impossible timestamps).",
        ["T1558.001"],
    ),
    "4769": (
        "Kerberos Service Ticket",
        "Kerberos service ticket requested. Kerberoasting shows many requests for service accounts from single host.",
        ["T1558.003"],
    ),
    "4776": (
        "Credential Validation",
        "Domain controller attempted NTLM credential validation. Monitor for unusual sources or non-existent accounts.",
        ["T1078", "T1110"],
    ),
    "7045": (
        "Service Installed",
        "A new Windows service was installed. Highly suspicious outside patching windows. PsExec, Cobalt Strike install services for persistence/execution.",
        ["T1543.003"],
    ),
    "1102": (
        "Audit Log Cleared",
        "The security audit log was cleared. Almost always malicious — attacker covering tracks. Correlate with recent logins.",
        ["T1070.001"],
    ),
    "4104": (
        "PowerShell Script Block",
        "PowerShell script block logged. Review decoded content for Invoke-Expression, DownloadString, -EncodedCommand, AMSI bypass attempts.",
        ["T1059.001"],
    ),
    "4657": (
        "Registry Value Modified",
        "Registry object modification. Monitor HKLM/HKCU Run keys, AppInit_DLLs, Image File Execution Options for persistence.",
        ["T1547.001"],
    ),
    "5140": (
        "Network Share Accessed",
        "Network share object accessed. Monitor ADMIN$, C$, IPC$ access from unusual sources — common in PsExec lateral movement.",
        ["T1021.002"],
    ),
    "4656": (
        "Handle Requested (LSASS)",
        "Object handle requested. Critical when targeting lsass.exe for credential dumping via Mimikatz or Procdump.",
        ["T1003.001"],
    ),
}

# Allowlisted RAG source URLs — only these exact origins are permitted.
# Prevents SSRF if an attacker somehow influences the URL being fetched.
_ALLOWED_RAG_ORIGINS: frozenset[str] = frozenset(
    {
        "https://raw.githubusercontent.com",
        "https://www.cisa.gov",
        "https://lolbas-project.github.io",
    }
)

# Maximum response body size per source (prevents memory exhaustion).
_MAX_RAG_RESPONSE_BYTES = 25 * 1024 * 1024  # 25 MiB


def _validate_rag_url(url: str) -> None:
    """Raise ValueError if URL is not in the allowlist or uses a disallowed scheme."""
    import urllib.parse

    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in ("https",):
        raise ValueError(f"RAG URL must use HTTPS, got: {parsed.scheme!r}")
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if origin not in _ALLOWED_RAG_ORIGINS:
        raise ValueError(f"RAG URL origin not allowlisted: {origin!r}")


# ─── HTTP helper ──────────────────────────────────────────────────────────────


async def _http_get(client: httpx.AsyncClient, url: str) -> bytes | None:
    try:
        _validate_rag_url(url)
    except ValueError as exc:
        log.error("rag_http_url_rejected", url=url, reason=str(exc))
        return None

    for attempt in range(3):
        try:
            resp = await client.get(url)
            if resp.status_code == 200:
                body = resp.content
                if len(body) > _MAX_RAG_RESPONSE_BYTES:
                    log.warning(
                        "rag_http_response_too_large",
                        url=url,
                        size=len(body),
                        limit=_MAX_RAG_RESPONSE_BYTES,
                    )
                    return None
                return body
            if resp.status_code == 429:
                await asyncio.sleep(5 * (2**attempt))
                continue
            if resp.status_code >= 500:
                await asyncio.sleep(2**attempt)
                continue
            log.warning("rag_http_error", url=url, status=resp.status_code)
            return None
        except Exception as exc:
            log.warning("rag_http_fetch_failed", url=url, error=str(exc)[:120])
            if attempt < 2:
                await asyncio.sleep(2**attempt)
    return None


# ─── Upsert helper ────────────────────────────────────────────────────────────


async def _upsert_chunks(db: AsyncSession, rows: list[dict[str, Any]]) -> int:
    """
    Bulk upsert using INSERT ... ON CONFLICT (chunk_id) DO UPDATE.
    Generates embeddings for rows that don't already have one.
    Returns number of rows processed.
    """
    if not rows:
        return 0

    # Generate embeddings for rows that lack one (best-effort, non-blocking)
    for row in rows:
        if row.get("embedding") is None:
            content = row.get("content", "")
            title = row.get("title", "")
            row["embedding"] = await _get_embedding(f"{title}\n\n{content}")

    stmt = pg_insert(RAGChunk.__table__).values(rows)
    stmt = stmt.on_conflict_do_update(
        index_elements=["chunk_id"],
        set_={
            "content": stmt.excluded.content,
            "title": stmt.excluded.title,
            "tags": stmt.excluded.tags,
            "metadata": stmt.excluded.metadata,
            "embedding": stmt.excluded.embedding,
            "updated_at": func.now(),
        },
    )
    await db.execute(stmt)
    await db.commit()
    return len(rows)


# ─── Source 1: MITRE ATT&CK ───────────────────────────────────────────────────


async def _ingest_mitre(db: AsyncSession, client: httpx.AsyncClient) -> int:
    log.info("rag_ingest_mitre_starting")
    raw = await _http_get(
        client,
        "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
    )
    if not raw:
        log.warning("rag_ingest_mitre_download_failed")
        return 0

    def _parse() -> list[dict[str, Any]]:
        data = json.loads(raw)
        rows: list[dict[str, Any]] = []
        count = 0
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("x_mitre_deprecated"):
                continue
            platforms = obj.get("x_mitre_platforms", [])
            if not any(p.lower() in ("windows", "linux", "macos") for p in platforms):
                continue

            tech_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    tech_id = ref.get("external_id")
                    break
            if not tech_id:
                continue

            tactic = None
            tactic_name = None
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    tactic = phase.get("phase_name", "")
                    tactic_name = tactic.replace("-", " ").title()
                    break

            name = obj.get("name", "")
            description = (obj.get("description") or "")[:1000]
            detection = (obj.get("x_mitre_detection") or "")[:500]
            is_sub = "." in tech_id

            content = (
                f"MITRE ATT&CK Technique: {name} ({tech_id})\n\n"
                f"Tactic: {tactic_name or 'Unknown'}\n"
                f"Platforms: {', '.join(platforms)}\n\n"
                f"Description:\n{description}\n\n"
                f"Detection:\n{detection or 'Monitor platform telemetry for indicators of this technique.'}"
            )

            rows.append(
                {
                    "source": "mitre_attack",
                    "chunk_id": f"mitre_{tech_id}",
                    "title": f"{tech_id}: {name}",
                    "content": content,
                    "tags": [tech_id, tactic or "unknown"],
                    "metadata": {
                        "tactic": tactic,
                        "platforms": platforms,
                        "is_subtechnique": is_sub,
                    },
                }
            )
            count += 1
            if count >= 400:
                break
        return rows

    rows = await asyncio.to_thread(_parse)
    log.info("rag_ingest_mitre_parsed", count=len(rows))
    ingested = await _upsert_chunks(db, rows)
    log.info("rag_ingest_mitre_done", ingested=ingested)
    return ingested


# ─── Source 2: Threat Actors (static) ────────────────────────────────────────


async def _ingest_threat_actors(db: AsyncSession) -> int:
    rows: list[dict[str, Any]] = []
    for actor in THREAT_ACTORS:
        name = actor["name"]
        content = (
            f"Threat Actor: {name}\n\n"
            f"Origin: {actor['origin']}\n"
            f"Targets: {actor['targets']}\n\n"
            f"Description: {actor['description']}\n\n"
            f"Common TTPs: {', '.join(actor['ttps'])}\n"
            f"Tools Used: {', '.join(actor['tools'])}"
        )
        slug = name.lower().replace(" ", "_")
        tags = actor["ttps"] + [name.lower()] + [a.lower() for a in actor["aliases"]]
        rows.append(
            {
                "source": "threat_actors",
                "chunk_id": f"actor_{slug}",
                "title": f"Threat Actor: {name}",
                "content": content,
                "tags": tags,
                "metadata": {
                    "origin": actor["origin"],
                    "targets": actor["targets"],
                    "aliases": actor["aliases"],
                },
            }
        )
    ingested = await _upsert_chunks(db, rows)
    log.info("rag_ingest_threat_actors_done", ingested=ingested)
    return ingested


# ─── Source 3: Windows Event IDs (static) ────────────────────────────────────


async def _ingest_windows_events(db: AsyncSession) -> int:
    rows: list[dict[str, Any]] = []
    for event_id, (name, description, ttps) in WINDOWS_EVENTS.items():
        content = (
            f"Windows Event ID {event_id}: {name}\n\n"
            f"Description: {description}\n\n"
            f"MITRE ATT&CK Techniques: {', '.join(ttps)}\n\n"
            f"Detection: Monitor Windows Security event log for EventID {event_id}. "
            f"Correlate with source IP, username, process name, and frequency."
        )
        rows.append(
            {
                "source": "windows_events",
                "chunk_id": f"winevent_{event_id}",
                "title": f"Windows Event {event_id}: {name}",
                "content": content,
                "tags": ttps + [f"eventid_{event_id}", "windows"],
                "metadata": {"event_id": event_id, "platform": "windows"},
            }
        )
    ingested = await _upsert_chunks(db, rows)
    log.info("rag_ingest_windows_events_done", ingested=ingested)
    return ingested


# ─── Source 4: CISA KEV (top 50 most recent) ──────────────────────────────────


async def _ingest_cisa_kev(db: AsyncSession, client: httpx.AsyncClient) -> int:
    log.info("rag_ingest_cisa_kev_starting")
    raw = await _http_get(
        client,
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    )
    if not raw:
        log.warning("rag_ingest_cisa_kev_download_failed")
        return 0

    data = json.loads(raw)
    vulns: list[dict] = data.get("vulnerabilities", [])

    # Sort by dateAdded descending, take top 50
    def _date_key(v: dict) -> str:
        return v.get("dateAdded", "0000-00-00")

    vulns_sorted = sorted(vulns, key=_date_key, reverse=True)[:50]
    log.info("rag_ingest_cisa_kev_entries", count=len(vulns_sorted))

    rows: list[dict[str, Any]] = []
    for v in vulns_sorted:
        cve_id = v.get("cveID", "")
        vendor = v.get("vendorProject", "")
        product = v.get("product", "")
        vuln_name = v.get("vulnerabilityName", "")
        short_desc = v.get("shortDescription", "")
        req_action = v.get("requiredAction", "")
        date_added = v.get("dateAdded", "")
        ransomware = v.get("knownRansomwareCampaignUse", "Unknown")

        content = (
            f"CVE: {cve_id}\n"
            f"Vendor: {vendor}\n"
            f"Product: {product}\n"
            f"Vulnerability: {vuln_name}\n"
            f"Description: {short_desc}\n"
            f"Required Action: {req_action}\n"
            f"Added to CISA KEV: {date_added}\n"
            f"Known Ransomware Use: {ransomware}"
        )
        rows.append(
            {
                "source": "cisa_kev",
                "chunk_id": f"kev_{cve_id}",
                "title": f"CISA KEV: {cve_id} — {product}",
                "content": content,
                "tags": [cve_id, vendor.lower(), product.lower(), "cisa_kev", "vulnerability"],
                "metadata": {
                    "cve_id": cve_id,
                    "vendor": vendor,
                    "product": product,
                    "date_added": date_added,
                    "ransomware": ransomware,
                },
            }
        )

    ingested = await _upsert_chunks(db, rows)
    log.info("rag_ingest_cisa_kev_done", ingested=ingested)
    return ingested


# ─── Source 5: LOLBAS ─────────────────────────────────────────────────────────


async def _ingest_lolbas(db: AsyncSession, client: httpx.AsyncClient) -> int:
    log.info("rag_ingest_lolbas_starting")
    raw = await _http_get(client, "https://lolbas-project.github.io/api/lolbas.json")
    if not raw:
        log.warning("rag_ingest_lolbas_download_failed")
        return 0

    entries = json.loads(raw)
    rows: list[dict[str, Any]] = []

    for entry in entries:
        if not isinstance(entry, dict):
            continue

        name = entry.get("Name", "")
        description = entry.get("Description", "")
        commands = entry.get("Commands") or []
        paths = entry.get("Paths") or []
        path_str = paths[0].get("Path", "") if paths and isinstance(paths[0], dict) else ""

        # Filter: only binaries with Execute/Download/AWL-Bypass commands
        useful_types = {"execute", "download", "awl bypass", "compile", "upload"}
        cmd_descriptions: list[str] = []
        for cmd in commands[:5]:
            if not isinstance(cmd, dict):
                continue
            cmd_type = (cmd.get("Type") or "").lower()
            if any(t in cmd_type for t in useful_types):
                d = cmd.get("Description", "")
                c = cmd.get("Command", "")
                if d or c:
                    cmd_descriptions.append(f"{d}: {c}"[:200])

        if not cmd_descriptions:
            continue

        content = (
            f"Binary: {name}\n"
            f"Path: {path_str}\n"
            f"Uses: {description}\n"
            f"Commands:\n" + "\n".join(f"  - {c}" for c in cmd_descriptions) + "\n"
            f"Detection: Monitor for unusual use of {name} with these arguments."
        )
        rows.append(
            {
                "source": "lolbas",
                "chunk_id": f"lolbas_{name.lower().replace(' ', '_')}",
                "title": f"LOLBAS: {name}",
                "content": content,
                "tags": ["lolbas", "T1218", name.lower()],
                "metadata": {"binary": name, "path": path_str},
            }
        )

    ingested = await _upsert_chunks(db, rows)
    log.info("rag_ingest_lolbas_done", ingested=ingested)
    return ingested


# ─── Main ingestion entry point ───────────────────────────────────────────────


async def ingest_all(db: AsyncSession, force: bool = False) -> dict[str, int]:
    """
    Ingest all 5 knowledge sources into rag_knowledge_base.
    If force=False, skips sources that already have data.
    Returns {"source": count} dict.
    """
    results: dict[str, int] = {}

    async def _source_has_data(source_name: str) -> bool:
        if force:
            return False
        result = await db.execute(
            select(func.count()).select_from(RAGChunk).where(RAGChunk.source == source_name)
        )
        return (result.scalar() or 0) > 0

    async with httpx.AsyncClient(
        timeout=60,
        headers={"User-Agent": "NEURASHIELD-SOC-RAG/2.0"},
        follow_redirects=False,  # never follow redirects — prevents SSRF via open redirect
    ) as client:
        # Static sources (no HTTP — always fast)
        for source_name, fn in [
            ("threat_actors", lambda: _ingest_threat_actors(db)),
            ("windows_events", lambda: _ingest_windows_events(db)),
        ]:
            if not await _source_has_data(source_name):
                try:
                    results[source_name] = await fn()
                except Exception as exc:
                    log.error("rag_ingest_source_failed", source=source_name, error=str(exc))
                    results[source_name] = 0
            else:
                log.info("rag_source_already_populated", source=source_name)
                results[source_name] = -1  # sentinel: skipped

        # Network sources (may be slow — run with per-source error handling)
        for source_name, fn in [
            ("mitre_attack", lambda: _ingest_mitre(db, client)),
            ("cisa_kev", lambda: _ingest_cisa_kev(db, client)),
            ("lolbas", lambda: _ingest_lolbas(db, client)),
        ]:
            if not await _source_has_data(source_name):
                try:
                    results[source_name] = await fn()
                except Exception as exc:
                    log.error("rag_ingest_source_failed", source=source_name, error=str(exc))
                    results[source_name] = 0
            else:
                log.info("rag_source_already_populated", source=source_name)
                results[source_name] = -1

    total = sum(v for v in results.values() if v >= 0)
    log.info("rag_ingest_all_complete", results=results, total_ingested=total)
    return results


# ─── Retrieval ────────────────────────────────────────────────────────────────


async def retrieve(
    db: AsyncSession,
    ttps: list[str],
    keywords: list[str] | None = None,
    limit: int = 8,
) -> list[RAGChunk]:
    """
    Retrieve relevant RAG chunks for a set of MITRE TTPs and optional keywords.

    Strategy:
      1. pgvector cosine similarity on query embedding   → semantic relevance
      2. Exact JSONB tag match on TTP codes              → precise TTP hits
      3. Full-text search on content                     → keyword coverage
      4. Broad keyword fallback if still short
    """
    if keywords is None:
        keywords = []

    seen_ids: set[str] = set()
    chunks: list[RAGChunk] = []

    # Step 1 — vector similarity (primary path when embeddings are populated)
    query_text = " ".join(ttps[:6] + (keywords[:4] if keywords else []))
    query_embedding = await _get_embedding(query_text) if query_text else None
    if query_embedding is not None:
        try:
            from pgvector.sqlalchemy import Vector
            from sqlalchemy import cast

            vec_result = await db.execute(
                select(RAGChunk)
                .where(RAGChunk.embedding.is_not(None))
                .order_by(RAGChunk.embedding.cosine_distance(cast(query_embedding, Vector(1536))))
                .limit(limit)
            )
            for row in vec_result.scalars().all():
                cid = str(row.chunk_id)
                if cid not in seen_ids:
                    seen_ids.add(cid)
                    chunks.append(row)
        except Exception as exc:
            log.debug("rag_vector_search_failed", error=str(exc)[:120])

    if len(chunks) >= limit:
        return chunks[:limit]

    # Step 2 — exact tag matches for each TTP (tags @> '["T1059.001"]'::jsonb)
    if ttps:
        for ttp in ttps[:6]:
            result = await db.execute(
                select(RAGChunk).where(RAGChunk.tags.contains([ttp])).limit(3)
            )
            for row in result.scalars().all():
                cid = str(row.chunk_id)
                if cid not in seen_ids:
                    seen_ids.add(cid)
                    chunks.append(row)
                    if len(chunks) >= limit:
                        return chunks

    # Step 3 — FTS on content using technique IDs + keywords
    # Strip dots/dashes to a single alphanumeric token (T1059.001 -> T1059001)
    # so to_tsquery never sees the <-> phrase operator.
    search_terms = ttps[:4] + (keywords[:4] if keywords else [])
    if search_terms:
        ts_query = " | ".join(
            "".join(c for c in term if c.isalnum())
            for term in search_terms
            if any(c.isalnum() for c in term)
        )
        if ts_query:
            fts_result = await db.execute(
                select(RAGChunk)
                .where(
                    func.to_tsvector("english", RAGChunk.content).op("@@")(
                        func.to_tsquery("english", ts_query)
                    )
                )
                .order_by(
                    func.ts_rank(
                        func.to_tsvector("english", RAGChunk.content),
                        func.to_tsquery("english", ts_query),
                    ).desc()
                )
                .limit(limit * 2)
            )
            for row in fts_result.scalars().all():
                cid = str(row.chunk_id)
                if cid not in seen_ids:
                    seen_ids.add(cid)
                    chunks.append(row)
                    if len(chunks) >= limit:
                        return chunks

    # Step 4 — broad keyword fallback if still short
    if len(chunks) < 3 and keywords:
        kw_query = " | ".join(
            kw for kw in keywords[:6] if kw.isalnum() or (kw.replace("_", "").isalnum())
        )
        if kw_query:
            broad_result = await db.execute(
                select(RAGChunk)
                .where(
                    func.to_tsvector("english", RAGChunk.content).op("@@")(
                        func.to_tsquery("english", kw_query)
                    )
                )
                .limit(limit)
            )
            for row in broad_result.scalars().all():
                cid = str(row.chunk_id)
                if cid not in seen_ids:
                    seen_ids.add(cid)
                    chunks.append(row)
                    if len(chunks) >= limit:
                        break

    return chunks[:limit]
