"""
Entity extractor: produces an ExtractionResult from a NormalizedEvent.

Design principles
─────────────────
* Fault-tolerant — individual field failures are debug-logged, never raised.
  A partial ExtractionResult is always returned.
* No recursion — all dict traversal uses safe_get() or direct .get() calls.
* No per-event regex — all patterns are pre-compiled in utils.py.
* Dict-keyed deduplication — O(1) identity check per entity via key strings.
* Single shared instance — EntityExtractor is stateless; use the module-level
  extract_entities() convenience function or one long-lived instance per worker.

Integration
───────────
    from app.correlation.extractor import extract_entities
    from app.correlation.enrichment import enrich_normalized_payload

    result = extract_entities(normalized_event, event_db_id=str(event.id))
    enrich_normalized_payload(norm_payload, result)

Raw field coverage
──────────────────
Windows Sysmon EID 1  (Process Create)   – ProcessGuid, Image, CommandLine,
                                            ParentProcessGuid, ParentImage,
                                            Hashes, LogonId, User
Windows Sysmon EID 3  (Network Connect)  – SourceIp, DestinationIp,
                                            DestinationHostname, ProcessGuid
Windows Sysmon EID 22 (DNS Query)        – QueryName, ProcessGuid
Windows Security 4624/4625 (Logon)       – SubjectUserName/Domain/LogonId,
                                            TargetUserName/Domain/LogonId, IpAddress
Linux auditd EXECVE                      – uid, auid, pid, ppid, exe, comm,
                                            proctitle
"""

from __future__ import annotations

from typing import Any

import structlog

from app.correlation.entities import (
    DomainEntity,
    HashEntity,
    HostEntity,
    IPEntity,
    ProcessEntity,
    UserEntity,
)
from app.correlation.schemas import CorrelationMetadata, EntitySet, ExtractionResult
from app.correlation.utils import (
    canonical_str,
    extract_domain_from_url,
    is_valid_ip,
    make_correlation_id,
    make_event_chain_id,
    make_process_tree_id,
    make_session_id,
    parse_sysmon_hashes,
    safe_get,
)
from app.normalization.models import NormalizedEvent

logger = structlog.get_logger(__name__)

# IPs that carry no correlation value — loopback, unspecified, broadcast,
# and the Windows Security log placeholder "-".
_SKIP_IPS: frozenset[str] = frozenset(
    {
        "127.0.0.1",
        "::1",
        "0.0.0.0",
        "::",
        "255.255.255.255",
        "-",
        "::ffff:127.0.0.1",
    }
)

# Windows well-known system account names that produce noise when indexed.
_SYSTEM_ACCOUNTS: frozenset[str] = frozenset(
    {
        "system",
        "local service",
        "network service",
        "anonymous logon",
        "iis apppool\\defaultapppool",
        "-",
    }
)


class EntityExtractor:
    """
    Stateless entity extractor.  Safe to use as a module-level singleton and
    share across concurrent async tasks (no mutable instance state).
    """

    def extract(
        self,
        event: NormalizedEvent,
        event_db_id: str | None = None,
    ) -> ExtractionResult:
        """
        Extract all entities and compute correlation metadata from a NormalizedEvent.

        Partial extraction is always returned — individual field failures
        produce a debug log entry and are skipped, not propagated.
        """
        users: dict[str, UserEntity] = {}
        hosts: dict[str, HostEntity] = {}
        ips: dict[str, IPEntity] = {}
        domains: dict[str, DomainEntity] = {}
        processes: dict[str, ProcessEntity] = {}
        hashes: dict[str, HashEntity] = {}

        try:
            self._extract_hostname(event, hosts)
            self._extract_user_field(event, users)
            self._extract_network_field(event, ips, domains)
            self._extract_process_field(event, processes, hashes)
            self._extract_file_hashes(event, hashes)
            self._extract_raw(event.raw, users, hosts, ips, domains, processes, hashes)
        except Exception as exc:
            logger.debug(
                "entity_extraction_partial_failure",
                event_id=event.event_id,
                tenant_id=event.tenant_id,
                error=str(exc),
            )

        logon_id = _first_logon_id(users)
        proc_guid = _first_process_guid(processes)
        ppid = _first_ppid(processes)
        parent_guid = _first_parent_guid(processes)

        meta = self._build_metadata(
            event,
            logon_id=logon_id,
            process_guid=proc_guid,
            ppid=ppid,
            parent_guid=parent_guid,
        )

        return ExtractionResult(
            event_id=event.event_id,
            tenant_id=event.tenant_id,
            entities=EntitySet(
                users=list(users.values()),
                hosts=list(hosts.values()),
                ips=list(ips.values()),
                domains=list(domains.values()),
                processes=list(processes.values()),
                hashes=list(hashes.values()),
            ),
            correlation_metadata=meta,
        )

    # ── NormalizedEvent sub-object extractors ─────────────────────────────────

    def _extract_hostname(
        self,
        event: NormalizedEvent,
        hosts: dict[str, HostEntity],
    ) -> None:
        h = canonical_str(event.hostname)
        if not h:
            return
        key = HostEntity.make_key(h)
        if key not in hosts:
            hosts[key] = HostEntity(hostname=h, key=key)

    def _extract_user_field(
        self,
        event: NormalizedEvent,
        users: dict[str, UserEntity],
    ) -> None:
        if not event.user:
            return
        u = event.user
        name = canonical_str(u.name)
        if not name or name in _SYSTEM_ACCOUNTS:
            return
        domain = canonical_str(u.domain)
        key = UserEntity.make_key(name, domain)
        if key not in users:
            users[key] = UserEntity(
                name=name,
                domain=domain,
                user_id=canonical_str(u.id),
                is_privileged=u.is_privileged,
                key=key,
            )

    def _extract_network_field(
        self,
        event: NormalizedEvent,
        ips: dict[str, IPEntity],
        domains: dict[str, DomainEntity],
    ) -> None:
        if not event.network:
            return
        n = event.network
        _add_ip(ips, n.src_ip, "src")
        _add_ip(ips, n.dst_ip, "dst")

    def _extract_process_field(
        self,
        event: NormalizedEvent,
        processes: dict[str, ProcessEntity],
        hashes: dict[str, HashEntity],
    ) -> None:
        if not event.process:
            return
        p = event.process
        name = canonical_str(p.name)
        if not name:
            return

        exe = canonical_str(p.executable)
        md5 = canonical_str(p.hash_md5)
        sha256 = canonical_str(p.hash_sha256)

        key = ProcessEntity.make_key(None, exe, name)
        if key not in processes:
            processes[key] = ProcessEntity(
                name=name,
                executable=exe,
                command_line=p.command_line,
                pid=p.pid,
                ppid=p.ppid,
                user=canonical_str(p.user),
                hash_md5=md5,
                hash_sha256=sha256,
                key=key,
            )

        if md5:
            _add_hash(hashes, "md5", md5)
        if sha256:
            _add_hash(hashes, "sha256", sha256)

    def _extract_file_hashes(
        self,
        event: NormalizedEvent,
        hashes: dict[str, HashEntity],
    ) -> None:
        if not event.file:
            return
        f = event.file
        if f.hash_md5:
            _add_hash(hashes, "md5", canonical_str(f.hash_md5) or "")
        if f.hash_sha256:
            _add_hash(hashes, "sha256", canonical_str(f.hash_sha256) or "")

    # ── Raw dict extraction (Sysmon / Windows Security / Linux auditd) ────────

    def _extract_raw(
        self,
        raw: dict[str, Any],
        users: dict[str, UserEntity],
        hosts: dict[str, HostEntity],
        ips: dict[str, IPEntity],
        domains: dict[str, DomainEntity],
        processes: dict[str, ProcessEntity],
        hashes: dict[str, HashEntity],
    ) -> None:
        if not isinstance(raw, dict) or not raw:
            return
        self._raw_users(raw, users)
        self._raw_process(raw, processes, hashes)
        self._raw_network(raw, ips, domains)
        self._raw_dns(raw, domains)

    def _raw_users(
        self,
        raw: dict[str, Any],
        users: dict[str, UserEntity],
    ) -> None:
        # ── Windows Security: SubjectUser + TargetUser pair ───────────────────
        for name_key, domain_key, logon_key in (
            ("SubjectUserName", "SubjectDomainName", "SubjectLogonId"),
            ("TargetUserName", "TargetDomainName", "TargetLogonId"),
        ):
            name = canonical_str(raw.get(name_key))
            if not name or name in _SYSTEM_ACCOUNTS or name.endswith("$"):
                continue
            domain = canonical_str(raw.get(domain_key))
            logon_id = canonical_str(raw.get(logon_key))
            key = UserEntity.make_key(name, domain)
            if key not in users:
                users[key] = UserEntity(
                    name=name,
                    domain=domain,
                    logon_id=logon_id,
                    key=key,
                )

        # ── Sysmon: User field (DOMAIN\user or plain user) ────────────────────
        sysmon_user = canonical_str(raw.get("User"))
        if sysmon_user and sysmon_user not in _SYSTEM_ACCOUNTS and not sysmon_user.endswith("$"):
            if "\\" in sysmon_user:
                domain_part, _, uname = sysmon_user.partition("\\")
            else:
                domain_part, uname = None, sysmon_user  # type: ignore[assignment]
            key = UserEntity.make_key(uname, domain_part)
            if key not in users:
                users[key] = UserEntity(
                    name=uname,
                    domain=domain_part or None,
                    logon_id=canonical_str(raw.get("LogonId")),
                    key=key,
                )

        # ── Linux auditd: uid / auid ──────────────────────────────────────────
        for uid_key in ("uid", "auid"):
            uid_val = canonical_str(raw.get(uid_key))
            if uid_val and uid_val not in ("-1", "4294967295", "unset", "-"):
                key = UserEntity.make_key(uid_val, None)
                if key not in users:
                    users[key] = UserEntity(
                        name=uid_val,
                        user_id=uid_val,
                        key=key,
                    )

    def _raw_process(
        self,
        raw: dict[str, Any],
        processes: dict[str, ProcessEntity],
        hashes: dict[str, HashEntity],
    ) -> None:
        # ── Sysmon process fields ─────────────────────────────────────────────
        proc_guid = canonical_str(raw.get("ProcessGuid"))
        parent_guid = canonical_str(raw.get("ParentProcessGuid"))
        image = canonical_str(raw.get("Image"))
        parent_img = canonical_str(raw.get("ParentImage"))
        cmd_line = raw.get("CommandLine")  # preserve case
        service_nm = canonical_str(raw.get("ServiceName"))

        # PID / PPID — accept Sysmon (ProcessId) or generic (pid/ppid)
        pid = _int_or_none(raw.get("ProcessId") or raw.get("pid"))
        ppid = _int_or_none(raw.get("ParentProcessId") or raw.get("ppid"))

        # Sysmon Hashes field + standalone hash fields — extracted unconditionally
        # so a Hashes-only event (e.g. EID 7 Image Load) still indexes them.
        sysmon_h = parse_sysmon_hashes(raw.get("Hashes"))
        md5 = sysmon_h.get("md5") or canonical_str(raw.get("hash_md5"))
        sha1 = sysmon_h.get("sha1") or canonical_str(raw.get("hash_sha1"))
        sha256 = sysmon_h.get("sha256") or canonical_str(raw.get("hash_sha256"))

        if md5:
            _add_hash(hashes, "md5", md5)
        if sha1:
            _add_hash(hashes, "sha1", sha1)
        if sha256:
            _add_hash(hashes, "sha256", sha256)

        if image or proc_guid:
            # Derive basename from Image path (handles both \ and / separators)
            if image:
                name = image.replace("\\", "/").split("/")[-1]
            elif proc_guid:
                # No image — use a guid-anchored placeholder name
                name = f"proc:{proc_guid[:8]}"
            else:
                name = "unknown"

            parent_name = parent_img.replace("\\", "/").split("/")[-1] if parent_img else None
            key = ProcessEntity.make_key(proc_guid, image, name)
            if key not in processes:
                processes[key] = ProcessEntity(
                    name=name,
                    executable=image,
                    command_line=cmd_line,
                    pid=pid,
                    ppid=ppid,
                    guid=proc_guid,
                    parent_name=parent_name,
                    parent_guid=parent_guid,
                    service_name=service_nm,
                    hash_md5=md5,
                    hash_sha256=sha256,
                    key=key,
                )
            return

        # ── Linux auditd: exe + comm ──────────────────────────────────────────
        exe_raw = canonical_str(raw.get("exe"))
        comm = canonical_str(raw.get("comm"))
        if exe_raw or comm:
            name = (exe_raw.split("/")[-1] if exe_raw else None) or comm or "unknown"
            key = ProcessEntity.make_key(None, exe_raw, name)
            if key not in processes:
                processes[key] = ProcessEntity(
                    name=name,
                    executable=exe_raw,
                    command_line=raw.get("proctitle"),  # preserve case
                    pid=pid,
                    ppid=ppid,
                    key=key,
                )

    def _raw_network(
        self,
        raw: dict[str, Any],
        ips: dict[str, IPEntity],
        domains: dict[str, DomainEntity],
    ) -> None:
        # Windows Security logon source
        _add_ip(ips, raw.get("IpAddress"), "src")

        # Sysmon EID 3 Network Connect
        _add_ip(ips, raw.get("SourceIp"), "src")
        _add_ip(ips, raw.get("DestinationIp"), "dst")

        # Generic raw field names (agent-normalized)
        _add_ip(ips, raw.get("source_ip"), "src")
        _add_ip(ips, raw.get("destination_ip"), "dst")
        _add_ip(ips, raw.get("dest_ip"), "dst")

        # Sysmon DestinationHostname → DomainEntity
        dest_host = canonical_str(raw.get("DestinationHostname"))
        if dest_host and not is_valid_ip(dest_host):
            key = DomainEntity.make_key(dest_host)
            if key not in domains:
                domains[key] = DomainEntity(fqdn=dest_host, key=key)

    def _raw_dns(
        self,
        raw: dict[str, Any],
        domains: dict[str, DomainEntity],
    ) -> None:
        # Sysmon EID 22 DNS query
        query = canonical_str(raw.get("QueryName"))
        if query:
            key = DomainEntity.make_key(query)
            if key not in domains:
                domains[key] = DomainEntity(fqdn=query, key=key)

        # ECS-style dns.question.name
        dns_q = safe_get(raw, "dns", "question", "name")
        if dns_q:
            fqdn = canonical_str(dns_q)
            if fqdn:
                key = DomainEntity.make_key(fqdn)
                if key not in domains:
                    domains[key] = DomainEntity(fqdn=fqdn, key=key)

        # URL fields — extract and index the hostname component
        for url_field in ("url", "Url", "URL"):
            url_val = raw.get(url_field)
            if isinstance(url_val, str):
                fqdn = extract_domain_from_url(url_val)
                if fqdn and not is_valid_ip(fqdn):
                    key = DomainEntity.make_key(fqdn)
                    if key not in domains:
                        domains[key] = DomainEntity(fqdn=fqdn, key=key)

    # ── Correlation metadata ──────────────────────────────────────────────────

    def _build_metadata(
        self,
        event: NormalizedEvent,
        logon_id: str | None,
        process_guid: str | None,
        ppid: int | None,
        parent_guid: str | None,
    ) -> CorrelationMetadata:
        tid = event.tenant_id
        host = canonical_str(event.hostname) or ""

        return CorrelationMetadata(
            correlation_id=make_correlation_id(tid, host, logon_id),
            session_id=(make_session_id(tid, host, logon_id) if logon_id else None),
            process_tree_id=make_process_tree_id(tid, host, process_guid, ppid),
            event_chain_id=make_event_chain_id(tid, host, process_guid),
            related_entity_keys=[],  # populated by enrich_normalized_payload()
            parent_event_id=parent_guid,
        )


# ── Module-level helpers ───────────────────────────────────────────────────────


def _add_ip(
    ips: dict[str, IPEntity],
    value: Any,
    direction: str | None,
) -> None:
    if not value or not isinstance(value, str):
        return
    v = value.strip()
    if not v or v in _SKIP_IPS or not is_valid_ip(v):
        return
    key = IPEntity.make_key(v)
    if key not in ips:
        ips[key] = IPEntity(address=v, direction=direction, key=key)


def _add_hash(
    hashes: dict[str, HashEntity],
    algo: str,
    value: str,
) -> None:
    if not value:
        return
    key = HashEntity.make_key(algo, value)
    if key not in hashes:
        hashes[key] = HashEntity(algorithm=algo, value=value, key=key)


def _int_or_none(value: Any) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def _first_logon_id(users: dict[str, UserEntity]) -> str | None:
    for u in users.values():
        if u.logon_id:
            return u.logon_id
    return None


def _first_process_guid(processes: dict[str, ProcessEntity]) -> str | None:
    for p in processes.values():
        if p.guid:
            return p.guid
    return None


def _first_parent_guid(processes: dict[str, ProcessEntity]) -> str | None:
    for p in processes.values():
        if p.parent_guid:
            return p.parent_guid
    return None


def _first_ppid(processes: dict[str, ProcessEntity]) -> int | None:
    for p in processes.values():
        if p.ppid is not None:
            return p.ppid
    return None


# ── Convenience function (module-level singleton) ─────────────────────────────

_default_extractor = EntityExtractor()


def extract_entities(
    event: NormalizedEvent,
    event_db_id: str | None = None,
) -> ExtractionResult:
    """
    Module-level convenience wrapper using a shared stateless EntityExtractor.
    Prefer this over constructing a new EntityExtractor per call in worker code.
    """
    return _default_extractor.extract(event, event_db_id=event_db_id)
