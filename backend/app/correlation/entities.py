"""
Canonical entity types for the correlation layer.

Each entity is an immutable Pydantic model with a precomputed `key` field that
uniquely identifies the entity within its type.  Keys are used for O(1)
deduplication inside EntityExtractor and for fast reverse-lookup indexing.

All string fields that participate in `key` computation are stored in
canonical (lowercase, stripped) form.  `command_line` is the sole exception —
argument casing is preserved because case changes alter meaning.

Tenant isolation is NOT enforced at the entity level; it is the responsibility
of ExtractionResult (which carries tenant_id) and the calling pipeline stage.
"""

from __future__ import annotations

from pydantic import BaseModel


class UserEntity(BaseModel):
    """A user account or security principal."""

    name: str  # canonical lowercase
    domain: str | None = None  # Windows domain or AD realm, canonical lowercase
    user_id: str | None = None  # SID (Windows) or UID string (Linux)
    logon_id: str | None = None  # Windows LogonId or session reference
    is_privileged: bool = False  # SYSTEM, root, admin, sudoer
    key: str  # precomputed dedup key

    @staticmethod
    def make_key(name: str, domain: str | None) -> str:
        if domain:
            return f"user:{domain}\\{name}"
        return f"user:{name}"


class HostEntity(BaseModel):
    """A machine / endpoint."""

    hostname: str  # canonical lowercase
    key: str

    @staticmethod
    def make_key(hostname: str) -> str:
        return f"host:{hostname}"


class IPEntity(BaseModel):
    """A network IP address (v4 or v6)."""

    address: str  # canonical form (no leading zeros, compressed IPv6)
    direction: str | None = None  # "src" | "dst" | None
    key: str

    @staticmethod
    def make_key(address: str) -> str:
        return f"ip:{address}"


class DomainEntity(BaseModel):
    """A DNS domain name, query target, or URL hostname."""

    fqdn: str  # canonical lowercase
    key: str

    @staticmethod
    def make_key(fqdn: str) -> str:
        return f"domain:{fqdn}"


class ProcessEntity(BaseModel):
    """A process or executable observed on a host."""

    name: str  # canonical lowercase image name (basename only)
    executable: str | None = None  # full path, canonical lowercase
    command_line: str | None = None  # raw — NOT lowercased, argument case matters
    pid: int | None = None
    ppid: int | None = None
    guid: str | None = None  # Sysmon ProcessGuid (primary lineage anchor)
    parent_name: str | None = None  # parent image basename, canonical lowercase
    parent_guid: str | None = None  # Sysmon ParentProcessGuid
    user: str | None = None  # running-as user, canonical lowercase
    hash_md5: str | None = None  # lowercase hex
    hash_sha256: str | None = None  # lowercase hex
    service_name: str | None = None  # Windows service name backing this process
    key: str

    @staticmethod
    def make_key(
        guid: str | None,
        executable: str | None,
        name: str,
    ) -> str:
        if guid:
            return f"proc:guid:{guid}"
        if executable:
            return f"proc:exe:{executable}"
        return f"proc:name:{name}"


class HashEntity(BaseModel):
    """A cryptographic file or image hash."""

    algorithm: str  # "md5" | "sha1" | "sha256"
    value: str  # lowercase hexadecimal
    key: str

    @staticmethod
    def make_key(algorithm: str, value: str) -> str:
        return f"hash:{algorithm}:{value}"
