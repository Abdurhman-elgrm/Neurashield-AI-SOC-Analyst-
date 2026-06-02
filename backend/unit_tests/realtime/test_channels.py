from __future__ import annotations

"""Tests for realtime channel constants and factory helpers."""

import pytest

from app.realtime import channels as ch

TENANT_ID = "aaa00000-0000-0000-0000-000000000001"


# ─── Constants ────────────────────────────────────────────────────────────────

def test_all_channels_contains_six_entries():
    assert len(ch.ALL_CHANNELS) == 6


def test_all_channels_contains_expected_names():
    assert ch.ALERTS in ch.ALL_CHANNELS
    assert ch.INVESTIGATIONS in ch.ALL_CHANNELS
    assert ch.CASES in ch.ALL_CHANNELS
    assert ch.ACTIVITY in ch.ALL_CHANNELS
    assert ch.HUNTS in ch.ALL_CHANNELS
    assert ch.PRESENCE in ch.ALL_CHANNELS


def test_realtime_subsystem_label():
    assert ch.REALTIME_SUBSYSTEM == "realtime"


def test_pubsub_pattern_is_wildcard():
    assert "*" in ch.PUBSUB_PATTERN
    assert "tenant" in ch.PUBSUB_PATTERN
    assert "realtime" in ch.PUBSUB_PATTERN


# ─── pubsub_channel ───────────────────────────────────────────────────────────

def test_pubsub_channel_format():
    result = ch.pubsub_channel(TENANT_ID, "alerts")
    assert result == f"tenant:{TENANT_ID}:realtime:alerts"


def test_pubsub_channel_different_channels():
    for channel in ch.ALL_CHANNELS:
        result = ch.pubsub_channel(TENANT_ID, channel)
        assert result.startswith(f"tenant:{TENANT_ID}:realtime:")
        assert result.endswith(channel)


# ─── presence_key / presence_set_key ─────────────────────────────────────────

def test_presence_key_contains_analyst_id():
    key = ch.presence_key("analyst-abc")
    assert "analyst-abc" in key
    assert "presence" in key


def test_presence_set_key_is_stable():
    assert ch.presence_set_key() == ch.presence_set_key()
    assert "presence" in ch.presence_set_key()


# ─── lock_key ─────────────────────────────────────────────────────────────────

def test_lock_key_contains_investigation_id():
    key = ch.lock_key("inv-123")
    assert "inv-123" in key
    assert "lock" in key


# ─── subscription_channel_suffix ─────────────────────────────────────────────

def test_subscription_channel_suffix_format():
    suffix = ch.subscription_channel_suffix("alerts")
    assert suffix == "realtime:alerts"


def test_subscription_channel_suffix_all_channels():
    for channel in ch.ALL_CHANNELS:
        suffix = ch.subscription_channel_suffix(channel)
        assert suffix == f"realtime:{channel}"


# ─── is_valid_channel ─────────────────────────────────────────────────────────

def test_is_valid_channel_returns_true_for_all():
    for channel in ch.ALL_CHANNELS:
        assert ch.is_valid_channel(channel) is True


def test_is_valid_channel_returns_false_for_unknown():
    assert ch.is_valid_channel("unknown_channel") is False
    assert ch.is_valid_channel("") is False
    assert ch.is_valid_channel("raw_events") is False


# ─── extract_tenant_from_pubsub ──────────────────────────────────────────────

def test_extract_tenant_valid():
    full = f"tenant:{TENANT_ID}:realtime:alerts"
    result = ch.extract_tenant_from_pubsub(full)
    assert result == TENANT_ID


def test_extract_tenant_invalid_format_returns_none():
    assert ch.extract_tenant_from_pubsub("bad:channel") is None
    assert ch.extract_tenant_from_pubsub("") is None
    assert ch.extract_tenant_from_pubsub("tenant:abc:wrong:alerts") is None


# ─── extract_channel_from_pubsub ─────────────────────────────────────────────

def test_extract_channel_valid():
    full = f"tenant:{TENANT_ID}:realtime:investigations"
    result = ch.extract_channel_from_pubsub(full)
    assert result == "investigations"


def test_extract_channel_all_channels():
    for channel in ch.ALL_CHANNELS:
        full = ch.pubsub_channel(TENANT_ID, channel)
        extracted = ch.extract_channel_from_pubsub(full)
        assert extracted == channel


def test_extract_channel_invalid_returns_none():
    assert ch.extract_channel_from_pubsub("totally:wrong") is None
    assert ch.extract_channel_from_pubsub("") is None
