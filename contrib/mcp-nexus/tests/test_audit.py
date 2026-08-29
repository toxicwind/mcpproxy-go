"""Tests for audit logging."""

import time

from mcp_nexus.middleware.audit import AuditEntry, AuditLog


def test_audit_record():
    log = AuditLog(max_entries=100)
    entry = AuditEntry(
        timestamp=time.time(),
        tool="read_file",
        client_id="test",
        args={"path": "/etc/hostname"},
        success=True,
        duration_ms=42.5,
    )
    log.record(entry)
    recent = log.recent(10)
    assert len(recent) == 1
    assert recent[0]["tool"] == "read_file"


def test_audit_stats():
    log = AuditLog(max_entries=100)
    for i in range(10):
        log.record(
            AuditEntry(
                timestamp=time.time(),
                tool="execute_command" if i % 2 == 0 else "read_file",
                client_id="test",
                args={},
                success=i != 5,
                duration_ms=float(i * 10),
            )
        )
    stats = log.stats()
    assert stats["total"] == 10
    assert stats["errors"] == 1


def test_audit_filter_by_tool():
    log = AuditLog()
    log.record(AuditEntry(time.time(), "read_file", "c1", {}, True, 10))
    log.record(AuditEntry(time.time(), "write_file", "c1", {}, True, 20))
    log.record(AuditEntry(time.time(), "read_file", "c1", {}, True, 15))

    reads = log.recent(10, tool="read_file")
    assert len(reads) == 2
