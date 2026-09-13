from __future__ import annotations

from dataclasses import replace
from datetime import datetime, timedelta, timezone
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import shutil
import sqlite3
import stat
import threading
import time
from types import SimpleNamespace

import pytest

import hermes_lcm.periodic_backup as periodic
from hermes_lcm.config import LCMConfig
from hermes_lcm.engine import LCMEngine
from hermes_lcm.externalize import externalize_ingest_payload, load_externalized_payload
from hermes_lcm.ingest_protection import (
    _externalize_quarantined_assistant_output,
    extract_all_externalized_payload_refs,
    extract_ingest_externalized_refs,
    is_externalized_ingest_placeholder,
    protect_messages_for_ingest,
    restore_ingest_payload_placeholders,
)


UTC = timezone.utc


def _engine(
    tmp_path: Path,
    *,
    name: str = "lcm.db",
    enabled: bool = False,
    destination: Path | None = None,
    payload_root: Path | None = None,
    interval_hours: float = 6.0,
    keep_last: int = 10,
) -> LCMEngine:
    # Most harnesses need a valid empty payload root. Tests for missing-root
    # admission pass an explicit path so they retain control of materialization.
    effective_payload_root = payload_root or tmp_path / "payloads"
    if payload_root is None:
        effective_payload_root.mkdir(parents=True, exist_ok=True)
        effective_payload_root.chmod(0o700)
    return LCMEngine(
        config=LCMConfig(
            database_path=str(tmp_path / "database" / name),
            large_output_externalization_path=str(effective_payload_root),
            periodic_backup_enabled=enabled,
            periodic_backup_interval_hours=interval_hours,
            periodic_backup_keep_last=keep_last,
            periodic_backup_path=str(destination or tmp_path / "periodic"),
        ),
        hermes_home=str(tmp_path / "home"),
    )


def _payload(path: Path, content: str, **extra) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    value = {
        "kind": "tool_result",
        "tool_call_id": "call-1",
        "session_id": "session",
        "content": content,
        "content_chars": len(content),
        "content_bytes": len(content.encode("utf-8")),
        **extra,
    }
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)


def _add_unmanifested_entry(path: Path, mode: str, *, dangling_target: Path) -> None:
    if mode == "regular":
        path.write_text("unmanifested", encoding="utf-8")
    elif mode == "dangling_symlink":
        path.symlink_to(dangling_target)
    elif mode == "directory":
        path.mkdir()
    else:
        assert mode == "fifo"
        os.mkfifo(path)


def _placeholder(ref: str) -> str:
    return f"[Externalized tool output: tool_call_id=call-1; chars=7; bytes=7; ref={ref}]"


def _append(
    engine: LCMEngine,
    *,
    content: str,
    tool_calls=None,
    role: str = "tool",
    session_id: str = "session",
) -> None:
    engine._store.append(
        session_id,
        {
            "role": role,
            "content": content,
            "tool_calls": tool_calls,
            "timestamp": time.time(),
        },
    )
    engine._store.commit()


def _wait_for(predicate, *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.02)
    raise AssertionError("condition did not become true before timeout")


def _generation_dirs(spec: periodic.PeriodicBackupSpec) -> list[Path]:
    if not spec.namespace.exists():
        return []
    return sorted(
        path
        for path in spec.namespace.iterdir()
        if path.is_dir() and path.name.startswith("lcm-periodic-") and not path.name.endswith(".partial")
    )


def _run_holding_backup(spec, acquired, release, result_queue) -> None:
    def fault(stage: str) -> None:
        if stage == "locked":
            acquired.set()
            if not release.wait(10):
                raise RuntimeError("test lock release timed out")

    result_queue.put(periodic.run_periodic_backup(spec, due_only=False, _fault=fault))


def _run_crashing_staged_backup(spec) -> None:
    def fault(stage: str) -> None:
        if stage == "stage_fsync":
            os._exit(17)

    periodic.run_periodic_backup(spec, due_only=False, _fault=fault)


def test_periodic_config_defaults_env_and_strict_validation(monkeypatch, tmp_path):
    config = LCMConfig()
    assert config.periodic_backup_enabled is False
    assert config.periodic_backup_interval_hours == 6.0
    assert config.periodic_backup_keep_last == 10
    assert config.periodic_backup_path == ""

    monkeypatch.setenv("LCM_PERIODIC_BACKUP_ENABLED", "true")
    monkeypatch.setenv("LCM_PERIODIC_BACKUP_INTERVAL_HOURS", "1.5")
    monkeypatch.setenv("LCM_PERIODIC_BACKUP_KEEP_LAST", "3")
    monkeypatch.setenv("LCM_PERIODIC_BACKUP_PATH", "/tmp/synthetic-periodic")
    configured = LCMConfig.from_env()
    assert configured.periodic_backup_enabled is True
    assert configured.periodic_backup_interval_hours == 1.5
    assert configured.periodic_backup_keep_last == 3
    assert configured.periodic_backup_path == "/tmp/synthetic-periodic"
    assert {
        "periodic_backup_enabled": "env:LCM_PERIODIC_BACKUP_ENABLED",
        "periodic_backup_interval_hours": "env:LCM_PERIODIC_BACKUP_INTERVAL_HOURS",
        "periodic_backup_keep_last": "env:LCM_PERIODIC_BACKUP_KEEP_LAST",
        "periodic_backup_path": "env:LCM_PERIODIC_BACKUP_PATH",
    }.items() <= configured.config_sources.items()

    for key in (
        "LCM_PERIODIC_BACKUP_ENABLED",
        "LCM_PERIODIC_BACKUP_INTERVAL_HOURS",
        "LCM_PERIODIC_BACKUP_KEEP_LAST",
        "LCM_PERIODIC_BACKUP_PATH",
    ):
        monkeypatch.delenv(key)
    hermes_home = tmp_path / "hermes-home"
    hermes_home.mkdir()
    (hermes_home / "config.yaml").write_text(
        "lcm:\n"
        "  periodic_backup_enabled: true\n"
        "  periodic_backup_interval_hours: 2.5\n"
        "  periodic_backup_keep_last: 4\n"
        "  periodic_backup_path: /tmp/yaml-periodic\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_home))
    yaml_configured = LCMConfig.from_env()
    assert yaml_configured.periodic_backup_enabled is True
    assert yaml_configured.periodic_backup_interval_hours == 2.5
    assert yaml_configured.periodic_backup_keep_last == 4
    assert yaml_configured.periodic_backup_path == "/tmp/yaml-periodic"
    assert yaml_configured.ignored_config_yaml_lcm_keys == []
    for field in (
        "periodic_backup_enabled",
        "periodic_backup_interval_hours",
        "periodic_backup_keep_last",
        "periodic_backup_path",
    ):
        assert yaml_configured.config_sources[field] == f"config_yaml:lcm.{field}"

    invalid = [
        ("LCM_PERIODIC_BACKUP_ENABLED", "maybe"),
        ("LCM_PERIODIC_BACKUP_INTERVAL_HOURS", "nan"),
        ("LCM_PERIODIC_BACKUP_INTERVAL_HOURS", "0"),
        ("LCM_PERIODIC_BACKUP_INTERVAL_HOURS", "inf"),
        ("LCM_PERIODIC_BACKUP_INTERVAL_HOURS", "1e308"),
        ("LCM_PERIODIC_BACKUP_KEEP_LAST", "0"),
        ("LCM_PERIODIC_BACKUP_KEEP_LAST", "1.5"),
    ]
    for key, value in invalid:
        monkeypatch.setenv("LCM_PERIODIC_BACKUP_ENABLED", "false")
        monkeypatch.setenv("LCM_PERIODIC_BACKUP_INTERVAL_HOURS", "6")
        monkeypatch.setenv("LCM_PERIODIC_BACKUP_KEEP_LAST", "10")
        monkeypatch.setenv(key, value)
        with pytest.raises(ValueError):
            LCMConfig.from_env()

    with pytest.raises(ValueError):
        LCMConfig(periodic_backup_enabled=1)
    with pytest.raises(ValueError):
        LCMConfig(periodic_backup_interval_hours=float("nan"))
    with pytest.raises(ValueError):
        LCMConfig(periodic_backup_interval_hours=1e308)
    with pytest.raises(ValueError):
        LCMConfig(
            periodic_backup_interval_hours=(threading.TIMEOUT_MAX + 1.0) / 3600.0
        )
    with pytest.raises(ValueError):
        LCMConfig(periodic_backup_keep_last=True)

    engine = _engine(tmp_path / "mutated-config")
    try:
        engine._config.periodic_backup_interval_hours = 1e308
        with pytest.raises(periodic.PeriodicBackupError, match="scheduler timeout"):
            periodic.build_periodic_backup_spec(engine)
    finally:
        engine.shutdown()


def test_disabled_is_filesystem_noop_and_idle_scheduler_owns_clones(tmp_path):
    disabled = _engine(tmp_path / "disabled")
    try:
        assert disabled._periodic_backup_registration.active is False
        assert not (tmp_path / "disabled" / "periodic").exists()
    finally:
        disabled.shutdown()
    assert periodic.active_periodic_backup_scheduler_count() == 0

    enabled = _engine(tmp_path / "enabled", enabled=True, interval_hours=0.0001)
    clone = enabled.clone_for_agent()
    try:
        assert enabled._periodic_backup_registration.active is True
        assert clone._periodic_backup_registration.active is True
        assert periodic.active_periodic_backup_scheduler_count() == 1
        spec = periodic.build_periodic_backup_spec(enabled)
        _wait_for(lambda: (spec.namespace / "latest-good.json").exists())
        first_count = len(_generation_dirs(spec))
        _wait_for(lambda: len(_generation_dirs(spec)) > first_count)
        clone.shutdown()
        assert periodic.active_periodic_backup_scheduler_count() == 1
    finally:
        enabled.shutdown()
    assert periodic.active_periodic_backup_scheduler_count() == 0
    assert not any(thread.name.startswith("lcm-periodic-backup-") for thread in threading.enumerate())


def test_conflicting_same_db_registration_fails_closed(tmp_path):
    shared_db_root = tmp_path / "shared"
    (tmp_path / "payload-a").mkdir()
    (tmp_path / "payload-b").mkdir()
    (tmp_path / "payload-a").chmod(0o700)
    (tmp_path / "payload-b").chmod(0o700)
    first = _engine(
        shared_db_root,
        enabled=True,
        destination=tmp_path / "destination",
        payload_root=tmp_path / "payload-a",
    )
    second = _engine(
        shared_db_root,
        enabled=True,
        destination=tmp_path / "destination",
        payload_root=tmp_path / "payload-b",
    )
    try:
        assert first._periodic_backup_registration.active is False
        assert first._periodic_backup_registration.state == "suspended"
        assert second._periodic_backup_registration.active is False
        assert second._periodic_backup_registration.state == "suspended"
        assert second._periodic_backup_registration.reason == "payload_root_ambiguous"
        status = periodic.periodic_backup_source_status(
            second._periodic_backup_registration.source_key
        )
        assert status is not None and status["state"] == "SUSPENDED"
        assert status["active_leases"] == 0
        _wait_for(lambda: periodic.active_periodic_backup_scheduler_count() == 0)
    finally:
        second.shutdown()
        first.shutdown()


def test_bundle_roundtrip_uses_exact_refs_and_existing_loader(tmp_path):
    payload_root = tmp_path / "payloads"
    _payload(payload_root / "content.json", "content payload")
    _payload(
        payload_root / "ingest.json",
        "ingest payload",
        kind="ingest_payload",
        role="user",
        field_path="content",
    )
    _payload(payload_root / "tool-call.json", "nested tool-call payload")
    engine = _engine(tmp_path, payload_root=payload_root)
    try:
        _append(engine, content=_placeholder("content.json"))
        _append(
            engine,
            role="assistant",
            content='quoted example: "' + _placeholder("fake-quoted.json") + '"',
            tool_calls=[
                {
                    "id": "call-2",
                    "function": {
                        "arguments": json.dumps({"recovery": _placeholder("tool-call.json")})
                    },
                }
            ],
        )
        _append(
            engine,
            role="user",
            content=(
                "[Externalized LCM ingest payload: kind=ingest_payload; field=content; "
                "chars=14; bytes=14; ref=ingest.json]"
            ),
        )
        _append(engine, role="user", content="template: {{ " + _placeholder("fake-template.json") + " }}")
        spec = periodic.build_periodic_backup_spec(engine)
        source_before = hashlib.sha256(spec.source_db.read_bytes()).hexdigest()
        result = periodic.run_periodic_backup(spec, due_only=False)
        assert result["status"] == "ok"
        assert hashlib.sha256(spec.source_db.read_bytes()).hexdigest() == source_before

        generation = Path(result["generation"])
        assert {child.name for child in generation.iterdir()} == {
            "lcm.sqlite3",
            "manifest.json",
            "payloads",
        }
        manifest = json.loads((generation / "manifest.json").read_text(encoding="utf-8"))
        assert manifest["schema"] == periodic.BUNDLE_SCHEMA
        assert manifest["source_identity"]["sha256"] == spec.source_identity
        assert [item["basename"] for item in manifest["payloads"]] == [
            "content.json",
            "ingest.json",
            "tool-call.json",
        ]

        restore = tmp_path / "disposable-restore"
        shutil.copytree(generation, restore)
        with sqlite3.connect(restore / "lcm.sqlite3") as conn:
            assert conn.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
            stored = conn.execute("SELECT content FROM messages ORDER BY store_id LIMIT 1").fetchone()[0]
        ref = extract_all_externalized_payload_refs(stored)[0]
        loaded = load_externalized_payload(
            ref,
            config=SimpleNamespace(
                large_output_externalization_path=str(restore / "payloads")
            ),
        )
        assert loaded is not None
        assert loaded["content"] == "content payload"
    finally:
        engine.shutdown()


def test_production_inline_ingest_ref_survives_disposable_bundle_recovery(tmp_path):
    engine = _engine(tmp_path)
    try:
        original = "before data:image/png;base64," + "AbCdEfGh01234567" * 32 + " after"
        protected = protect_messages_for_ingest(
            [{"role": "user", "content": original}],
            config=engine._config,
            hermes_home=engine._hermes_home,
            session_id="session",
        )[0]["content"]
        refs = extract_ingest_externalized_refs(protected)
        assert len(refs) == 1
        assert restore_ingest_payload_placeholders(
            protected,
            config=engine._config,
            hermes_home=engine._hermes_home,
            session_id="session",
        ) == original
        _append(engine, role="user", content=protected)

        result = periodic.run_periodic_backup(
            periodic.build_periodic_backup_spec(engine), due_only=False
        )
        assert result["status"] == "ok"
        assert result["payload_count"] == 1
        restored = tmp_path / "disposable-restore"
        shutil.copytree(Path(result["generation"]), restored)
        restored_config = SimpleNamespace(
            large_output_externalization_path=str(restored / "payloads")
        )
        assert restore_ingest_payload_placeholders(
            protected,
            config=restored_config,
            session_id="session",
        ) == original
    finally:
        engine.shutdown()


def test_production_nested_tool_call_ref_survives_disposable_recovery(tmp_path):
    engine = _engine(tmp_path)
    try:
        original = "data:image/png;base64," + "QrStUvWx01234567" * 32
        protected = protect_messages_for_ingest(
            [
                {
                    "role": "assistant",
                    "content": "",
                    "tool_calls": [
                        {
                            "id": "call-image",
                            "type": "function",
                            "function": {
                                "name": "inspect",
                                "arguments": json.dumps(
                                    {"payload": f"before {original} after"}
                                ),
                            },
                        }
                    ],
                }
            ],
            config=engine._config,
            hermes_home=engine._hermes_home,
            session_id="session",
        )[0]
        serialized = json.dumps(protected["tool_calls"])
        refs = extract_ingest_externalized_refs(serialized)
        assert len(refs) == 1
        _append(
            engine,
            role="assistant",
            content="",
            tool_calls=protected["tool_calls"],
        )

        result = periodic.run_periodic_backup(
            periodic.build_periodic_backup_spec(engine), due_only=False
        )
        assert result["status"] == "ok", result
        assert result["payload_count"] == 1
        restored = tmp_path / "disposable-tool-call-restore"
        shutil.copytree(Path(result["generation"]), restored)
        restored_config = SimpleNamespace(
            large_output_externalization_path=str(restored / "payloads")
        )
        marker_match = periodic._INGEST_MARKER_RE.search(serialized)
        assert marker_match is not None
        restored_marker = restore_ingest_payload_placeholders(
            marker_match.group(0),
            config=restored_config,
            session_id="session",
        )
        assert restored_marker == original
    finally:
        engine.shutdown()


def test_invalid_genuine_ref_is_not_silently_omitted(tmp_path):
    engine = _engine(tmp_path)
    try:
        marker = (
            "[Externalized LCM ingest payload: kind=ingest_payload; field=content; "
            "chars=4; bytes=4; ref=../outside.json]"
        )
        assert is_externalized_ingest_placeholder(marker)
        _append(engine, role="user", content=marker)
        result = periodic.run_periodic_backup(
            periodic.build_periodic_backup_spec(engine), due_only=False
        )
        assert result["status"] == "failed"
        assert "invalid externalized payload reference" in result["error"]
    finally:
        engine.shutdown()


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ({"session_id": "wrong-session"}, "session identity"),
        ({"kind": "wrong-kind"}, "kind"),
        ({"field_path": "tool_calls[0]"}, "field"),
        ({"content": {"not": "text"}}, "content"),
    ],
)
def test_ingest_payload_schema_and_context_mismatch_is_rejected(
    tmp_path, mutation, expected_error
):
    engine = _engine(tmp_path)
    try:
        created = externalize_ingest_payload(
            "recover this",
            role="user",
            session_id="session",
            field_path="content",
            config=engine._config,
            hermes_home=engine._hermes_home,
        )
        assert created is not None
        _append(engine, role="user", content=created["placeholder"])
        payload = json.loads(created["path"].read_text(encoding="utf-8"))
        payload.update(mutation)
        created["path"].write_text(json.dumps(payload), encoding="utf-8")

        result = periodic.run_periodic_backup(
            periodic.build_periodic_backup_spec(engine), due_only=False
        )
        assert result["status"] == "failed"
        assert expected_error in result["error"]
    finally:
        engine.shutdown()


def test_reverification_checks_db_reference_completeness(tmp_path):
    engine = _engine(tmp_path)
    try:
        created = externalize_ingest_payload(
            "recover this",
            role="user",
            session_id="session",
            field_path="content",
            config=engine._config,
            hermes_home=engine._hermes_home,
        )
        assert created is not None
        _append(engine, role="user", content=created["placeholder"])
        spec = periodic.build_periodic_backup_spec(engine)
        result = periodic.run_periodic_backup(spec, due_only=False)
        assert result["status"] == "ok"
        generation = Path(result["generation"])
        manifest = json.loads((generation / "manifest.json").read_text(encoding="utf-8"))
        assert len(manifest["payloads"]) == 1
        (generation / "payloads" / manifest["payloads"][0]["basename"]).unlink()
        manifest["payloads"] = []
        (generation / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")

        with pytest.raises(periodic.PeriodicBackupError):
            periodic._read_verified_pointer(spec)
    finally:
        engine.shutdown()


@pytest.mark.parametrize("mode", ["missing", "corrupt", "symlink", "hardlink"])
def test_missing_corrupt_and_symlink_payloads_reject_generation(tmp_path, mode):
    payload_root = tmp_path / "payloads"
    payload_root.mkdir()
    payload_root.chmod(0o700)
    ref = "bad.json"
    if mode == "corrupt":
        (payload_root / ref).write_text("not-json", encoding="utf-8")
    elif mode == "symlink":
        target = tmp_path / "outside.json"
        _payload(target, "outside")
        (payload_root / ref).symlink_to(target)
    elif mode == "hardlink":
        target = tmp_path / "outside.json"
        _payload(target, "outside")
        os.link(target, payload_root / ref)
    engine = _engine(tmp_path, payload_root=payload_root)
    try:
        _append(engine, content=_placeholder(ref))
        spec = periodic.build_periodic_backup_spec(engine)
        result = periodic.run_periodic_backup(spec, due_only=False)
        assert result["status"] == "failed"
        assert not (spec.namespace / "latest-good.json").exists()
        assert _generation_dirs(spec) == []
    finally:
        engine.shutdown()


def test_payload_replaced_during_copy_is_rejected(tmp_path, monkeypatch):
    payload_root = tmp_path / "payloads"
    ref = "changing.json"
    _payload(payload_root / ref, "x" * (2 * 1024 * 1024))
    engine = _engine(tmp_path, payload_root=payload_root)
    try:
        _append(engine, content=_placeholder(ref))
        spec = periodic.build_periodic_backup_spec(engine)
        real_read = periodic.os.read
        replaced = False

        def replacing_read(fd, count):
            nonlocal replaced
            value = real_read(fd, count)
            if value and not replaced:
                replaced = True
                replacement = payload_root / "replacement.json"
                _payload(replacement, "replacement")
                os.replace(replacement, payload_root / ref)
            return value

        monkeypatch.setattr(periodic.os, "read", replacing_read)
        result = periodic.run_periodic_backup(spec, due_only=False)
        assert result["status"] == "failed"
        assert "changed during copy" in result["error"]
        assert not (spec.namespace / "latest-good.json").exists()
    finally:
        engine.shutdown()


def test_new_destination_and_namespace_entries_are_fsynced(monkeypatch, tmp_path):
    engine = _engine(tmp_path)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        fsynced: list[Path] = []
        real_fsync_directory = periodic._fsync_directory

        def recording_fsync(path):
            fsynced.append(Path(path))
            real_fsync_directory(path)

        monkeypatch.setattr(periodic, "_fsync_directory", recording_fsync)
        assert periodic.run_periodic_backup(spec, due_only=False)["status"] == "ok"
        assert spec.destination_root.parent in fsynced
        assert spec.destination_root in fsynced
        assert spec.namespace in fsynced
    finally:
        engine.shutdown()


def test_payload_copy_cancels_before_publication(monkeypatch, tmp_path):
    payload_root = tmp_path / "payloads"
    _payload(payload_root / "large.json", "x" * (2 * 1024 * 1024))
    engine = _engine(tmp_path, payload_root=payload_root)
    try:
        _append(engine, content=_placeholder("large.json"))
        spec = periodic.build_periodic_backup_spec(engine)
        cancel = threading.Event()
        entered = threading.Event()
        release = threading.Event()
        real_read = periodic.os.read
        blocked = False

        def blocking_read(fd, count):
            nonlocal blocked
            if count == 1024 * 1024 and not blocked:
                blocked = True
                entered.set()
                assert release.wait(5)
            return real_read(fd, count)

        monkeypatch.setattr(periodic.os, "read", blocking_read)
        results: list[dict] = []
        worker = threading.Thread(
            target=lambda: results.append(
                periodic.run_periodic_backup(spec, due_only=False, cancel=cancel)
            )
        )
        worker.start()
        assert entered.wait(5)
        cancel.set()
        release.set()
        worker.join(5)
        assert not worker.is_alive()
        assert results[0]["status"] == "cancelled"
        assert _generation_dirs(spec) == []
        assert not (spec.namespace / "latest-good.json").exists()
    finally:
        engine.shutdown()


def test_scheduler_registry_does_not_overlap_during_last_owner_shutdown(
    monkeypatch,
    tmp_path,
):
    first = _engine(tmp_path, enabled=True)
    second = _engine(tmp_path, enabled=False)
    entered = threading.Event()
    release = threading.Event()
    real_stop = periodic._Scheduler.stop

    def delayed_stop(scheduler):
        entered.set()
        assert release.wait(5)
        return real_stop(scheduler)

    monkeypatch.setattr(periodic._Scheduler, "stop", delayed_stop)
    unregister_results: list[bool] = []
    register_results = []
    unregister_thread = threading.Thread(
        target=lambda: unregister_results.append(
            periodic.unregister_periodic_backup(first._periodic_backup_registration)
        )
    )
    try:
        unregister_thread.start()
        assert entered.wait(5)
        second._config.periodic_backup_enabled = True
        register_thread = threading.Thread(
            target=lambda: register_results.append(
                periodic.register_periodic_backup(second)
            )
        )
        register_thread.start()
        time.sleep(0.05)
        assert register_results == []
        release.set()
        unregister_thread.join(15)
        register_thread.join(15)
        assert not unregister_thread.is_alive()
        assert not register_thread.is_alive()
        assert unregister_results in ([True], [False])
        assert register_results[0].state in {"active", "pending"}
        second._periodic_backup_registration = register_results[0]
        assert periodic.active_periodic_backup_scheduler_count() == 1
    finally:
        release.set()
        unregister_thread.join(5)
        second.shutdown()
        first.shutdown()


def test_two_process_lock_collision_and_release_on_exit(tmp_path):
    engine = _engine(tmp_path)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        context = multiprocessing.get_context("fork")
        acquired = context.Event()
        release = context.Event()
        queue = context.Queue()
        process = context.Process(
            target=_run_holding_backup,
            args=(spec, acquired, release, queue),
        )
        process.start()
        assert acquired.wait(10)
        contender = periodic.run_periodic_backup(spec, due_only=False)
        assert contender["status"] == "deferred_busy"
        release.set()
        process.join(15)
        assert process.exitcode == 0
        assert queue.get(timeout=2)["status"] == "ok"
        after_exit = periodic.run_periodic_backup(spec, due_only=False)
        assert after_exit["status"] == "ok"
        lock_path = spec.namespace / ".periodic-backup.lock"
        assert lock_path.exists()
    finally:
        engine.shutdown()


def test_same_basename_sources_share_root_without_state_collision(tmp_path):
    destination = tmp_path / "shared-destination"
    first = _engine(tmp_path / "one", destination=destination)
    second = _engine(tmp_path / "two", destination=destination)
    try:
        _append(first, content="first", role="user")
        _append(second, content="second", role="user")
        first_spec = periodic.build_periodic_backup_spec(first)
        second_spec = periodic.build_periodic_backup_spec(second)
        assert first_spec.source_db.name == second_spec.source_db.name == "lcm.db"
        assert first_spec.namespace != second_spec.namespace
        assert periodic.run_periodic_backup(first_spec, due_only=False)["status"] == "ok"
        assert periodic.run_periodic_backup(second_spec, due_only=False)["status"] == "ok"
        assert (first_spec.namespace / "latest-good.json").exists()
        assert (second_spec.namespace / "latest-good.json").exists()
        assert len(_generation_dirs(first_spec)) == 1
        assert len(_generation_dirs(second_spec)) == 1
    finally:
        second.shutdown()
        first.shutdown()


def test_due_restart_and_wall_clock_jumps(monkeypatch, tmp_path):
    engine = _engine(tmp_path, interval_hours=6.0)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        start = datetime(2030, 1, 2, 3, 4, 5, tzinfo=UTC)
        monkeypatch.setattr(periodic, "_utc_now", lambda: start)
        assert periodic.run_periodic_backup(spec, due_only=True, now=start)["status"] == "ok"
        assert periodic._seconds_until_due(spec, now=start + timedelta(hours=3)) == pytest.approx(3 * 3600)
        assert periodic._seconds_until_due(spec, now=start - timedelta(days=2)) == pytest.approx(6 * 3600)
        assert periodic.run_periodic_backup(
            spec,
            due_only=True,
            now=start + timedelta(hours=3),
        )["status"] == "noop_not_due"
        monkeypatch.setattr(periodic, "_utc_now", lambda: start + timedelta(hours=7))
        assert periodic.run_periodic_backup(
            spec,
            due_only=True,
            now=start + timedelta(hours=7),
        )["status"] == "ok"
        assert len(_generation_dirs(spec)) == 2
    finally:
        engine.shutdown()


@pytest.mark.parametrize(
    "wall_delta",
    [timedelta(days=-1), timedelta(days=1)],
    ids=["backward", "forward"],
)
def test_wall_clock_jump_during_worker_keeps_monotonic_interval(
    tmp_path, monkeypatch, wall_delta
):
    engine = _engine(tmp_path, interval_hours=0.00005)
    real_run = periodic.run_periodic_backup
    wall = [datetime.now(UTC)]
    statuses: list[str] = []
    first = threading.Event()

    def observe(*args, **kwargs):
        result = real_run(*args, **kwargs)
        statuses.append(result["status"])
        if result["status"] == "ok" and not first.is_set():
            wall[0] += wall_delta
            first.set()
        return result

    monkeypatch.setattr(periodic, "_utc_now", lambda: wall[0])
    monkeypatch.setattr(periodic, "run_periodic_backup", observe)
    scheduler = periodic._Scheduler(periodic.build_periodic_backup_spec(engine))
    try:
        assert first.wait(3)
        _wait_for(lambda: statuses.count("ok") >= 2, timeout=3)
    finally:
        assert scheduler.stop()
        engine.shutdown()


def test_scheduler_rechecks_due_after_other_process_publishes(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    spec = periodic.build_periodic_backup_spec(engine)
    context = multiprocessing.get_context("fork")
    acquired = context.Event()
    release = context.Event()
    queue = context.Queue()
    deferred = threading.Event()
    second_done = threading.Event()
    child = context.Process(
        target=_run_holding_backup,
        args=(spec, acquired, release, queue),
    )
    child.start()
    assert acquired.wait(5)
    statuses: list[str] = []
    due_flags: list[bool] = []
    real_run = periodic.run_periodic_backup

    def observe(*args, **kwargs):
        result = real_run(*args, **kwargs)
        statuses.append(result["status"])
        due_flags.append(kwargs.get("due_only", True))
        if result["status"] == "deferred_busy":
            deferred.set()
        elif deferred.is_set():
            second_done.set()
        return result

    monkeypatch.setattr(periodic, "run_periodic_backup", observe)
    monkeypatch.setattr(periodic, "_MAX_FAILURE_BACKOFF_SECONDS", 0.05)
    scheduler = periodic._Scheduler(spec)
    try:
        assert deferred.wait(5)
        release.set()
        child.join(5)
        assert child.exitcode == 0
        assert queue.get(timeout=2)["status"] == "ok"
        assert second_done.wait(5)
    finally:
        release.set()
        assert scheduler.stop()
        child.join(5)
        engine.shutdown()
    assert len(_generation_dirs(spec)) == 1
    assert due_flags[:2] == [True, True]


def test_scheduler_retries_its_own_uncertain_generation(monkeypatch, tmp_path):
    engine = _engine(tmp_path, interval_hours=1.0)
    spec = periodic.build_periodic_backup_spec(engine)
    real_run = periodic.run_periodic_backup
    completed = threading.Event()
    results: list[dict] = []

    def fail_pointer_fsync(stage: str) -> None:
        if stage == "pointer_fsync":
            raise OSError("synthetic uncertainty after pointer rename")

    def observe(*args, **kwargs):
        result = (
            real_run(*args, **kwargs, _fault=fail_pointer_fsync)
            if not results
            else real_run(*args, **kwargs)
        )
        results.append(result)
        if len(results) >= 2:
            completed.set()
        return result

    monkeypatch.setattr(periodic, "run_periodic_backup", observe)
    monkeypatch.setattr(periodic, "_MAX_FAILURE_BACKOFF_SECONDS", 0.05)
    scheduler = periodic._Scheduler(spec)
    try:
        assert completed.wait(5)
    finally:
        assert scheduler.stop() is True
        engine.shutdown()

    assert [result["status"] for result in results[:2]] == [
        "published_pointer_failed",
        "ok",
    ]
    assert len(_generation_dirs(spec)) == 2


def test_uncertain_retry_is_suppressed_by_other_process_success(monkeypatch, tmp_path):
    engine = _engine(tmp_path, interval_hours=1.0)
    spec = periodic.build_periodic_backup_spec(engine)
    context = multiprocessing.get_context("fork")
    queue = context.Queue()
    real_run = periodic.run_periodic_backup
    retry_ready = threading.Event()
    resume_retry = threading.Event()
    retry_done = threading.Event()
    results: list[dict] = []

    def fail_pointer_fsync(stage: str) -> None:
        if stage == "pointer_fsync":
            raise OSError("synthetic uncertainty after pointer rename")

    def observe(*args, **kwargs):
        if not results:
            result = real_run(*args, **kwargs, _fault=fail_pointer_fsync)
        else:
            retry_ready.set()
            assert resume_retry.wait(5)
            result = real_run(*args, **kwargs)
        results.append(result)
        if len(results) >= 2:
            retry_done.set()
        return result

    def publish_from_other_process() -> None:
        periodic.run_periodic_backup = real_run
        queue.put(periodic.run_periodic_backup(spec, due_only=False))

    monkeypatch.setattr(periodic, "run_periodic_backup", observe)
    monkeypatch.setattr(periodic, "_MAX_FAILURE_BACKOFF_SECONDS", 0.05)
    scheduler = periodic._Scheduler(spec)
    child = None
    try:
        assert retry_ready.wait(5)
        assert results[0]["status"] == "published_pointer_failed"
        assert results[0]["pointer_renamed"] is True

        child = context.Process(target=publish_from_other_process)
        child.start()
        child.join(5)
        assert child.exitcode == 0
        assert queue.get(timeout=2)["status"] == "ok"
        assert real_run(spec, due_only=True)["status"] == "noop_not_due"

        resume_retry.set()
        assert retry_done.wait(5)
    finally:
        resume_retry.set()
        assert scheduler.stop() is True
        if child is not None:
            child.join(5)
        engine.shutdown()

    assert [result["status"] for result in results[:2]] == [
        "published_pointer_failed",
        "noop_not_due",
    ]
    assert len(_generation_dirs(spec)) == 2


def test_concurrent_sqlite_writer_yields_consistent_committed_snapshot(tmp_path):
    engine = _engine(tmp_path)
    try:
        source = Path(engine._store.db_path)
        engine._store.connection.execute(
            "CREATE TABLE writer_probe (sequence INTEGER PRIMARY KEY, batch INTEGER NOT NULL)"
        )
        engine._store.connection.commit()
        stop = threading.Event()
        commits: list[int] = []

        def writer() -> None:
            conn = sqlite3.connect(source, timeout=5)
            try:
                for batch in range(50):
                    if stop.is_set():
                        return
                    conn.execute("BEGIN")
                    base = batch * 10
                    conn.executemany(
                        "INSERT INTO writer_probe(sequence, batch) VALUES (?, ?)",
                        [(base + offset, batch) for offset in range(10)],
                    )
                    conn.commit()
                    commits.append(batch)
                    time.sleep(0.002)
            finally:
                conn.close()

        thread = threading.Thread(target=writer)
        thread.start()
        _wait_for(lambda: bool(commits))
        spec = periodic.build_periodic_backup_spec(engine)
        result = periodic.run_periodic_backup(spec, due_only=False)
        stop.set()
        thread.join(5)
        assert result["status"] == "ok"
        with sqlite3.connect(Path(result["generation"]) / "lcm.sqlite3") as restored:
            assert restored.execute("PRAGMA integrity_check").fetchall() == [("ok",)]
            rows = restored.execute(
                "SELECT sequence, batch FROM writer_probe ORDER BY sequence"
            ).fetchall()
        assert rows
        assert len(rows) % 10 == 0
        assert [sequence for sequence, _batch in rows] == list(range(len(rows)))
        assert all(batch == sequence // 10 for sequence, batch in rows)
    finally:
        engine.shutdown()


def test_corrupted_staged_snapshot_is_rejected_before_publication(monkeypatch, tmp_path):
    engine = _engine(tmp_path)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        good = periodic.run_periodic_backup(spec, due_only=False)
        assert good["status"] == "ok"
        good_generation = Path(good["generation"])
        old_pointer = (spec.namespace / "latest-good.json").read_bytes()
        real_snapshot = periodic._snapshot_database

        def corrupt_snapshot(snapshot_spec, destination, *, cancel):
            real_snapshot(snapshot_spec, destination, cancel=cancel)
            with destination.open("r+b") as handle:
                handle.seek(0)
                handle.write(b"not sqlite")
                handle.flush()
                os.fsync(handle.fileno())

        monkeypatch.setattr(periodic, "_snapshot_database", corrupt_snapshot)
        rejected = periodic.run_periodic_backup(spec, due_only=False)
        assert rejected["status"] == "failed"
        assert good_generation.exists()
        assert (spec.namespace / "latest-good.json").read_bytes() == old_pointer
        assert len(_generation_dirs(spec)) == 1
    finally:
        engine.shutdown()


@pytest.mark.parametrize(
    "stage",
    [
        "snapshot",
        "integrity",
        "manifest",
        "stage_fsync",
        "final_rename",
        "final_fsync",
        "pointer_write",
        "pointer_rename",
        "pointer_fsync",
    ],
)
def test_faults_never_prune_previous_good(stage, tmp_path):
    engine = _engine(tmp_path, keep_last=1)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        first = periodic.run_periodic_backup(spec, due_only=False)
        assert first["status"] == "ok"
        first_generation = Path(first["generation"])
        old_pointer = (spec.namespace / "latest-good.json").read_bytes()
        retention_called = False

        def fault(current: str) -> None:
            nonlocal retention_called
            if current == "retention":
                retention_called = True
            if current == stage:
                raise OSError(f"synthetic {stage} failure")

        failed = periodic.run_periodic_backup(spec, due_only=False, _fault=fault)
        assert failed["status"] in {"failed", "published_pointer_failed"}
        assert retention_called is False
        assert first_generation.exists()
        if stage != "pointer_fsync":
            assert (spec.namespace / "latest-good.json").read_bytes() == old_pointer
        else:
            assert failed["pointer_renamed"] is True
            assert failed["pointer_durability"] == "uncertain"
    finally:
        engine.shutdown()


@pytest.mark.parametrize("fail_at", [1, 2, 3])
def test_payload_fault_and_retention_delete_failure_stop_without_losing_latest(tmp_path, fail_at):
    payload_root = tmp_path / "payloads"
    _payload(payload_root / "payload.json", "payload")
    engine = _engine(tmp_path, payload_root=payload_root, keep_last=4)
    try:
        _append(engine, content=_placeholder("payload.json"))
        wide = periodic.build_periodic_backup_spec(engine)
        for _ in range(3):
            assert periodic.run_periodic_backup(wide, due_only=False)["status"] == "ok"
        prior = _generation_dirs(wide)

        def payload_fault(stage: str) -> None:
            if stage == "payload:payload.json":
                raise OSError("synthetic payload failure")

        failed_payload = periodic.run_periodic_backup(wide, due_only=False, _fault=payload_fault)
        assert failed_payload["status"] == "failed"
        assert _generation_dirs(wide) == prior

        narrow = replace(wide, keep_last=1)
        deletion_attempts = 0

        def retention_fault(stage: str) -> None:
            nonlocal deletion_attempts
            if stage.startswith("retention_delete:"):
                deletion_attempts += 1
                if deletion_attempts == fail_at:
                    raise OSError("synthetic retention deletion failure")

        result = periodic.run_periodic_backup(narrow, due_only=False, _fault=retention_fault)
        assert result["status"] == "ok_retention_failed"
        assert deletion_attempts == fail_at
        pointer = periodic._read_verified_pointer(narrow)
        assert pointer is not None
        assert pointer[0] == Path(result["generation"])
        assert len(_generation_dirs(narrow)) == 5 - fail_at
    finally:
        engine.shutdown()


def test_canonical_aliases_share_identity_and_symlink_namespace_is_rejected(tmp_path):
    engine = _engine(tmp_path / "source")
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        db_alias = tmp_path / "db-alias"
        db_alias.symlink_to(spec.source_db)
        destination = tmp_path / "destination"
        destination.mkdir()
        (tmp_path / "payloads").mkdir()
        (tmp_path / "payloads").chmod(0o700)
        destination_alias = tmp_path / "destination-alias"
        destination_alias.symlink_to(destination, target_is_directory=True)
        alias_engine = SimpleNamespace(
            _store=SimpleNamespace(db_path=db_alias),
            _config=LCMConfig(
                periodic_backup_path=str(destination_alias),
                large_output_externalization_path=str(tmp_path / "payloads"),
            ),
            _hermes_home="",
            backup_dir=lambda: tmp_path / "unused",
        )
        alias_spec = periodic.build_periodic_backup_spec(alias_engine)
        assert alias_spec.source_db == spec.source_db
        assert alias_spec.source_identity == spec.source_identity
        assert alias_spec.destination_root == destination.resolve()

        outside = tmp_path / "outside"
        outside.mkdir()
        alias_spec.namespace.symlink_to(outside, target_is_directory=True)
        result = periodic.run_periodic_backup(alias_spec, due_only=False)
        assert result["status"] == "failed"
        assert list(outside.iterdir()) == []
    finally:
        engine.shutdown()


def test_same_second_ids_identity_mismatch_and_foreign_entries(tmp_path):
    engine = _engine(tmp_path)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        fixed = datetime(2035, 6, 7, 8, 9, 10, tzinfo=UTC)
        first = periodic.run_periodic_backup(spec, due_only=False, now=fixed)
        second = periodic.run_periodic_backup(spec, due_only=False, now=fixed)
        assert first["status"] == second["status"] == "ok"
        assert Path(first["generation"]).name != Path(second["generation"]).name

        foreign = spec.namespace / "manual-do-not-touch"
        foreign.mkdir()
        (foreign / "sentinel").write_text("keep", encoding="utf-8")
        partial = spec.namespace / "lcm-periodic-hostile.partial"
        partial.mkdir()
        assert periodic.run_periodic_backup(
            replace(spec, keep_last=1), due_only=False
        )["status"] == "ok"
        assert (foreign / "sentinel").read_text(encoding="utf-8") == "keep"
        assert partial.exists()

        pointer_path = spec.namespace / "latest-good.json"
        pointer = json.loads(pointer_path.read_text(encoding="utf-8"))
        pointer["source_identity"]["sha256"] = "0" * 64
        pointer_path.write_text(json.dumps(pointer), encoding="utf-8")
        before = set(spec.namespace.iterdir())
        assert periodic._seconds_until_due(spec) == 0.0
        failed = periodic.run_periodic_backup(spec, due_only=False)
        assert failed["status"] == "failed"
        assert "identity mismatch" in failed["error"]
        assert set(spec.namespace.iterdir()) == before
    finally:
        engine.shutdown()


def test_corrupt_latest_good_blocks_future_publication_and_pruning(tmp_path):
    engine = _engine(tmp_path, keep_last=2)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        first = periodic.run_periodic_backup(spec, due_only=False)
        second = periodic.run_periodic_backup(spec, due_only=False)
        assert first["status"] == second["status"] == "ok"
        latest = Path(second["generation"])
        with (latest / "lcm.sqlite3").open("r+b") as handle:
            handle.seek(0)
            handle.write(b"corrupt")
        before = set(spec.namespace.iterdir())
        result = periodic.run_periodic_backup(replace(spec, keep_last=1), due_only=False)
        assert result["status"] == "failed"
        assert set(spec.namespace.iterdir()) == before
        assert latest.exists()
        assert Path(first["generation"]).exists()
    finally:
        engine.shutdown()


def test_unsupported_locking_fails_closed_without_publication(monkeypatch, tmp_path):
    engine = _engine(tmp_path)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        monkeypatch.setattr(periodic, "_fcntl", None)
        result = periodic.run_periodic_backup(spec, due_only=False)
        assert result["status"] == "unsupported"
        assert _generation_dirs(spec) == []
        assert not (spec.namespace / "latest-good.json").exists()
    finally:
        engine.shutdown()


def test_production_quarantined_assistant_ref_survives_disposable_recovery(tmp_path):
    engine = _engine(tmp_path)
    try:
        original = ("broken repetitive assistant output " * 4096).strip()
        marker = _externalize_quarantined_assistant_output(
            original,
            role="assistant",
            session_id="session",
            config=engine._config,
            hermes_home=engine._hermes_home,
            reason="high_repetition",
        )
        assert marker is not None
        refs = extract_ingest_externalized_refs(marker)
        assert len(refs) == 1
        loaded = load_externalized_payload(
            refs[0], config=engine._config, hermes_home=engine._hermes_home
        )
        assert loaded is not None
        assert loaded["kind"] == "quarantined_assistant_output"
        assert loaded["role"] == "assistant"
        assert loaded["session_id"] == "session"
        assert loaded["field_path"] == "content"
        assert loaded["content"] == original
        _append(engine, role="assistant", content=marker)

        result = periodic.run_periodic_backup(
            periodic.build_periodic_backup_spec(engine), due_only=False
        )
        assert result["status"] == "ok", result
        restored = tmp_path / "disposable-quarantine-restore"
        shutil.copytree(Path(result["generation"]), restored)
        restored_payload = load_externalized_payload(
            refs[0],
            config=SimpleNamespace(
                large_output_externalization_path=str(restored / "payloads")
            ),
        )
        assert restored_payload is not None
        assert restored_payload["content"] == original
        assert restored_payload["kind"] == "quarantined_assistant_output"
    finally:
        engine.shutdown()


@pytest.mark.parametrize(
    ("session_id", "metadata_key"),
    [
        ("séance", "métadonnée"),
        ("会話", "追加情報"),
        ("thread-😀", "emoji-😀"),
    ],
)
@pytest.mark.parametrize("serialization", ["production", "raw-utf8", "escaped"])
def test_production_payload_unicode_metadata_survives_disposable_recovery(
    tmp_path, session_id, metadata_key, serialization
):
    engine = _engine(tmp_path)
    try:
        original = 'actual UTF-8 content café 😀 with "escapes"\n'
        created = externalize_ingest_payload(
            original,
            role="user",
            session_id=session_id,
            field_path="content",
            config=engine._config,
            hermes_home=engine._hermes_home,
        )
        assert created is not None
        if serialization != "production":
            payload = json.loads(created["path"].read_text(encoding="utf-8"))
            payload[metadata_key] = {"ignored": "unicode metadata value 🧪"}
            created["path"].write_text(
                json.dumps(payload, ensure_ascii=serialization == "escaped"),
                encoding="utf-8",
            )
        loaded = load_externalized_payload(
            created["path"].name,
            config=engine._config,
            hermes_home=engine._hermes_home,
        )
        assert loaded is not None
        assert loaded["session_id"] == session_id
        assert loaded["content"] == original
        assert (
            restore_ingest_payload_placeholders(
                created["placeholder"],
                config=engine._config,
                session_id=session_id,
            )
            == original
        )
        _append(
            engine,
            role="user",
            content=created["placeholder"],
            session_id=session_id,
        )

        result = periodic.run_periodic_backup(
            periodic.build_periodic_backup_spec(engine), due_only=False
        )
        assert result["status"] == "ok", result
        restored_config = SimpleNamespace(
            large_output_externalization_path=str(
                Path(result["generation"]) / "payloads"
            )
        )
        restored = load_externalized_payload(
            created["path"].name,
            config=restored_config,
        )
        assert restored is not None
        assert restored["session_id"] == session_id
        assert restored["content"] == original
        assert (
            restore_ingest_payload_placeholders(
                created["placeholder"],
                config=restored_config,
                session_id=session_id,
            )
            == original
        )
    finally:
        engine.shutdown()


@pytest.mark.parametrize(
    "replacement",
    [
        b'"session_id": "\xff"',
        b'"session_id": "\\u12xz"',
    ],
    ids=["invalid-utf8", "invalid-unicode-escape"],
)
def test_malformed_unicode_metadata_is_rejected_without_publication(
    tmp_path, replacement
):
    engine = _engine(tmp_path)
    try:
        created = externalize_ingest_payload(
            "recover this payload",
            role="user",
            session_id="session",
            field_path="content",
            config=engine._config,
            hermes_home=engine._hermes_home,
        )
        assert created is not None
        original = created["path"].read_bytes()
        mutated = original.replace(b'"session_id": "session"', replacement, 1)
        assert mutated != original
        created["path"].write_bytes(mutated)
        _append(engine, role="user", content=created["placeholder"])

        spec = periodic.build_periodic_backup_spec(engine)
        result = periodic.run_periodic_backup(spec, due_only=False)
        assert result["status"] == "failed"
        assert "valid JSON" in result["error"]
        assert not (spec.namespace / "latest-good.json").exists()
    finally:
        engine.shutdown()


@pytest.mark.parametrize(
    ("mutation", "expected_error"),
    [
        ({"session_id": "wrong-session"}, "session identity"),
        ({"session_id": ""}, "session identity"),
        ({"role": "user"}, "role mismatch"),
        ({"role": ""}, "role mismatch"),
        ({"kind": "ingest_payload"}, "kind mismatch"),
        ({"field_path": "tool_calls[0]"}, "field"),
        ({"field_path": ""}, "field"),
    ],
)
def test_quarantined_assistant_payload_identity_mismatch_is_rejected(
    tmp_path, mutation, expected_error
):
    engine = _engine(tmp_path)
    try:
        marker = _externalize_quarantined_assistant_output(
            "repetitive output " * 4096,
            role="assistant",
            session_id="session",
            config=engine._config,
            hermes_home=engine._hermes_home,
            reason="high_repetition",
        )
        assert marker is not None
        ref = extract_ingest_externalized_refs(marker)[0]
        path = Path(engine._config.large_output_externalization_path) / ref
        payload = json.loads(path.read_text(encoding="utf-8"))
        payload.update(mutation)
        path.write_text(json.dumps(payload), encoding="utf-8")
        _append(engine, role="assistant", content=marker)

        result = periodic.run_periodic_backup(
            periodic.build_periodic_backup_spec(engine), due_only=False
        )
        assert result["status"] == "failed"
        assert expected_error in result["error"]
    finally:
        engine.shutdown()


def test_production_payload_above_64_mib_survives_backup_boundary(monkeypatch, tmp_path):
    engine = _engine(tmp_path)
    try:
        original = "x" * (64 * 1024 * 1024 + 1)
        created = externalize_ingest_payload(
            original,
            role="user",
            session_id="session",
            field_path="content",
            config=engine._config,
            hermes_home=engine._hermes_home,
        )
        assert created is not None
        assert created["path"].stat().st_size > 64 * 1024 * 1024
        loaded = load_externalized_payload(
            created["path"].name,
            config=engine._config,
            hermes_home=engine._hermes_home,
        )
        assert loaded is not None and loaded["content"] == original
        _append(engine, role="user", content=created["placeholder"])

        real_json_loads = periodic.json.loads

        def bounded_json_loads(value, *args, **kwargs):
            if isinstance(value, (bytes, bytearray, str)):
                assert len(value) <= periodic._MAX_METADATA_BYTES
            return real_json_loads(value, *args, **kwargs)

        with monkeypatch.context() as isolated:
            isolated.setattr(periodic.json, "loads", bounded_json_loads)
            result = periodic.run_periodic_backup(
                periodic.build_periodic_backup_spec(engine), due_only=False
            )
        assert result["status"] == "ok", result
        copied = Path(result["generation"]) / "payloads" / created["path"].name
        assert copied.stat().st_size == created["path"].stat().st_size
        restored = load_externalized_payload(
            copied.name,
            config=SimpleNamespace(
                large_output_externalization_path=str(copied.parent)
            ),
        )
        assert restored is not None and restored["content"] == original
    finally:
        engine.shutdown()


@pytest.mark.parametrize("cut", [1, 17, 101])
def test_truncated_production_payload_is_rejected_without_publication(tmp_path, cut):
    engine = _engine(tmp_path)
    try:
        created = externalize_ingest_payload(
            "recover this payload",
            role="user",
            session_id="session",
            field_path="content",
            config=engine._config,
            hermes_home=engine._hermes_home,
        )
        assert created is not None
        raw = created["path"].read_bytes()
        created["path"].write_bytes(raw[:-cut])
        _append(engine, role="user", content=created["placeholder"])

        spec = periodic.build_periodic_backup_spec(engine)
        result = periodic.run_periodic_backup(spec, due_only=False)
        assert result["status"] == "failed"
        assert "valid JSON" in result["error"]
        assert not (spec.namespace / "latest-good.json").exists()
    finally:
        engine.shutdown()


def test_destination_root_permissions_are_preserved_and_new_namespace_is_private(
    tmp_path,
):
    existing_root = tmp_path / "operator-shared"
    existing_root.mkdir(mode=0o750)
    existing_root.chmod(0o750)
    engine = _engine(tmp_path / "existing", destination=existing_root)
    new_engine = _engine(tmp_path / "new", destination=tmp_path / "new-root")
    try:
        existing_spec = periodic.build_periodic_backup_spec(engine)
        assert periodic.run_periodic_backup(existing_spec, due_only=False)["status"] == "ok"
        assert stat.S_IMODE(os.lstat(existing_root).st_mode) == 0o750
        assert stat.S_IMODE(os.lstat(existing_spec.namespace).st_mode) == 0o700

        new_spec = periodic.build_periodic_backup_spec(new_engine)
        assert periodic.run_periodic_backup(new_spec, due_only=False)["status"] == "ok"
        assert stat.S_IMODE(os.lstat(new_spec.destination_root).st_mode) == 0o700
        assert stat.S_IMODE(os.lstat(new_spec.namespace).st_mode) == 0o700
    finally:
        new_engine.shutdown()
        engine.shutdown()


def test_existing_foreign_owned_namespace_is_rejected_without_chmod(
    monkeypatch,
    tmp_path,
):
    engine = _engine(tmp_path)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        spec.destination_root.mkdir(parents=True, mode=0o750)
        spec.namespace.mkdir(mode=0o750)
        spec.namespace.chmod(0o750)
        actual_uid = getattr(os, "geteuid", lambda: 0)()
        monkeypatch.setattr(periodic.os, "geteuid", lambda: actual_uid + 1)

        result = periodic.run_periodic_backup(spec, due_only=False)
        assert result["status"] == "failed"
        assert "not owned" in result["error"]
        assert stat.S_IMODE(os.lstat(spec.namespace).st_mode) == 0o750
    finally:
        engine.shutdown()


def test_scheduler_reaps_dead_timed_out_worker_and_reregistration_race(
    monkeypatch,
    tmp_path,
):
    real_run = periodic.run_periodic_backup
    entered = threading.Event()
    release = threading.Event()

    def blocked_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        entered.set()
        assert release.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_run)
    monkeypatch.setattr(periodic, "_SCHEDULER_SHUTDOWN_TIMEOUT_SECONDS", 0.05)
    first = _engine(tmp_path, enabled=True)
    second = _engine(tmp_path, enabled=False)
    third = _engine(tmp_path, enabled=False)
    registrations = []
    try:
        assert entered.wait(5)
        assert periodic.unregister_periodic_backup(first._periodic_backup_registration) is False
        key = str(periodic.build_periodic_backup_spec(first).source_db)
        old = periodic._SCHEDULERS[key]
        old_worker = old.scheduler
        assert old.cancel.is_set() and old.thread.is_alive()

        second._config.periodic_backup_enabled = True
        still_live = periodic.register_periodic_backup(second)
        assert still_live.active is False
        assert still_live.state == "pending"
        assert still_live.reason == "waiting_for_stopping_worker"

        release.set()
        assert old_worker is not None
        old_worker.thread.join(5)
        assert not old_worker.thread.is_alive()
        monkeypatch.setattr(periodic, "run_periodic_backup", real_run)
        third._config.periodic_backup_enabled = True
        barrier = threading.Barrier(3)

        def register(engine):
            barrier.wait()
            registrations.append(periodic.register_periodic_backup(engine))

        workers = [
            threading.Thread(target=register, args=(candidate,))
            for candidate in (second, third)
        ]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(5)
            assert not worker.is_alive()

        assert len(registrations) == 2
        assert all(registration.active for registration in registrations)
        assert periodic.active_periodic_backup_scheduler_count() == 1
        second._periodic_backup_registration = registrations[0]
        third._periodic_backup_registration = registrations[1]
    finally:
        release.set()
        third.shutdown()
        second.shutdown()
        first.shutdown()


def test_large_inventory_manifest_is_verified_and_failed_successor_preserves_last_good(
    tmp_path,
):
    payload_root = tmp_path / "payloads"
    payload_root.mkdir()
    payload_root.chmod(0o700)
    payload_bytes = json.dumps(
        {
            "kind": "tool_result",
            "tool_call_id": "call-1",
            "session_id": "session",
            "content": "x",
            "content_chars": 1,
            "content_bytes": 1,
        }
    ).encode("utf-8")
    engine = _engine(tmp_path, payload_root=payload_root, keep_last=1)
    try:
        suffix = "x" * 220
        for index in range(12_000):
            ref = f"p{index:05d}-{suffix}.json"
            (payload_root / ref).write_bytes(payload_bytes)
            engine._store.append(
                "session",
                {
                    "role": "tool",
                    "content": _placeholder(ref),
                    "timestamp": time.time(),
                },
            )
        engine._store.commit()

        spec = periodic.build_periodic_backup_spec(engine)
        good = periodic.run_periodic_backup(spec, due_only=False)
        assert good["status"] == "ok", good
        generation = Path(good["generation"])
        manifest_path = generation / "manifest.json"
        assert manifest_path.stat().st_size > periodic._MAX_METADATA_BYTES
        verified = periodic._read_verified_pointer(spec)
        assert verified is not None and verified[0] == generation

        pointer_path = spec.namespace / "latest-good.json"
        pointer_before = pointer_path.read_bytes()
        generations_before = _generation_dirs(spec)
        _append(engine, content=_placeholder("missing-successor.json"))
        failed = periodic.run_periodic_backup(spec, due_only=False)

        assert failed["status"] == "failed"
        assert pointer_path.read_bytes() == pointer_before
        assert _generation_dirs(spec) == generations_before
        recovered = periodic._read_verified_pointer(spec)
        assert recovered is not None and recovered[0] == generation
    finally:
        engine.shutdown()


def test_manifest_inventory_bound_does_not_unbound_other_metadata(tmp_path):
    engine = _engine(tmp_path)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        result = periodic.run_periodic_backup(spec, due_only=False)
        assert result["status"] == "ok", result
        manifest_path = Path(result["generation"]) / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["unmanifested_padding"] = "x" * periodic._MAX_METADATA_BYTES
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        assert manifest_path.stat().st_size > periodic._MAX_METADATA_BYTES

        with pytest.raises(periodic.PeriodicBackupError, match="size is unsafe"):
            periodic._read_verified_pointer(spec)
    finally:
        engine.shutdown()


@pytest.mark.parametrize("mode", ["regular", "dangling_symlink", "directory", "fifo"])
def test_reverification_rejects_every_unmanifested_payload_entry_and_preserves_last_good(
    tmp_path,
    mode,
):
    engine = _engine(tmp_path, keep_last=1)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        good = periodic.run_periodic_backup(spec, due_only=False)
        assert good["status"] == "ok", good
        generation = Path(good["generation"])
        pointer_path = spec.namespace / "latest-good.json"
        pointer_before = pointer_path.read_bytes()
        generations_before = _generation_dirs(spec)
        extra = generation / "payloads" / "unmanifested"
        _add_unmanifested_entry(
            extra,
            mode,
            dangling_target=tmp_path / "does-not-exist",
        )

        with pytest.raises(periodic.PeriodicBackupError):
            periodic._read_verified_pointer(spec)
        failed = periodic.run_periodic_backup(spec, due_only=False)
        assert failed["status"] == "failed"
        assert pointer_path.read_bytes() == pointer_before
        assert _generation_dirs(spec) == generations_before

        if mode == "directory":
            extra.rmdir()
        else:
            extra.unlink()
        recovered = periodic._read_verified_pointer(spec)
        assert recovered is not None and recovered[0] == generation
    finally:
        engine.shutdown()


@pytest.mark.parametrize("mode", ["regular", "dangling_symlink", "directory", "fifo"])
def test_reverification_rejects_payload_entry_added_during_database_hash(
    tmp_path,
    monkeypatch,
    mode,
):
    engine = _engine(tmp_path, keep_last=1)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        good = periodic.run_periodic_backup(spec, due_only=False)
        assert good["status"] == "ok", good
        generation = Path(good["generation"])
        pointer_path = spec.namespace / "latest-good.json"
        pointer_before = pointer_path.read_bytes()
        extra = generation / "payloads" / "injected-during-verification"
        real_hash = periodic._sha256_file
        injected = False

        def hash_with_concurrent_add(path, **kwargs):
            nonlocal injected
            if Path(path) == generation / "lcm.sqlite3" and not injected:
                injected = True
                _add_unmanifested_entry(
                    extra,
                    mode,
                    dangling_target=tmp_path / "does-not-exist",
                )
            return real_hash(path, **kwargs)

        monkeypatch.setattr(periodic, "_sha256_file", hash_with_concurrent_add)
        with pytest.raises(periodic.PeriodicBackupError):
            periodic._read_verified_pointer(spec)
        assert injected is True
        assert pointer_path.read_bytes() == pointer_before

        if mode == "directory":
            extra.rmdir()
        else:
            extra.unlink()
        verified = periodic._read_verified_pointer(spec)
        assert verified is not None and verified[0] == generation
    finally:
        engine.shutdown()


@pytest.mark.parametrize("mode", ["regular", "dangling_symlink", "directory", "fifo"])
@pytest.mark.parametrize("phase", ["database_hash", "payload_recovery"])
def test_successor_payload_entry_added_during_verification_preserves_last_good(
    tmp_path,
    monkeypatch,
    mode,
    phase,
):
    payload_root = tmp_path / "payloads"
    _payload(payload_root / "payload.json", "payload")
    engine = _engine(tmp_path, payload_root=payload_root, keep_last=1)
    try:
        _append(engine, content=_placeholder("payload.json"))
        spec = periodic.build_periodic_backup_spec(engine)
        good = periodic.run_periodic_backup(spec, due_only=False)
        assert good["status"] == "ok", good
        pointer_path = spec.namespace / "latest-good.json"
        pointer_before = pointer_path.read_bytes()
        generations_before = _generation_dirs(spec)
        real_hash = periodic._sha256_file
        real_validate = periodic._validate_payload_context
        injected = False
        retention_called = False

        def add_during_verification(payload_dir: Path) -> None:
            nonlocal injected
            if (
                injected
                or not payload_dir.parent.name.endswith(".partial")
                or not (payload_dir.parent / "manifest.json").exists()
            ):
                return
            injected = True
            _add_unmanifested_entry(
                payload_dir / "injected-during-verification",
                mode,
                dangling_target=tmp_path / "does-not-exist",
            )

        def hash_with_concurrent_add(path, **kwargs):
            path = Path(path)
            if (
                phase == "database_hash"
                and path.name == "lcm.sqlite3"
                and path.parent.name.endswith(".partial")
            ):
                add_during_verification(path.parent / "payloads")
            return real_hash(path, **kwargs)

        def validate_with_concurrent_add(payload_dir, reference, *, cancel):
            if phase == "payload_recovery":
                add_during_verification(payload_dir)
            return real_validate(payload_dir, reference, cancel=cancel)

        def observe_retention(stage: str) -> None:
            nonlocal retention_called
            if stage == "retention":
                retention_called = True

        monkeypatch.setattr(periodic, "_sha256_file", hash_with_concurrent_add)
        monkeypatch.setattr(periodic, "_validate_payload_context", validate_with_concurrent_add)
        failed = periodic.run_periodic_backup(
            spec,
            due_only=False,
            _fault=observe_retention,
        )

        assert injected is True
        assert failed["status"] == "failed", failed
        assert failed["published"] is False
        assert failed["pointer_renamed"] is False
        assert retention_called is False
        assert pointer_path.read_bytes() == pointer_before
        assert _generation_dirs(spec) == generations_before
        verified = periodic._read_verified_pointer(spec)
        assert verified is not None and verified[0] == Path(good["generation"])
    finally:
        engine.shutdown()


def test_reverification_rejects_payload_directory_replacement_during_database_hash(
    tmp_path,
    monkeypatch,
):
    engine = _engine(tmp_path)
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        good = periodic.run_periodic_backup(spec, due_only=False)
        assert good["status"] == "ok", good
        generation = Path(good["generation"])
        payload_dir = generation / "payloads"
        displaced = generation / "payloads-displaced"
        pointer_path = spec.namespace / "latest-good.json"
        pointer_before = pointer_path.read_bytes()
        real_hash = periodic._sha256_file
        replaced = False

        def hash_with_directory_replacement(path, **kwargs):
            nonlocal replaced
            if Path(path) == generation / "lcm.sqlite3" and not replaced:
                replaced = True
                payload_dir.rename(displaced)
                payload_dir.mkdir(mode=0o700)
            return real_hash(path, **kwargs)

        monkeypatch.setattr(periodic, "_sha256_file", hash_with_directory_replacement)
        with pytest.raises(periodic.PeriodicBackupError):
            periodic._read_verified_pointer(spec)
        assert replaced is True
        assert pointer_path.read_bytes() == pointer_before

        payload_dir.rmdir()
        displaced.rename(payload_dir)
        verified = periodic._read_verified_pointer(spec)
        assert verified is not None and verified[0] == generation
    finally:
        engine.shutdown()


def test_configured_database_rebind_suspends_before_releasing_prior_root_authority(
    monkeypatch,
    tmp_path,
):
    entered = threading.Event()
    release = threading.Event()

    def blocked_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        entered.set()
        assert release.wait(20)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_run)
    home_a = tmp_path / "profile-a"
    home_b = tmp_path / "profile-b"
    home_c = tmp_path / "profile-c"
    for home in (home_a, home_b, home_c):
        (home / "lcm-large-outputs").mkdir(parents=True)
        (home / "lcm-large-outputs").chmod(0o700)
    engine = LCMEngine(
        config=LCMConfig(
            database_path=str(tmp_path / "shared-lcm.db"),
            periodic_backup_enabled=True,
            periodic_backup_interval_hours=6.0,
            periodic_backup_keep_last=2,
        ),
        hermes_home=str(home_a),
    )
    key = str(periodic.build_periodic_backup_spec(engine).source_db)
    old = periodic._SCHEDULERS[key]
    old_worker = old.scheduler
    try:
        assert entered.wait(5)
        assert engine._rebind_storage_for_home(str(home_b)) is True
        spec_b = periodic.build_periodic_backup_spec(engine)
        assert engine._periodic_backup_registration.state == "suspended"
        assert engine._periodic_backup_registration.reason == "payload_root_ambiguous"
        assert periodic._SCHEDULERS[key] is old
        assert old.thread.is_alive() and old.cancel.is_set()

        assert engine._rebind_storage_for_home(str(home_c)) is True
        spec_c = periodic.build_periodic_backup_spec(engine)
        assert spec_b != spec_c
        assert engine._periodic_backup_registration.state == "suspended"
        assert periodic._SCHEDULERS[key] is old

        release.set()
        assert old_worker is not None
        old_worker.thread.join(5)
        assert not old_worker.thread.is_alive()
        status = periodic.periodic_backup_source_status(key)
        assert status is not None and status["state"] == "SUSPENDED"
        assert not (spec_b.namespace / "latest-good.json").exists()
        assert not (spec_c.namespace / "latest-good.json").exists()
    finally:
        release.set()
        engine.shutdown()
        with periodic._REGISTRY_LOCK:
            leftover = periodic._SCHEDULERS.pop(key, None)
        if leftover is not None and leftover.scheduler is not None and leftover.thread.is_alive():
            leftover.scheduler.stop()


def test_configured_database_fast_rebind_preserves_root_authority_until_readmission(
    tmp_path,
):
    home_one = tmp_path / "profile-one"
    home_two = tmp_path / "profile-two"
    root_one = home_one / "lcm-large-outputs"
    root_two = home_two / "lcm-large-outputs"
    for root in (root_one, root_two):
        root.mkdir(parents=True)
        root.chmod(0o700)
    _payload(root_one / "shared.json", "approved root payload")
    _payload(root_two / "shared.json", "different candidate payload")
    engine = LCMEngine(
        config=LCMConfig(
            database_path=str(tmp_path / "shared-lcm.db"),
            periodic_backup_enabled=False,
            periodic_backup_interval_hours=6.0,
            periodic_backup_keep_last=2,
            periodic_backup_path=str(tmp_path / "periodic"),
        ),
        hermes_home=str(home_one),
    )
    try:
        _append(engine, content=_placeholder("shared.json"))
        spec_one = periodic.build_periodic_backup_spec(engine)
        published = periodic.run_periodic_backup(spec_one, due_only=False)
        assert published["status"] == "ok", published
        pointer_before = (spec_one.namespace / "latest-good.json").read_bytes()
        generations_before = _generation_dirs(spec_one)

        engine._config.periodic_backup_enabled = True
        engine._periodic_backup_registration = periodic.acquire_backup_lease(engine)
        key = engine._periodic_backup_registration.source_key
        assert engine._periodic_backup_registration.state == "active"
        _wait_for(
            lambda: bool((periodic.periodic_backup_source_status(key) or {}).get("worker_alive"))
        )

        assert engine._rebind_storage_for_home(str(home_two)) is True
        assert engine._periodic_backup_registration.state == "suspended"
        assert engine._periodic_backup_registration.reason == "payload_root_ambiguous"
        _wait_for(
            lambda: not bool((periodic.periodic_backup_source_status(key) or {}).get("worker_alive"))
        )
        suspended = periodic.periodic_backup_source_status(key)
        assert suspended is not None
        assert suspended["state"] == "SUSPENDED"
        assert suspended["active_leases"] == 0
        assert suspended["suspended_leases"] == 1
        assert (spec_one.namespace / "latest-good.json").read_bytes() == pointer_before
        assert _generation_dirs(spec_one) == generations_before

        rejected = periodic.resume_backup_source(key, root_two)
        assert rejected.state == "suspended"
        assert "bytes differ from retained generation" in rejected.reason
        assert (spec_one.namespace / "latest-good.json").read_bytes() == pointer_before
        assert _generation_dirs(spec_one) == generations_before

        _payload(root_two / "shared.json", "approved root payload")
        admitted = periodic.resume_backup_source(key, root_two)
        assert admitted.state == "active"
        resumed = periodic.periodic_backup_source_status(key)
        assert resumed is not None
        assert resumed["state"] == "ACTIVE"
        assert resumed["active_leases"] == 1
        assert resumed["suspended_leases"] == 0
        assert engine._periodic_backup_registration.state == "active"
    finally:
        engine.shutdown()


def test_configured_database_failed_rebind_preserves_authority_for_later_root_retry(
    tmp_path,
):
    home_one = tmp_path / "profile-one"
    home_two = tmp_path / "profile-two"
    root_one = home_one / "lcm-large-outputs"
    root_two = home_two / "lcm-large-outputs"
    root_one.mkdir(parents=True)
    root_one.chmod(0o700)
    _payload(root_one / "shared.json", "approved root payload")
    engine = LCMEngine(
        config=LCMConfig(
            database_path=str(tmp_path / "shared-lcm.db"),
            periodic_backup_enabled=False,
            periodic_backup_interval_hours=6.0,
            periodic_backup_keep_last=2,
            periodic_backup_path=str(tmp_path / "periodic"),
        ),
        hermes_home=str(home_one),
    )
    retry = None
    try:
        _append(engine, content=_placeholder("shared.json"))
        spec_one = periodic.build_periodic_backup_spec(engine)
        published = periodic.run_periodic_backup(spec_one, due_only=False)
        assert published["status"] == "ok", published
        pointer_before = (spec_one.namespace / "latest-good.json").read_bytes()
        generations_before = _generation_dirs(spec_one)

        engine._config.periodic_backup_enabled = True
        engine._periodic_backup_registration = periodic.acquire_backup_lease(engine)
        key = engine._periodic_backup_registration.source_key
        assert engine._periodic_backup_registration.state == "active"

        assert engine._rebind_storage_for_home(str(home_two)) is True
        assert engine._periodic_backup_registration.state == "suspended"
        assert engine._periodic_backup_registration.reason == "payload_root_ambiguous"
        status = periodic.periodic_backup_source_status(key)
        assert status is not None
        assert status["state"] == "SUSPENDED"
        assert status["reason"] == "payload_root_ambiguous"
        assert status["active_leases"] == 0
        assert status["suspended_leases"] == 1
        assert (spec_one.namespace / "latest-good.json").read_bytes() == pointer_before
        assert _generation_dirs(spec_one) == generations_before

        _payload(root_two / "shared.json", "different candidate payload")
        retry = periodic.acquire_backup_lease(engine)
        assert retry.state == "suspended"
        assert retry.reason == "payload_root_ambiguous"
        status = periodic.periodic_backup_source_status(key)
        assert status is not None
        assert status["state"] == "SUSPENDED"
        assert status["worker_alive"] is False
        assert status["suspended_leases"] == 2
        assert (spec_one.namespace / "latest-good.json").read_bytes() == pointer_before
        assert _generation_dirs(spec_one) == generations_before
    finally:
        if retry is not None:
            periodic.release_backup_lease(retry)
        engine.shutdown()


def test_timed_out_scheduler_handoff_serializes_concurrent_owners_and_cancellation(
    monkeypatch,
    tmp_path,
):
    real_run = periodic.run_periodic_backup
    entered = threading.Event()
    release = threading.Event()

    def blocked_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        entered.set()
        assert release.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_run)
    monkeypatch.setattr(periodic, "_SCHEDULER_SHUTDOWN_TIMEOUT_SECONDS", 0.05)
    first = _engine(tmp_path, enabled=True)
    second = _engine(tmp_path, enabled=False)
    third = _engine(tmp_path, enabled=False)
    key = str(periodic.build_periodic_backup_spec(first).source_db)
    old = periodic._SCHEDULERS[key]
    old_worker = old.scheduler
    registrations = []
    try:
        assert entered.wait(5)
        assert periodic.unregister_periodic_backup(first._periodic_backup_registration) is False
        second._config.periodic_backup_enabled = True
        third._config.periodic_backup_enabled = True
        barrier = threading.Barrier(3)

        def register(engine):
            barrier.wait()
            registrations.append(periodic.register_periodic_backup(engine))

        workers = [
            threading.Thread(target=register, args=(candidate,))
            for candidate in (second, third)
        ]
        for worker in workers:
            worker.start()
        barrier.wait()
        for worker in workers:
            worker.join(5)
            assert not worker.is_alive()

        assert len(registrations) == 2
        assert all(registration.state == "pending" for registration in registrations)
        assert periodic._SCHEDULERS[key] is old
        assert old_worker is not None and old.scheduler is old_worker
        assert old_worker.thread.is_alive()

        cancelled, retained = registrations
        second._periodic_backup_registration = cancelled
        third._periodic_backup_registration = retained
        assert periodic.unregister_periodic_backup(cancelled) is True
        second._periodic_backup_registration = None

        monkeypatch.setattr(periodic, "run_periodic_backup", real_run)
        release.set()
        assert old_worker is not None
        old_worker.thread.join(5)
        _wait_for(
            lambda: (periodic.periodic_backup_source_status(key) or {}).get("state") == "ACTIVE"
        )
        successor = periodic._SCHEDULERS[key]
        assert successor is old
        assert not old_worker.thread.is_alive()
        assert successor.owners == {retained.owner}
        assert cancelled.owner not in successor.owners
        _wait_for(
            lambda: (periodic.build_periodic_backup_spec(third).namespace / "latest-good.json").exists()
        )
    finally:
        release.set()
        third.shutdown()
        second.shutdown()
        first.shutdown()
        with periodic._REGISTRY_LOCK:
            leftover = periodic._SCHEDULERS.pop(key, None)
        if leftover is not None and leftover.scheduler is not None and leftover.thread.is_alive():
            leftover.scheduler.stop()


def test_dead_owned_staging_is_cleaned_but_active_and_foreign_paths_are_retained(
    tmp_path,
):
    engine = _engine(tmp_path)
    sleeper = multiprocessing.get_context("fork").Process(target=time.sleep, args=(10,))
    try:
        spec = periodic.build_periodic_backup_spec(engine)
        context = multiprocessing.get_context("fork")
        child = context.Process(target=_run_crashing_staged_backup, args=(spec,))
        child.start()
        child.join(15)
        assert child.exitcode == 17
        abandoned = list(spec.namespace.glob("lcm-periodic-*.partial"))
        assert len(abandoned) == 1
        assert (abandoned[0] / "lcm.sqlite3").is_file()
        assert (abandoned[0] / "manifest.json").is_file()

        sleeper.start()
        active_id = "lcm-periodic-20300102T030405.000000Z-aaaaaaaaaaaa"
        active = spec.namespace / f"{active_id}.partial"
        active.mkdir(mode=0o700)
        (active / ".owner.json").write_text(
            json.dumps(
                {
                    "schema": "lcm-periodic-backup-staging/v1",
                    "source_identity": periodic._identity_payload(spec),
                    "generation_id": active_id,
                    "creator_pid": sleeper.pid,
                }
            ),
            encoding="utf-8",
        )
        foreign_id = "lcm-periodic-20300102T030405.000000Z-bbbbbbbbbbbb"
        foreign = spec.namespace / f"{foreign_id}.partial"
        foreign.mkdir(mode=0o700)
        (foreign / ".owner.json").write_text(
            json.dumps(
                {
                    "schema": "lcm-periodic-backup-staging/v1",
                    "source_identity": {
                        "version": 1,
                        "canonical_db_path": "/foreign",
                        "sha256": "0" * 64,
                    },
                    "generation_id": foreign_id,
                    "creator_pid": 99999999,
                }
            ),
            encoding="utf-8",
        )
        outside = tmp_path / "outside"
        outside.mkdir()
        symlink = spec.namespace / "lcm-periodic-20300102T030405.000000Z-cccccccccccc.partial"
        symlink.symlink_to(outside, target_is_directory=True)

        result = periodic.run_periodic_backup(spec, due_only=False)
        assert result["status"] == "ok", result
        assert not abandoned[0].exists()
        assert active.exists()
        assert foreign.exists()
        assert symlink.is_symlink()
        assert list(outside.iterdir()) == []
    finally:
        if sleeper.is_alive():
            sleeper.terminate()
        sleeper.join(5)
        engine.shutdown()


def test_n1_root_ambiguity_suspends_source_and_readmission_proves_retained_bytes(tmp_path):
    root_one = tmp_path / "payload-root-one"
    root_two = tmp_path / "payload-root-two"
    _payload(root_one / "shared.json", "approved root payload")
    _payload(root_two / "shared.json", "different candidate payload")
    first = _engine(tmp_path, payload_root=root_one)
    clone = None
    rebinding = None
    try:
        _append(first, content=_placeholder("shared.json"))
        spec = periodic.build_periodic_backup_spec(first)
        published = periodic.run_periodic_backup(spec, due_only=False)
        assert published["status"] == "ok", published
        pointer_before = (spec.namespace / "latest-good.json").read_bytes()
        generations_before = _generation_dirs(spec)

        first._config.periodic_backup_enabled = True
        first._periodic_backup_registration = periodic.acquire_backup_lease(first)
        assert first._periodic_backup_registration.state == "active"
        clone = first.clone_for_agent()
        assert clone._periodic_backup_registration.state == "active"

        rebinding = _engine(tmp_path, enabled=True, payload_root=root_two)
        key = first._periodic_backup_registration.source_key
        assert rebinding._periodic_backup_registration.state == "suspended"
        assert rebinding._periodic_backup_registration.reason == "payload_root_ambiguous"
        _wait_for(
            lambda: not bool((periodic.periodic_backup_source_status(key) or {}).get("worker_alive"))
        )
        status = periodic.periodic_backup_source_status(key)
        assert status is not None and status["state"] == "SUSPENDED"
        assert status["active_leases"] == 0
        assert status["pending_leases"] == 0
        assert status["suspended_leases"] == 3
        assert first._periodic_backup_registration.state == "suspended"
        assert clone._periodic_backup_registration.state == "suspended"
        assert rebinding._periodic_backup_registration.state == "suspended"
        assert status["approved_root"] == str(root_one.resolve())
        assert (spec.namespace / "latest-good.json").read_bytes() == pointer_before
        assert _generation_dirs(spec) == generations_before

        rejected = periodic.resume_backup_source(key, root_two)
        assert rejected.state == "suspended"
        assert "bytes differ from retained generation" in rejected.reason
        assert (spec.namespace / "latest-good.json").read_bytes() == pointer_before
        assert _generation_dirs(spec) == generations_before

        approved_payload = root_one / "shared.json"
        approved_payload.unlink()
        approved_payload.symlink_to(root_two / "shared.json")
        unsafe = periodic.resume_backup_source(key, root_one)
        assert unsafe.state == "suspended"
        assert "candidate payload is unsafe" in unsafe.reason
        assert (spec.namespace / "latest-good.json").read_bytes() == pointer_before
        assert _generation_dirs(spec) == generations_before
        approved_payload.unlink()
        _payload(approved_payload, "approved root payload")

        admitted = periodic.resume_backup_source(key, root_one)
        assert admitted.state == "active"
        resumed = periodic.periodic_backup_source_status(key)
        assert resumed is not None and resumed["readmission"]["ok"] is True
        assert resumed["readmission"]["snapshot_reference_count"] == 1
        assert resumed["approved_root_identity"] != (0, 0)
        assert resumed["active_leases"] == 2
        assert resumed["suspended_leases"] == 1
        assert clone._periodic_backup_registration.state == "active"
        assert rebinding._periodic_backup_registration.state == "suspended"
    finally:
        if rebinding is not None:
            rebinding.shutdown()
        if clone is not None:
            clone.shutdown()
        first.shutdown()


def test_n3_staged_mutation_and_suspension_gate_preserve_prior_pointer(tmp_path):
    root = tmp_path / "payloads"
    root_two = tmp_path / "payloads-two"
    _payload(root / "payload.json", "original payload")
    _payload(root_two / "payload.json", "different root payload")
    engine = _engine(tmp_path, payload_root=root)
    rebinding = None
    try:
        _append(engine, content=_placeholder("payload.json"))
        spec = periodic.build_periodic_backup_spec(engine)
        good = periodic.run_periodic_backup(spec, due_only=False)
        assert good["status"] == "ok", good
        pointer_before = (spec.namespace / "latest-good.json").read_bytes()
        generations_before = _generation_dirs(spec)

        published_payload = Path(good["generation"]) / "payloads" / "payload.json"
        original_published_bytes = published_payload.read_bytes()
        published_payload.write_bytes(b"Y" * len(original_published_bytes))
        with pytest.raises(periodic.PeriodicBackupError):
            periodic._read_verified_pointer(spec)
        assert (spec.namespace / "latest-good.json").read_bytes() == pointer_before
        published_payload.write_bytes(original_published_bytes)
        assert periodic._read_verified_pointer(spec) is not None

        mutated = threading.Event()

        def mutate_staged(stage: str) -> None:
            if stage != "before_final_validation":
                return
            partial = next(spec.namespace.glob("lcm-periodic-*.partial"))
            payload = partial / "payloads" / "payload.json"
            original = payload.read_bytes()
            payload.write_bytes(b"X" * len(original))
            mutated.set()

        failed = periodic.run_periodic_backup(spec, due_only=False, _fault=mutate_staged)
        assert mutated.is_set()
        assert failed["status"] == "failed"
        assert failed["pointer_renamed"] is False
        assert (spec.namespace / "latest-good.json").read_bytes() == pointer_before
        assert _generation_dirs(spec) == generations_before
        verified = periodic._read_verified_pointer(spec)
        assert verified is not None and verified[0] == Path(good["generation"])

        engine._config.periodic_backup_enabled = True
        engine._periodic_backup_registration = periodic.acquire_backup_lease(engine)
        key = engine._periodic_backup_registration.source_key
        source = periodic._SCHEDULERS[key]
        entered = threading.Event()
        release = threading.Event()
        results: list[dict] = []
        captured_epoch = source.publication_epoch

        def block_before_gate(stage: str) -> None:
            if stage == "before_final_validation":
                entered.set()
                assert release.wait(5)

        transaction = threading.Thread(
            target=lambda: results.append(
                periodic.run_periodic_backup(
                    spec,
                    due_only=False,
                    _fault=block_before_gate,
                    _publication_gate=lambda: source.publication_gate(captured_epoch),
                )
            )
        )
        transaction.start()
        assert entered.wait(5)
        rebinding = _engine(tmp_path, enabled=True, payload_root=root_two)
        assert rebinding._periodic_backup_registration.state == "suspended"
        status = periodic.periodic_backup_source_status(key)
        assert status is not None and status["state"] == "SUSPENDED"
        assert status["active_leases"] == 0
        release.set()
        transaction.join(10)
        assert not transaction.is_alive()
        assert results[0]["status"] == "cancelled"
        assert (spec.namespace / "latest-good.json").read_bytes() == pointer_before
        assert _generation_dirs(spec) == generations_before
    finally:
        if rebinding is not None:
            rebinding.shutdown()
        engine.shutdown()


def test_final_generation_verification_rehashes_after_recovery_before_publication(
    monkeypatch, tmp_path
):
    root = tmp_path / "payloads"
    _payload(root / "payload.json", "original payload")
    engine = _engine(tmp_path, payload_root=root)
    try:
        _append(engine, content=_placeholder("payload.json"))
        spec = periodic.build_periodic_backup_spec(engine)
        good = periodic.run_periodic_backup(spec, due_only=False)
        assert good["status"] == "ok", good
        pointer_before = (spec.namespace / "latest-good.json").read_bytes()
        generations_before = _generation_dirs(spec)

        real_verify_recovery = periodic._verify_payload_recovery
        partial_recovery_calls = 0
        mutated = threading.Event()

        def mutate_after_final_recovery(payload_dir, references, *, cancel):
            nonlocal partial_recovery_calls
            result = real_verify_recovery(payload_dir, references, cancel=cancel)
            if payload_dir.parent.name.endswith(".partial"):
                partial_recovery_calls += 1
                # The transaction performs recovery once before manifest creation,
                # then once in each staged verification. The final call is the
                # source-gated verification immediately before publication.
                if partial_recovery_calls == 3:
                    payload = payload_dir / "payload.json"
                    original = payload.read_bytes()
                    payload.write_bytes(b"X" * len(original))
                    mutated.set()
            return result

        monkeypatch.setattr(periodic, "_verify_payload_recovery", mutate_after_final_recovery)
        failed = periodic.run_periodic_backup(spec, due_only=False)
        assert mutated.is_set()
        assert failed["status"] == "failed"
        assert failed["pointer_renamed"] is False
        assert (spec.namespace / "latest-good.json").read_bytes() == pointer_before
        assert _generation_dirs(spec) == generations_before
        verified = periodic._read_verified_pointer(spec)
        assert verified is not None and verified[0] == Path(good["generation"])
    finally:
        engine.shutdown()


def test_n4_initial_worker_start_failure_isolated_and_retryable(monkeypatch, tmp_path):
    real_start = threading.Thread.start

    def fail_only_periodic_worker(thread: threading.Thread) -> None:
        if thread.name.startswith("lcm-periodic-backup-"):
            raise RuntimeError("injected initial worker start failure")
        real_start(thread)

    monkeypatch.setattr(threading.Thread, "start", fail_only_periodic_worker)
    engine = _engine(tmp_path, enabled=True)
    try:
        registration = engine._periodic_backup_registration
        assert registration.state == "error"
        assert registration.reason.startswith("periodic_worker_start_failed:")
        assert periodic.periodic_backup_source_status(registration.source_key) is None
        _append(engine, content="engine remains usable after optional scheduler failure")
        monkeypatch.setattr(threading.Thread, "start", real_start)
        engine._periodic_backup_registration = periodic.acquire_backup_lease(engine)
        assert engine._periodic_backup_registration.state == "active"
        _wait_for(
            lambda: bool(
                (periodic.periodic_backup_source_status(engine._periodic_backup_registration.source_key) or {}).get("worker_alive")
            )
        )
    finally:
        engine.shutdown()


@pytest.mark.parametrize("failure", ["handoff", "successor", "all_cancelled"])
def test_n2_optional_handoff_and_successor_start_failures_cleanup_and_retry(
    monkeypatch,
    tmp_path,
    failure,
):
    entered = threading.Event()
    release = threading.Event()
    real_start = threading.Thread.start

    def blocked_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        entered.set()
        assert release.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_run)
    monkeypatch.setattr(periodic, "_SCHEDULER_SHUTDOWN_TIMEOUT_SECONDS", 0.05)
    first = _engine(tmp_path, enabled=True)
    second = _engine(tmp_path, enabled=False)
    key = first._periodic_backup_registration.source_key
    old_worker = periodic._SCHEDULERS[key].scheduler
    try:
        assert entered.wait(5)
        second._config.periodic_backup_enabled = True

        if failure == "handoff":
            def fail_handoff_start(thread: threading.Thread) -> None:
                if thread.name.startswith("lcm-backup-handoff-"):
                    raise RuntimeError("injected handoff start failure")
                real_start(thread)

            monkeypatch.setattr(threading.Thread, "start", fail_handoff_start)
            assert periodic.release_backup_lease(first._periodic_backup_registration) is False
            second._periodic_backup_registration = periodic.acquire_backup_lease(second)
        elif failure == "successor":
            assert periodic.release_backup_lease(first._periodic_backup_registration) is False
            second._periodic_backup_registration = periodic.acquire_backup_lease(second)
            assert second._periodic_backup_registration.state == "pending"

            def fail_successor_start(thread: threading.Thread) -> None:
                if thread.name.startswith("lcm-periodic-backup-"):
                    raise RuntimeError("injected successor start failure")
                real_start(thread)

            monkeypatch.setattr(threading.Thread, "start", fail_successor_start)

        else:
            assert periodic.release_backup_lease(first._periodic_backup_registration) is False
            second._periodic_backup_registration = periodic.acquire_backup_lease(second)
            assert second._periodic_backup_registration.state == "pending"
            assert periodic.release_backup_lease(second._periodic_backup_registration) is True
            release.set()
            assert old_worker is not None
            old_worker.thread.join(5)
            assert not old_worker.thread.is_alive()
            _wait_for(lambda: periodic.periodic_backup_source_status(key) is None)
            return

        release.set()
        assert old_worker is not None
        old_worker.thread.join(5)
        assert not old_worker.thread.is_alive()
        _wait_for(lambda: second._periodic_backup_registration.state == "error")
        reason_prefix = "periodic_handoff_start_failed:" if failure == "handoff" else "periodic_worker_start_failed:"
        assert second._periodic_backup_registration.reason.startswith(reason_prefix)
        _wait_for(lambda: periodic.periodic_backup_source_status(key) is None)

        monkeypatch.setattr(threading.Thread, "start", real_start)
        second._periodic_backup_registration = periodic.acquire_backup_lease(second)
        assert second._periodic_backup_registration.state == "active"
        _wait_for(
            lambda: bool(
                (periodic.periodic_backup_source_status(key) or {}).get("worker_alive")
            )
        )
    finally:
        release.set()
        second.shutdown()
        first.shutdown()


def test_n1_same_path_payload_root_replacement_cancels_real_scheduler_publication(
    monkeypatch,
    tmp_path,
):
    root = tmp_path / "payloads"
    _payload(root / "payload.json", "approved root payload")
    engine = _engine(tmp_path, payload_root=root, interval_hours=0.000001)
    original_root = tmp_path / "payloads-original"
    entered_final_validation = threading.Event()
    try:
        _append(engine, content=_placeholder("payload.json"))
        baseline_spec = periodic.build_periodic_backup_spec(engine)
        baseline = periodic.run_periodic_backup(baseline_spec, due_only=False)
        assert baseline["status"] == "ok", baseline
        pointer_before = (baseline_spec.namespace / "latest-good.json").read_bytes()
        generations_before = _generation_dirs(baseline_spec)
        real_run = periodic.run_periodic_backup

        def replace_root_at_final_validation(spec, **kwargs):
            def replace_root(stage: str) -> None:
                if stage != "before_final_validation":
                    return
                root.rename(original_root)
                _payload(root / "payload.json", "replacement root payload")
                entered_final_validation.set()

            return real_run(spec, _fault=replace_root, **kwargs)

        monkeypatch.setattr(periodic, "run_periodic_backup", replace_root_at_final_validation)
        engine._config.periodic_backup_enabled = True
        engine._periodic_backup_registration = periodic.acquire_backup_lease(engine)
        key = engine._periodic_backup_registration.source_key
        assert engine._periodic_backup_registration.state == "active"
        assert entered_final_validation.wait(10)
        _wait_for(
            lambda: not bool((periodic.periodic_backup_source_status(key) or {}).get("worker_alive"))
        )

        status = periodic.periodic_backup_source_status(key)
        assert status is not None
        assert status["state"] == "SUSPENDED"
        assert status["reason"] == "payload_root_identity_changed"
        assert status["approved_root_identity"] != (
            os.lstat(root).st_dev,
            os.lstat(root).st_ino,
        )
        assert (baseline_spec.namespace / "latest-good.json").read_bytes() == pointer_before
        assert _generation_dirs(baseline_spec) == generations_before
        assert periodic._read_verified_pointer(baseline_spec) is not None
    finally:
        engine.shutdown()


def test_n2_timed_out_final_release_reaps_unowned_source_after_real_worker_exit(
    monkeypatch,
    tmp_path,
):
    entered = threading.Event()
    release = threading.Event()

    def blocked_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        entered.set()
        assert release.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_run)
    monkeypatch.setattr(periodic, "_SCHEDULER_SHUTDOWN_TIMEOUT_SECONDS", 0.05)
    engine = _engine(tmp_path, enabled=True)
    key = engine._periodic_backup_registration.source_key
    try:
        assert entered.wait(5)
        source = periodic._SCHEDULERS[key]
        old_worker = source.scheduler
        assert old_worker is not None
        assert periodic.release_backup_lease(engine._periodic_backup_registration) is False
        stopping = periodic.periodic_backup_source_status(key)
        assert stopping is not None
        assert stopping["state"] == "STOPPING"
        assert stopping["active_leases"] == 0
        assert stopping["pending_leases"] == 0
        assert stopping["handoff_alive"] is True

        release.set()
        old_worker.thread.join(5)
        assert not old_worker.thread.is_alive()
        _wait_for(lambda: periodic.periodic_backup_source_status(key) is None)
    finally:
        release.set()
        engine.shutdown()


def test_n1_failed_rebind_shutdown_reaps_unowned_suspended_source_after_worker_exit(
    monkeypatch,
    tmp_path,
):
    entered = threading.Event()
    release = threading.Event()

    def blocked_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        entered.set()
        assert release.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_run)
    monkeypatch.setattr(periodic, "_SCHEDULER_SHUTDOWN_TIMEOUT_SECONDS", 0.05)
    home_one = tmp_path / "home-one"
    home_two = tmp_path / "home-two"
    root_one = home_one / "lcm-large-outputs"
    root_one.mkdir(parents=True)
    root_one.chmod(0o700)
    engine = LCMEngine(
        config=LCMConfig(
            database_path=str(tmp_path / "shared.db"),
            periodic_backup_enabled=True,
            periodic_backup_interval_hours=0.00001,
            periodic_backup_keep_last=2,
            periodic_backup_path=str(tmp_path / "periodic"),
        ),
        hermes_home=str(home_one),
    )
    key = engine._periodic_backup_registration.source_key
    try:
        assert entered.wait(5)
        assert engine._rebind_storage_for_home(str(home_two)) is True
        suspended = periodic.periodic_backup_source_status(key)
        assert suspended is not None
        assert suspended["state"] == "SUSPENDED"
        assert suspended["worker_alive"] is True

        engine.shutdown()
        unowned = periodic.periodic_backup_source_status(key)
        assert unowned is not None
        assert unowned["active_leases"] == 0
        assert unowned["pending_leases"] == 0
        assert unowned["suspended_leases"] == 0

        release.set()
        _wait_for(lambda: periodic.periodic_backup_source_status(key) is None)
    finally:
        release.set()
        engine.shutdown()


def test_n1_suspended_source_cannot_readmit_until_old_worker_actually_exits(
    monkeypatch,
    tmp_path,
):
    home_one = tmp_path / "home-one"
    home_two = tmp_path / "home-two"
    root_one = home_one / "lcm-large-outputs"
    root_one.mkdir(parents=True)
    root_one.chmod(0o700)
    old_run_entered = threading.Event()
    release_old_run = threading.Event()
    scheduler_run_body_returned = threading.Event()
    allow_old_thread_exit = threading.Event()

    def blocked_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        old_run_entered.set()
        assert release_old_run.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    real_scheduler_run = periodic._Scheduler._run

    def pause_after_scheduler_run_body(worker):
        real_scheduler_run(worker)
        scheduler_run_body_returned.set()
        assert allow_old_thread_exit.wait(5)

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_run)
    monkeypatch.setattr(periodic._Scheduler, "_run", pause_after_scheduler_run_body)
    engine = LCMEngine(
        config=LCMConfig(
            database_path=str(tmp_path / "shared.db"),
            periodic_backup_enabled=True,
            periodic_backup_interval_hours=0.00001,
            periodic_backup_keep_last=2,
            periodic_backup_path=str(tmp_path / "periodic"),
        ),
        hermes_home=str(home_one),
    )
    key = engine._periodic_backup_registration.source_key
    source = periodic._SCHEDULERS[key]
    old_worker = source.scheduler
    assert old_worker is not None
    try:
        assert old_run_entered.wait(5)
        assert engine._rebind_storage_for_home(str(home_two)) is True
        assert engine._periodic_backup_registration.state == "suspended"
        release_old_run.set()
        assert scheduler_run_body_returned.wait(5)
        assert old_worker.thread.is_alive()

        resumed = periodic.resume_backup_source(key, root_one)
        assert resumed.state != "active"
        assert source.scheduler is old_worker
    finally:
        allow_old_thread_exit.set()
        old_worker.thread.join(5)
        engine.shutdown()


def test_n1_suspension_handoff_start_failure_is_error_and_reaps_after_worker_exit(
    monkeypatch,
    tmp_path,
):
    home_one = tmp_path / "home-one"
    home_two = tmp_path / "home-two"
    for home in (home_one, home_two):
        root = home / "lcm-large-outputs"
        root.mkdir(parents=True)
        root.chmod(0o700)
    entered = threading.Event()
    release = threading.Event()
    real_start = threading.Thread.start

    def blocked_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        entered.set()
        assert release.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    def fail_only_handoff_start(thread: threading.Thread) -> None:
        if thread.name.startswith("lcm-backup-handoff-"):
            raise RuntimeError("injected suspension handoff start failure")
        real_start(thread)

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_run)
    engine = LCMEngine(
        config=LCMConfig(
            database_path=str(tmp_path / "shared.db"),
            periodic_backup_enabled=True,
            periodic_backup_interval_hours=0.00001,
            periodic_backup_keep_last=2,
            periodic_backup_path=str(tmp_path / "periodic"),
        ),
        hermes_home=str(home_one),
    )
    key = engine._periodic_backup_registration.source_key
    source = periodic._SCHEDULERS[key]
    old_worker = source.scheduler
    assert old_worker is not None
    try:
        assert entered.wait(5)
        monkeypatch.setattr(threading.Thread, "start", fail_only_handoff_start)
        assert engine._rebind_storage_for_home(str(home_two)) is True
        registration = engine._periodic_backup_registration
        assert registration.state == "error"
        assert registration.reason.startswith("periodic_handoff_start_failed:")
        assert source.state == "ERROR"
        assert not source.active_owners
        assert not source.pending_owners
        assert not source.suspended_owners
        release.set()
        old_worker.thread.join(5)
        assert not old_worker.thread.is_alive()
        _wait_for(lambda: periodic.periodic_backup_source_status(key) is None)
    finally:
        monkeypatch.setattr(threading.Thread, "start", real_start)
        release.set()
        old_worker.thread.join(5)
        engine.shutdown()


def test_n1_failed_suspension_handoff_preserves_history_until_explicit_readmission(
    monkeypatch,
    tmp_path,
):
    home_one = tmp_path / "home-one"
    home_two = tmp_path / "home-two"
    root_one = home_one / "lcm-large-outputs"
    root_two = home_two / "lcm-large-outputs"
    _payload(root_one / "shared.json", "approved root payload")
    _payload(root_two / "shared.json", "different candidate payload")
    engine = LCMEngine(
        config=LCMConfig(
            database_path=str(tmp_path / "shared.db"),
            periodic_backup_enabled=False,
            periodic_backup_interval_hours=0.000001,
            periodic_backup_keep_last=2,
            periodic_backup_path=str(tmp_path / "periodic"),
        ),
        hermes_home=str(home_one),
    )
    _append(engine, content=_placeholder("shared.json"))
    original_spec = periodic.build_periodic_backup_spec(engine)
    assert periodic.run_periodic_backup(original_spec, due_only=False)["status"] == "ok"
    pointer_before = (original_spec.namespace / "latest-good.json").read_bytes()
    generations_before = [path.name for path in _generation_dirs(original_spec)]

    entered = threading.Event()
    release = threading.Event()
    real_start = threading.Thread.start
    real_run = periodic.run_periodic_backup

    def blocked_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        entered.set()
        assert release.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    def fail_only_handoff_start(thread: threading.Thread) -> None:
        if thread.name.startswith("lcm-backup-handoff-"):
            raise RuntimeError("injected suspension handoff start failure")
        real_start(thread)

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_run)
    engine._config.periodic_backup_enabled = True
    engine._periodic_backup_registration = periodic.acquire_backup_lease(engine)
    key = engine._periodic_backup_registration.source_key
    source = periodic._SCHEDULERS[key]
    old_worker = source.scheduler
    assert old_worker is not None
    retry = None
    try:
        assert entered.wait(5)
        monkeypatch.setattr(threading.Thread, "start", fail_only_handoff_start)
        assert engine._rebind_storage_for_home(str(home_two)) is True
        failed = engine._periodic_backup_registration
        assert failed.state == "error"
        assert failed.reason.startswith("periodic_handoff_start_failed:")
        assert source.state == "ERROR"
        assert source.readmission_required is True
        assert not source.active_owners
        assert not source.pending_owners
        assert not source.suspended_owners

        release.set()
        old_worker.thread.join(5)
        assert not old_worker.thread.is_alive()
        monkeypatch.setattr(threading.Thread, "start", real_start)
        monkeypatch.setattr(periodic, "run_periodic_backup", real_run)

        retry = periodic.acquire_backup_lease(engine)
        assert retry.state == "suspended"
        status = periodic.periodic_backup_source_status(key)
        assert status is not None
        assert status["state"] == "SUSPENDED"
        assert status["readmission_required"] is True
        assert status["approved_root"] == str(root_one.resolve())
        assert (original_spec.namespace / "latest-good.json").read_bytes() == pointer_before
        assert [path.name for path in _generation_dirs(original_spec)] == generations_before

        rejected = periodic.resume_backup_source(key, root_two)
        assert rejected.state == "suspended"
        assert "historical_reference_readmission_failed:" in rejected.reason
        assert (original_spec.namespace / "latest-good.json").read_bytes() == pointer_before
        assert [path.name for path in _generation_dirs(original_spec)] == generations_before

        assert periodic.release_backup_lease(retry) is True
        retry = None
        admitted = periodic.resume_backup_source(key, root_one)
        assert admitted.state == "active"
        assert engine._rebind_storage_for_home(str(home_one)) is True
        registration = engine._periodic_backup_registration
        assert registration.state == "active"
        resumed = periodic.periodic_backup_source_status(key)
        assert resumed is not None
        assert resumed["readmission_required"] is False
        assert resumed["approved_root"] == str(root_one.resolve())
        assert resumed["worker_alive"] is True
    finally:
        monkeypatch.setattr(threading.Thread, "start", real_start)
        monkeypatch.setattr(periodic, "run_periodic_backup", real_run)
        release.set()
        if retry is not None:
            periodic.release_backup_lease(retry)
        engine.shutdown()


def test_n1_direct_readmission_reaps_dead_failed_suspension_handoff(
    monkeypatch,
    tmp_path,
):
    home_one = tmp_path / "home-one"
    home_two = tmp_path / "home-two"
    root_one = home_one / "lcm-large-outputs"
    root_two = home_two / "lcm-large-outputs"
    _payload(root_one / "shared.json", "approved root payload")
    _payload(root_two / "shared.json", "different candidate payload")
    engine = LCMEngine(
        config=LCMConfig(
            database_path=str(tmp_path / "shared.db"),
            periodic_backup_enabled=False,
            periodic_backup_interval_hours=0.000001,
            periodic_backup_keep_last=2,
            periodic_backup_path=str(tmp_path / "periodic"),
        ),
        hermes_home=str(home_one),
    )
    _append(engine, content=_placeholder("shared.json"))
    original_spec = periodic.build_periodic_backup_spec(engine)
    assert periodic.run_periodic_backup(original_spec, due_only=False)["status"] == "ok"
    pointer_before = (original_spec.namespace / "latest-good.json").read_bytes()

    entered = threading.Event()
    release = threading.Event()
    real_start = threading.Thread.start
    real_run = periodic.run_periodic_backup

    def blocked_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        entered.set()
        assert release.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    def fail_only_handoff_start(thread: threading.Thread) -> None:
        if thread.name.startswith("lcm-backup-handoff-"):
            raise RuntimeError("injected suspension handoff start failure")
        real_start(thread)

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_run)
    engine._config.periodic_backup_enabled = True
    engine._periodic_backup_registration = periodic.acquire_backup_lease(engine)
    key = engine._periodic_backup_registration.source_key
    source = periodic._SCHEDULERS[key]
    old_worker = source.scheduler
    assert old_worker is not None
    try:
        assert entered.wait(5)
        monkeypatch.setattr(threading.Thread, "start", fail_only_handoff_start)
        assert engine._rebind_storage_for_home(str(home_two)) is True
        assert engine._periodic_backup_registration.state == "error"
        assert source.state == "ERROR"
        assert source.readmission_required is True

        release.set()
        old_worker.thread.join(5)
        assert not old_worker.thread.is_alive()
        monkeypatch.setattr(threading.Thread, "start", real_start)
        monkeypatch.setattr(periodic, "run_periodic_backup", real_run)

        # Readmission itself must reconcile the retained ERROR tombstone. No
        # status query or ordinary acquisition may be needed as a side effect.
        admitted = periodic.resume_backup_source(key, root_one)
        assert admitted.state == "active"
        assert source.state == "ACTIVE"
        assert source.scheduler is None
        assert source.readmission_required is False
        assert source.readmission_armed is True
        assert source.approved_root.path == root_one.resolve()
        assert (original_spec.namespace / "latest-good.json").read_bytes() == pointer_before
        status = periodic.periodic_backup_source_status(key)
        assert status is not None
        assert status["readmission_armed"] is True
        assert periodic.resume_backup_source(key, root_one).state == "active"

        # The next compatible ordinary admission consumes the armed authority,
        # owns the source, and is the only path that starts a replacement.
        assert engine._rebind_storage_for_home(str(home_one)) is True
        assert engine._periodic_backup_registration.state == "active"
        assert source.readmission_armed is False
        assert source.scheduler is not None
        assert source.scheduler is not old_worker
    finally:
        monkeypatch.setattr(threading.Thread, "start", real_start)
        monkeypatch.setattr(periodic, "run_periodic_backup", real_run)
        release.set()
        old_worker.thread.join(5)
        engine.shutdown()


def test_n4_worker_start_failure_after_ownerless_readmission_retains_authority(
    monkeypatch,
    tmp_path,
):
    home_one = tmp_path / "home-one"
    home_two = tmp_path / "home-two"
    root_one = home_one / "lcm-large-outputs"
    root_two = home_two / "lcm-large-outputs"
    _payload(root_one / "shared.json", "approved root payload")
    _payload(root_two / "shared.json", "different candidate payload")
    engine = LCMEngine(
        config=LCMConfig(
            database_path=str(tmp_path / "shared.db"),
            periodic_backup_enabled=False,
            periodic_backup_interval_hours=0.000001,
            periodic_backup_keep_last=2,
            periodic_backup_path=str(tmp_path / "periodic"),
        ),
        hermes_home=str(home_one),
    )
    _append(engine, content=_placeholder("shared.json"))
    original_spec = periodic.build_periodic_backup_spec(engine)
    assert periodic.run_periodic_backup(original_spec, due_only=False)["status"] == "ok"
    pointer_before = (original_spec.namespace / "latest-good.json").read_bytes()
    generations_before = [path.name for path in _generation_dirs(original_spec)]

    entered = threading.Event()
    release_old = threading.Event()
    replacement_started = threading.Event()
    release_replacement = threading.Event()
    real_start = threading.Thread.start
    real_run = periodic.run_periodic_backup

    def blocked_old_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        entered.set()
        assert release_old.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    def blocked_replacement_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        replacement_started.set()
        assert release_replacement.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    def fail_handoff_start(thread: threading.Thread) -> None:
        if thread.name.startswith("lcm-backup-handoff-"):
            raise RuntimeError("injected suspension handoff start failure")
        real_start(thread)

    def fail_worker_start(thread: threading.Thread) -> None:
        if thread.name.startswith("lcm-periodic-backup-"):
            raise RuntimeError("injected post-readmission worker start failure")
        real_start(thread)

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_old_run)
    engine._config.periodic_backup_enabled = True
    engine._periodic_backup_registration = periodic.acquire_backup_lease(engine)
    key = engine._periodic_backup_registration.source_key
    source = periodic._SCHEDULERS[key]
    old_worker = source.scheduler
    assert old_worker is not None
    try:
        assert entered.wait(5)
        monkeypatch.setattr(threading.Thread, "start", fail_handoff_start)
        assert engine._rebind_storage_for_home(str(home_two)) is True
        assert engine._periodic_backup_registration.state == "error"
        release_old.set()
        old_worker.thread.join(5)
        assert not old_worker.thread.is_alive()

        monkeypatch.setattr(threading.Thread, "start", real_start)
        assert periodic.resume_backup_source(key, root_one).state == "active"
        assert source.readmission_armed is True

        monkeypatch.setattr(threading.Thread, "start", fail_worker_start)
        assert engine._rebind_storage_for_home(str(home_one)) is True
        failed = engine._periodic_backup_registration
        assert failed.state == "error"
        assert failed.reason.startswith("periodic_worker_start_failed:")
        assert periodic._SCHEDULERS.get(key) is source
        assert source.readmission_armed is True
        assert source.approved_root.path == root_one.resolve()

        monkeypatch.setattr(threading.Thread, "start", real_start)
        monkeypatch.setattr(periodic, "run_periodic_backup", blocked_replacement_run)
        assert engine._rebind_storage_for_home(str(home_two)) is True
        assert engine._periodic_backup_registration.state == "error"
        assert periodic._SCHEDULERS.get(key) is source
        assert source.approved_root.path == root_one.resolve()
        assert replacement_started.wait(0.2) is False
        with source.publication_gate(source.publication_epoch) as allowed:
            assert allowed is False
        assert (original_spec.namespace / "latest-good.json").read_bytes() == pointer_before
        assert [path.name for path in _generation_dirs(original_spec)] == generations_before

        # A compatible explicit retry may re-arm ordinary acquisition. The
        # authority is consumed only after exactly one worker really starts.
        assert periodic.resume_backup_source(key, root_one).state == "active"
        assert engine._rebind_storage_for_home(str(home_one)) is True
        assert engine._periodic_backup_registration.state == "active"
        assert replacement_started.wait(5)
        assert source.scheduler is not None
        assert source.scheduler is not old_worker
        assert source.readmission_armed is False
        worker_prefix = f"lcm-periodic-backup-{source.spec.source_identity[:12]}"
        assert len(
            [thread for thread in threading.enumerate() if thread.name.startswith(worker_prefix)]
        ) == 1
    finally:
        monkeypatch.setattr(threading.Thread, "start", real_start)
        monkeypatch.setattr(periodic, "run_periodic_backup", real_run)
        release_old.set()
        release_replacement.set()
        old_worker.thread.join(5)
        engine.shutdown()


def test_n4_retained_owner_readmission_start_failure_preserves_root_authority(
    monkeypatch,
    tmp_path,
):
    home_one = tmp_path / "home-one"
    home_two = tmp_path / "home-two"
    root_one = home_one / "lcm-large-outputs"
    root_two = home_two / "lcm-large-outputs"
    _payload(root_one / "shared.json", "approved root payload")
    _payload(root_two / "shared.json", "different candidate payload")
    def config():
        return LCMConfig(
            database_path=str(tmp_path / "shared.db"),
            periodic_backup_enabled=False,
            periodic_backup_interval_hours=0.000001,
            periodic_backup_keep_last=2,
            periodic_backup_path=str(tmp_path / "periodic"),
        )

    engine_one = LCMEngine(config=config(), hermes_home=str(home_one))
    _append(engine_one, content=_placeholder("shared.json"))
    original_spec = periodic.build_periodic_backup_spec(engine_one)
    assert periodic.run_periodic_backup(original_spec, due_only=False)["status"] == "ok"
    pointer_before = (original_spec.namespace / "latest-good.json").read_bytes()
    generations_before = [path.name for path in _generation_dirs(original_spec)]

    entered = threading.Event()
    release_old = threading.Event()
    replacement_started = threading.Event()
    release_replacement = threading.Event()
    real_start = threading.Thread.start
    real_run = periodic.run_periodic_backup

    def blocked_old_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        entered.set()
        assert release_old.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    def blocked_replacement_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        replacement_started.set()
        assert release_replacement.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    def fail_worker_start(thread: threading.Thread) -> None:
        if thread.name.startswith("lcm-periodic-backup-"):
            raise RuntimeError("injected retained-owner readmission worker start failure")
        real_start(thread)

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_old_run)
    engine_one._config.periodic_backup_enabled = True
    engine_one._periodic_backup_registration = periodic.acquire_backup_lease(engine_one)
    key = engine_one._periodic_backup_registration.source_key
    source = periodic._SCHEDULERS[key]
    old_worker = source.scheduler
    assert old_worker is not None
    engine_two = None
    engine_three = None
    engine_four = None
    try:
        assert entered.wait(5)
        engine_two = LCMEngine(config=config(), hermes_home=str(home_two))
        engine_two._config.periodic_backup_enabled = True
        engine_two._periodic_backup_registration = periodic.acquire_backup_lease(engine_two)
        assert engine_two._periodic_backup_registration.state == "suspended"
        assert engine_one._periodic_backup_registration.state == "suspended"
        assert source.readmission_required is True

        release_old.set()
        old_worker.thread.join(5)
        assert not old_worker.thread.is_alive()
        handoff = source.handoff_thread
        if handoff is not None:
            handoff.join(5)
            assert not handoff.is_alive()
        assert source.suspended_owners

        monkeypatch.setattr(threading.Thread, "start", fail_worker_start)
        failed = periodic.resume_backup_source(key, root_one)
        assert failed.state == "error"
        assert failed.reason.startswith("periodic_worker_start_failed:")
        assert periodic._SCHEDULERS.get(key) is source
        assert source.readmission_required is True
        assert source.approved_root.path == root_one.resolve()

        monkeypatch.setattr(threading.Thread, "start", real_start)
        monkeypatch.setattr(periodic, "run_periodic_backup", blocked_replacement_run)
        engine_three = LCMEngine(config=config(), hermes_home=str(home_two))
        engine_three._config.periodic_backup_enabled = True
        engine_three._periodic_backup_registration = periodic.acquire_backup_lease(engine_three)
        assert engine_three._periodic_backup_registration.state == "suspended"
        assert periodic._SCHEDULERS.get(key) is source
        assert source.approved_root.path == root_one.resolve()
        assert replacement_started.wait(0.2) is False
        with source.publication_gate(source.publication_epoch) as allowed:
            assert allowed is False
        assert (original_spec.namespace / "latest-good.json").read_bytes() == pointer_before
        assert [path.name for path in _generation_dirs(original_spec)] == generations_before

        # A compatible ordinary lease remains suspended until the sole explicit
        # readmission API validates R1, then that retained owner starts exactly
        # one replacement worker.
        engine_four = LCMEngine(config=config(), hermes_home=str(home_one))
        engine_four._config.periodic_backup_enabled = True
        engine_four._periodic_backup_registration = periodic.acquire_backup_lease(engine_four)
        assert engine_four._periodic_backup_registration.state == "suspended"
        assert periodic.resume_backup_source(key, root_one).state == "active"
        assert replacement_started.wait(5)
        assert source.scheduler is not None
        assert source.scheduler is not old_worker
        assert source.readmission_required is False
        assert source.readmission_armed is False
        worker_prefix = f"lcm-periodic-backup-{source.spec.source_identity[:12]}"
        assert len(
            [thread for thread in threading.enumerate() if thread.name.startswith(worker_prefix)]
        ) == 1
    finally:
        monkeypatch.setattr(threading.Thread, "start", real_start)
        monkeypatch.setattr(periodic, "run_periodic_backup", real_run)
        release_old.set()
        release_replacement.set()
        old_worker.thread.join(5)
        for engine in (engine_four, engine_three, engine_two, engine_one):
            if engine is not None:
                engine.shutdown()


def test_n1_unowned_suspended_source_blocks_ordinary_registration_until_old_exit(
    monkeypatch,
    tmp_path,
):
    home_one = tmp_path / "home-one"
    home_two = tmp_path / "home-two"
    for home in (home_one, home_two):
        root = home / "lcm-large-outputs"
        root.mkdir(parents=True)
        root.chmod(0o700)
    entered = threading.Event()
    release = threading.Event()

    def blocked_run(*_args, cancel=None, **_kwargs):
        assert cancel is not None
        entered.set()
        assert release.wait(5)
        return {"ok": False, "status": "cancelled" if cancel.is_set() else "failed"}

    monkeypatch.setattr(periodic, "run_periodic_backup", blocked_run)
    monkeypatch.setattr(periodic, "_SCHEDULER_SHUTDOWN_TIMEOUT_SECONDS", 0.05)
    first = LCMEngine(
        config=LCMConfig(
            database_path=str(tmp_path / "shared.db"),
            periodic_backup_enabled=True,
            periodic_backup_interval_hours=0.00001,
            periodic_backup_keep_last=2,
            periodic_backup_path=str(tmp_path / "periodic"),
        ),
        hermes_home=str(home_one),
    )
    second = LCMEngine(
        config=LCMConfig(
            database_path=str(tmp_path / "shared.db"),
            periodic_backup_enabled=False,
            periodic_backup_interval_hours=0.00001,
            periodic_backup_keep_last=2,
            periodic_backup_path=str(tmp_path / "periodic"),
        ),
        hermes_home=str(home_two),
    )
    key = first._periodic_backup_registration.source_key
    source = periodic._SCHEDULERS[key]
    old_worker = source.scheduler
    assert old_worker is not None
    try:
        assert entered.wait(5)
        assert first._rebind_storage_for_home(str(home_two)) is True
        assert first._periodic_backup_registration.state == "suspended"
        first.shutdown()
        assert not source.active_owners
        assert not source.pending_owners
        assert not source.suspended_owners
        assert old_worker.thread.is_alive()

        second._config.periodic_backup_enabled = True
        second._periodic_backup_registration = periodic.acquire_backup_lease(second)
        assert second._periodic_backup_registration.state == "suspended"
        assert source.scheduler is old_worker
        assert old_worker.thread.is_alive()

        release.set()
        old_worker.thread.join(5)
        assert not old_worker.thread.is_alive()
        assert periodic.periodic_backup_source_status(key) is not None
        second.shutdown()
        _wait_for(lambda: periodic.periodic_backup_source_status(key) is None)
    finally:
        release.set()
        old_worker.thread.join(5)
        second.shutdown()
        first.shutdown()


def test_n4_missing_payload_root_is_nonfatal_and_retry_admits_real_engine(tmp_path):
    payload_root = tmp_path / "missing-payload-root"
    engine = _engine(tmp_path, enabled=True, payload_root=payload_root)
    try:
        registration = engine._periodic_backup_registration
        assert registration.state == "error"
        assert registration.reason == "periodic payload root does not exist"
        assert registration.source_key == ""
        source_key = str((tmp_path / "database" / "lcm.db").resolve())
        assert source_key not in periodic._SCHEDULERS

        _payload(payload_root / "payload.json", "materialized after failed admission")
        _append(engine, content=_placeholder("payload.json"))
        engine._periodic_backup_registration = periodic.acquire_backup_lease(engine)
        registration = engine._periodic_backup_registration
        assert registration.state == "active"
        assert registration.reason == ""
        key = registration.source_key
        status = periodic.periodic_backup_source_status(key)
        assert status is not None
        assert status["approved_root"] == str(payload_root.resolve())
        assert status["approved_root_identity"] == (
            os.lstat(payload_root).st_dev,
            os.lstat(payload_root).st_ino,
        )
        assert status["approved_root_identity"] != (0, 0)
        assert status["active_leases"] == 1

        spec = periodic.build_periodic_backup_spec(engine)
        _wait_for(lambda: (spec.namespace / "latest-good.json").exists())
        assert periodic._read_verified_pointer(spec) is not None
    finally:
        engine.shutdown()


def test_n4_invalid_retention_is_nonfatal_and_allocates_no_backup_state(tmp_path):
    payload_root = tmp_path / "payloads"
    payload_root.mkdir(mode=0o700)
    config = LCMConfig(
        database_path=str(tmp_path / "database" / "lcm.db"),
        large_output_externalization_path=str(payload_root),
        periodic_backup_path=str(tmp_path / "periodic"),
    )
    # A mutable runtime config can change after dataclass construction. Enabled
    # admission must validate it again before allocating any backup state.
    config.periodic_backup_enabled = True
    config.periodic_backup_keep_last = 0
    engine = LCMEngine(config=config, hermes_home=str(tmp_path / "home"))
    try:
        registration = engine._periodic_backup_registration
        assert registration.state == "error"
        assert registration.source_key == ""
        assert "periodic_backup_keep_last must be an integer greater than zero" in registration.reason
        source_key = str((tmp_path / "database" / "lcm.db").resolve())
        assert source_key not in periodic._SCHEDULERS

        _append(engine, content="LCM remains usable after invalid retention admission failure")
        worker_prefix = f"lcm-periodic-backup-{periodic._source_identity(Path(source_key))[:12]}"
        assert not any(thread.name.startswith(worker_prefix) for thread in threading.enumerate())
    finally:
        engine.shutdown()


@pytest.mark.parametrize(
    ("failure", "expected_reason"),
    [
        ("unsafe_destination", "backup path is not a plain directory"),
        ("unsupported_lock", "POSIX flock is required"),
        ("unsafe_payload_root", "periodic payload root is not private"),
    ],
)
def test_n4_admission_errors_are_nonfatal_and_allocate_no_backup_state(
    monkeypatch,
    tmp_path,
    failure,
    expected_reason,
):
    destination = None
    payload_root = None
    if failure == "unsafe_destination":
        destination = tmp_path / "not-a-directory"
        destination.write_text("not a backup root", encoding="utf-8")
    elif failure == "unsupported_lock":
        monkeypatch.setattr(periodic, "_fcntl", None)
    else:
        payload_root = tmp_path / "world-readable-payloads"
        payload_root.mkdir(mode=0o777)
        payload_root.chmod(0o777)

    engine = _engine(
        tmp_path,
        enabled=True,
        destination=destination,
        payload_root=payload_root,
    )
    try:
        registration = engine._periodic_backup_registration
        assert registration.state == "error"
        assert registration.active is False
        assert registration.source_key == ""
        assert expected_reason in registration.reason
        source_key = str((tmp_path / "database" / "lcm.db").resolve())
        assert source_key not in periodic._SCHEDULERS

        # Scheduler admission is optional. The ordinary LCM store remains
        # usable without a registry entry, lease, worker, or watcher.
        _append(engine, content="LCM remains usable after backup admission failure")
        worker_prefix = (
            f"lcm-periodic-backup-"
            f"{periodic._source_identity(Path(source_key))[:12]}"
        )
        assert not any(
            thread.name.startswith(worker_prefix) for thread in threading.enumerate()
        )
    finally:
        engine.shutdown()
