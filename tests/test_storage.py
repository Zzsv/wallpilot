from __future__ import annotations

from pathlib import Path

import pytest

from wallpilot.config import Settings
from wallpilot.security import totp_code
from wallpilot.storage import Store


def make_store(tmp_path: Path) -> Store:
    return Store(Settings(state_dir=tmp_path, apply_timeout_seconds=1))


def initialize_admin(store: Store) -> None:
    bootstrap = store.ensure_bootstrap()
    store.create_admin(
        bootstrap["token"],
        "Correct-Horse-42!",
        totp_code(bootstrap["totp_secret"]),
    )


def test_bootstrap_can_only_initialize_once(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    initialize_admin(store)
    assert store.is_initialized()
    try:
        store.ensure_bootstrap()
    except RuntimeError as exc:
        assert "已经" in str(exc)
    else:
        raise AssertionError("bootstrap unexpectedly reused")


def test_session_is_stored_as_a_hash(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    initialize_admin(store)
    with store.connect() as conn:
        secret = conn.execute("SELECT totp_secret FROM admin WHERE id=1").fetchone()[0]
    raw, csrf = store.authenticate(
        "Correct-Horse-42!", totp_code(secret), "127.0.0.1"
    )
    assert store.verify_session(raw)["csrf"] == csrf
    with store.connect() as conn:
        persisted = conn.execute("SELECT token_hash FROM sessions").fetchone()[0]
    assert persisted != raw


def test_recycle_snapshot_is_checksummed_and_audited(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    item = store.add_recycle_item(
        backend="ufw",
        system_version="Ubuntu 24.04",
        object_type="rule",
        object_name="443/tcp",
        fingerprint="abc",
        payload={"port": "443"},
        dependencies=[],
        runtime_before={"rules": []},
        permanent_before={"rules": []},
        source="127.0.0.1",
        reason="test",
    )
    assert item["integrity_ok"] is True
    assert (tmp_path / "recycle" / f"{item['id']}.json").exists()
    with store.connect() as conn:
        conn.execute(
            "UPDATE recycle_bin SET payload='{\"port\":\"22\"}' WHERE id=?",
            (item["id"],),
        )
    assert store.get_recycle_item(item["id"])["integrity_ok"] is False


def test_purge_removes_snapshot_but_keeps_audit(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    item = store.add_recycle_item(
        backend="ufw",
        system_version="Ubuntu",
        object_type="rule",
        object_name="53/udp",
        fingerprint="dns",
        payload={"port": "53"},
        dependencies=[],
        runtime_before={},
        permanent_before={},
        source="local",
        reason="cleanup",
    )
    store.purge_recycle_item(item["id"])
    assert store.get_recycle_item(item["id"]) is None
    assert any(row["event"] == "recycle.purged" for row in store.list_audit())


def test_corrupt_database_stops_without_overwriting_data(tmp_path: Path) -> None:
    settings = Settings(state_dir=tmp_path)
    settings.ensure_directories()
    original = b"not a sqlite database"
    settings.database_path.write_bytes(original)
    with pytest.raises(RuntimeError, match="停止启动"):
        Store(settings)
    assert settings.database_path.read_bytes() == original


def test_recovery_code_is_returned_once_and_consumed_once(tmp_path: Path) -> None:
    store = make_store(tmp_path)
    bootstrap = store.ensure_bootstrap()
    codes = store.create_admin(
        bootstrap["token"],
        "Correct-Horse-42!",
        totp_code(bootstrap["totp_secret"]),
    )
    assert len(codes) == 8
    raw, _csrf = store.authenticate(
        "Correct-Horse-42!", codes[0].lower(), "127.0.0.1"
    )
    store.logout(raw)
    with pytest.raises(ValueError, match="错误"):
        store.authenticate(
            "Correct-Horse-42!", codes[0], "127.0.0.1"
        )
