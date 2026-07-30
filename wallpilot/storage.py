from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Iterator

from .compat import UTC
from .config import Settings
from .security import (
    PasswordHasher,
    generate_totp_secret,
    new_session_token,
    secure_file_mode,
    token_hash,
    verify_totp,
)


def _now() -> datetime:
    return datetime.now(UTC)


def _json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


class Store:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.settings.ensure_directories()
        self.passwords = PasswordHasher()
        try:
            self._initialize()
        except sqlite3.DatabaseError as exc:
            raise RuntimeError(
                "WallPilot 数据库无法读取，已停止启动以避免覆盖恢复数据"
            ) from exc

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.settings.database_path, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=FULL")
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def _initialize(self) -> None:
        with self.connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS settings (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS admin (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    username TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    totp_secret TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS sessions (
                    token_hash TEXT PRIMARY KEY,
                    csrf TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    last_seen TEXT NOT NULL,
                    absolute_expires_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS login_attempts (
                    source TEXT NOT NULL,
                    attempted_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS recovery_codes (
                    code_hash TEXT PRIMARY KEY,
                    used_at TEXT
                );
                CREATE TABLE IF NOT EXISTS drafts (
                    id TEXT PRIMARY KEY,
                    operation TEXT NOT NULL,
                    object_type TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    risk TEXT NOT NULL,
                    confirmation_hash TEXT NOT NULL,
                    requires_totp INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS apply_sessions (
                    id TEXT PRIMARY KEY,
                    draft_id TEXT,
                    kind TEXT NOT NULL,
                    operation TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    inverse_operation TEXT NOT NULL,
                    before_snapshot TEXT NOT NULL,
                    deadline TEXT NOT NULL,
                    status TEXT NOT NULL,
                    recycle_id TEXT,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS recycle_bin (
                    id TEXT PRIMARY KEY,
                    batch_id TEXT NOT NULL,
                    backend TEXT NOT NULL,
                    system_version TEXT NOT NULL,
                    object_type TEXT NOT NULL,
                    object_name TEXT NOT NULL,
                    fingerprint TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    dependencies TEXT NOT NULL,
                    runtime_before TEXT NOT NULL,
                    permanent_before TEXT NOT NULL,
                    deleted_at TEXT NOT NULL,
                    deleted_by TEXT NOT NULL,
                    source TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    config_hash TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    status TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    event TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    source TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS backups (
                    id TEXT PRIMARY KEY,
                    label TEXT NOT NULL,
                    snapshot TEXT NOT NULL,
                    checksum TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS metrics (
                    collected_at TEXT PRIMARY KEY,
                    payload TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS temporary_rules (
                    id TEXT PRIMARY KEY,
                    backend TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    status TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
            )
            recycle_columns = {
                str(row["name"])
                for row in conn.execute("PRAGMA table_info(recycle_bin)").fetchall()
            }
            if "config_hash" not in recycle_columns:
                conn.execute(
                    "ALTER TABLE recycle_bin "
                    "ADD COLUMN config_hash TEXT NOT NULL DEFAULT ''"
                )
            if conn.execute("SELECT 1 FROM settings WHERE key='state_secret'").fetchone() is None:
                conn.execute(
                    "INSERT INTO settings(key,value) VALUES('state_secret',?)",
                    (secrets.token_hex(32),),
                )
            quick_check = conn.execute("PRAGMA quick_check").fetchone()
            if not quick_check or str(quick_check[0]).lower() != "ok":
                raise sqlite3.DatabaseError("SQLite quick_check failed")
        secure_file_mode(self.settings.database_path)

    def _setting(self, key: str) -> str | None:
        with self.connect() as conn:
            row = conn.execute("SELECT value FROM settings WHERE key=?", (key,)).fetchone()
        return str(row["value"]) if row else None

    def _set_setting(self, key: str, value: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, value),
            )

    def is_initialized(self) -> bool:
        with self.connect() as conn:
            return conn.execute("SELECT 1 FROM admin WHERE id=1").fetchone() is not None

    def ensure_bootstrap(self) -> dict[str, str]:
        if self.is_initialized():
            raise RuntimeError("管理员已经初始化")
        expires_raw = self._setting("bootstrap_expires")
        token = ""
        secret = self._setting("bootstrap_totp") or ""
        if self.settings.bootstrap_path.exists() and expires_raw:
            try:
                if datetime.fromisoformat(expires_raw) > _now():
                    document = json.loads(
                        self.settings.bootstrap_path.read_text(encoding="utf-8")
                    )
                    token = str(document.get("token", ""))
                    secret = str(document.get("totp_secret", secret))
            except (OSError, ValueError, json.JSONDecodeError):
                token = ""
        if not token:
            token = secrets.token_urlsafe(32)
            secret = generate_totp_secret()
            expires = _now() + timedelta(seconds=self.settings.bootstrap_lifetime_seconds)
            self._set_setting("bootstrap_hash", token_hash(token))
            self._set_setting("bootstrap_totp", secret)
            self._set_setting("bootstrap_expires", expires.isoformat())
            self.settings.bootstrap_path.write_text(
                _json({"token": token, "totp_secret": secret, "expires": expires.isoformat()}),
                encoding="utf-8",
            )
            secure_file_mode(self.settings.bootstrap_path)
        return {
            "token": token,
            "totp_secret": secret,
            "expires": self._setting("bootstrap_expires") or "",
        }

    def create_admin(self, token: str, password: str, totp: str) -> list[str]:
        if self.is_initialized():
            raise ValueError("管理员已经初始化")
        expected = self._setting("bootstrap_hash") or ""
        expires = self._setting("bootstrap_expires") or ""
        secret = self._setting("bootstrap_totp") or ""
        if not expected or not hmac.compare_digest(expected, token_hash(token)):
            raise ValueError("引导令牌无效")
        try:
            if datetime.fromisoformat(expires) <= _now():
                raise ValueError("引导令牌已过期")
        except ValueError as exc:
            raise ValueError("引导令牌已过期") from exc
        if not verify_totp(secret, totp):
            raise ValueError("动态验证码无效")
        password_hash = self.passwords.hash(password)
        alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
        recovery_codes = [
            "".join(secrets.choice(alphabet) for _ in range(4))
            + "-"
            + "".join(secrets.choice(alphabet) for _ in range(4))
            for _ in range(8)
        ]
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO admin(id,username,password_hash,totp_secret,created_at) "
                "VALUES(1,'admin',?,?,?)",
                (password_hash, secret, _now().isoformat()),
            )
            conn.execute(
                "DELETE FROM settings WHERE key IN "
                "('bootstrap_hash','bootstrap_totp','bootstrap_expires')"
            )
            conn.executemany(
                "INSERT INTO recovery_codes(code_hash,used_at) VALUES(?,NULL)",
                [(token_hash(code),) for code in recovery_codes],
            )
        try:
            self.settings.bootstrap_path.unlink()
        except FileNotFoundError:
            pass
        self.audit("auth.setup", "admin", "local", {"result": "success"})
        return recovery_codes

    def authenticate(
        self, password: str, totp: str, source: str
    ) -> tuple[str, str]:
        self._check_rate_limit(source)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT password_hash,totp_secret FROM admin WHERE id=1"
            ).fetchone()
        password_valid = bool(
            row and self.passwords.verify(str(row["password_hash"]), password)
        )
        second_factor_valid = bool(
            row and verify_totp(str(row["totp_secret"]), totp)
        )
        used_recovery = False
        if password_valid and not second_factor_valid:
            normalized = totp.strip().upper()
            if len(normalized) <= 32:
                digest = token_hash(normalized)
                with self.connect() as conn:
                    code = conn.execute(
                        "SELECT used_at FROM recovery_codes WHERE code_hash=?",
                        (digest,),
                    ).fetchone()
                    if code and code["used_at"] is None:
                        updated = conn.execute(
                            "UPDATE recovery_codes SET used_at=? "
                            "WHERE code_hash=? AND used_at IS NULL",
                            (_now().isoformat(), digest),
                        )
                        used_recovery = updated.rowcount == 1
        valid = password_valid and (second_factor_valid or used_recovery)
        if not valid:
            with self.connect() as conn:
                conn.execute(
                    "INSERT INTO login_attempts(source,attempted_at) VALUES(?,?)",
                    (source, _now().isoformat()),
                )
            self.audit("auth.login_failed", "anonymous", source, {})
            raise ValueError("用户名、密码或动态验证码错误")
        session = new_session_token()
        now = _now()
        absolute = now + timedelta(seconds=self.settings.session_absolute_seconds)
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO sessions(token_hash,csrf,created_at,last_seen,absolute_expires_at) "
                "VALUES(?,?,?,?,?)",
                (session.digest, session.csrf, now.isoformat(), now.isoformat(), absolute.isoformat()),
            )
        self.audit(
            "auth.login",
            "admin",
            source,
            {"recovery_code": used_recovery},
        )
        return session.raw, session.csrf

    def _check_rate_limit(self, source: str) -> None:
        cutoff = (_now() - timedelta(minutes=15)).isoformat()
        with self.connect() as conn:
            conn.execute("DELETE FROM login_attempts WHERE attempted_at < ?", (cutoff,))
            count = conn.execute(
                "SELECT COUNT(*) AS count FROM login_attempts "
                "WHERE source=? AND attempted_at>=?",
                (source, cutoff),
            ).fetchone()["count"]
        if int(count) >= 5:
            raise ValueError("登录失败次数过多，请稍后再试")

    def verify_session(self, raw_token: str) -> dict[str, str] | None:
        digest = token_hash(raw_token)
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM sessions WHERE token_hash=?", (digest,)
            ).fetchone()
            if row is None:
                return None
            now = _now()
            last_seen = datetime.fromisoformat(str(row["last_seen"]))
            absolute = datetime.fromisoformat(str(row["absolute_expires_at"]))
            if (
                now - last_seen > timedelta(seconds=self.settings.session_idle_seconds)
                or now >= absolute
            ):
                conn.execute("DELETE FROM sessions WHERE token_hash=?", (digest,))
                return None
            conn.execute(
                "UPDATE sessions SET last_seen=? WHERE token_hash=?",
                (now.isoformat(), digest),
            )
        return {"username": "admin", "csrf": str(row["csrf"])}

    def logout(self, raw_token: str) -> None:
        with self.connect() as conn:
            conn.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash(raw_token),))

    def verify_admin(self, password: str, totp: str) -> bool:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT password_hash,totp_secret FROM admin WHERE id=1"
            ).fetchone()
        return bool(
            row
            and self.passwords.verify(str(row["password_hash"]), password)
            and verify_totp(str(row["totp_secret"]), totp)
        )

    def verify_admin_totp(self, code: str) -> bool:
        with self.connect() as conn:
            row = conn.execute("SELECT totp_secret FROM admin WHERE id=1").fetchone()
        return bool(row and verify_totp(str(row["totp_secret"]), code))

    def create_draft(
        self,
        operation: str,
        object_type: str,
        payload: dict[str, Any],
        reason: str,
        risk: str,
        requires_totp: bool,
    ) -> tuple[dict[str, Any], str]:
        draft_id = str(uuid.uuid4())
        code = f"{secrets.randbelow(1_000_000):06d}"
        created = _now().isoformat()
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO drafts VALUES(?,?,?,?,?,?,?,?,?,?)",
                (
                    draft_id,
                    operation,
                    object_type,
                    _json(payload),
                    reason,
                    risk,
                    token_hash(code),
                    int(requires_totp),
                    "pending",
                    created,
                ),
            )
        self.audit(
            "draft.created",
            "admin",
            "web",
            {"id": draft_id, "operation": operation, "object_type": object_type},
        )
        return self.get_draft(draft_id) or {}, code

    def get_draft(self, draft_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute("SELECT * FROM drafts WHERE id=?", (draft_id,)).fetchone()
        return self._row_document(row, json_fields={"payload"}) if row else None

    def confirm_draft_code(self, draft_id: str, code: str) -> dict[str, Any]:
        draft = self.get_draft(draft_id)
        if not draft or draft["status"] != "pending":
            raise ValueError("草稿不存在或已经处理")
        if not hmac.compare_digest(str(draft["confirmation_hash"]), token_hash(code)):
            raise ValueError("二次确认码错误")
        with self.connect() as conn:
            conn.execute("UPDATE drafts SET status='applying' WHERE id=?", (draft_id,))
        return draft

    def set_draft_status(self, draft_id: str, status: str) -> None:
        with self.connect() as conn:
            conn.execute("UPDATE drafts SET status=? WHERE id=?", (status, draft_id))

    def create_apply_session(
        self,
        *,
        draft_id: str | None,
        kind: str,
        operation: str,
        payload: dict[str, Any],
        inverse_operation: str,
        before_snapshot: dict[str, Any],
        deadline: datetime,
        recycle_id: str | None = None,
    ) -> dict[str, Any]:
        apply_id = str(uuid.uuid4())
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO apply_sessions VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (
                    apply_id,
                    draft_id,
                    kind,
                    operation,
                    _json(payload),
                    inverse_operation,
                    _json(before_snapshot),
                    deadline.isoformat(),
                    "pending",
                    recycle_id,
                    _now().isoformat(),
                ),
            )
        return self.get_apply_session(apply_id) or {}

    def get_apply_session(self, apply_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM apply_sessions WHERE id=?", (apply_id,)
            ).fetchone()
        return (
            self._row_document(row, json_fields={"payload", "before_snapshot"})
            if row
            else None
        )

    def pending_apply_sessions(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM apply_sessions WHERE status='pending' ORDER BY created_at"
            ).fetchall()
        return [
            self._row_document(row, json_fields={"payload", "before_snapshot"})
            for row in rows
        ]

    def set_apply_status(self, apply_id: str, status: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE apply_sessions SET status=? WHERE id=?", (status, apply_id)
            )

    def add_recycle_item(
        self,
        *,
        backend: str,
        system_version: str,
        object_type: str,
        object_name: str,
        fingerprint: str,
        payload: dict[str, Any],
        dependencies: list[dict[str, Any]],
        runtime_before: dict[str, Any],
        permanent_before: dict[str, Any],
        source: str,
        reason: str,
        batch_id: str | None = None,
    ) -> dict[str, Any]:
        recycle_id = str(uuid.uuid4())
        batch_id = batch_id or str(uuid.uuid4())
        document = {
            "id": recycle_id,
            "batch_id": batch_id,
            "backend": backend,
            "system_version": system_version,
            "object_type": object_type,
            "object_name": object_name,
            "fingerprint": fingerprint,
            "payload": payload,
            "dependencies": dependencies,
            "runtime_before": runtime_before,
            "permanent_before": permanent_before,
            "deleted_at": _now().isoformat(),
            "deleted_by": "admin",
            "source": source,
            "reason": reason,
            "config_hash": hashlib.sha256(
                _json(payload).encode("utf-8")
            ).hexdigest(),
        }
        checksum = self._checksum(document)
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO recycle_bin("
                "id,batch_id,backend,system_version,object_type,object_name,"
                "fingerprint,payload,dependencies,runtime_before,permanent_before,"
                "deleted_at,deleted_by,source,reason,config_hash,checksum,status"
                ") VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    recycle_id,
                    batch_id,
                    backend,
                    system_version,
                    object_type,
                    object_name,
                    fingerprint,
                    _json(payload),
                    _json(dependencies),
                    _json(runtime_before),
                    _json(permanent_before),
                    document["deleted_at"],
                    "admin",
                    source,
                    reason,
                    document["config_hash"],
                    checksum,
                    "deleted",
                ),
            )
        snapshot_path = self.settings.recycle_dir / f"{recycle_id}.json"
        snapshot_path.write_text(_json({**document, "checksum": checksum}), encoding="utf-8")
        secure_file_mode(snapshot_path)
        self.audit("recycle.added", "admin", source, {"id": recycle_id})
        return self.get_recycle_item(recycle_id) or {}

    def list_recycle_items(self, *, include_restored: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM recycle_bin"
        if not include_restored:
            query += " WHERE status='deleted'"
        query += " ORDER BY deleted_at DESC"
        with self.connect() as conn:
            rows = conn.execute(query).fetchall()
        items = [self._recycle_document(row) for row in rows]
        for item in items:
            item["integrity_ok"] = self._verify_recycle_checksum(item)
        return items

    def get_recycle_item(self, recycle_id: str) -> dict[str, Any] | None:
        with self.connect() as conn:
            row = conn.execute(
                "SELECT * FROM recycle_bin WHERE id=?", (recycle_id,)
            ).fetchone()
        if row is None:
            return None
        item = self._recycle_document(row)
        item["integrity_ok"] = self._verify_recycle_checksum(item)
        return item

    def list_recycle_batch(self, batch_id: str) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM recycle_bin "
                "WHERE batch_id=? AND status='deleted' ORDER BY deleted_at",
                (batch_id,),
            ).fetchall()
        items = [self._recycle_document(row) for row in rows]
        for item in items:
            item["integrity_ok"] = self._verify_recycle_checksum(item)
        return items

    def mark_recycle_restored(self, recycle_id: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE recycle_bin SET status='restored' WHERE id=?", (recycle_id,)
            )
        self.audit("recycle.restored", "admin", "web", {"id": recycle_id})

    def purge_recycle_item(self, recycle_id: str) -> None:
        item = self.get_recycle_item(recycle_id)
        if item is None:
            raise ValueError("回收站项目不存在")
        with self.connect() as conn:
            conn.execute("DELETE FROM recycle_bin WHERE id=?", (recycle_id,))
        try:
            (self.settings.recycle_dir / f"{recycle_id}.json").unlink()
        except FileNotFoundError:
            pass
        self.audit(
            "recycle.purged",
            "admin",
            "web",
            {"id": recycle_id, "fingerprint": item["fingerprint"]},
        )

    def create_backup(self, label: str, snapshot: dict[str, Any]) -> dict[str, Any]:
        backup_id = str(uuid.uuid4())
        checksum = self._checksum(snapshot)
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO backups VALUES(?,?,?,?,?)",
                (backup_id, label[:120], _json(snapshot), checksum, _now().isoformat()),
            )
        return {"id": backup_id, "label": label, "checksum": checksum}

    def list_backups(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT id,label,checksum,created_at FROM backups ORDER BY created_at DESC"
            ).fetchall()
        return [dict(row) for row in rows]

    def audit(self, event: str, actor: str, source: str, details: dict[str, Any]) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT INTO audit(event,actor,source,details,created_at) VALUES(?,?,?,?,?)",
                (event, actor, source, _json(details), _now().isoformat()),
            )

    def list_audit(self, limit: int = 200) -> list[dict[str, Any]]:
        limit = min(max(limit, 1), 1000)
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM audit ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_document(row, json_fields={"details"}) for row in rows]

    def save_metrics(self, payload: dict[str, Any]) -> None:
        collected = str(payload.get("collected_at") or _now().isoformat())
        cutoff = (_now() - timedelta(hours=24)).isoformat()
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO metrics(collected_at,payload) VALUES(?,?)",
                (collected, _json(payload)),
            )
            conn.execute("DELETE FROM metrics WHERE collected_at < ?", (cutoff,))

    def list_metrics(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM metrics ORDER BY collected_at"
            ).fetchall()
        return [json.loads(str(row["payload"])) for row in rows]

    def schedule_temporary_rule(
        self, rule_id: str, backend: str, payload: dict[str, Any], expires_at: datetime
    ) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO temporary_rules VALUES(?,?,?,?,?,?)",
                (
                    rule_id,
                    backend,
                    _json(payload),
                    expires_at.isoformat(),
                    "active",
                    _now().isoformat(),
                ),
            )
        self.audit(
            "rule.expiration_scheduled",
            "wallpilot",
            "local",
            {"rule": rule_id, "expires_at": expires_at.isoformat()},
        )

    def due_temporary_rules(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM temporary_rules "
                "WHERE status='active' AND expires_at<=? ORDER BY expires_at",
                (_now().isoformat(),),
            ).fetchall()
        return [self._row_document(row, json_fields={"payload"}) for row in rows]

    def set_temporary_rule_status(self, rule_id: str, status: str) -> None:
        with self.connect() as conn:
            conn.execute(
                "UPDATE temporary_rules SET status=? WHERE id=?", (status, rule_id)
            )

    def _checksum(self, document: Any) -> str:
        secret = bytes.fromhex(self._setting("state_secret") or "")
        return hmac.new(secret, _json(document).encode("utf-8"), hashlib.sha256).hexdigest()

    def _verify_recycle_checksum(self, item: dict[str, Any]) -> bool:
        document = {
            key: item[key]
            for key in (
                "id",
                "batch_id",
                "backend",
                "system_version",
                "object_type",
                "object_name",
                "fingerprint",
                "payload",
                "dependencies",
                "runtime_before",
                "permanent_before",
                "deleted_at",
                "deleted_by",
                "source",
                "reason",
                *(() if not item.get("config_hash") else ("config_hash",)),
            )
        }
        return hmac.compare_digest(str(item["checksum"]), self._checksum(document))

    @staticmethod
    def _row_document(
        row: sqlite3.Row, *, json_fields: set[str] | None = None
    ) -> dict[str, Any]:
        document = dict(row)
        for field in json_fields or set():
            document[field] = json.loads(str(document[field]))
        return document

    def _recycle_document(self, row: sqlite3.Row) -> dict[str, Any]:
        return self._row_document(
            row,
            json_fields={
                "payload",
                "dependencies",
                "runtime_before",
                "permanent_before",
            },
        )
