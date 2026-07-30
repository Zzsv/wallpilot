from __future__ import annotations

import asyncio
import hashlib
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable, Literal
from urllib.parse import urlsplit

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import ConfigDict, BaseModel, Field

from .config import Settings
from .control import ControlPlane
from .models import (
    DraftConfirmation,
    DraftCreate,
    FirewallObject,
    FirewallRule,
    PurgeRequest,
    ServiceActionRequest,
)
from .storage import Store


class SetupRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    token: str = Field(min_length=20, max_length=256)
    password: str = Field(min_length=12, max_length=512)
    totp: str = Field(min_length=6, max_length=8)


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=512)
    totp: str = Field(min_length=6, max_length=32)


class ImportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    format: Literal["wallpilot-config"] = "wallpilot-config"
    version: Literal[1] = 1
    created_at: str | None = Field(default=None, max_length=80)
    backend: str | None = Field(default=None, max_length=40)
    rules: list[FirewallRule] = Field(default_factory=list, max_length=500)
    objects: list[FirewallObject] = Field(default_factory=list, max_length=100)
    reason: str = Field(default="批量导入配置", max_length=240)


class ObjectReference(BaseModel):
    model_config = ConfigDict(extra="forbid")
    object_type: Literal["zone", "policy", "service", "ipset"]
    name: str = Field(min_length=1, max_length=64)


class BatchDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    rule_ids: list[str] = Field(default_factory=list, max_length=500)
    objects: list[ObjectReference] = Field(default_factory=list, max_length=100)
    reason: str = Field(default="批量删除", max_length=240)


class BatchPurgeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    password: str = Field(min_length=1, max_length=512)
    totp: str = Field(min_length=6, max_length=8)
    confirmation: str = Field(min_length=1, max_length=80)


def create_app(
    settings: Settings | None = None,
    store: Store | None = None,
    control: ControlPlane | None = None,
) -> FastAPI:
    settings = settings or Settings()
    settings.ensure_directories()
    access_path = settings.ensure_access_path()
    store = store or Store(settings)
    if control is None:
        remote_adapter = None
        if (
            os.name == "posix"
            and settings.agent_socket.exists()
            and settings.agent_key_path.exists()
        ):
            try:
                from .agent_client import AgentClient, RemoteFirewallAdapter

                remote_adapter = RemoteFirewallAdapter(AgentClient(settings))
            except Exception:
                remote_adapter = None
        control = ControlPlane(settings, store, adapter=remote_adapter)
    prefix = f"/manage/{access_path}"
    static_dir = Path(__file__).with_name("static")

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        stop = asyncio.Event()

        async def watchdog() -> None:
            while not stop.is_set():
                try:
                    control.rollback_expired()
                    control.expire_temporary_rules()
                except Exception as exc:
                    store.audit(
                        "watchdog.error",
                        "wallpilot",
                        "local",
                        {"error": str(exc)},
                    )
                try:
                    await asyncio.wait_for(stop.wait(), timeout=2)
                except TimeoutError:
                    continue

        async def sampler() -> None:
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=60)
                    continue
                except TimeoutError:
                    pass
                try:
                    control.server_status(persist_metrics=True)
                except Exception as exc:
                    store.audit(
                        "metrics.error",
                        "wallpilot",
                        "local",
                        {"error": str(exc)},
                    )

        task = asyncio.create_task(watchdog())
        sampler_task = asyncio.create_task(sampler())
        yield
        stop.set()
        await asyncio.gather(task, sampler_task)

    app = FastAPI(
        title="WallPilot",
        version="0.1.0",
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
        lifespan=lifespan,
    )
    app.state.settings = settings
    app.state.store = store
    app.state.control = control
    app.state.management_prefix = prefix

    @app.middleware("http")
    async def security_middleware(request: Request, call_next: Callable[..., Any]) -> Response:
        raw_host = request.headers.get("host", "")
        host = raw_host
        if raw_host.startswith("[") and "]" in raw_host:
            host = raw_host[: raw_host.index("]") + 1]
        elif ":" in raw_host:
            host = raw_host.rsplit(":", 1)[0]
        allowed = set(settings.allowed_hosts)
        allowed.update(
            item.strip()
            for item in os.environ.get("WALLPILOT_ALLOWED_HOSTS", "").split(",")
            if item.strip()
        )
        if host not in allowed:
            return JSONResponse(status_code=400, content={"detail": "Host 不在允许列表"})
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
            "base-uri 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        return response

    app.mount(f"{prefix}/static", StaticFiles(directory=static_dir), name="static")

    def source_of(request: Request) -> str:
        return request.client.host if request.client else "unknown"

    def current_session(request: Request) -> dict[str, str]:
        token = request.cookies.get("wallpilot_session", "")
        session = store.verify_session(token) if token else None
        if not session:
            raise HTTPException(status_code=401, detail="需要登录")
        return session

    def csrf_session(
        request: Request,
        session: dict[str, str] = Depends(current_session),
    ) -> dict[str, str]:
        csrf = request.headers.get("x-csrf-token", "")
        if not csrf or csrf != session["csrf"]:
            raise HTTPException(status_code=403, detail="CSRF 验证失败")
        origin = request.headers.get("origin")
        if origin:
            origin_host = urlsplit(origin).netloc
            if origin_host != request.headers.get("host", ""):
                raise HTTPException(status_code=403, detail="Origin 验证失败")
        return session

    @app.get("/", include_in_schema=False)
    def hidden_root() -> Response:
        return Response(status_code=404)

    @app.get(prefix, response_class=HTMLResponse)
    @app.get(f"{prefix}/", response_class=HTMLResponse)
    def index() -> str:
        html = (static_dir / "index.html").read_text(encoding="utf-8")
        return html.replace("__WALLPILOT_BASE__", prefix)

    @app.get(f"{prefix}/api/v1/auth/state")
    def auth_state() -> dict[str, Any]:
        return {
            "initialized": store.is_initialized(),
            "management_path": prefix,
            "hostname": control.hostname,
        }

    @app.post(f"{prefix}/api/v1/auth/setup")
    def setup(payload: SetupRequest, request: Request) -> dict[str, Any]:
        try:
            recovery_codes = store.create_admin(
                payload.token, payload.password, payload.totp
            )
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "status": "initialized",
            "recovery_codes": recovery_codes,
        }

    @app.post(f"{prefix}/api/v1/auth/login")
    def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, str]:
        try:
            raw, csrf = store.authenticate(payload.password, payload.totp, source_of(request))
        except ValueError as exc:
            raise HTTPException(status_code=401, detail=str(exc)) from exc
        response.set_cookie(
            "wallpilot_session",
            raw,
            httponly=True,
            secure=os.environ.get("WALLPILOT_COOKIE_SECURE") == "1",
            samesite="strict",
            max_age=settings.session_absolute_seconds,
            path=prefix,
        )
        return {"status": "ok", "csrf": csrf}

    @app.post(f"{prefix}/api/v1/auth/logout")
    def logout(
        request: Request,
        response: Response,
        _session: dict[str, str] = Depends(csrf_session),
    ) -> dict[str, str]:
        token = request.cookies.get("wallpilot_session", "")
        if token:
            store.logout(token)
        response.delete_cookie("wallpilot_session", path=prefix)
        return {"status": "logged_out"}

    @app.get(f"{prefix}/api/v1/system/status")
    def system_status(_session: dict[str, str] = Depends(current_session)) -> dict[str, Any]:
        return control.server_status()

    @app.get(f"{prefix}/api/v1/system/metrics")
    def metric_history(_session: dict[str, str] = Depends(current_session)) -> list[dict[str, Any]]:
        return store.list_metrics()

    @app.get(f"{prefix}/api/v1/firewall/status")
    def firewall_status(_session: dict[str, str] = Depends(current_session)) -> dict[str, Any]:
        return control.firewall_status()

    @app.get(f"{prefix}/api/v1/firewall/rules")
    def firewall_rules(_session: dict[str, str] = Depends(current_session)) -> list[dict[str, Any]]:
        return control.rules()

    @app.get(f"{prefix}/api/v1/firewall/objects")
    def firewall_objects(
        _session: dict[str, str] = Depends(current_session),
    ) -> list[dict[str, Any]]:
        return control.objects()

    @app.get(f"{prefix}/api/v1/firewall/logs")
    def firewall_logs(
        query: str = "",
        limit: int = 200,
        _session: dict[str, str] = Depends(current_session),
    ) -> list[str]:
        if len(query) > 120:
            raise HTTPException(status_code=422, detail="日志筛选文字过长")
        lines = control.rejection_logs(min(max(limit, 1), 500))
        if query:
            needle = query.casefold()
            lines = [line for line in lines if needle in line.casefold()]
        return lines

    @app.get(f"{prefix}/api/v1/firewall/objects/{{object_type}}/{{name}}")
    def firewall_object(
        object_type: str,
        name: str,
        _session: dict[str, str] = Depends(current_session),
    ) -> dict[str, Any]:
        try:
            return control.get_object(object_type, name)
        except Exception as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from exc

    @app.post(f"{prefix}/api/v1/firewall/service-action")
    def service_action(
        payload: ServiceActionRequest,
        request: Request,
        _session: dict[str, str] = Depends(csrf_session),
    ) -> dict[str, Any]:
        dangerous = payload.action.value in {"stop", "disable"}
        if dangerous:
            if payload.hostname != control.hostname:
                raise HTTPException(status_code=400, detail="主机名确认不匹配")
            if not payload.totp or not store.verify_admin_totp(payload.totp):
                raise HTTPException(status_code=403, detail="动态验证码错误")
        try:
            apply_session = control.service_action(payload.action, source=source_of(request))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {
            "status": "pending_confirmation" if apply_session else "completed",
            "apply_session": apply_session,
        }

    @app.post(f"{prefix}/api/v1/drafts")
    def create_draft(
        payload: DraftCreate,
        _session: dict[str, str] = Depends(csrf_session),
    ) -> dict[str, Any]:
        try:
            rule_analysis: dict[str, list[str]] = {
                "duplicates": [],
                "conflicts": [],
            }
            if payload.object_type == "rule":
                rule_payload = payload.payload.get("rule", payload.payload)
                item: FirewallRule | FirewallObject = FirewallRule.model_validate(
                    rule_payload
                )
                risk, requires_totp = control.assess_rule_risk(
                    payload.operation, item
                )
                rule_analysis = control.rule_conflicts(item)
                if (
                    payload.operation == "add"
                    and rule_analysis["duplicates"]
                ):
                    raise ValueError("相同规则已经存在，不会重复添加")
            else:
                object_payload = payload.payload.get("object", payload.payload)
                item = FirewallObject.model_validate(object_payload)
                if item.object_type != payload.object_type:
                    raise ValueError("对象类型与草稿类型不一致")
                risk, requires_totp = control.assess_object_risk(
                    payload.operation, item
                )
                if risk == "blocked":
                    raise ValueError("内置对象不能删除或覆盖")
            draft, code = store.create_draft(
                payload.operation,
                payload.object_type,
                payload.payload,
                payload.reason,
                risk,
                requires_totp,
            )
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        return {
            "draft": _public_draft(draft),
            "confirmation_code": code,
            "impact": (
                _rule_impact(payload.operation, item, risk)
                if isinstance(item, FirewallRule)
                else _object_impact(payload.operation, item, risk)
            ),
            **(
                {
                    "dependencies": control.object_dependencies(item)
                    if payload.operation in {"delete", "update"}
                    else []
                }
                if isinstance(item, FirewallObject)
                else {}
            ),
            **(
                {"rule_analysis": rule_analysis}
                if isinstance(item, FirewallRule)
                else {}
            ),
        }

    @app.post(f"{prefix}/api/v1/batch-delete")
    def batch_delete(
        payload: BatchDeleteRequest,
        _session: dict[str, str] = Depends(csrf_session),
    ) -> dict[str, Any]:
        try:
            document = control.prepare_delete_batch(
                payload.rule_ids,
                [
                    (reference.object_type, reference.name)
                    for reference in payload.objects
                ],
            )
            draft, code = store.create_draft(
                "delete",
                "batch",
                document,
                payload.reason,
                document["risk"],
                bool(document["requires_totp"]),
            )
        except Exception as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            "draft": _public_draft(draft),
            "confirmation_code": code,
            "impact": {
                "summary": (
                    f"删除 {len(document['rules'])} 条规则和 "
                    f"{len(document['objects'])} 个高级对象"
                ),
                "risk": document["risk"],
                "batch_id": document["batch_id"],
                "recoverable": True,
            },
        }

    @app.post(f"{prefix}/api/v1/drafts/{{draft_id}}/confirm")
    def confirm_draft(
        draft_id: str,
        payload: DraftConfirmation,
        request: Request,
        _session: dict[str, str] = Depends(csrf_session),
    ) -> dict[str, Any]:
        try:
            draft = store.confirm_draft_code(draft_id, payload.code)
            if bool(draft["requires_totp"]):
                if not payload.totp or not store.verify_admin_totp(payload.totp):
                    store.set_draft_status(draft_id, "pending")
                    raise ValueError("高风险操作需要有效的动态验证码")
                if payload.hostname != control.hostname:
                    store.set_draft_status(draft_id, "pending")
                    raise ValueError("主机名确认不匹配")
            if draft["object_type"] == "rule":
                apply_session = control.begin_rule_apply(
                    draft, source=source_of(request)
                )
            elif draft["object_type"] == "batch":
                apply_session = control.begin_batch_apply(
                    draft, source=source_of(request)
                )
            else:
                apply_session = control.begin_object_apply(
                    draft, source=source_of(request)
                )
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"status": "pending_confirmation", "apply_session": apply_session}

    @app.post(f"{prefix}/api/v1/apply-sessions/{{apply_id}}/confirm")
    def confirm_apply(
        apply_id: str,
        request: Request,
        _session: dict[str, str] = Depends(csrf_session),
    ) -> dict[str, Any]:
        try:
            return control.confirm_apply(apply_id, source_of(request))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

    @app.post(f"{prefix}/api/v1/apply-sessions/{{apply_id}}/rollback")
    def rollback_apply(
        apply_id: str,
        _session: dict[str, str] = Depends(csrf_session),
    ) -> dict[str, str]:
        control.rollback_apply(apply_id, "manual-web")
        return {"status": "rolled_back"}

    @app.get(f"{prefix}/api/v1/recycle-bin")
    def recycle_bin(_session: dict[str, str] = Depends(current_session)) -> list[dict[str, Any]]:
        return store.list_recycle_items()

    @app.post(f"{prefix}/api/v1/recycle-bin/{{recycle_id}}/restore")
    def restore_recycle(
        recycle_id: str,
        _session: dict[str, str] = Depends(csrf_session),
    ) -> dict[str, Any]:
        item = store.get_recycle_item(recycle_id)
        if not item or item["status"] != "deleted":
            raise HTTPException(status_code=404, detail="回收站项目不存在")
        if not item["integrity_ok"]:
            raise HTTPException(status_code=409, detail="回收快照校验失败，禁止恢复")
        if item["object_type"] == "rule":
            existing = {rule["id"] for rule in control.rules()}
            if item["fingerprint"] in existing:
                store.mark_recycle_restored(recycle_id)
                return {"status": "already_restored"}
            restored_item: FirewallRule | FirewallObject = FirewallRule.model_validate(
                item["payload"]
            )
        else:
            restored_item = FirewallObject.model_validate(item["payload"])
            missing_dependencies: list[str] = []
            for dependency in item.get("dependencies", []):
                if not str(dependency.get("relation", "")).startswith("requires-"):
                    continue
                try:
                    control.get_object(
                        str(dependency["type"]), str(dependency["name"])
                    )
                except Exception:
                    missing_dependencies.append(
                        f"{dependency.get('type')}:{dependency.get('name')}"
                    )
            if missing_dependencies:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        "恢复所需依赖缺失："
                        + ", ".join(missing_dependencies)
                        + "。请先恢复这些对象。"
                    ),
                )
            matching = [
                value
                for value in control.objects()
                if value["object_type"] == restored_item.object_type
                and value["name"] == restored_item.name
            ]
            if matching:
                try:
                    current = FirewallObject.model_validate(
                        control.get_object(
                            restored_item.object_type, restored_item.name
                        )
                    )
                except Exception as exc:
                    raise HTTPException(
                        status_code=409,
                        detail=f"同名对象已经存在且无法比较：{exc}",
                    ) from exc
                if current.settings == restored_item.settings:
                    store.mark_recycle_restored(recycle_id)
                    return {"status": "already_restored"}
                raise HTTPException(
                    status_code=409,
                    detail="同名对象已经存在但内容不同，恢复不会覆盖当前配置",
                )
        if isinstance(restored_item, FirewallRule):
            risk, requires_totp = control.assess_rule_risk("restore", restored_item)
        else:
            risk, requires_totp = control.assess_object_risk(
                "restore", restored_item
            )
        draft, code = store.create_draft(
            "restore",
            item["object_type"],
            {
                "rule" if item["object_type"] == "rule" else "object": item["payload"],
                "recycle_id": recycle_id,
            },
            f"恢复回收站项目 {recycle_id}",
            risk,
            requires_totp,
        )
        return {
            "draft": _public_draft(draft),
            "confirmation_code": code,
            "impact": (
                _rule_impact("restore", restored_item, risk)
                if isinstance(restored_item, FirewallRule)
                else _object_impact("restore", restored_item, risk)
            ),
        }

    @app.post(f"{prefix}/api/v1/recycle-bin/batches/{{batch_id}}/restore")
    def restore_recycle_batch(
        batch_id: str,
        _session: dict[str, str] = Depends(csrf_session),
    ) -> dict[str, Any]:
        items = store.list_recycle_batch(batch_id)
        if not items:
            raise HTTPException(status_code=404, detail="回收批次不存在")
        if any(not item["integrity_ok"] for item in items):
            raise HTTPException(
                status_code=409, detail="批次中存在校验失败的回收快照"
            )
        rules = [
            FirewallRule.model_validate(item["payload"])
            for item in items
            if item["object_type"] == "rule"
        ]
        objects = [
            FirewallObject.model_validate(item["payload"])
            for item in items
            if item["object_type"] != "rule"
        ]
        batch_object_keys = {
            (item.object_type, item.name) for item in objects
        }
        missing: list[str] = []
        for recycle_item in items:
            for dependency in recycle_item.get("dependencies", []):
                if not str(dependency.get("relation", "")).startswith(
                    "requires-"
                ):
                    continue
                key = (
                    str(dependency.get("type")),
                    str(dependency.get("name")),
                )
                if key in batch_object_keys:
                    continue
                try:
                    control.get_object(*key)
                except Exception:
                    missing.append(f"{key[0]}:{key[1]}")
        if missing:
            raise HTTPException(
                status_code=409,
                detail="批次恢复缺少依赖：" + ", ".join(sorted(set(missing))),
            )
        try:
            document = control.prepare_import(rules, objects)
        except ValueError as exc:
            if "已经全部存在" not in str(exc):
                raise HTTPException(status_code=409, detail=str(exc)) from exc
            for item in items:
                store.mark_recycle_restored(str(item["id"]))
            return {"status": "already_restored"}
        pending_rule_ids = {
            str(value["id"]) for value in document["rules"]
        }
        pending_object_keys = {
            (str(value["object_type"]), str(value["name"]))
            for value in document["objects"]
        }
        restore_ids: list[str] = []
        for item in items:
            key = (
                str(item["object_type"]),
                str(item["object_name"]),
            )
            pending = (
                str(item["fingerprint"]) in pending_rule_ids
                if item["object_type"] == "rule"
                else key in pending_object_keys
            )
            if pending:
                restore_ids.append(str(item["id"]))
            else:
                store.mark_recycle_restored(str(item["id"]))
        document["restore_recycle_ids"] = restore_ids
        document["batch_id"] = batch_id
        draft, code = store.create_draft(
            "restore",
            "batch",
            document,
            f"恢复回收批次 {batch_id}",
            document["risk"],
            bool(document["requires_totp"]),
        )
        return {
            "draft": _public_draft(draft),
            "confirmation_code": code,
            "impact": {
                "summary": (
                    f"恢复 {len(document['rules'])} 条规则和 "
                    f"{len(document['objects'])} 个高级对象"
                ),
                "risk": document["risk"],
                "batch_id": batch_id,
            },
        }

    @app.post(f"{prefix}/api/v1/recycle-bin/{{recycle_id}}/purge")
    def purge_recycle(
        recycle_id: str,
        payload: PurgeRequest,
        _session: dict[str, str] = Depends(csrf_session),
    ) -> dict[str, str]:
        if payload.confirmation != "永久删除":
            raise HTTPException(status_code=400, detail="永久删除确认文字不匹配")
        if not store.verify_admin(payload.password, payload.totp):
            raise HTTPException(status_code=403, detail="管理员身份验证失败")
        store.purge_recycle_item(recycle_id)
        return {"status": "purged"}

    @app.post(f"{prefix}/api/v1/recycle-bin/batches/{{batch_id}}/purge")
    def purge_recycle_batch(
        batch_id: str,
        payload: BatchPurgeRequest,
        _session: dict[str, str] = Depends(csrf_session),
    ) -> dict[str, Any]:
        items = store.list_recycle_batch(batch_id)
        if not items:
            raise HTTPException(status_code=404, detail="回收批次不存在")
        expected = f"永久删除 {len(items)} 项"
        if payload.confirmation != expected:
            raise HTTPException(
                status_code=400,
                detail=f"确认文字不匹配，请输入：{expected}",
            )
        if not store.verify_admin(payload.password, payload.totp):
            raise HTTPException(status_code=403, detail="管理员身份验证失败")
        for item in items:
            store.purge_recycle_item(str(item["id"]))
        return {"status": "purged", "count": len(items)}

    @app.get(f"{prefix}/api/v1/backups")
    def backups(_session: dict[str, str] = Depends(current_session)) -> list[dict[str, Any]]:
        return store.list_backups()

    @app.post(f"{prefix}/api/v1/backups")
    def create_backup(_session: dict[str, str] = Depends(csrf_session)) -> dict[str, Any]:
        return store.create_backup("manual", control.snapshot())

    @app.get(f"{prefix}/api/v1/audit")
    def audit(_session: dict[str, str] = Depends(current_session)) -> list[dict[str, Any]]:
        return store.list_audit()

    @app.get(f"{prefix}/api/v1/diagnostics")
    def diagnostics(_session: dict[str, str] = Depends(current_session)) -> dict[str, Any]:
        status_doc = control.server_status()
        return _redact_diagnostics({
            "generated_by": "wallpilot",
            "status": status_doc,
            "firewall_rules": control.rules(),
            "audit_tail": store.list_audit(50),
        })

    @app.get(f"{prefix}/api/v1/export")
    def export_snapshot(_session: dict[str, str] = Depends(current_session)) -> Response:
        content = json.dumps(
            control.export_configuration(), ensure_ascii=False, indent=2
        )
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=wallpilot-config.json"},
        )

    @app.post(f"{prefix}/api/v1/import")
    def import_configuration(
        payload: ImportRequest,
        _session: dict[str, str] = Depends(csrf_session),
    ) -> dict[str, Any]:
        try:
            document = control.prepare_import(payload.rules, payload.objects)
            draft, code = store.create_draft(
                "add",
                "batch",
                document,
                payload.reason,
                document["risk"],
                bool(document["requires_totp"]),
            )
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        return {
            "draft": _public_draft(draft),
            "confirmation_code": code,
            "impact": {
                "summary": (
                    f"导入 {len(document['rules'])} 条规则和 "
                    f"{len(document['objects'])} 个高级对象"
                ),
                "risk": document["risk"],
                "skipped": document["skipped"],
                "may_disconnect": bool(document["requires_totp"]),
            },
        }

    return app


def _public_draft(draft: dict[str, Any]) -> dict[str, Any]:
    hidden = {"confirmation_hash"}
    return {key: value for key, value in draft.items() if key not in hidden}


def _rule_impact(operation: str, rule: FirewallRule, risk: str) -> dict[str, Any]:
    label = rule.service or (f"{rule.port}/{rule.protocol}" if rule.port else rule.id)
    return {
        "summary": f"{operation} {label}",
        "zone": rule.zone or "默认区域",
        "source": rule.source or "任意来源",
        "risk": risk,
        "may_disconnect": risk == "critical",
        "recoverable": operation == "delete",
    }


def _object_impact(
    operation: str, item: FirewallObject, risk: str
) -> dict[str, Any]:
    return {
        "summary": f"{operation} {item.object_type} {item.name}",
        "object_type": item.object_type,
        "risk": risk,
        "may_disconnect": item.object_type in {"zone", "policy"},
        "recoverable": operation == "delete",
        "builtin": item.builtin,
    }


def _redact_diagnostics(document: Any, key: str = "") -> Any:
    sensitive_keys = {
        "hostname",
        "source",
        "destination",
        "local",
        "remote",
        "gateway",
        "addresses",
        "dns_servers",
    }
    if isinstance(document, dict):
        return {
            item_key: _redact_diagnostics(value, item_key)
            for item_key, value in document.items()
        }
    if isinstance(document, list):
        return [_redact_diagnostics(value, key) for value in document]
    if key in sensitive_keys and document not in {None, "", "any", "anywhere"}:
        raw = str(document)
        token = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:10]
        return f"<redacted:{token}>"
    return document


app = create_app()
