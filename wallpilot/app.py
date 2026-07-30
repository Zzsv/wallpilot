from __future__ import annotations

import asyncio
import json
import os
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Callable
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
    totp: str = Field(min_length=6, max_length=8)


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
    def setup(payload: SetupRequest, request: Request) -> dict[str, str]:
        try:
            store.create_admin(payload.token, payload.password, payload.totp)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return {"status": "initialized"}

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
        if payload.object_type != "rule":
            raise HTTPException(
                status_code=501,
                detail="当前版本已建立对象回收模型；区域、策略、服务和 IP 集合编辑器将在后续界面开放",
            )
        try:
            rule_payload = payload.payload.get("rule", payload.payload)
            rule = FirewallRule.model_validate(rule_payload)
            risk, requires_totp = control.assess_rule_risk(payload.operation, rule)
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
            "impact": _rule_impact(payload.operation, rule, risk),
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
            apply_session = control.begin_rule_apply(draft, source=source_of(request))
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
        existing = {rule["id"] for rule in control.rules()}
        if item["fingerprint"] in existing:
            store.mark_recycle_restored(recycle_id)
            return {"status": "already_restored"}
        draft, code = store.create_draft(
            "restore",
            item["object_type"],
            {"rule": item["payload"], "recycle_id": recycle_id},
            f"恢复回收站项目 {recycle_id}",
            "normal",
            False,
        )
        rule = FirewallRule.model_validate(item["payload"])
        return {
            "draft": _public_draft(draft),
            "confirmation_code": code,
            "impact": _rule_impact("restore", rule, "normal"),
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
        for listener in status_doc.get("listeners", []):
            listener.pop("users", None)
        return {
            "generated_by": "wallpilot",
            "status": status_doc,
            "firewall_rules": control.rules(),
            "audit_tail": store.list_audit(50),
        }

    @app.get(f"{prefix}/api/v1/export")
    def export_snapshot(_session: dict[str, str] = Depends(current_session)) -> Response:
        content = json.dumps(control.snapshot(), ensure_ascii=False, indent=2)
        return Response(
            content=content,
            media_type="application/json",
            headers={"Content-Disposition": "attachment; filename=wallpilot-snapshot.json"},
        )

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


app = create_app()
