from __future__ import annotations

import json
import os
import uuid
from pathlib import Path
from typing import Any
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, Response, FileResponse
from starlette.status import HTTP_302_FOUND, HTTP_401_UNAUTHORIZED

from app.core.vault import (
    ServerDef,
    PostgresTargetDef,
    VaultError,
)
from app.core.vault_manager import (
    any_vault_files_exist,
    consume_pending_recovery_key,
    create_session,
    create_vault,
    create_named_vault,
    destroy_session,
    ensure_profile_active_and_unlocked,
    export_vault_bytes,
    get_session,
    get_active_vault_name,
    get_vault_data,
    import_vault_bytes,
    lock_vault,
    list_vaults,
    save_vault,
    reset_master_password_with_recovery,
    set_shared_agent_enabled,
    set_shared_agent_key,
    switch_active_vault,
    unlock_vault,
    vault_exists,
    vault_is_unlocked,
)
from app.core.agent_key import generate_agent_token, hash_agent_token
from app.core.audit import write_audit_event


class UnauthorizedRedirect(Exception):
    pass


templates = __import__("jinja2").Environment(
    loader=__import__("jinja2").FileSystemLoader(
        os.path.join(os.path.dirname(__file__), "..", "templates")
    ),
    autoescape=True,
)


def _admin_headers(headers: dict[str, str]) -> None:
    headers.update({
        "Cache-Control": "no-store, no-cache, must-revalidate, max-age=0",
        "Pragma": "no-cache",
        "Referrer-Policy": "no-referrer",
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
    })


SESSION_COOKIE = "pgsentinel_session"


def _cookie_secure() -> bool:
    value = os.environ.get("PGSENTINEL_COOKIE_SECURE", "").strip().lower()
    if value in {"1", "true", "yes", "on"}:
        return True
    if value in {"0", "false", "no", "off"}:
        return False
    return os.environ.get("PGSENTINEL_ENV", "").strip().lower() == "production"


def _admin_audit(event: str, **fields: str) -> None:
    write_audit_event({"actor_type": "admin", "event": event, **fields})


def _require_unlocked(request: Request) -> None:
    session_id = request.cookies.get(SESSION_COOKIE)
    if not session_id or get_session(session_id) is None or not vault_is_unlocked():
        raise UnauthorizedRedirect()


def _render(template_name: str, status: int = 200, request: Request | None = None, **kwargs: Any) -> HTMLResponse:
    if request is not None:
        kwargs["request"] = request
    html = templates.get_template(template_name).render(**kwargs)
    resp = HTMLResponse(content=html, status_code=status)
    _admin_headers(resp.headers)
    return resp


def _j2_date(value: str | None) -> str:
    if not value:
        return "N/A"
    return value


templates.filters["j2_date"] = _j2_date


router = APIRouter(prefix="/admin")


def _redirect_login() -> RedirectResponse:
    return RedirectResponse(url="/admin/login", status_code=HTTP_302_FOUND)


def _redirect_dashboard() -> RedirectResponse:
    return RedirectResponse(url="/admin/dashboard", status_code=HTTP_302_FOUND)


def _redirect_setup() -> RedirectResponse:
    return RedirectResponse(url="/admin/setup", status_code=HTTP_302_FOUND)


def _redirect_agent() -> RedirectResponse:
    return RedirectResponse(url="/admin/agent", status_code=HTTP_302_FOUND)


def _redirect_settings() -> RedirectResponse:
    return RedirectResponse(url="/admin/settings", status_code=HTTP_302_FOUND)


def _redirect_definitions() -> RedirectResponse:
    return RedirectResponse(url="/admin/definitions", status_code=HTTP_302_FOUND)


def _existing_vault_names() -> list[str]:
    try:
        return [str(v["name"]) for v in list_vaults() if bool(v.get("exists"))]
    except Exception:
        return []


# ── first-run setup ──

@router.get("/setup")
def setup_page(request: Request) -> HTMLResponse:
    if any_vault_files_exist():
        return _redirect_login()
    if _existing_vault_names():
        return _redirect_login()
    return _render("setup.html.j2", request=request)


@router.post("/setup")
def setup_submit(request: Request, master_password: str = Form(...), confirm_password: str = Form(...)) -> Response:
    if any_vault_files_exist():
        return _redirect_login()
    if _existing_vault_names():
        return _redirect_login()
    errors = []
    if not master_password or len(master_password) < 8:
        errors.append("Master password must be at least 8 characters.")
    if master_password != confirm_password:
        errors.append("Passwords do not match.")
    if errors:
        return _render("setup.html.j2", 400, request=request, errors=errors)
    try:
        agent_key = create_vault(master_password, agent_enabled=True)
    except VaultError as e:
        return _render("setup.html.j2", 400, request=request, errors=[str(e)])
    except Exception:
        return _render("setup.html.j2", 500, request=request, errors=["Internal error while creating vault. Check data path permissions."])
    session_id = create_session()
    session = get_session(session_id)
    if session is not None:
        session["show_agent_key"] = agent_key
        session["show_recovery_key"] = consume_pending_recovery_key()
    _admin_audit("first_run_setup_completed")
    resp = RedirectResponse(url="/admin/agent", status_code=HTTP_302_FOUND)
    _admin_headers(resp.headers)
    resp.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="strict", secure=_cookie_secure(), max_age=3600)
    return resp


# ── login / unlock ──

@router.get("/login")
def login_page(request: Request) -> HTMLResponse:
    existing = _existing_vault_names()
    exists = any_vault_files_exist()
    if not exists and not existing:
        return _redirect_setup()
    if vault_is_unlocked():
        session_id = request.cookies.get(SESSION_COOKIE)
        if session_id and get_session(session_id):
            return _redirect_dashboard()
    message = None
    if not exists and existing:
        message = "Active vault is missing. Select an existing vault and unlock."
    return _render("login.html.j2", request=request, vault_names=existing, message=message)


@router.post("/login")
def login_submit(request: Request, master_password: str = Form(...)) -> RedirectResponse:
    if not vault_exists() and not _existing_vault_names():
        return _redirect_setup()
    try:
        unlock_vault(master_password)
    except VaultError:
        _admin_audit("vault_unlock_failed")
        return _render("login.html.j2", 401, request=request, error="Invalid master password.")
    _admin_audit("vault_unlock_success")
    session_id = create_session()
    resp = _redirect_dashboard()
    _admin_headers(resp.headers)
    resp.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="strict", secure=_cookie_secure(), max_age=3600)
    return resp


@router.post("/login/select_vault")
def login_select_vault(request: Request, name: str = Form(...)) -> RedirectResponse:
    try:
        selected = switch_active_vault(name)
    except VaultError as exc:
        existing = _existing_vault_names()
        return _render("login.html.j2", 400, request=request, vault_names=existing, error=str(exc))
    _admin_audit("vault_selected_for_login", target=selected)
    return _redirect_login()


@router.post("/login/recovery_reset")
def login_recovery_reset(
    request: Request,
    recovery_key: str = Form(...),
    new_master_password: str = Form(...),
    confirm_master_password: str = Form(...),
) -> Response:
    if new_master_password != confirm_master_password:
        existing = _existing_vault_names()
        return _render("login.html.j2", 400, request=request, vault_names=existing, error="New passwords do not match.")
    if len(new_master_password) < 8:
        existing = _existing_vault_names()
        return _render("login.html.j2", 400, request=request, vault_names=existing, error="New master password must be at least 8 characters.")
    try:
        new_recovery = reset_master_password_with_recovery(recovery_key=recovery_key.strip(), new_master_password=new_master_password)
        unlock_vault(new_master_password)
    except VaultError as exc:
        _admin_audit("vault_recovery_failed")
        existing = _existing_vault_names()
        return _render("login.html.j2", 401, request=request, vault_names=existing, error=str(exc))
    _admin_audit("vault_recovery_success")
    session_id = create_session()
    session = get_session(session_id)
    if session is not None:
        session["show_recovery_key"] = new_recovery
    resp = _redirect_dashboard()
    _admin_headers(resp.headers)
    resp.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="strict", secure=_cookie_secure(), max_age=3600)
    return resp


@router.post("/logout")
def logout(request: Request) -> RedirectResponse:
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        destroy_session(session_id)
    resp = _redirect_login()
    resp.delete_cookie(SESSION_COOKIE)
    resp.delete_cookie("pgs_show_key")
    return resp


# ── dashboard ──

@router.get("/dashboard")
def dashboard_page(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    try:
        data = get_vault_data()
    except VaultError:
        return _render("login.html.j2", 401, request=request, error="Vault locked.")
    server = data.servers[0] if data.servers else None
    pg = data.postgres_targets[0] if data.postgres_targets else None
    return _render("dashboard.html.j2", request=request,
                   active_vault=get_active_vault_name(),
                   definition_count=len(list_vaults()),
                   server=server,
                   has_postgres=pg is not None,
                   access_level=_access_level_of(data, pg),
                   agent_enabled=data.agent.enabled,
                   vault_data=data)


@router.post("/lock")
def lock(request: Request) -> RedirectResponse:
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        destroy_session(session_id)
    lock_vault()
    _admin_audit("vault_lock")
    resp = _redirect_login()
    resp.delete_cookie(SESSION_COOKIE)
    return resp


# ── definition backup (export / import) ──

@router.post("/vaults/import")
async def vaults_import(request: Request, name: str = Form(...), activate: bool = Form(False),
                        overwrite: bool = Form(False), file: UploadFile = File(...)) -> Response:
    _require_unlocked(request)
    body = await file.read()
    if not body:
        return _render_definitions(request, 400, error="Uploaded file is empty.")
    try:
        imported = import_vault_bytes(name=name, content=body, activate=activate, overwrite=overwrite)
    except VaultError as e:
        return _render_definitions(request, 400, error=str(e))
    _admin_audit("vault_imported", target=imported)
    if activate:
        session_id = request.cookies.get(SESSION_COOKIE)
        if session_id:
            destroy_session(session_id)
        resp = _redirect_login()
        resp.delete_cookie(SESSION_COOKIE)
        return resp
    return _redirect_definitions()


@router.get("/vaults/download")
def vaults_download_current(request: Request) -> FileResponse:
    _require_unlocked(request)
    name, _ = export_vault_bytes(None)
    path = [item["path"] for item in list_vaults() if item["name"] == name]
    if not path:
        raise HTTPException(status_code=404, detail="Vault not found")
    _admin_audit("vault_downloaded", target=name)
    return FileResponse(path[0], media_type="application/octet-stream", filename=f"{name}.vault.enc")


@router.get("/vaults/{name}/download")
def vaults_download_named(request: Request, name: str) -> FileResponse:
    _require_unlocked(request)
    normalized, _ = export_vault_bytes(name)
    path = [item["path"] for item in list_vaults() if item["name"] == normalized]
    if not path:
        raise HTTPException(status_code=404, detail="Vault not found")
    _admin_audit("vault_downloaded", target=normalized)
    return FileResponse(path[0], media_type="application/octet-stream", filename=f"{normalized}.vault.enc")


# ── definitions (single-form 8-char targets) ──


def _render_definitions(request: Request, status: int = 200, **kwargs: Any) -> HTMLResponse:
    saved = kwargs.pop("saved", request.query_params.get("saved", ""))
    return _render("definitions.html.j2", status, request=request,
                   vaults=list_vaults(), active_vault=get_active_vault_name(),
                   saved=saved, **kwargs)


def _access_level_of(data: Any, pg: PostgresTargetDef | None) -> str:
    if pg is None or not pg.sql_query_enabled:
        return "readonly"
    if data.settings.sql_policy_mode == "guarded_write":
        return "write"
    return "sql"


def _apply_access_level(data: Any, pg: PostgresTargetDef | None, level: str) -> None:
    if level == "write":
        if pg is not None:
            pg.sql_query_enabled = True
        data.settings.sql_policy_mode = "guarded_write"
        data.settings.sql_allow_insert = True
        data.settings.sql_allow_update = True
        data.settings.sql_allow_delete = True
    elif level == "sql":
        if pg is not None:
            pg.sql_query_enabled = True
        data.settings.sql_policy_mode = "readonly_default"
    else:  # readonly (default)
        if pg is not None:
            pg.sql_query_enabled = False
        data.settings.sql_policy_mode = "readonly_default"


def _apply_definition_form(
    data: Any, code: str, *, docker_mode: str, host: str, ssh_port: int, ssh_username: str,
    ssh_private_key: str, container_list: str, postgres_enabled: bool, postgres_mode: str,
    pg_host: str, pg_port: int, pg_container: str, pg_database: str, pg_username: str,
    pg_password: str, pg_ssl_mode: str, pg_ca_cert: str, pg_client_cert: str,
    pg_client_key: str, access_level: str,
) -> None:
    server = data.servers[0] if data.servers else ServerDef(id=str(uuid.uuid4()), name=code)
    server.name = code
    server.environment = "production"
    server.connection_mode = docker_mode
    if docker_mode == "ssh":
        server.host = host
        server.ssh_port = ssh_port
        server.ssh_username = ssh_username
        if ssh_private_key.strip():
            server.ssh_private_key = ssh_private_key.strip()
    else:
        server.host = ""
        server.ssh_username = ""
        server.ssh_private_key = ""
    server.allowed_containers = [c.strip() for c in container_list.split(",") if c.strip()]
    server.allow_all_containers = not bool(container_list.strip())
    server.enabled = True
    data.servers = [server]

    pg: PostgresTargetDef | None = None
    if postgres_enabled:
        pg = data.postgres_targets[0] if data.postgres_targets else PostgresTargetDef(id=str(uuid.uuid4()), name=f"{code}-pg")
        pg.name = f"{code}-pg"
        pg.server_id = server.id
        pg.connection_mode = postgres_mode
        pg.host = pg_host
        pg.port = pg_port
        pg.container_name = pg_container
        pg.database_name = pg_database
        pg.readonly_username = pg_username
        if pg_password:
            pg.readonly_password = pg_password
        pg.ssl_mode = pg_ssl_mode or "prefer"
        if pg_ca_cert.strip():
            pg.ca_cert = pg_ca_cert.strip()
        if pg_client_cert.strip():
            pg.client_cert = pg_client_cert.strip()
        if pg_client_key.strip():
            pg.client_key = pg_client_key.strip()
        pg.allow_all_tables = True
        pg.enabled = True
        data.postgres_targets = [pg]
    else:
        data.postgres_targets = []
    _apply_access_level(data, pg, access_level)


@router.get("/definitions")
def definitions_list(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    return _render_definitions(request)


@router.get("/definitions/new")
def definitions_new(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    return _render(
        "definition_form.html.j2",
        request=request,
        is_new=True,
        code="",
        server=ServerDef(id="", name="", connection_mode="local"),
        pg_target=None,
        access_level="readonly",
    )


@router.post("/definitions/new")
def definitions_create(
    request: Request,
    code: str = Form(...),
    docker_mode: str = Form("local"),
    host: str = Form(""),
    ssh_port: int = Form(22),
    ssh_username: str = Form(""),
    ssh_private_key: str = Form(""),
    container_list: str = Form(""),
    postgres_enabled: bool = Form(False),
    postgres_mode: str = Form("postgres_direct_tcp"),
    pg_host: str = Form(""),
    pg_port: int = Form(5432),
    pg_container: str = Form(""),
    pg_database: str = Form(""),
    pg_username: str = Form(""),
    pg_password: str = Form(""),
    pg_ssl_mode: str = Form("prefer"),
    pg_ca_cert: str = Form(""),
    pg_client_cert: str = Form(""),
    pg_client_key: str = Form(""),
    access_level: str = Form("readonly"),
) -> Response:
    _require_unlocked(request)
    code = code.lower()
    try:
        agent_key = create_named_vault(name=code, master_password=None, agent_enabled=True)
    except VaultError as exc:
        server = ServerDef(id="", name=code, connection_mode=docker_mode, host=host, ssh_port=ssh_port, ssh_username=ssh_username, allowed_containers=[c.strip() for c in container_list.split(",") if c.strip()])
        pg_target = PostgresTargetDef(id="", name=f"{code}-pg", connection_mode=postgres_mode, host=pg_host, port=pg_port, container_name=pg_container, database_name=pg_database, readonly_username=pg_username) if postgres_enabled else None
        return _render("definition_form.html.j2", 400, request=request, is_new=True, code=code, error=str(exc), server=server, pg_target=pg_target, access_level=access_level)
    recovery_key = consume_pending_recovery_key()
    data = get_vault_data()
    _apply_definition_form(
        data, code, docker_mode=docker_mode, host=host, ssh_port=ssh_port,
        ssh_username=ssh_username, ssh_private_key=ssh_private_key, container_list=container_list,
        postgres_enabled=postgres_enabled, postgres_mode=postgres_mode, pg_host=pg_host,
        pg_port=pg_port, pg_container=pg_container, pg_database=pg_database, pg_username=pg_username,
        pg_password=pg_password, pg_ssl_mode=pg_ssl_mode, pg_ca_cert=pg_ca_cert,
        pg_client_cert=pg_client_cert, pg_client_key=pg_client_key, access_level=access_level,
    )
    save_vault()
    _admin_audit("definition_created", target=code)
    session_id = create_session()
    session = get_session(session_id)
    if session is not None:
        session["show_agent_key"] = agent_key
        session["show_recovery_key"] = recovery_key
    resp = RedirectResponse(url="/admin/agent", status_code=HTTP_302_FOUND)
    _admin_headers(resp.headers)
    resp.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="strict", secure=_cookie_secure(), max_age=3600)
    return resp


@router.get("/definitions/{code}/edit")
def definitions_edit(request: Request, code: str) -> Response:
    _require_unlocked(request)
    try:
        ensure_profile_active_and_unlocked(code)
    except VaultError:
        raise HTTPException(status_code=404, detail="Definition not found")
    data = get_vault_data()
    server = data.servers[0] if data.servers else ServerDef(id="", name=code.lower(), connection_mode="local")
    pg_target = data.postgres_targets[0] if data.postgres_targets else None
    return _render(
        "definition_form.html.j2",
        request=request,
        is_new=False,
        code=code.lower(),
        server=server,
        pg_target=pg_target,
        agent=data.agent,
        access_level=_access_level_of(data, pg_target),
        saved=request.query_params.get("saved", ""),
    )


@router.post("/definitions/{code}/edit")
def definitions_update(
    request: Request,
    code: str,
    docker_mode: str = Form("local"),
    host: str = Form(""),
    ssh_port: int = Form(22),
    ssh_username: str = Form(""),
    ssh_private_key: str = Form(""),
    container_list: str = Form(""),
    postgres_enabled: bool = Form(False),
    postgres_mode: str = Form("postgres_direct_tcp"),
    pg_host: str = Form(""),
    pg_port: int = Form(5432),
    pg_container: str = Form(""),
    pg_database: str = Form(""),
    pg_username: str = Form(""),
    pg_password: str = Form(""),
    pg_ssl_mode: str = Form("prefer"),
    pg_ca_cert: str = Form(""),
    pg_client_cert: str = Form(""),
    pg_client_key: str = Form(""),
    access_level: str = Form("readonly"),
) -> Response:
    _require_unlocked(request)
    try:
        ensure_profile_active_and_unlocked(code)
    except VaultError:
        raise HTTPException(status_code=404, detail="Definition not found")
    data = get_vault_data()
    _apply_definition_form(
        data, code.lower(), docker_mode=docker_mode, host=host, ssh_port=ssh_port,
        ssh_username=ssh_username, ssh_private_key=ssh_private_key, container_list=container_list,
        postgres_enabled=postgres_enabled, postgres_mode=postgres_mode, pg_host=pg_host,
        pg_port=pg_port, pg_container=pg_container, pg_database=pg_database, pg_username=pg_username,
        pg_password=pg_password, pg_ssl_mode=pg_ssl_mode, pg_ca_cert=pg_ca_cert,
        pg_client_cert=pg_client_cert, pg_client_key=pg_client_key, access_level=access_level,
    )
    save_vault()
    _admin_audit("definition_updated", target=code.lower())
    return RedirectResponse(url=f"/admin/definitions/{code.lower()}/edit?saved=updated", status_code=HTTP_302_FOUND)


@router.post("/definitions/{code}/archive")
def definitions_archive(request: Request, code: str) -> Response:
    _require_unlocked(request)
    normalized = code.strip().lower()
    if normalized == get_active_vault_name():
        return _render_definitions(request, 400, error="Cannot archive the active definition. Open another definition first, then archive this one.")
    match = [item["path"] for item in list_vaults() if item["name"] == normalized and item["exists"]]
    if not match:
        raise HTTPException(status_code=404, detail="Definition not found")
    vault_path = Path(str(match[0]))
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    # Archive (never hard-delete): rename the vault and its sidecars to a timestamped
    # .archived-* name so credentials can always be recovered from disk.
    for sidecar in (vault_path, Path(str(vault_path) + ".bak"), Path(str(vault_path) + ".recovery")):
        if sidecar.exists():
            sidecar.rename(sidecar.with_name(f"{sidecar.name}.archived-{stamp}"))
    _admin_audit("definition_archived", target=normalized)
    return _redirect_definitions()


# ── connection test (VPS + PostgreSQL) ──

@router.post("/definitions/test")
def definitions_test(
    request: Request,
    target: str = Form("postgres"),
    docker_mode: str = Form("local"),
    host: str = Form(""),
    ssh_port: int = Form(22),
    ssh_username: str = Form(""),
    ssh_private_key: str = Form(""),
    postgres_mode: str = Form("postgres_direct_tcp"),
    pg_host: str = Form(""),
    pg_port: int = Form(5432),
    pg_container: str = Form(""),
    pg_database: str = Form(""),
    pg_username: str = Form(""),
    pg_password: str = Form(""),
    pg_ssl_mode: str = Form("prefer"),
) -> HTMLResponse:
    _require_unlocked(request)
    data = get_vault_data()
    stored_server = data.servers[0] if data.servers else None
    stored_pg = data.postgres_targets[0] if data.postgres_targets else None
    if target == "vps":
        result = _test_vps(data, docker_mode, host, ssh_port, ssh_username, ssh_private_key, stored_server)
        mode = docker_mode
    else:
        result = _test_postgres(data, postgres_mode, pg_host, pg_port, pg_container, pg_database,
                                pg_username, pg_password, pg_ssl_mode, stored_server, stored_pg)
        mode = postgres_mode
    _admin_audit("connection_test", mode=mode, result=result["status"])
    return _render("_test_result.html.j2", request=request, result=result)


def _test_vps(data: Any, docker_mode: str, host: str, ssh_port: int, ssh_username: str,
              ssh_private_key: str, stored_server: ServerDef | None) -> dict[str, str]:
    from app.remote.connection import ConnectionAdapter
    timeout = min(20, data.settings.command_timeout_seconds)
    ps_cmd = ["docker", "ps", "--format", "{{.Names}}"]
    if docker_mode == "local":
        try:
            res = ConnectionAdapter(server=None).run(ps_cmd, command_label="vps_test_local", check=False, timeout=timeout)
        except FileNotFoundError:
            return {"status": "error", "message": "Local Docker CLI/socket unavailable in this container. Mount /var/run/docker.sock or use SSH mode."}
        except Exception as e:
            return {"status": "error", "message": str(e)}
        if res.ok:
            count = len([n for n in res.stdout.strip().splitlines() if n.strip()])
            return {"status": "ok", "message": f"Local Docker reachable ({count} container(s))."}
        return {"status": "error", "message": (res.stderr or res.stdout or "docker ps failed.").strip()}

    if not host or not ssh_username:
        return {"status": "skipped", "message": "Enter SSH host and username to test."}
    key = ssh_private_key.strip() or (stored_server.ssh_private_key if stored_server else "")
    if not key:
        return {"status": "skipped", "message": "Paste the SSH private key to test (saved key is never re-shown)."}
    srv = ServerDef(id="test", name="test", connection_mode="ssh", host=host, ssh_port=ssh_port,
                    ssh_username=ssh_username, ssh_private_key=key)
    try:
        res = ConnectionAdapter(server=srv).run(ps_cmd, command_label="vps_test_ssh", check=False, timeout=timeout)
    except Exception as e:
        return {"status": "error", "message": f"SSH connection failed: {e}"}
    if res.ok:
        count = len([n for n in res.stdout.strip().splitlines() if n.strip()])
        return {"status": "ok", "message": f"SSH OK; Docker reachable ({count} container(s))."}
    return {"status": "error", "message": f"SSH connected but 'docker ps' failed: {(res.stderr or res.stdout or '').strip()}"}


def _test_postgres(data: Any, postgres_mode: str, pg_host: str, pg_port: int, pg_container: str,
                   pg_database: str, pg_username: str, pg_password: str, pg_ssl_mode: str,
                   stored_server: ServerDef | None, stored_pg: PostgresTargetDef | None) -> dict[str, str]:
    if not pg_username:
        return {"status": "skipped", "message": "Enter the PostgreSQL username and password first."}
    password = pg_password or (stored_pg.readonly_password if stored_pg else "")
    timeout = min(20, data.settings.command_timeout_seconds)

    if postgres_mode == "docker_exec_psql_over_ssh":
        if not pg_container:
            return {"status": "skipped", "message": "Enter the PostgreSQL container name (must be the postgres container, e.g. 'marketing-apilot-postgres')."}
        # VPS local => exec via the mounted Docker socket; VPS ssh => exec over SSH.
        try:
            from app.remote.connection import ConnectionAdapter
            check = ConnectionAdapter(server=stored_server).run_psql(
                container=pg_container, host=pg_host or "localhost", port=pg_port, user=pg_username,
                db=pg_database or "postgres", sql="SELECT 1", password=password, timeout=timeout)
            if check.exit_code == 0 and "1" in (check.stdout or ""):
                return {"status": "ok", "message": f"docker exec psql on '{pg_container}' OK (SELECT 1)."}
            err = (check.stderr or check.stdout or "docker exec psql failed.").strip()
            if "executable file not found" in err or ("psql" in err and "not found" in err):
                err += "  — that container has no psql; point DB Container at the actual PostgreSQL container."
            return {"status": "error", "message": err}
        except FileNotFoundError:
            return {"status": "error", "message": "Local Docker socket/CLI unavailable. Mount /var/run/docker.sock or set VPS mode to SSH."}
        except Exception as e:
            return {"status": "error", "message": str(e)}

    if postgres_mode == "ssh_tunnel_direct_postgres" and stored_server is None:
        return {"status": "skipped", "message": "Save the SSH VPS first; the tunnel uses it."}
    if postgres_mode in ("postgres_direct_tcp", "postgres_direct_tls") and not pg_host:
        return {"status": "skipped", "message": "Enter DB host (use 127.0.0.1 for a local database)."}
    try:
        from app.remote.direct_postgres import DirectPostgresClient
        test_target = PostgresTargetDef(
            id="test", name="Connection Test",
            server_id=(stored_server.id if stored_server else ""),
            connection_mode=postgres_mode, host=pg_host, port=pg_port,
            database_name=pg_database or "postgres", readonly_username=pg_username,
            readonly_password=password, ssl_mode=pg_ssl_mode or "prefer")
        server = stored_server if postgres_mode == "ssh_tunnel_direct_postgres" else None
        check = DirectPostgresClient(test_target, server=server, timeout=timeout).run_json_sql("SELECT json_build_object('ok', true)")
        if check.ok:
            return {"status": "ok", "message": f"Direct connection to {pg_host or '127.0.0.1'}:{pg_port} OK."}
        return {"status": "error", "message": check.stderr or check.stdout or "Direct PostgreSQL connection failed."}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# ── agent key ──

@router.get("/agent")
def agent_page(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    data = get_vault_data()
    show_key = ""
    show_recovery_key = ""
    session_id = request.cookies.get(SESSION_COOKIE)
    session = get_session(session_id) if session_id else None
    if session is not None:
        show_key = session.pop("show_agent_key", "")
        show_recovery_key = session.pop("show_recovery_key", "")
    return _render("agent.html.j2", request=request, agent=data.agent, show_key=show_key, show_recovery_key=show_recovery_key)


@router.post("/agent/rotate")
def agent_rotate(request: Request, key_ttl_days: int = Form(0), key_never_expires: bool = Form(False)) -> RedirectResponse:
    _require_unlocked(request)
    token = generate_agent_token()
    key_hash = hash_agent_token(token)
    now = datetime.now(timezone.utc)
    last_rotated = now.strftime("%Y-%m-%dT%H:%M:%SZ")
    if key_never_expires:
        expires_at = ""
    else:
        days = max(1, min(int(key_ttl_days or 30), 3650))
        expires_at = (now + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    # Shared key: the same key/expiry applies to every definition.
    set_shared_agent_key(key_hash=key_hash, last_rotated=last_rotated, expires_at=expires_at)
    _admin_audit("agent_key_rotated")
    session_id = request.cookies.get(SESSION_COOKIE)
    session = get_session(session_id) if session_id else None
    if session is not None:
        session["show_agent_key"] = token
    resp = _redirect_agent()
    _admin_headers(resp.headers)
    resp.delete_cookie("pgs_show_key")
    return resp


@router.post("/agent/toggle")
def agent_toggle(request: Request, enabled: bool = Form(False)) -> RedirectResponse:
    _require_unlocked(request)
    set_shared_agent_enabled(bool(enabled))
    _admin_audit("agent_access_disabled" if not enabled else "agent_access_enabled")
    return _redirect_agent()


# ── settings ──

@router.get("/settings")
def settings_page(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    data = get_vault_data()
    return _render("settings.html.j2", request=request, settings=data.settings,
                   patterns=data.masking_patterns)


@router.post("/settings")
def settings_update(request: Request, auto_lock_minutes: int = Form(30),
                    max_log_lines: int = Form(300), max_query_rows: int = Form(100),
                    command_timeout_seconds: int = Form(20),
                    sql_policy_mode: str = Form("readonly_default"),
                    sql_hard_max_query_rows: int = Form(1000),
                    sql_allow_insert: bool = Form(False),
                    sql_allow_update: bool = Form(False),
                    sql_allow_delete: bool = Form(False),
                    sql_allow_create: bool = Form(False),
                    sql_allow_alter: bool = Form(False),
                    sql_allow_drop: bool = Form(False),
                    sql_allow_truncate: bool = Form(False),
                    sql_allow_maintenance: bool = Form(False),
                    sql_allow_privilege: bool = Form(False),
                    sql_allow_transaction: bool = Form(False),
                    masking_patterns_text: str = Form("")) -> RedirectResponse:
    _require_unlocked(request)
    data = get_vault_data()
    data.settings.auto_lock_minutes = max(1, min(auto_lock_minutes, 1440))
    data.settings.max_log_lines = max(1, min(max_log_lines, 5000))
    data.settings.max_query_rows = max(1, min(max_query_rows, 1000))
    data.settings.command_timeout_seconds = max(1, min(command_timeout_seconds, 300))
    data.settings.sql_policy_mode = "guarded_write" if sql_policy_mode == "guarded_write" else "readonly_default"
    data.settings.sql_hard_max_query_rows = max(1, min(sql_hard_max_query_rows, 5000))
    data.settings.sql_allow_insert = bool(sql_allow_insert)
    data.settings.sql_allow_update = bool(sql_allow_update)
    data.settings.sql_allow_delete = bool(sql_allow_delete)
    data.settings.sql_allow_create = bool(sql_allow_create)
    data.settings.sql_allow_alter = bool(sql_allow_alter)
    data.settings.sql_allow_drop = bool(sql_allow_drop)
    data.settings.sql_allow_truncate = bool(sql_allow_truncate)
    data.settings.sql_allow_maintenance = bool(sql_allow_maintenance)
    data.settings.sql_allow_privilege = bool(sql_allow_privilege)
    data.settings.sql_allow_transaction = bool(sql_allow_transaction)
    data.masking_patterns = [p.strip() for p in masking_patterns_text.split("\n") if p.strip()]
    save_vault()
    _admin_audit("settings_updated")
    return _redirect_settings()


# ── audit log viewer ──

@router.get("/audit")
def audit_page(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    audit_path = os.environ.get("PGSENTINEL_AUDIT_LOG", "audit/pgsentinel-audit.jsonl")
    events = []
    try:
        with open(audit_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    events.append(json.loads(line))
    except (FileNotFoundError, PermissionError, json.JSONDecodeError):
        pass
    events.reverse()
    return _render("audit.html.j2", request=request, events=events[:200])
