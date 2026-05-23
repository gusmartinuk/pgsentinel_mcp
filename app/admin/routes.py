from __future__ import annotations

import json
import os
import uuid
from typing import Any

from fastapi import APIRouter, Form, HTTPException, Request, UploadFile, File
from fastapi.responses import HTMLResponse, RedirectResponse, Response, FileResponse
from starlette.status import HTTP_302_FOUND, HTTP_401_UNAUTHORIZED

from app.core.vault import (
    ServerDef,
    PostgresTargetDef,
    MonitoringTargetDef,
    VaultError,
)
from app.core.vault_manager import (
    create_session,
    create_vault,
    create_named_vault,
    destroy_session,
    export_vault_bytes,
    get_session,
    get_active_vault_name,
    get_vault_data,
    import_vault_bytes,
    lock_vault,
    list_vaults,
    save_vault,
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


def _redirect_servers() -> RedirectResponse:
    return RedirectResponse(url="/admin/servers", status_code=HTTP_302_FOUND)


def _redirect_postgres() -> RedirectResponse:
    return RedirectResponse(url="/admin/postgres", status_code=HTTP_302_FOUND)


def _redirect_monitoring() -> RedirectResponse:
    return RedirectResponse(url="/admin/monitoring", status_code=HTTP_302_FOUND)


def _redirect_agent() -> RedirectResponse:
    return RedirectResponse(url="/admin/agent", status_code=HTTP_302_FOUND)


def _redirect_settings() -> RedirectResponse:
    return RedirectResponse(url="/admin/settings", status_code=HTTP_302_FOUND)


def _redirect_vaults() -> RedirectResponse:
    return RedirectResponse(url="/admin/vaults", status_code=HTTP_302_FOUND)


def _existing_vault_names() -> list[str]:
    try:
        return [str(v["name"]) for v in list_vaults() if bool(v.get("exists"))]
    except Exception:
        return []


# ── first-run setup ──

@router.get("/setup")
def setup_page(request: Request) -> HTMLResponse:
    if vault_exists():
        return _redirect_login()
    if _existing_vault_names():
        return _redirect_login()
    return _render("setup.html.j2", request=request)


@router.post("/setup")
def setup_submit(request: Request, master_password: str = Form(...), confirm_password: str = Form(...)) -> Response:
    if vault_exists():
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
    session_id = create_session()
    session = get_session(session_id)
    if session is not None:
        session["show_agent_key"] = agent_key
    _admin_audit("first_run_setup_completed")
    resp = RedirectResponse(url="/admin/agent", status_code=HTTP_302_FOUND)
    _admin_headers(resp.headers)
    resp.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="strict", secure=_cookie_secure(), max_age=3600)
    return resp


# ── login / unlock ──

@router.get("/login")
def login_page(request: Request) -> HTMLResponse:
    existing = _existing_vault_names()
    if not vault_exists() and not existing:
        return _redirect_setup()
    if vault_is_unlocked():
        session_id = request.cookies.get(SESSION_COOKIE)
        if session_id and get_session(session_id):
            return _redirect_dashboard()
    message = None
    if not vault_exists() and existing:
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
    return _render("dashboard.html.j2", request=request,
                   server_count=len(data.servers),
                   pg_count=len(data.postgres_targets),
                   monitoring_count=len(data.monitoring_targets),
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


# ── vault management ──

@router.get("/vaults")
def vaults_page(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    items = list_vaults()
    active = get_active_vault_name()
    return _render("vaults.html.j2", request=request, vaults=items, active_vault=active)


@router.post("/vaults/switch")
def vaults_switch(request: Request, name: str = Form(...)) -> RedirectResponse:
    _require_unlocked(request)
    selected = switch_active_vault(name)
    _admin_audit("vault_switched", target=selected)
    session_id = request.cookies.get(SESSION_COOKIE)
    if session_id:
        destroy_session(session_id)
    resp = _redirect_login()
    resp.delete_cookie(SESSION_COOKIE)
    return resp


@router.post("/vaults/create")
def vaults_create(request: Request, name: str = Form(...), master_password: str = Form(...), confirm_password: str = Form(...)) -> Response:
    _require_unlocked(request)
    errors: list[str] = []
    if len(master_password) < 8:
        errors.append("Master password must be at least 8 characters.")
    if master_password != confirm_password:
        errors.append("Passwords do not match.")
    if errors:
        items = list_vaults()
        active = get_active_vault_name()
        return _render("vaults.html.j2", 400, request=request, vaults=items, active_vault=active, errors=errors)
    try:
        agent_key = create_named_vault(name=name, master_password=master_password, agent_enabled=True)
    except VaultError as e:
        items = list_vaults()
        active = get_active_vault_name()
        return _render("vaults.html.j2", 400, request=request, vaults=items, active_vault=active, errors=[str(e)])
    _admin_audit("vault_created", target=name)
    session_id = create_session()
    session = get_session(session_id)
    if session is not None:
        session["show_agent_key"] = agent_key
    resp = RedirectResponse(url="/admin/agent", status_code=HTTP_302_FOUND)
    _admin_headers(resp.headers)
    resp.set_cookie(SESSION_COOKIE, session_id, httponly=True, samesite="strict", secure=_cookie_secure(), max_age=3600)
    return resp


@router.post("/vaults/import")
async def vaults_import(request: Request, name: str = Form(...), activate: bool = Form(True),
                        overwrite: bool = Form(False), file: UploadFile = File(...)) -> Response:
    _require_unlocked(request)
    body = await file.read()
    if not body:
        items = list_vaults()
        active = get_active_vault_name()
        return _render("vaults.html.j2", 400, request=request, vaults=items, active_vault=active, errors=["Uploaded file is empty."])
    try:
        imported = import_vault_bytes(name=name, content=body, activate=activate, overwrite=overwrite)
    except VaultError as e:
        items = list_vaults()
        active = get_active_vault_name()
        return _render("vaults.html.j2", 400, request=request, vaults=items, active_vault=active, errors=[str(e)])
    _admin_audit("vault_imported", target=imported)
    if activate:
        session_id = request.cookies.get(SESSION_COOKIE)
        if session_id:
            destroy_session(session_id)
        resp = _redirect_login()
        resp.delete_cookie(SESSION_COOKIE)
        return resp
    return _redirect_vaults()


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


# ── servers ──

@router.get("/servers")
def servers_list(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    data = get_vault_data()
    return _render("servers.html.j2", request=request, servers=data.servers)


@router.get("/servers/new")
def servers_new(request: Request, copy_from: str | None = None) -> HTMLResponse:
    _require_unlocked(request)
    server = ServerDef(id="", name="")
    if copy_from:
        data = get_vault_data()
        existing = data.get_server(copy_from)
        if existing:
            server = existing
    return _render("server_form.html.j2", request=request, server=server, is_new=True)


@router.post("/servers/new")
def servers_create(request: Request, name: str = Form(...), environment: str = Form("staging"),
                   connection_mode: str = Form("ssh"), host: str = Form(""),
                   ssh_port: int = Form(22), ssh_username: str = Form(""),
                   ssh_private_key: str = Form(""), ssh_private_key_passphrase: str = Form(""),
                   allowed_containers_text: str = Form(""),
                   allow_all_containers: bool = Form(False),
                   allowed_log_sources_text: str = Form(""), enabled: bool = Form(True),
                   notes: str = Form("")) -> RedirectResponse:
    _require_unlocked(request)
    data = get_vault_data()
    server = ServerDef(
        id=str(uuid.uuid4()), name=name, environment=environment,
        connection_mode=connection_mode, host=host, ssh_port=ssh_port,
        ssh_username=ssh_username, ssh_private_key=ssh_private_key.strip(),
        ssh_private_key_passphrase=ssh_private_key_passphrase,
        allowed_containers=[c.strip() for c in allowed_containers_text.split(",") if c.strip()],
        allowed_log_sources=[l.strip() for l in allowed_log_sources_text.split(",") if l.strip()],
        allow_all_containers=allow_all_containers,
        enabled=enabled, notes=notes,
    )
    data.servers.append(server)
    save_vault()
    _admin_audit("server_created", target=server.id)
    return _redirect_servers()


@router.get("/servers/{server_id}/edit")
def servers_edit(request: Request, server_id: str) -> HTMLResponse:
    _require_unlocked(request)
    data = get_vault_data()
    server = data.get_server(server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")
    return _render("server_form.html.j2", request=request, server=server, is_new=False)


@router.post("/servers/{server_id}/edit")
def servers_update(request: Request, server_id: str, name: str = Form(...),
                   environment: str = Form("staging"), connection_mode: str = Form("ssh"),
                   host: str = Form(""), ssh_port: int = Form(22),
                   ssh_username: str = Form(""), ssh_private_key: str = Form(""),
                   ssh_private_key_passphrase: str = Form(""),
                   allowed_containers_text: str = Form(""),
                   allow_all_containers: bool = Form(False),
                   allowed_log_sources_text: str = Form(""), enabled: bool = Form(True),
                   notes: str = Form("")) -> RedirectResponse:
    _require_unlocked(request)
    data = get_vault_data()
    server = data.get_server(server_id)
    if server is None:
        raise HTTPException(status_code=404, detail="Server not found")
    server.name = name
    server.environment = environment
    server.connection_mode = connection_mode
    server.host = host
    server.ssh_port = ssh_port
    server.ssh_username = ssh_username
    if ssh_private_key.strip():
        server.ssh_private_key = ssh_private_key.strip()
    if ssh_private_key_passphrase:
        server.ssh_private_key_passphrase = ssh_private_key_passphrase
    server.allowed_containers = [c.strip() for c in allowed_containers_text.split(",") if c.strip()]
    server.allowed_log_sources = [l.strip() for l in allowed_log_sources_text.split(",") if l.strip()]
    server.allow_all_containers = allow_all_containers
    server.enabled = enabled
    server.notes = notes
    save_vault()
    _admin_audit("server_updated", target=server_id)
    return _redirect_servers()


@router.post("/servers/{server_id}/delete")
def servers_delete(request: Request, server_id: str) -> RedirectResponse:
    _require_unlocked(request)
    data = get_vault_data()
    data.servers = [s for s in data.servers if s.id != server_id]
    data.postgres_targets = [p for p in data.postgres_targets if p.server_id != server_id]
    save_vault()
    _admin_audit("server_deleted", target=server_id)
    return _redirect_servers()


# ── postgres targets ──

@router.get("/postgres")
def postgres_list(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    data = get_vault_data()
    return _render("postgres.html.j2", request=request, targets=data.postgres_targets, servers=data.servers)


@router.get("/postgres/new")
def postgres_new(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    data = get_vault_data()
    return _render("postgres_form.html.j2", request=request,
                   target=PostgresTargetDef(id="", name=""), servers=data.servers, is_new=True)


@router.post("/postgres/new")
def postgres_create(request: Request, name: str = Form(...), server_id: str = Form(""),
                    connection_mode: str = Form("docker_exec_psql_over_ssh"),
                    host: str = Form(""), port: int = Form(5432),
                    container_name: str = Form(""), database_name: str = Form(""),
                    readonly_username: str = Form(""), readonly_password: str = Form(""),
                    ssl_mode: str = Form("prefer"), ca_cert: str = Form(""),
                    client_cert: str = Form(""), client_key: str = Form(""),
                    allowed_schemas_text: str = Form(""),
                    allowed_tables_text: str = Form(""),
                    allow_all_tables: bool = Form(False),
                    sql_query_enabled: bool = Form(False),
                    sensitive_columns_text: str = Form(""), max_rows: int = Form(100),
                    enabled: bool = Form(True), notes: str = Form("")) -> RedirectResponse:
    _require_unlocked(request)
    data = get_vault_data()
    target = PostgresTargetDef(
        id=str(uuid.uuid4()), name=name, server_id=server_id,
        connection_mode=connection_mode, host=host, port=port,
        container_name=container_name, database_name=database_name,
        readonly_username=readonly_username, readonly_password=readonly_password,
        ssl_mode=ssl_mode, ca_cert=ca_cert.strip(),
        client_cert=client_cert.strip(), client_key=client_key.strip(),
        allowed_schemas=[s.strip() for s in allowed_schemas_text.split(",") if s.strip()] or ["public"],
        allowed_tables=[t.strip() for t in allowed_tables_text.split(",") if t.strip()],
        allow_all_tables=allow_all_tables,
        sql_query_enabled=sql_query_enabled,
        sensitive_columns=[c.strip() for c in sensitive_columns_text.split(",") if c.strip()],
        max_rows=max_rows, enabled=enabled, notes=notes,
    )
    data.postgres_targets.append(target)
    save_vault()
    _admin_audit("postgres_target_created", target=target.id)
    return _redirect_postgres()


@router.get("/postgres/{target_id}/edit")
def postgres_edit(request: Request, target_id: str) -> HTMLResponse:
    _require_unlocked(request)
    data = get_vault_data()
    target = data.get_postgres_target(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return _render("postgres_form.html.j2", request=request, target=target, servers=data.servers, is_new=False)


@router.post("/postgres/{target_id}/edit")
def postgres_update(request: Request, target_id: str, name: str = Form(...),
                    server_id: str = Form(""), connection_mode: str = Form("docker_exec_psql_over_ssh"),
                    host: str = Form(""), port: int = Form(5432),
                    container_name: str = Form(""), database_name: str = Form(""),
                    readonly_username: str = Form(""), readonly_password: str = Form(""),
                    ssl_mode: str = Form("prefer"), ca_cert: str = Form(""),
                    client_cert: str = Form(""), client_key: str = Form(""),
                    allowed_schemas_text: str = Form(""),
                    allowed_tables_text: str = Form(""),
                    allow_all_tables: bool = Form(False),
                    sql_query_enabled: bool = Form(False),
                    sensitive_columns_text: str = Form(""), max_rows: int = Form(100),
                    enabled: bool = Form(True), notes: str = Form("")) -> RedirectResponse:
    _require_unlocked(request)
    data = get_vault_data()
    target = data.get_postgres_target(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    target.name = name
    target.server_id = server_id
    target.connection_mode = connection_mode
    target.host = host
    target.port = port
    target.container_name = container_name
    target.database_name = database_name
    target.readonly_username = readonly_username
    if readonly_password:
        target.readonly_password = readonly_password
    target.ssl_mode = ssl_mode
    if ca_cert.strip():
        target.ca_cert = ca_cert.strip()
    if client_cert.strip():
        target.client_cert = client_cert.strip()
    if client_key.strip():
        target.client_key = client_key.strip()
    target.allowed_schemas = [s.strip() for s in allowed_schemas_text.split(",") if s.strip()] or ["public"]
    target.allowed_tables = [t.strip() for t in allowed_tables_text.split(",") if t.strip()]
    target.allow_all_tables = allow_all_tables
    target.sql_query_enabled = sql_query_enabled
    target.sensitive_columns = [c.strip() for c in sensitive_columns_text.split(",") if c.strip()]
    target.max_rows = max_rows
    target.enabled = enabled
    target.notes = notes
    save_vault()
    _admin_audit("postgres_target_updated", target=target_id)
    return _redirect_postgres()


@router.post("/postgres/{target_id}/delete")
def postgres_delete(request: Request, target_id: str) -> RedirectResponse:
    _require_unlocked(request)
    data = get_vault_data()
    data.postgres_targets = [p for p in data.postgres_targets if p.id != target_id]
    save_vault()
    _admin_audit("postgres_target_deleted", target=target_id)
    return _redirect_postgres()


@router.post("/postgres/test")
def postgres_test(request: Request, host: str = Form(""), port: int = Form(5432),
                  database_name: str = Form(""), readonly_username: str = Form(""),
                  readonly_password: str = Form(""), container_name: str = Form(""),
                  connection_mode: str = Form("docker_exec_psql_over_ssh"),
                  server_id: str = Form("")) -> HTMLResponse:
    _require_unlocked(request)
    data = get_vault_data()
    result = {"status": "skipped", "message": "No credentials provided."}
    if not readonly_username:
        return _render("_test_result.html.j2", request=request,
                       result={"status": "skipped", "message": "Enter username and password first."})

    ssh_modes = ("docker_exec_psql_over_ssh",)
    direct_modes = ("postgres_direct_tcp", "postgres_direct_tls", "ssh_tunnel_direct_postgres")

    if connection_mode in ssh_modes:
        if container_name:
            try:
                if server_id:
                    from app.remote.connection import ConnectionAdapter
                    server = data.get_server(server_id)
                    if server is None:
                        result = {"status": "error", "message": "Linked server not found."}
                    else:
                        adapter = ConnectionAdapter(server=server)
                        check = adapter.run_psql(
                            container=container_name,
                            host=host or "localhost",
                            port=port,
                            user=readonly_username,
                            db=database_name or "postgres",
                            sql="SELECT 1",
                            password=readonly_password,
                            timeout=min(20, data.settings.command_timeout_seconds),
                        )
                        if check.exit_code == 0 and "1" in (check.stdout or ""):
                            result = {"status": "ok", "message": f"SSH docker exec connection to '{container_name}' successful (SELECT 1)."}
                        else:
                            result = {"status": "error", "message": (check.stderr or check.stdout or "SSH docker exec failed.").strip()}
                else:
                    import subprocess, os
                    cmd = ["docker", "exec", "-e", "PGPASSWORD", container_name, "psql",
                           "-h", host or "localhost", "-p", str(port), "-U", readonly_username,
                           "-d", database_name or "postgres", "-X", "-A", "-t", "-c", "SELECT 1"]
                    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10,
                                         env={**os.environ, "PGPASSWORD": readonly_password})
                    if proc.returncode == 0 and "1" in proc.stdout:
                        result = {"status": "ok", "message": f"Connection to container '{container_name}' successful (SELECT 1)."}
                    else:
                        result = {"status": "error", "message": proc.stderr.strip() or proc.stdout.strip() or "Docker exec failed."}
            except FileNotFoundError:
                if server_id:
                    result = {"status": "error", "message": "Local Docker socket unavailable and SSH linked-server test could not be executed."}
                else:
                    result = {"status": "error", "message": "PgSentinel container has no Docker socket. Link a server and test over SSH, or use MCP tools."}
            except Exception as e:
                result = {"status": "error", "message": str(e)}
        else:
            result = {"status": "skipped", "message": "Enter container_name to test (e.g. 'postgres'). Save first, then test via MCP get_postgres_health."}

    elif connection_mode in direct_modes:
        if connection_mode == "ssh_tunnel_direct_postgres" and not server_id:
            return _render("_test_result.html.j2", request=request,
                           result={"status": "skipped", "message": "Select a linked SSH server for SSH tunnel testing."})
        if connection_mode in ("postgres_direct_tcp", "postgres_direct_tls") and not host:
            return _render("_test_result.html.j2", request=request,
                           result={"status": "skipped", "message": "Host required for direct TCP/TLS connection."})
        try:
            from app.remote.direct_postgres import DirectPostgresClient
            target = PostgresTargetDef(
                id="test",
                name="Connection Test",
                server_id=server_id,
                connection_mode=connection_mode,
                host=host,
                port=port,
                database_name=database_name or "postgres",
                readonly_username=readonly_username,
                readonly_password=readonly_password,
            )
            server = data.get_server(server_id) if server_id else None
            check = DirectPostgresClient(target, server=server, timeout=data.settings.command_timeout_seconds).run_json_sql("SELECT json_build_object('ok', true)")
            if check.ok:
                endpoint = f"{host or '127.0.0.1'}:{port}"
                result = {"status": "ok", "message": f"Direct connection to {endpoint} successful (SELECT 1)."}
            else:
                result = {"status": "error", "message": check.stderr or check.stdout or "Direct PostgreSQL connection failed."}
        except Exception as e:
            result = {"status": "error", "message": str(e)}
    else:
        result = {"status": "skipped", "message": f"Mode '{connection_mode}' tested via MCP client only."}

    _admin_audit("connection_test", mode=connection_mode, result=result["status"])
    return _render("_test_result.html.j2", request=request, result=result)


# ── monitoring targets ──

@router.get("/monitoring")
def monitoring_list(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    data = get_vault_data()
    return _render("monitoring.html.j2", request=request, targets=data.monitoring_targets)


@router.get("/monitoring/new")
def monitoring_new(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    return _render("monitoring_form.html.j2", request=request,
                   target=MonitoringTargetDef(id="", name=""), is_new=True)


@router.post("/monitoring/new")
def monitoring_create(request: Request, name: str = Form(...), environment: str = Form("staging"),
                      connection_mode: str = Form("https_api"), base_url: str = Form(""),
                      api_token: str = Form(""), tls_verify: bool = Form(True),
                      allowed_operations_text: str = Form(""), enabled: bool = Form(True),
                      notes: str = Form("")) -> RedirectResponse:
    _require_unlocked(request)
    data = get_vault_data()
    target = MonitoringTargetDef(
        id=str(uuid.uuid4()), name=name, environment=environment,
        connection_mode=connection_mode, base_url=base_url,
        api_token=api_token, tls_verify=tls_verify,
        allowed_operations=[o.strip() for o in allowed_operations_text.split(",") if o.strip()],
        enabled=enabled, notes=notes,
    )
    data.monitoring_targets.append(target)
    save_vault()
    _admin_audit("monitoring_target_created", target=target.id)
    return _redirect_monitoring()


@router.get("/monitoring/{target_id}/edit")
def monitoring_edit(request: Request, target_id: str) -> HTMLResponse:
    _require_unlocked(request)
    data = get_vault_data()
    target = data.get_monitoring_target(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    return _render("monitoring_form.html.j2", request=request, target=target, is_new=False)


@router.post("/monitoring/{target_id}/edit")
def monitoring_update(request: Request, target_id: str, name: str = Form(...),
                      environment: str = Form("staging"),
                      connection_mode: str = Form("https_api"), base_url: str = Form(""),
                      api_token: str = Form(""), tls_verify: bool = Form(True),
                      allowed_operations_text: str = Form(""), enabled: bool = Form(True),
                      notes: str = Form("")) -> RedirectResponse:
    _require_unlocked(request)
    data = get_vault_data()
    target = data.get_monitoring_target(target_id)
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")
    target.name = name
    target.environment = environment
    target.connection_mode = connection_mode
    target.base_url = base_url
    if api_token:
        target.api_token = api_token
    target.tls_verify = tls_verify
    target.allowed_operations = [o.strip() for o in allowed_operations_text.split(",") if o.strip()]
    target.enabled = enabled
    target.notes = notes
    save_vault()
    _admin_audit("monitoring_target_updated", target=target_id)
    return _redirect_monitoring()


@router.post("/monitoring/{target_id}/delete")
def monitoring_delete(request: Request, target_id: str) -> RedirectResponse:
    _require_unlocked(request)
    data = get_vault_data()
    data.monitoring_targets = [m for m in data.monitoring_targets if m.id != target_id]
    save_vault()
    _admin_audit("monitoring_target_deleted", target=target_id)
    return _redirect_monitoring()


# ── agent key ──

@router.get("/agent")
def agent_page(request: Request) -> HTMLResponse:
    _require_unlocked(request)
    data = get_vault_data()
    show_key = ""
    session_id = request.cookies.get(SESSION_COOKIE)
    session = get_session(session_id) if session_id else None
    if session is not None:
        show_key = session.pop("show_agent_key", "")
    return _render("agent.html.j2", request=request, agent=data.agent, show_key=show_key)


@router.post("/agent/rotate")
def agent_rotate(request: Request) -> RedirectResponse:
    _require_unlocked(request)
    data = get_vault_data()
    token = generate_agent_token()
    data.agent.key_hash = hash_agent_token(token)
    data.agent.enabled = True
    data.agent.last_rotated = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    save_vault()
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
    data = get_vault_data()
    data.agent.enabled = enabled
    save_vault()
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
