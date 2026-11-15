"""Проверка и изменение записей прокси-клиентов в состоянии панели."""
from __future__ import annotations

import re

from . import proxy_auth
from .store import ID_RE, new_id

USERNAME = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
MAX_CLIENTS = 64


def public(client: dict) -> dict:
    """Пароль и его хеш никогда не попадают в ответ панели."""
    return {**{k: client[k] for k in ("id", "username", "port", "upstream", "enabled")},
            "protocol": client.get("protocol", "https")}


def save(state: dict, body: dict, uid: str | None = None) -> dict:
    clients = state.setdefault("proxy_clients", [])
    old = next((c for c in clients if c["id"] == uid), None) if uid else None
    if uid and not old:
        raise ValueError("proxy client not found")
    if not uid and len(clients) >= MAX_CLIENTS:
        raise ValueError("too many proxy clients")
    name = body.get("username", old["username"] if old else "")
    port = body.get("port", old["port"] if old else None)
    upstream = body.get("upstream", old["upstream"] if old else "")
    enabled = body.get("enabled", old["enabled"] if old else True)
    protocol = body.get("protocol", old.get("protocol", "https") if old else "https")
    password = body.get("password")
    if not isinstance(name, str) or not USERNAME.fullmatch(name):
        raise ValueError("invalid username")
    if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535:
        raise ValueError("invalid port")
    if not isinstance(enabled, bool):
        raise ValueError("invalid enabled flag")
    if protocol not in ("http", "https"):
        raise ValueError("invalid proxy protocol")
    if not isinstance(upstream, str) or not any(u["id"] == upstream for u in state["upstreams"]):
        raise ValueError("unknown exit")
    if any(c is not old and c["username"] == name for c in clients):
        raise ValueError("px.username_taken")
    if any(c is not old and c["port"] == port for c in clients):
        raise ValueError("px.port_taken")
    if not old and not password:
        raise ValueError("password required")
    record = proxy_auth.password_record(password) if password else old["password"]
    entry = {"id": uid or new_id("px"), "username": name, "port": port,
             "upstream": upstream, "enabled": enabled, "protocol": protocol, "password": record}
    if old:
        clients[clients.index(old)] = entry
    else:
        clients.append(entry)
    return public(entry)


def delete(state: dict, uid: str) -> bool:
    clients = state.setdefault("proxy_clients", [])
    n = len(clients)
    clients[:] = [c for c in clients if c["id"] != uid]
    return len(clients) != n


def restore(state: dict, entries) -> None:
    """Проверять каждое поле резервной копии до применения."""
    if not isinstance(entries, list) or len(entries) > MAX_CLIENTS:
        raise ValueError("invalid proxy clients")
    restored = []
    for entry in entries:
        if not isinstance(entry, dict):
            raise ValueError("invalid proxy client")
        uid, name, port = entry.get("id"), entry.get("username"), entry.get("port")
        upstream, enabled, pw = entry.get("upstream"), entry.get("enabled"), entry.get("password")
        protocol = entry.get("protocol", "https")
        if protocol not in ("http", "https"):
            raise ValueError("invalid proxy protocol")
        if not isinstance(uid, str) or not ID_RE.fullmatch(uid) or not isinstance(name, str) or not USERNAME.fullmatch(name):
            raise ValueError("invalid proxy identity")
        if not isinstance(port, int) or isinstance(port, bool) or not 1024 <= port <= 65535 or not isinstance(enabled, bool):
            raise ValueError("invalid proxy settings")
        if not any(u["id"] == upstream for u in state["upstreams"]):
            raise ValueError("unknown proxy exit")
        if not isinstance(pw, dict) or pw.get("iterations") != proxy_auth.ITERATIONS \
                or not isinstance(pw.get("salt"), str) or not re.fullmatch(r"[a-f0-9]{32}", pw["salt"]) \
                or not isinstance(pw.get("hash"), str) or not re.fullmatch(r"[a-f0-9]{64}", pw["hash"]):
            raise ValueError("invalid password hash")
        if any(c["id"] == uid or c["username"] == name or c["port"] == port for c in restored):
            raise ValueError("duplicate proxy client")
        restored.append({"id": uid, "username": name, "port": port, "upstream": upstream,
                         "enabled": enabled, "protocol": protocol, "password": dict(pw)})
    state["proxy_clients"] = restored
