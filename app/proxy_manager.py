"""Управление HTTP и HTTPS приёмниками прокси-клиентов."""
from __future__ import annotations

import threading

from . import config, nftgen, proxy_bridge, proxy_listener


class Manager:
    def __init__(self, store, engine, tls):
        self.store, self.engine, self.tls = store, engine, tls
        self.listeners = {}
        self.errors = {}
        self.lock = threading.RLock()

    def _credentials(self, uid):
        clients = self.store.snapshot().get("proxy_clients", [])
        client = next((c for c in clients if c["id"] == uid and c["enabled"]), None)
        return {"username": client["username"], "password": client["password"],
                "upstream": client["upstream"]} if client else None

    def _account(self, uid, direction, count):
        state = self.store.snapshot()
        up = next((u for u in state["upstreams"] if u["id"] == uid and u.get("enabled", True)), None)
        if not up:
            return False
        # Проверка и резервирование байтов под одной блокировкой: встречное направление
        # или другое соединение не обойдёт квоту до обновления счётчика.
        with self.engine.traffic.lock:
            if self.engine.over_quota(up):
                return False
            if count:
                self.engine.traffic.add_proxy(uid, direction, count)
            return True

    def _connect(self, uid, host, port):
        state = self.store.snapshot()
        client = next((c for c in state.get("proxy_clients", []) if c["id"] == uid and c["enabled"]), None)
        if not client:
            raise OSError("client disabled")
        up = next((u for u in state["upstreams"] if u["id"] == client["upstream"] and u.get("enabled", True)), None)
        if not up:
            raise OSError("exit missing")
        if self.engine.over_quota(up):
            raise OSError("exit quota exceeded")
        with self.engine.lock:
            rt = self.engine.rt.get(up["id"])
            target = self.engine.target
            health = self.engine.health.get(up["id"], {})
            if not target or not target.exists or not rt or rt.target_key != target.key or not health.get("healthy"):
                raise OSError("exit unavailable")
            pid, iface, mark = target.pid, rt.iface, nftgen.mark_for(rt.num)
        return proxy_bridge.connect(pid, iface, mark, host, port)

    def sync(self):
        """Применить настройки; ошибка порта одного клиента не останавливает остальные."""
        with self.lock:
            state = self.store.snapshot()
            if config.DRY_RUN:
                return
            wanted = {c["id"]: c for c in state.get("proxy_clients", []) if c["enabled"]}
            for uid in list(self.listeners):
                server, port = self.listeners[uid]
                if (uid not in wanted or wanted[uid]["port"] != port
                        or wanted[uid].get("protocol", "https") != getattr(server, "proxy_protocol", "https")):
                    server.close_active()
                    server.shutdown()
                    server.server_close()
                    del self.listeners[uid]
            self.errors = {uid: err for uid, err in self.errors.items() if uid in wanted}
            for uid, client in wanted.items():
                if uid in self.listeners:
                    server, _ = self.listeners[uid]
                    signature = (client["username"], client["password"]["hash"], client["upstream"])
                    if server.proxy_signature != signature:
                        server.close_active()
                        server.proxy_signature = signature
                    continue
                try:
                    protocol = client.get("protocol", "https")
                    context = self.tls.context if protocol == "https" else None
                    server = proxy_listener.create(("0.0.0.0", client["port"]), context,
                                                   lambda u=uid: self._credentials(u),
                                                   lambda host, port, u=uid: self._connect(u, host, port),
                                                   self._account)
                except OSError as exc:
                    self.errors[uid] = str(exc)
                    continue
                self.listeners[uid] = (server, client["port"])
                server.proxy_protocol = protocol
                server.proxy_signature = (client["username"], client["password"]["hash"], client["upstream"])
                self.errors.pop(uid, None)
                threading.Thread(target=server.serve_forever, name="proxy-" + uid, daemon=True).start()

    def stop(self):
        with self.lock:
            for server, _ in self.listeners.values():
                server.close_active()
                server.shutdown()
                server.server_close()
            self.listeners.clear()
