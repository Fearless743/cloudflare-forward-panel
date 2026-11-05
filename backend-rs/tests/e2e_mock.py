#!/usr/bin/env python3
"""End-to-end test: real Rust server + stateful mock Cloudflare API."""
"""端到端测试：真实 Rust 服务 + 有状态的 Cloudflare API mock。

用法：
    cd backend-rs
    cargo build
    python3 tests/e2e_mock.py
"""
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER = os.environ.get("CF_PANEL_SERVER", str(ROOT / "backend-rs/target/debug/server"))
TMP_DIR = tempfile.mkdtemp(prefix="cfp-e2e-")


def free_port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


DB = os.path.join(TMP_DIR, "e2e.db")
PORT = free_port()
MOCK_PORT = free_port()

state = {
    "zones": [],
    "zone_seq": 0,
    "rulesets": {},
    "rs_seq": 0,
    "rule_seq": 0,
    "dns": {},
    "dns_seq": 0,
    "settings": {},
}


def next_id(prefix, key):
    state[key] += 1
    return f"{prefix}-{state[key]}"


def assign_rule_ids(ruleset):
    for rule in ruleset.get("rules", []):
        if not rule.get("id"):
            rule["id"] = next_id("rule", "rule_seq")
    return ruleset


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    def _send(self, code, payload):
        data = json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _cf(self, result):
        self._send(200, {"success": True, "errors": [], "result": result})

    def _body(self):
        length = int(self.headers.get("Content-Length", "0"))
        if not length:
            return {}
        return json.loads(self.rfile.read(length))

    def do_GET(self):
        path = self.path.split("?")[0].replace("/client/v4", "")
        query = self.path.split("?", 1)[1] if "?" in self.path else ""
        parts = [p for p in path.split("/") if p]

        if path == "/__state":
            self._send(200, state)
            return

        if parts[:1] == ["zones"] and len(parts) == 1:
            page = 1
            for item in query.split("&"):
                if item.startswith("page="):
                    page = int(item[5:] or 1)
            self._cf(state["zones"] if page == 1 else [])
            return

        if parts[:1] == ["zones"] and len(parts) == 2:
            zone = next((z for z in state["zones"] if z["id"] == parts[1]), None)
            self._cf(zone or {})
            return

        if parts[:1] == ["zones"] and parts[2:] == ["rulesets"]:
            self._cf(list(state["rulesets"].values()))
            return

        if parts[:1] == ["zones"] and len(parts) == 4 and parts[2] == "rulesets":
            rs = state["rulesets"].get(parts[3])
            if rs is None:
                self._send(404, {"success": False, "errors": [{"code": 10001, "message": "could not find ruleset"}], "result": None})
            else:
                self._cf(rs)
            return

        if parts[:1] == ["zones"] and len(parts) == 3 and parts[2] == "dns_records":
            records = [r for r in state["dns"].values() if r["zone_id"] == parts[1]]
            self._cf(records)
            return

        self._send(404, {"success": False, "errors": [{"code": 9999, "message": "not found"}], "result": None})

    def do_POST(self):
        path = self.path.split("?")[0].replace("/client/v4", "")
        parts = [p for p in path.split("/") if p]
        body = self._body()

        if path == "/zones":
            existing = next((z for z in state["zones"] if z["name"] == body.get("name")), None)
            if existing:
                self._cf(existing)
                return
            zone = {
                "id": f"zone-{len(state['zones']) + 1}",
                "name": body.get("name"),
                "status": "active",
                "name_servers": ["ns1.example.net", "ns2.example.net"],
                "plan": {"name": "Free Website"},
            }
            state["zones"].append(zone)
            self._cf(zone)
            return

        if parts[:1] == ["zones"] and parts[2:] == ["rulesets"]:
            rs = dict(body)
            rs["id"] = next_id("rs", "rs_seq")
            rs["version"] = "1"
            assign_rule_ids(rs)
            state["rulesets"][rs["id"]] = rs
            self._cf(rs)
            return

        if parts[:1] == ["zones"] and len(parts) == 3 and parts[2] == "dns_records":
            record = dict(body)
            record["id"] = next_id("dns", "dns_seq")
            record["zone_id"] = parts[1]
            record["proxied"] = bool(record.get("proxied"))
            state["dns"][record["id"]] = record
            self._cf(record)
            return

        if path == "/certificates":
            self._cf({
                "id": "cert-1",
                "certificate": "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----\n",
                "hostnames": body.get("hostnames", []),
                "issuer": "Cloudflare, Inc.",
                "expires_on": "2040-01-01T00:00:00Z",
                "request_type": "origin-rsa",
                "status": "active",
            })
            return

        self._send(404, {"success": False, "errors": [{"code": 9999, "message": "not found"}], "result": None})

    def do_PUT(self):
        path = self.path.split("?")[0].replace("/client/v4", "")
        parts = [p for p in path.split("/") if p]
        body = self._body()

        if parts[:1] == ["zones"] and len(parts) == 4 and parts[2] == "rulesets":
            rs = dict(body)
            rs["id"] = parts[3]
            assign_rule_ids(rs)
            state["rulesets"][rs["id"]] = rs
            self._cf(rs)
            return

        self._send(404, {"success": False, "errors": [{"code": 9999, "message": "not found"}], "result": None})

    def do_PATCH(self):
        path = self.path.split("?")[0].replace("/client/v4", "")
        parts = [p for p in path.split("/") if p]
        body = self._body()

        if parts[:1] == ["zones"] and len(parts) == 4 and parts[2] == "dns_records":
            record = state["dns"].get(parts[3])
            if not record:
                self._send(404, {"success": False, "errors": [{"code": 10001, "message": "not found"}], "result": None})
                return
            record.update({k: v for k, v in body.items() if k in ("name", "type", "content", "ttl", "proxied")})
            self._cf(record)
            return

        if parts[:1] == ["zones"] and len(parts) == 4 and parts[2] == "settings":
            setting = {"id": parts[3], "value": body.get("value"), "editable": True}
            state["settings"][parts[3]] = setting
            self._cf(setting)
            return

        self._send(404, {"success": False, "errors": [{"code": 9999, "message": "not found"}], "result": None})

    def do_DELETE(self):
        path = self.path.split("?")[0].replace("/client/v4", "")
        parts = [p for p in path.split("/") if p]
        if parts[:1] == ["zones"] and len(parts) == 4 and parts[2] == "dns_records":
            state["dns"].pop(parts[3], None)
            self._cf({"id": parts[3]})
            return
        if parts[:1] == ["zones"] and len(parts) == 4 and parts[2] == "rulesets":
            state["rulesets"].pop(parts[3], None)
            self._cf({"id": parts[3]})
            return
        self._send(404, {"success": False, "errors": [{"code": 9999, "message": "not found"}], "result": None})


BASE = f"http://127.0.0.1:{PORT}"
token = ""
failures = []


def req(method, path, body=None, expect=200, auth=True):
    data = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request(BASE + path, data=data, method=method)
    request.add_header("Content-Type", "application/json")
    if auth and token:
        request.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(request, timeout=30) as resp:
            payload = json.loads(resp.read() or b"{}")
            status = resp.status
    except urllib.error.HTTPError as err:
        payload = json.loads(err.read() or b"{}")
        status = err.code
    if status != expect:
        raise AssertionError(f"{method} {path}: got HTTP {status} {payload}, want {expect}")
    return payload


def check(name, condition, detail=""):
    if condition:
        print(f"PASS  {name}")
    else:
        failures.append(name)
        print(f"FAIL  {name} {detail}")


def wait_port(port):
    for _ in range(100):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.1)
    raise RuntimeError(f"port {port} not ready")


def main():
    global token
    mock = ThreadingHTTPServer(("127.0.0.1", MOCK_PORT), Handler)
    threading.Thread(target=mock.serve_forever, daemon=True).start()

    env = dict(os.environ)
    env.update({
        "DB_PATH": DB,
        "SERVER_PORT": str(PORT),
        "CF_API_BASE_URL": f"http://127.0.0.1:{MOCK_PORT}/client/v4",
        "RUST_LOG": "warn",
    })
    server = subprocess.Popen([SERVER], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        wait_port(PORT)

        login = req("POST", "/api/auth/login", {"username": "admin", "password": "admin123"}, auth=False)
        token = login["result"]["token"]
        req("POST", "/api/auth/change-password", {"old_password": "admin123", "new_password": "admin456"})
        login = req("POST", "/api/auth/login", {"username": "admin", "password": "admin456"}, auth=False)
        token = login["result"]["token"]

        # 创建 CF 账号（会触发 Zone 同步）
        account = req("POST", "/api/accounts", {"email": "a@b.com", "api_key": "key-123456789", "account_id": "acc"})
        check("create account", account["result"]["id"] == 1)

        # 手动添加域名
        zone = req("POST", "/api/zones", {"account_id": 1, "domain": "example.com"})
        zone_id = zone["result"]["id"]
        check("create zone", zone_id == "zone-1", zone_id)
        check("zone nameservers", zone["result"]["name_servers"] == ["ns1.example.net", "ns2.example.net"])
        check("zone not duplicated", req("POST", "/api/zones", {"account_id": 1, "domain": "example.com"})["existed"] is True)
        bad = req("POST", "/api/zones", {"account_id": 1, "domain": "bad_domain"}, expect=400)

        # 分配域名给 admin
        req("PUT", f"/api/zones/{zone_id}/users", {"user_ids": [1]})
        zones = req("GET", "/api/forward-rules/zones")["result"]
        check("assigned zone visible", len(zones) == 1 and zones[0]["cf_id"] == zone_id)

        # 创建第一条转发规则
        rule1 = req("POST", "/api/forward-rules", {"origin_port": 8080, "origin_host": "1.2.3.4", "enabled": True})["result"]
        check("rule1 created", rule1["origin_port"] == 8080)
        check("rule1 dns is A", state["dns"][rule1["dns_record_id"]]["type"] == "A")
        check("ssl set to full", state["settings"].get("ssl", {}).get("value") == "full")
        rs = state["rulesets"][rule1["cf_ruleset_id"]]
        check("ruleset has one rule", len(rs["rules"]) == 1)
        check("rule1 expression", rule1["hostname"] in rs["rules"][0]["expression"])
        check("rule1 cf_rule_id", rule1["cf_rule_id"] == rs["rules"][0]["id"])

        # 同端口第二个目标：复用同一条 CF rule
        rule2 = req("POST", "/api/forward-rules", {"origin_port": 8080, "origin_host": "origin.example.com", "enabled": True})["result"]
        check("rule2 reuses ruleset", rule2["cf_ruleset_id"] == rule1["cf_ruleset_id"])
        check("rule2 reuses rule", rule2["cf_rule_id"] == rule1["cf_rule_id"])
        check("rule2 dns is CNAME", state["dns"][rule2["dns_record_id"]]["type"] == "CNAME")
        rs = state["rulesets"][rule1["cf_ruleset_id"]]
        check("expression merged", rule1["hostname"] in rs["rules"][0]["expression"] and rule2["hostname"] in rs["rules"][0]["expression"])

        # 禁用 rule2：表达式移除其 host，rule 仍启用
        req("POST", f"/api/forward-rules/{rule2['id']}/toggle")
        rs = state["rulesets"][rule1["cf_ruleset_id"]]
        check("disabled host removed", rule2["hostname"] not in rs["rules"][0]["expression"])
        check("rule stays enabled", rs["rules"][0]["enabled"] is True)

        # 两个都禁用：整条 rule 禁用
        req("POST", f"/api/forward-rules/{rule1['id']}/toggle")
        rs = state["rulesets"][rule1["cf_ruleset_id"]]
        check("all disabled -> rule disabled", rs["rules"][0]["enabled"] is False)

        # 重新启用
        req("POST", f"/api/forward-rules/{rule1['id']}/toggle")
        req("POST", f"/api/forward-rules/{rule2['id']}/toggle")

        # 修改 rule1 端口：从共享规则拆分为独立规则
        updated = req("PUT", f"/api/forward-rules/{rule1['id']}", {"origin_port": 9090, "origin_host": "1.2.3.4", "enabled": True})["result"]
        check("rule1 moved to new ruleset", updated["cf_ruleset_id"] != rule2["cf_ruleset_id"])
        old_rs = state["rulesets"][rule2["cf_ruleset_id"]]
        check("old rule keeps rule2 only", rule1["hostname"] not in old_rs["rules"][0]["expression"] and rule2["hostname"] in old_rs["rules"][0]["expression"])
        new_rs = state["rulesets"][updated["cf_ruleset_id"]]
        check("new rule port 9090", new_rs["rules"][0]["action_parameters"]["origin"]["port"] == 9090)

        # rule2 改到 9090：并入 rule1 的新规则
        merged = req("PUT", f"/api/forward-rules/{rule2['id']}", {"origin_port": 9090, "origin_host": "origin.example.com", "enabled": True})["result"]
        check("rule2 merged into 9090", merged["cf_ruleset_id"] == updated["cf_ruleset_id"])
        check("rule2 cf_rule_id merged", merged["cf_rule_id"] == updated["cf_rule_id"])

        # 只改目标地址：DNS 原地更新
        dns_id = merged["dns_record_id"]
        changed = req("PUT", f"/api/forward-rules/{rule2['id']}", {"origin_port": 9090, "origin_host": "9.9.9.9", "enabled": True})["result"]
        check("dns type changed to A", state["dns"][changed["dns_record_id"]]["type"] == "A", state["dns"].get(changed["dns_record_id"]))
        check("old dns removed", dns_id not in state["dns"])

        # 删除 rule1：共享规则保留 rule2
        req("DELETE", f"/api/forward-rules/{rule1['id']}")
        check("rule1 dns deleted", rule1["dns_record_id"] not in state["dns"])
        rs = state["rulesets"][updated["cf_ruleset_id"]]
        check("shared rule keeps rule2 host", rule1["hostname"] not in rs["rules"][0]["expression"] and changed["hostname"] in rs["rules"][0]["expression"])

        # 删除 rule2：ruleset 清理
        req("DELETE", f"/api/forward-rules/{rule2['id']}")
        check("ruleset deleted after last rule", updated["cf_ruleset_id"] not in state["rulesets"])
        check("all dns deleted", state["dns"] == {})

        # Origin 证书缓存
        cert1 = req("POST", "/api/origin-certificates", {"zone_id": zone_id, "hostnames": ["A.example.com", "b.example.com"]})
        check("cert generated", cert1["cached"] is False and cert1["result"]["certificate"].startswith("-----BEGIN CERTIFICATE"))
        check("cert has private key", "BEGIN RSA PRIVATE KEY" in cert1["result"]["private_key"])
        cert2 = req("POST", "/api/origin-certificates", {"zone_id": zone_id, "hostnames": ["b.example.com", "a.example.com"]})
        check("cert cache hit", cert2["cached"] is True)

        # 对账：手工删掉 CF 规则后，编辑/删除应自动补回
        rule3 = req("POST", "/api/forward-rules", {"origin_port": 7070, "origin_host": "7.7.7.7", "enabled": True})["result"]
        req("POST", f"/api/forward-rules/{rule3['id']}/toggle")  # 先禁用，CF 规则禁用
        state["rulesets"].pop(rule3["cf_ruleset_id"], None)
        req("POST", f"/api/forward-rules/{rule3['id']}/toggle")  # 再启用，触发对账重建
        check("reconcile rebuilt ruleset", len(state["rulesets"]) == 1)
        req("DELETE", f"/api/forward-rules/{rule3['id']}")

        # 无权限域名：创建第二个用户后不能使用未分配域名
        user = req("POST", "/api/users", {"username": "bob", "password": "bob12345", "role": "user"})["result"]
        bob_login = req("POST", "/api/auth/login", {"username": "bob", "password": "bob12345"}, auth=False)
        bob_token = bob_login["result"]["token"]
        old_token = token
        token = bob_token
        bob_rules = req("GET", "/api/forward-rules")["result"]
        check("bob sees no rules", bob_rules == [])
        check("bob sees no zones", req("GET", "/api/forward-rules/zones")["result"] == [])
        req("POST", "/api/forward-rules", {"origin_port": 1234, "origin_host": "1.1.1.1", "enabled": True}, expect=400)
        req("GET", "/api/users", expect=403)
        token = old_token

    finally:
        server.send_signal(signal.SIGTERM)
        try:
            server.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server.kill()
        mock.shutdown()

    print()
    if failures:
        print(f"{len(failures)} FAILED: {failures}")
        sys.exit(1)
    print("ALL PASSED")


if __name__ == "__main__":
    main()
