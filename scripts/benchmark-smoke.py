#!/usr/bin/env python3
"""Isolated loopback smoke test; writes evidence, never uses production state."""
import argparse
import http.cookiejar
import json
import os
from pathlib import Path
import platform
import resource
import subprocess
import tempfile
import time
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("--out", required=True, type=Path)
args = parser.parse_args()
root = Path(__file__).resolve().parent.parent
out = args.out.resolve()
out.mkdir(parents=True, exist_ok=True)
soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
resource.setrlimit(resource.RLIMIT_NOFILE, (min(8192, hard) if hard != resource.RLIM_INFINITY else 8192, hard))
env = {**os.environ, "GOMEMLIMIT": "2GiB"}
processes = []

def run(*cmd):
    return subprocess.run([str(x) for x in cmd], cwd=root, env=env, check=True, capture_output=True, text=True).stdout

with tempfile.TemporaryDirectory(prefix="waf-capacity-") as tmp:
    tmp = Path(tmp)
    cfg = tmp / "waf.json"
    password = tmp / "password"
    password.write_text("local-smoke-password")
    password.chmod(0o600)
    run(root / "bin/waf", "init", "--development", "--config", cfg, "--data-dir", tmp / "data", "--password-file", password)
    boot = json.loads(cfg.read_text())
    boot["http_listen"] = "127.0.0.1:18080"
    boot["ops_listen"] = "127.0.0.1:19090"
    cfg.write_text(json.dumps(boot))
    jar = http.cookiejar.CookieJar()
    client = urllib.request.build_opener(urllib.request.ProxyHandler({}), urllib.request.HTTPCookieProcessor(jar))
    csrf = ""

    def api(path, method="GET", data=None):
        headers = {"Host": "admin.localhost", "Origin": "http://admin.localhost", "Content-Type": "application/json", "X-CSRF-Token": csrf}
        request = urllib.request.Request("http://127.0.0.1:18080/api/v1" + path, method=method, headers=headers, data=json.dumps(data).encode() if data is not None else None)
        with client.open(request, timeout=30) as response:
            return json.load(response)

    log = (out / "server.log").open("w")
    try:
        processes.append(subprocess.Popen([str(root / "bin/waforigin"), "--listen", "127.0.0.1:18081"], stdout=log, stderr=log, env=env))
        processes.append(subprocess.Popen([str(root / "bin/waf"), "serve", "--config", str(cfg)], stdout=log, stderr=log, env=env))
        for attempt in range(100):
            if any(p.poll() is not None for p in processes):
                raise RuntimeError("fixture exited; see server.log")
            try:
                with urllib.request.urlopen("http://127.0.0.1:19090/readyz", timeout=1):
                    break
            except OSError:
                time.sleep(0.1)
        else:
            raise RuntimeError("fixture did not start")
        csrf = api("/auth/login", "POST", {"username": "admin", "password": password.read_text(), "code": ""})["csrf_token"]
        bundle = tmp / "bundle.json"
        run(root / "bin/wafbench", "--config-out", bundle, "--sites", "50")
        draft = api("/config/draft")
        draft["bundle"] = json.loads(bundle.read_text())
        draft = api("/config/draft", "PUT", draft)
        api("/config/publish", "POST", {"version": draft["version"], "base_revision": draft["base_revision"]})
        for mode, flags in [
            ("http", ["--rps", "1000", "--duration", "10s"]),
            ("sse", ["--connections", "1000", "--ramp", "15s", "--duration", "20s"]),
            ("websocket", ["--connections", "1000", "--ramp", "15s", "--duration", "20s"]),
        ]:
            command = [str(root / "bin/wafbench"), "--url", "http://127.0.0.1:18080", "--sites", "50", "--mode", mode, *flags]
            process = subprocess.Popen(command, cwd=root, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            metrics = []
            while process.poll() is None:
                try:
                    with urllib.request.urlopen("http://127.0.0.1:19090/metrics", timeout=2) as response:
                        lines = response.read().decode().splitlines()
                    metrics.append({"time": time.time(), "values": [line for line in lines if line.startswith(("process_", "go_goroutines ", "go_memstats_heap_alloc_bytes ", "waf_connections ", "waf_inflight_requests ", "waf_body_reserved_bytes ", "waf_log_"))]})
                except OSError:
                    pass
                time.sleep(0.5)
            stdout, stderr = process.communicate()
            (out / f"{mode}.json").write_text(stdout)
            (out / f"{mode}-metrics.json").write_text(json.dumps(metrics, indent=2))
            print(stdout, flush=True)
            if process.returncode:
                raise RuntimeError(f"{mode} failed: {stderr}")
        time.sleep(2)
        with urllib.request.urlopen("http://127.0.0.1:19090/metrics", timeout=3) as response:
            (out / "idle-metrics.txt").write_bytes(response.read())
        (out / "environment.json").write_text(json.dumps({"platform": platform.platform(), "cpu_count": os.cpu_count(), "go": run("go", "version").strip(), "shared_host": True, "gomemlimit": env["GOMEMLIMIT"], "measured_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "kind": "loopback smoke; not fixed-hardware production acceptance"}, indent=2))
    finally:
        for process in reversed(processes):
            process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=40)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        log.close()

    # Exercise the actual CLI restore after the serving process has stopped.
    backup = tmp / "backup.age"
    run(root / "bin/waf", "backup", "--config", cfg, "--out", backup, "--password-file", password)
    run(root / "bin/waf", "restore", "--config", cfg, "--in", backup, "--password-file", password)
    checked = run(root / "bin/waf", "check", "--config", cfg)
    (out / "restore.txt").write_text(checked)
