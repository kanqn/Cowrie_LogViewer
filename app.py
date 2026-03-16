#!/usr/bin/env python3
"""
Cowrie SSH Honeypot JSON Log Viewer - Flask App
Python 3.11+
"""

from flask import Flask, render_template, request, jsonify
import json
import os
from pathlib import Path
from collections import defaultdict
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()  # .env を読み込む

app = Flask(__name__)

LOG_DIR = Path(os.environ.get("COWRIE_LOG_DIR", "./logs"))
LOG_DIR.mkdir(exist_ok=True)

SHODAN_API_KEY = os.environ.get("SHODAN_API_KEY", "")


def parse_log_file(filepath: Path) -> list[dict]:
    events = []
    with open(filepath, encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def categorize(ev: dict) -> str:
    eid = ev.get("eventid", "")
    if eid == "cowrie.session.connect":     return "connect"
    if eid == "cowrie.login.success":       return "login_ok"
    if eid == "cowrie.login.failed":        return "login_fail"
    if "command" in eid:                    return "cmd"
    if eid == "cowrie.client.kex":          return "kex"
    if eid == "cowrie.client.version":      return "version"
    if "closed" in eid:                     return "closed"
    return "other"


def build_stats(events: list[dict]) -> dict:
    sessions     = set()
    ips          = defaultdict(int)
    passwords    = defaultdict(int)
    login_ok     = 0
    login_fail   = 0
    cmds         = []
    ssh_versions = defaultdict(int)
    hourly       = defaultdict(int)

    for ev in events:
        if s := ev.get("session"):
            sessions.add(s)
        if ip := ev.get("src_ip"):
            ips[ip] += 1
        eid = ev.get("eventid", "")
        if eid == "cowrie.login.success":
            login_ok += 1
            if pw := ev.get("password"):
                passwords[pw] += 1
        if eid == "cowrie.login.failed":
            login_fail += 1
            if pw := ev.get("password"):
                passwords[pw] += 1
        if "command" in eid and (cmd := ev.get("input")):
            cmds.append(cmd)
        if eid == "cowrie.client.version":
            if ver := ev.get("version"):
                ssh_versions[ver] += 1
        if ts := ev.get("timestamp"):
            try:
                hour = datetime.fromisoformat(ts.replace("Z", "+00:00")).hour
                hourly[hour] += 1
            except Exception:
                pass

    top_ips       = sorted(ips.items(),       key=lambda x: -x[1])[:10]
    top_passwords = sorted(passwords.items(), key=lambda x: -x[1])[:10]
    top_versions  = sorted(ssh_versions.items(), key=lambda x: -x[1])[:8]
    hourly_data   = [hourly.get(h, 0) for h in range(24)]

    return {
        "total":         len(events),
        "sessions":      len(sessions),
        "login_ok":      login_ok,
        "login_fail":    login_fail,
        "cmd_count":     len(cmds),
        "top_ips":       top_ips,
        "top_passwords": top_passwords,
        "top_versions":  top_versions,
        "hourly":        hourly_data,
    }


@app.route("/")
def index():
    log_files = sorted(LOG_DIR.glob("*.json")) + sorted(LOG_DIR.glob("*.log"))
    filenames = [f.name for f in log_files]
    return render_template("index.html", filenames=filenames)


@app.route("/api/load", methods=["POST"])
def api_load():
    data = request.get_json()
    filename = data.get("filename", "")
    if not filename:
        return jsonify({"error": "ファイル名が必要です"}), 400

    filepath = LOG_DIR / filename
    if not filepath.exists():
        return jsonify({"error": "ファイルが見つかりません"}), 404

    events = parse_log_file(filepath)
    stats  = build_stats(events)

    # eventsにcategoryを付与
    for ev in events:
        ev["_cat"] = categorize(ev)

    return jsonify({"events": events, "stats": stats})


@app.route("/api/upload", methods=["POST"])
def api_upload():
    if "file" not in request.files:
        return jsonify({"error": "ファイルが見つかりません"}), 400
    f = request.files["file"]
    if not f.filename:
        return jsonify({"error": "ファイル名が空です"}), 400

    save_path = LOG_DIR / f.filename
    f.save(save_path)
    events = parse_log_file(save_path)
    stats  = build_stats(events)
    for ev in events:
        ev["_cat"] = categorize(ev)

    return jsonify({"events": events, "stats": stats, "filename": f.filename})


@app.route("/api/shodan/status")
def api_shodan_status():
    """APIキーが設定されているか確認"""
    return jsonify({"configured": bool(SHODAN_API_KEY)})


@app.route("/api/shodan/lookup", methods=["POST"])
def api_shodan_lookup():
    """指定IPのShodan情報を取得"""
    if not SHODAN_API_KEY:
        return jsonify({"error": "SHODAN_API_KEY が .env に設定されていません"}), 400

    data = request.get_json()
    ip = (data.get("ip") or "").strip()
    if not ip:
        return jsonify({"error": "IPアドレスが必要です"}), 400

    try:
        import shodan
        api = shodan.Shodan(SHODAN_API_KEY)
        host = api.host(ip)

        # 必要な情報だけ抽出して返す
        ports = sorted({item["port"] for item in host.get("data", [])})
        services = []
        for item in host.get("data", []):
            svc = {
                "port":      item.get("port"),
                "transport": item.get("transport", "tcp"),
                "product":   item.get("product", ""),
                "version":   item.get("version", ""),
                "banner":    (item.get("data") or "")[:300],
                "timestamp": item.get("timestamp", ""),
            }
            if item.get("vulns"):
                svc["vulns"] = list(item["vulns"].keys())
            services.append(svc)

        # CVE まとめ
        all_vulns = {}
        for item in host.get("data", []):
            for cve, detail in (item.get("vulns") or {}).items():
                all_vulns[cve] = {
                    "cvss":    detail.get("cvss"),
                    "summary": detail.get("summary", ""),
                }

        result = {
            "ip":           host.get("ip_str"),
            "org":          host.get("org", ""),
            "isp":          host.get("isp", ""),
            "asn":          host.get("asn", ""),
            "country":      host.get("country_name", ""),
            "city":         host.get("city", ""),
            "hostnames":    host.get("hostnames", []),
            "domains":      host.get("domains", []),
            "tags":         host.get("tags", []),
            "os":           host.get("os", ""),
            "ports":        ports,
            "services":     services,
            "vulns":        all_vulns,
            "last_update":  host.get("last_update", ""),
        }
        return jsonify(result)

    except Exception as e:
        err = str(e)
        if "No information available" in err or "404" in err:
            return jsonify({"error": f"このIPのShodan情報は見つかりませんでした ({ip})"}), 404
        if "Invalid API key" in err or "401" in err:
            return jsonify({"error": "APIキーが無効です。.env を確認してください"}), 401
        return jsonify({"error": f"Shodanエラー: {err}"}), 500


if __name__ == "__main__":
    print("=" * 50)
    print("  Cowrie Log Viewer")
    print(f"  http://127.0.0.1:5000")
    print(f"  ログディレクトリ: {LOG_DIR.resolve()}")
    print("=" * 50)
    app.run(debug=True, port=5000)
