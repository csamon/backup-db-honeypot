#!/usr/bin/env python3
"""
backup-db-honeypot — Alertes Telegram temps réel
Lit les logs OpenCanary sur stdin et envoie des notifications Telegram
avec géolocalisation IP et stats cumulées.
"""
import sys, json, requests, os

# Charger la config
CONFIG_FILE = "/opt/opencanary/settings.conf"
STATS_FILE = "/opt/opencanary/stats.json"
GEO_CACHE = "/opt/opencanary/geo_cache.json"

def load_config():
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    k, v = line.split('=', 1)
                    config[k.strip()] = v.strip().strip('"')
    return config

cfg = load_config()
TOKEN = cfg.get("TELEGRAM_TOKEN", "")
CHAT_ID = cfg.get("TELEGRAM_CHAT_ID", "")

def send(msg):
    if not TOKEN or not CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    try:
        requests.post(url, data={"chat_id": CHAT_ID, "text": msg, "parse_mode": "HTML"}, timeout=5)
    except:
        pass

def geolocate(ip):
    cache = {}
    if os.path.exists(GEO_CACHE):
        try:
            with open(GEO_CACHE) as f:
                cache = json.load(f)
        except:
            pass
    if ip in cache:
        return cache[ip]
    try:
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        d = r.json()
        result = f"{d.get('country','?')} / {d.get('city','?')}" if d.get("status") == "success" else "?"
    except:
        result = "?"
    cache[ip] = result
    try:
        with open(GEO_CACHE, 'w') as f:
            json.dump(cache, f)
    except:
        pass
    return result

def load_stats():
    if os.path.exists(STATS_FILE):
        try:
            with open(STATS_FILE) as f:
                return json.load(f)
        except:
            pass
    return {"total": 0, "by_type": {}, "top_ips": {}, "top_users": {}, "top_passwords": {}}

def save_stats(s):
    try:
        with open(STATS_FILE, 'w') as f:
            json.dump(s, f)
    except:
        pass

IGNORE = {1001}

def get_label(logtype, port, extra):
    if logtype == 5001 and isinstance(extra, dict) and "PROTO" in extra:
        return "Scan de port"
    if logtype == 2000:
        return "Connexion FTP" if port == 21 else "Connexion HTTP"
    if logtype == 2001:
        return "Login FTP" if port == 21 else "Login HTTP"
    labels = {
        3000: "Visite HTTP (Grafana)",
        3001: "Login HTTP (Grafana)",
        4000: "Connexion SSH",
        4001: "Echange SSH",
        4002: "Tentative SSH",
        5001: "Connexion FTP",
        5002: "Login FTP",
        9001: "Tentative MySQL",
        9002: "Tentative Redis"
    }
    return labels.get(logtype, f"Evenement {logtype}")

for line in sys.stdin:
    try:
        log = json.loads(line.strip())
        logtype = log.get("logtype", 0)
        if logtype in IGNORE:
            continue
        src = log.get("src_host", "")
        port = log.get("dst_port", 0)
        t = log.get("local_time_adjusted", "?")
        extra = log.get("logdata", {})

        stats = load_stats()
        stats["total"] = stats.get("total", 0) + 1
        key = str(logtype)
        stats["by_type"][key] = stats["by_type"].get(key, 0) + 1
        if src:
            stats["top_ips"][src] = stats["top_ips"].get(src, 0) + 1
        if isinstance(extra, dict):
            user = extra.get("USERNAME", "")
            pwd = extra.get("PASSWORD", "")
            if user:
                stats["top_users"][user] = stats["top_users"].get(user, 0) + 1
            if pwd:
                stats["top_passwords"][pwd] = stats["top_passwords"].get(pwd, 0) + 1
        save_stats(stats)

        label = get_label(logtype, port, extra)
        geo = geolocate(src) if src else "?"
        msg = f"<b>{label}</b>\nHeure: {t}\nIP: {src} ({geo})\nPort: {port}"
        if isinstance(extra, dict):
            user = extra.get("USERNAME", "")
            pwd = extra.get("PASSWORD", "")
            if user:
                msg += f"\nUser: {user}"
            if pwd:
                msg += f"\nPassword: {pwd}"
        send(msg)
    except:
        pass
