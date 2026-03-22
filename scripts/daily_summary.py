#!/usr/bin/env python3
"""
backup-db-honeypot — Rapport quotidien Telegram
Envoie un résumé des intrusions du jour et remet les stats à zéro.
Planifié via cron : 0 8 * * *
"""
import json, requests, os
from datetime import datetime

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
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    requests.post(url, data={"chat_id": CHAT_ID, "text": msg, "parse_mode": "HTML"}, timeout=5)

def geolocate(ip):
    cache = {}
    if os.path.exists(GEO_CACHE):
        try:
            with open(GEO_CACHE) as f:
                cache = json.load(f)
        except:
            pass
    return cache.get(ip, "?")

def top5(d):
    return sorted(d.items(), key=lambda x: x[1], reverse=True)[:5]

if not os.path.exists(STATS_FILE):
    send("Aucune stat disponible.")
    exit()

with open(STATS_FILE) as f:
    stats = json.load(f)

TYPES = {
    "4002": "SSH brute", "4000": "Co SSH", "4001": "SSH version",
    "3000": "Visite Grafana", "3001": "Login Grafana",
    "2000": "HTTP/FTP", "2001": "Login HTTP/FTP",
    "5001": "Scan/FTP", "9001": "MySQL", "9002": "Redis"
}

msg = f"<b>Rapport quotidien — backup-db</b>\n"
msg += f"{datetime.now().strftime('%d/%m/%Y')}\n"
msg += f"Total événements: <b>{stats.get('total', 0)}</b>\n"

by_type = stats.get("by_type", {})
if by_type:
    msg += "\n<b>Par service:</b>\n"
    for k, v in sorted(by_type.items(), key=lambda x: x[1], reverse=True):
        msg += f"  {TYPES.get(k, 'Type '+k)}: {v}\n"

top_ips = top5(stats.get("top_ips", {}))
if top_ips:
    msg += "\n<b>Top 5 IPs:</b>\n"
    for ip, c in top_ips:
        geo = geolocate(ip)
        msg += f"  {ip} ({geo}): {c}\n"

top_users = top5(stats.get("top_users", {}))
if top_users:
    msg += "\n<b>Top 5 usernames:</b>\n"
    for u, c in top_users:
        msg += f"  {u}: {c}\n"

top_pwds = top5(stats.get("top_passwords", {}))
if top_pwds:
    msg += "\n<b>Top 5 passwords:</b>\n"
    for p, c in top_pwds:
        msg += f"  {p}: {c}\n"

send(msg)

# Reset stats
with open(STATS_FILE, 'w') as f:
    json.dump({"total": 0, "by_type": {}, "top_ips": {}, "top_users": {}, "top_passwords": {}}, f)
