#!/usr/bin/env python3
"""
backup-db-honeypot — Bot Telegram interactif
Long-polling sur l'API Telegram, répond aux commandes envoyées depuis le chat autorisé.

Commandes :
  /scan   Scan du réseau local (nmap -sn) — liste IPs + hostnames
  /status État des services honeypot
  /help   Liste des commandes
"""
import os, re, subprocess, time
import requests

CONFIG_FILE = "/opt/opencanary/settings.conf"


# ── Config ────────────────────────────────────────────────────────────────────

def load_config():
    config = {}
    if os.path.exists(CONFIG_FILE):
        with open(CONFIG_FILE) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    config[k.strip()] = v.strip().strip('"')
    return config


cfg = load_config()
TOKEN   = cfg.get("TELEGRAM_TOKEN", "")
CHAT_ID = cfg.get("TELEGRAM_CHAT_ID", "")
IFACE   = cfg.get("WIFI_INTERFACE", "wlan0")


# ── Telegram helpers ──────────────────────────────────────────────────────────

def send(text, chat_id=None):
    if not TOKEN:
        return
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    try:
        requests.post(
            url,
            data={"chat_id": chat_id or CHAT_ID, "text": text, "parse_mode": "HTML"},
            timeout=10,
        )
    except Exception:
        pass


def get_updates(offset=None):
    url = f"https://api.telegram.org/bot{TOKEN}/getUpdates"
    params = {"timeout": 30, "allowed_updates": ["message"]}
    if offset is not None:
        params["offset"] = offset
    try:
        r = requests.get(url, params=params, timeout=35)
        return r.json()
    except Exception:
        return {}


# ── Commandes ─────────────────────────────────────────────────────────────────

def cmd_scan():
    """Scan du réseau local via nmap -sn, retourne IPs + hostnames."""
    # Déterminer le réseau local à partir de l'interface configurée
    network = _get_local_network()
    if not network:
        return "Impossible de déterminer le réseau local."

    try:
        result = subprocess.run(
            ["nmap", "-sn", "--host-timeout", "3s", network],
            capture_output=True, text=True, timeout=90,
        )
    except FileNotFoundError:
        return "nmap non installé.\nInstalle-le : <code>sudo apt install nmap</code>"
    except subprocess.TimeoutExpired:
        return "Scan expiré (timeout 90 s)."

    hosts = _parse_nmap(result.stdout)
    if not hosts:
        return f"Aucun hôte trouvé sur <code>{network}</code>."

    lines = [f"<b>Scan réseau</b>  <code>{network}</code>", f"{len(hosts)} hôte(s) trouvé(s)\n"]
    for ip, name in _sort_ips(hosts):
        if name:
            lines.append(f"• <code>{ip}</code>  —  {name}")
        else:
            lines.append(f"• <code>{ip}</code>")
    return "\n".join(lines)


def cmd_status():
    """État des services systemd du honeypot."""
    services = [
        ("opencanary",          "OpenCanary (honeypot)"),
        ("opencanary-telegram", "Alertes Telegram"),
        ("telegram-bot",        "Bot Telegram"),
        ("mac-spoof",           "MAC spoofing"),
        ("nmbd",                "NetBIOS (nmbd)"),
    ]
    lines = ["<b>État des services</b>\n"]
    for svc, label in services:
        try:
            r = subprocess.run(
                ["systemctl", "is-active", svc],
                capture_output=True, text=True, timeout=5,
            )
            active = r.stdout.strip() == "active"
            icon = "🟢" if active else "🔴"
            lines.append(f"{icon} {label}")
        except Exception:
            lines.append(f"⬛ {label}  (erreur)")
    return "\n".join(lines)


def cmd_help():
    return (
        "<b>Commandes disponibles</b>\n\n"
        "/scan    — Scan du réseau local (IPs + hostnames)\n"
        "/status  — État des services honeypot\n"
        "/help    — Cette aide"
    )


# ── Helpers internes ──────────────────────────────────────────────────────────

def _get_local_network():
    """Retourne le réseau CIDR de l'interface configurée (ex: 192.168.1.0/24)."""
    try:
        out = subprocess.run(
            ["ip", "-4", "addr", "show", IFACE],
            capture_output=True, text=True, timeout=5,
        ).stdout
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
        if not match:
            return None
        ip_parts = match.group(1).split(".")
        prefix   = int(match.group(2))
        # Calcul de l'adresse réseau
        mask  = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        ip_int = (int(ip_parts[0]) << 24 | int(ip_parts[1]) << 16 |
                  int(ip_parts[2]) << 8  | int(ip_parts[3]))
        net_int = ip_int & mask
        net_ip  = ".".join(str((net_int >> s) & 0xFF) for s in (24, 16, 8, 0))
        return f"{net_ip}/{prefix}"
    except Exception:
        return None


def _parse_nmap(output):
    """Parse la sortie nmap -sn → liste de (ip, hostname|None)."""
    hosts = []
    current_ip = None
    current_name = None
    for line in output.splitlines():
        if "Nmap scan report for" in line:
            rest = line.replace("Nmap scan report for", "").strip()
            m = re.match(r"^(.+?)\s+\((\d[\d.]+)\)$", rest)
            if m:
                current_name = m.group(1)
                current_ip   = m.group(2)
            else:
                current_name = None
                current_ip   = rest
        elif "Host is up" in line and current_ip:
            hosts.append((current_ip, current_name))
            current_ip = current_name = None
    return hosts


def _sort_ips(hosts):
    """Trie les hôtes par ordre d'adresse IP."""
    def key(h):
        try:
            return tuple(int(p) for p in h[0].split("."))
        except Exception:
            return (0, 0, 0, 0)
    return sorted(hosts, key=key)


# ── Boucle principale ─────────────────────────────────────────────────────────

COMMANDS = {
    "/scan":   cmd_scan,
    "/status": cmd_status,
    "/help":   cmd_help,
}


def main():
    if not TOKEN or not CHAT_ID:
        print("TELEGRAM_TOKEN ou TELEGRAM_CHAT_ID manquant dans settings.conf")
        return

    offset = None
    print("Bot démarré — en attente de commandes Telegram...")

    while True:
        try:
            data = get_updates(offset)
            if not data.get("ok"):
                time.sleep(5)
                continue

            for update in data.get("result", []):
                offset = update["update_id"] + 1
                msg     = update.get("message", {})
                chat_id = str(msg.get("chat", {}).get("id", ""))
                text    = msg.get("text", "").strip()

                # Sécurité : on ne répond qu'au chat autorisé
                if chat_id != CHAT_ID:
                    continue

                # Commande reconnue (supporte aussi "/scan@botname")
                cmd = text.split("@")[0].lower()
                if cmd in COMMANDS:
                    send("⏳ " + {"/scan": "Scan en cours...",
                                  "/status": "Vérification des services...",
                                  "/help": ""}.get(cmd, "..."), chat_id=chat_id)
                    reply = COMMANDS[cmd]()
                    send(reply, chat_id=chat_id)

        except Exception:
            time.sleep(5)


if __name__ == "__main__":
    main()
