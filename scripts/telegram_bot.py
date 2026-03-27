#!/usr/bin/env python3
"""
backup-db-honeypot — Bot Telegram interactif
Long-polling sur l'API Telegram, répond aux commandes envoyées depuis le chat autorisé.

Commandes :
  /scan          Scan réseau enrichi (nmap + mDNS + NetBIOS + MAC analysis)
  /watch [on|off|N]  Surveillance réseau périodique (défaut 5 min)
  /ports <ip>    Scan des ports ouverts d'un hôte
  /who <ip>      Fiche complète d'un hôte
  /ping <ip>     Ping rapide depuis la Pi
  /stats         Statistiques du honeypot
  /last [N]      Dernières N tentatives d'intrusion
  /block <ip>    Bloquer une IP (iptables DROP)
  /unblock <ip>  Débloquer une IP
  /temp          Température CPU
  /disk          Espace disque
  /status        État des services + uptime + RAM
  /help          Liste des commandes
"""
import os, re, subprocess, time, json, threading, concurrent.futures
from datetime import datetime
import requests

CONFIG_FILE = "/opt/opencanary/settings.conf"
WATCH_STATE_FILE = "/opt/opencanary/watch_state.json"
OPENCANARY_LOG = "/var/log/opencanary.log"
STATS_FILE = "/opt/opencanary/stats.json"

LOG_TYPES = {
    2000: "FTP login",
    3000: "SSH login",
    3001: "SSH connexion",
    4000: "HTTP login (Grafana)",
    4001: "HTTP POST",
    4002: "HTTP connexion",
    5001: "Scan de port",
}


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
    for chunk in _split_message(text, 4000):
        try:
            requests.post(
                url,
                data={"chat_id": chat_id or CHAT_ID, "text": chunk, "parse_mode": "HTML"},
                timeout=10,
            )
        except Exception:
            pass


def _split_message(text, limit):
    if len(text) <= limit:
        return [text]
    chunks = []
    while text:
        if len(text) <= limit:
            chunks.append(text)
            break
        cut = text.rfind("\n", 0, limit)
        if cut == -1:
            cut = limit
        chunks.append(text[:cut])
        text = text[cut:].lstrip("\n")
    return chunks


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


# ── Résolution de noms ────────────────────────────────────────────────────────

def _resolve_mdns(ip):
    try:
        r = subprocess.run(
            ["avahi-resolve-address", ip],
            capture_output=True, text=True, timeout=3,
        )
        if r.returncode == 0 and r.stdout.strip():
            parts = r.stdout.strip().split("\t")
            if len(parts) >= 2:
                return parts[1].rstrip(".")
    except Exception:
        pass
    return None


def _resolve_mdns_batch(ips):
    results = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        futures = {pool.submit(_resolve_mdns, ip): ip for ip in ips}
        for future in concurrent.futures.as_completed(futures):
            ip = futures[future]
            try:
                name = future.result()
                if name:
                    results[ip] = name
            except Exception:
                pass
    return results


def _resolve_netbios_batch(network):
    results = {}
    try:
        r = subprocess.run(
            ["nbtscan", "-q", "-s", "\t", network],
            capture_output=True, text=True, timeout=15,
        )
        for line in r.stdout.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2:
                ip   = parts[0].strip()
                name = parts[1].strip()
                if ip and name and name != "<unknown>":
                    results[ip] = name
    except Exception:
        pass
    return results


def _resolve_nmblookup(ip):
    try:
        r = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            m = re.match(r"\s+(\S+)\s+<00>\s+", line)
            if m:
                name = m.group(1)
                if name != "IS~" and not name.startswith("__"):
                    return name
    except Exception:
        pass
    return None


def _is_mac_random(mac):
    if not mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except Exception:
        return False


# ── Scan réseau (partagé entre /scan et /watch) ──────────────────────────────

def _do_scan():
    """Exécute un scan complet enrichi, retourne la liste de hosts (dicts)."""
    network = _get_local_network()
    if not network:
        return None, []

    try:
        result = subprocess.run(
            ["nmap", "-sn", "-R", "--host-timeout", "3s", network],
            capture_output=True, text=True, timeout=90,
        )
    except Exception:
        return network, []

    hosts = _parse_nmap(result.stdout)
    if not hosts:
        return network, []

    ips = [h["ip"] for h in hosts]
    mdns_names   = _resolve_mdns_batch(ips)
    netbios_names = _resolve_netbios_batch(network)

    for h in hosts:
        ip = h["ip"]
        names = []
        if h.get("name"):         names.append(h["name"])
        if ip in mdns_names:       names.append(mdns_names[ip])
        if ip in netbios_names:    names.append(netbios_names[ip])
        seen = set()
        unique = []
        for n in names:
            key = n.lower().rstrip(".")
            if key not in seen:
                seen.add(key)
                unique.append(n)
        h["names"] = unique
        h["mac_random"] = _is_mac_random(h.get("mac", ""))

    return network, hosts


def _format_scan(network, hosts):
    """Formate les résultats de scan en texte HTML pour Telegram."""
    if not hosts:
        return f"Aucun hôte trouvé sur <code>{network}</code>."

    lines = [
        f"<b>Scan réseau</b>  <code>{network}</code>",
        f"<i>{len(hosts)} hôte(s)</i>\n",
    ]
    for h in _sort_ips(hosts):
        ip = h["ip"]
        name_str = ""
        if h.get("names"):
            name_str = "  " + "  /  ".join(f"<b>{n}</b>" for n in h["names"])
        lines.append(f"<code>{ip}</code>{name_str}")

        details = []
        if h.get("vendor"):
            details.append(h["vendor"])
        if h.get("mac"):
            mac_str = f'<code>{h["mac"]}</code>'
            if h.get("mac_random"):
                mac_str += " ⚡"
            details.append(mac_str)
        if h.get("latency"):
            details.append(h["latency"])
        if details:
            lines.append("    " + "  ·  ".join(details))
        lines.append("")

    lines.append("<i>⚡ = MAC aléatoire (appareil mobile probable)</i>")
    return "\n".join(lines).rstrip()


COMMAND_REMINDER = (
    "\n\n<i>Commandes : /ports &lt;ip&gt; · /who &lt;ip&gt; · "
    "/ping &lt;ip&gt; · /block &lt;ip&gt; · /help</i>"
)


# ── Watch (surveillance périodique) ──────────────────────────────────────────

watch_lock     = threading.Lock()
watch_active   = False
watch_interval = 300  # 5 minutes par défaut
watch_timer    = None
watch_known    = {}  # {ip: {"mac": ..., "names": [...], "vendor": ...}}


def _watch_save_state():
    """Persiste l'état du watch sur disque."""
    try:
        state = {
            "active": watch_active,
            "interval": watch_interval,
            "known": watch_known,
        }
        tmp = WATCH_STATE_FILE + ".tmp"
        with open(tmp, "w") as f:
            json.dump(state, f)
        os.replace(tmp, WATCH_STATE_FILE)
    except Exception:
        pass


def _watch_load_state():
    """Restaure l'état du watch depuis le disque."""
    global watch_active, watch_interval, watch_known
    try:
        if os.path.exists(WATCH_STATE_FILE):
            with open(WATCH_STATE_FILE) as f:
                state = json.load(f)
            watch_active   = state.get("active", False)
            watch_interval = state.get("interval", 300)
            watch_known    = state.get("known", {})
    except Exception:
        pass


def _watch_cycle():
    """Exécute un cycle de scan et compare avec les hôtes connus."""
    global watch_known, watch_timer
    if not watch_active:
        return

    network, hosts = _do_scan()
    if not hosts:
        _schedule_next_watch()
        return

    current = {}
    for h in hosts:
        current[h["ip"]] = {
            "mac": h.get("mac", ""),
            "names": h.get("names", []),
            "vendor": h.get("vendor", ""),
            "mac_random": h.get("mac_random", False),
        }

    # Comparer avec les hôtes connus
    current_ips = set(current.keys())
    known_ips   = set(watch_known.keys())
    new_ips     = current_ips - known_ips
    gone_ips    = known_ips - current_ips

    if new_ips or gone_ips:
        # Construire l'alerte diff
        lines = [f"🔔 <b>Watch — changement réseau détecté</b>\n"]

        if new_ips:
            lines.append(f"🆕 <b>{len(new_ips)} nouvel(aux) appareil(s)</b>")
            for ip in sorted(new_ips):
                info = current[ip]
                name_str = "  /  ".join(info["names"]) if info["names"] else ""
                random_flag = " ⚡" if info["mac_random"] else ""
                vendor = info["vendor"] or "Unknown"
                lines.append(f"  <code>{ip}</code>  {name_str}")
                lines.append(f"    {vendor}  ·  <code>{info['mac']}</code>{random_flag}")
            lines.append("")

        if gone_ips:
            lines.append(f"❌ <b>{len(gone_ips)} appareil(s) disparu(s)</b>")
            for ip in sorted(gone_ips):
                info = watch_known[ip]
                name_str = "  /  ".join(info.get("names", [])) if info.get("names") else ""
                lines.append(f"  <code>{ip}</code>  {name_str}")
            lines.append("")

        # Scan complet en dessous
        lines.append("─" * 30)
        lines.append(_format_scan(network, hosts))
        lines.append(COMMAND_REMINDER)

        send("\n".join(lines))

        # Mettre à jour la baseline
        watch_known = current
        _watch_save_state()

    _schedule_next_watch()


def _schedule_next_watch():
    """Programme le prochain cycle de watch."""
    global watch_timer
    if watch_active:
        watch_timer = threading.Timer(watch_interval, _watch_cycle)
        watch_timer.daemon = True
        watch_timer.start()


def cmd_watch(args):
    """Gère la surveillance périodique du réseau."""
    global watch_active, watch_interval, watch_known, watch_timer
    arg = args.strip().lower()

    if arg == "off":
        with watch_lock:
            watch_active = False
            if watch_timer:
                watch_timer.cancel()
                watch_timer = None
            _watch_save_state()
        return "🔴 <b>Watch désactivé</b>"

    # Changement d'intervalle ?
    if arg.isdigit():
        new_interval = int(arg)
        if new_interval < 1:
            return "Intervalle minimum : 1 minute."
        with watch_lock:
            watch_interval = new_interval * 60
            _watch_save_state()
        if watch_active:
            return f"⏱ Intervalle mis à jour : <b>{new_interval} min</b>"
        # Si pas encore actif, on active avec le nouvel intervalle
        arg = "on"

    if arg in ("", "on"):
        # Scan initial comme baseline
        network, hosts = _do_scan()
        if not hosts:
            return "Impossible de scanner le réseau."

        with watch_lock:
            watch_active = True
            watch_known = {}
            for h in hosts:
                watch_known[h["ip"]] = {
                    "mac": h.get("mac", ""),
                    "names": h.get("names", []),
                    "vendor": h.get("vendor", ""),
                    "mac_random": h.get("mac_random", False),
                }
            _watch_save_state()
            _schedule_next_watch()

        mins = watch_interval // 60
        lines = [
            f"🟢 <b>Watch activé</b> — scan toutes les <b>{mins} min</b>",
            f"<i>{len(hosts)} hôte(s) enregistrés comme baseline</i>\n",
            "─" * 30,
            _format_scan(network, hosts),
            COMMAND_REMINDER,
        ]
        return "\n".join(lines)

    return (
        "Usage :\n"
        "<code>/watch</code> ou <code>/watch on</code> — activer (5 min)\n"
        "<code>/watch off</code> — désactiver\n"
        "<code>/watch 15</code> — changer l'intervalle (15 min)"
    )


# ── Commandes réseau ─────────────────────────────────────────────────────────

def cmd_scan():
    network, hosts = _do_scan()
    if not network:
        return "Impossible de déterminer le réseau local."
    result = _format_scan(network, hosts)
    result += COMMAND_REMINDER
    return result


def cmd_ports(args):
    ip = args.strip()
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return "Usage : <code>/ports 192.168.150.XX</code>"
    try:
        result = subprocess.run(
            ["nmap", "-T4", "--top-ports", "200", "-sV", "--version-intensity", "0",
             "--host-timeout", "15s", ip],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return f"Scan de <code>{ip}</code> expiré."

    ports = []
    for line in result.stdout.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+(open)\s+(.+)$", line)
        if m:
            ports.append(f"<code>{m.group(1)}/{m.group(2)}</code>  {m.group(4).strip()}")

    if not ports:
        return f"<code>{ip}</code> — aucun port ouvert trouvé (top 200)."

    lines = [f"<b>Ports ouverts</b>  <code>{ip}</code>\n"]
    lines.extend(f"  {p}" for p in ports)
    return "\n".join(lines)


def cmd_who(args):
    ip = args.strip()
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return "Usage : <code>/who 192.168.150.XX</code>"

    lines = [f"<b>Fiche hôte</b>  <code>{ip}</code>\n"]

    # Noms
    names = []
    mdns = _resolve_mdns(ip)
    if mdns:
        names.append(f"mDNS: {mdns}")
    netbios = _resolve_nmblookup(ip)
    if netbios:
        names.append(f"NetBIOS: {netbios}")
    try:
        r = subprocess.run(["getent", "hosts", ip],
                           capture_output=True, text=True, timeout=3)
        if r.returncode == 0 and r.stdout.strip():
            dns_name = r.stdout.strip().split()[-1]
            if dns_name != ip:
                names.append(f"DNS: {dns_name}")
    except Exception:
        pass
    if names:
        lines.append("<b>Noms</b>")
        for n in names:
            lines.append(f"  {n}")
        lines.append("")

    # MAC
    try:
        arp = subprocess.run(["arp", "-a", ip],
                             capture_output=True, text=True, timeout=3)
        m = re.search(r"(([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})", arp.stdout)
        if m:
            mac = m.group(1).lower()
            random_flag = " ⚡ aléatoire" if _is_mac_random(mac) else ""
            lines.append(f"<b>MAC</b>  <code>{mac}</code>{random_flag}")
    except Exception:
        pass

    # Latence
    try:
        ping = subprocess.run(["ping", "-c", "3", "-W", "2", ip],
                              capture_output=True, text=True, timeout=10)
        m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)", ping.stdout)
        if m:
            lines.append(f"<b>Latence</b>  min {m.group(1)} / avg {m.group(2)} / max {m.group(3)} ms")
    except Exception:
        pass

    # Ports
    try:
        result = subprocess.run(
            ["nmap", "-T4", "-F", "--host-timeout", "10s", ip],
            capture_output=True, text=True, timeout=30,
        )
        ports = []
        for line in result.stdout.splitlines():
            pm = re.match(r"^(\d+)/(tcp|udp)\s+(open)\s+(.+)$", line)
            if pm:
                ports.append(f"<code>{pm.group(1)}/{pm.group(2)}</code> {pm.group(4).strip()}")
        if ports:
            lines.append("")
            lines.append(f"<b>Ports ouverts</b> ({len(ports)})")
            for p in ports:
                lines.append(f"  {p}")
        else:
            lines.append("\n<i>Aucun port ouvert (top 100)</i>")
    except Exception:
        pass

    return "\n".join(lines)


def cmd_ping(args):
    ip = args.strip()
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return "Usage : <code>/ping 192.168.150.XX</code>"
    try:
        r = subprocess.run(
            ["ping", "-c", "4", "-W", "2", ip],
            capture_output=True, text=True, timeout=15,
        )
        # Extraire les lignes utiles
        lines = []
        for line in r.stdout.splitlines():
            if "bytes from" in line or "packet loss" in line or "min/avg/max" in line:
                lines.append(line.strip())
        if not lines:
            if r.returncode != 0:
                return f"<code>{ip}</code> — ne répond pas."
        return f"<b>Ping</b>  <code>{ip}</code>\n\n" + "\n".join(lines)
    except subprocess.TimeoutExpired:
        return f"<code>{ip}</code> — timeout."


# ── Commandes honeypot ───────────────────────────────────────────────────────

def cmd_stats():
    """Statistiques du honeypot depuis stats.json + log."""
    # Depuis stats.json
    stats = {}
    try:
        with open(STATS_FILE) as f:
            stats = json.load(f)
    except Exception:
        pass

    # Compter aussi les lignes du log actuel (depuis le dernier reset)
    log_count = 0
    recent_types = {}
    try:
        with open(OPENCANARY_LOG) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                log_count += 1
                try:
                    entry = json.loads(line)
                    lt = entry.get("logtype", 0)
                    recent_types[lt] = recent_types.get(lt, 0) + 1
                except Exception:
                    pass
    except Exception:
        pass

    total = stats.get("total", 0) + log_count
    lines = [f"<b>Statistiques honeypot</b>\n"]
    lines.append(f"Total événements : <b>{total}</b>")

    # Par type
    by_type = {}
    for k, v in stats.get("by_type", {}).items():
        by_type[int(k)] = v
    for k, v in recent_types.items():
        by_type[k] = by_type.get(k, 0) + v
    if by_type:
        lines.append("")
        lines.append("<b>Par type</b>")
        for lt in sorted(by_type.keys()):
            label = LOG_TYPES.get(lt, f"Type {lt}")
            lines.append(f"  {label} : {by_type[lt]}")

    # Top IPs
    top_ips = stats.get("top_ips", {})
    if top_ips:
        lines.append("")
        lines.append("<b>Top IPs</b>")
        sorted_ips = sorted(top_ips.items(), key=lambda x: x[1], reverse=True)[:10]
        for ip, count in sorted_ips:
            lines.append(f"  <code>{ip}</code>  ×{count}")

    # Top passwords
    top_pw = stats.get("top_passwords", {})
    if top_pw:
        lines.append("")
        lines.append("<b>Top passwords</b>")
        sorted_pw = sorted(top_pw.items(), key=lambda x: x[1], reverse=True)[:10]
        for pw, count in sorted_pw:
            lines.append(f"  <code>{pw}</code>  ×{count}")

    return "\n".join(lines)


def cmd_last(args):
    """Affiche les N dernières tentatives d'intrusion."""
    n = 10
    arg = args.strip()
    if arg.isdigit():
        n = min(int(arg), 50)

    entries = []
    try:
        with open(OPENCANARY_LOG) as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        pass
    except Exception:
        return "Aucun log trouvé."

    if not entries:
        return "Aucune tentative enregistrée."

    entries = entries[-n:]
    lines = [f"<b>Dernières {len(entries)} tentatives</b>\n"]
    for e in reversed(entries):
        ts      = e.get("local_time", "?")[:19]
        src     = e.get("src_host", "?")
        dst_p   = e.get("dst_port", "?")
        lt      = e.get("logtype", 0)
        label   = LOG_TYPES.get(lt, f"Type {lt}")
        logdata = e.get("logdata", {})

        detail = ""
        if lt in (2000, 3000, 4000):  # Login attempts
            user = logdata.get("USERNAME", logdata.get("username", ""))
            pwd  = logdata.get("PASSWORD", logdata.get("password", ""))
            if user or pwd:
                detail = f"  {user}:{pwd}"

        lines.append(f"<code>{ts}</code>  {src}  →  :{dst_p}")
        lines.append(f"  {label}{detail}")
        lines.append("")

    return "\n".join(lines).rstrip()


def cmd_block(args):
    ip = args.strip()
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return "Usage : <code>/block 192.168.150.XX</code>"

    # Sécurité : ne pas bloquer notre propre IP ou le CHAT_ID caller
    local_ip = _get_local_ip()
    if ip == local_ip or ip == "127.0.0.1":
        return "Impossible de bloquer la Pi elle-même."

    try:
        # Vérifier si déjà bloquée
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5,
        )
        if check.returncode == 0:
            return f"<code>{ip}</code> est déjà bloquée."

        subprocess.run(
            ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5, check=True,
        )
        return f"🚫 <code>{ip}</code> bloquée (iptables DROP)."
    except Exception as e:
        return f"Erreur iptables : {e}"


def cmd_unblock(args):
    ip = args.strip()
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return "Usage : <code>/unblock 192.168.150.XX</code>"
    try:
        subprocess.run(
            ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=5, check=True,
        )
        return f"✅ <code>{ip}</code> débloquée."
    except subprocess.CalledProcessError:
        return f"<code>{ip}</code> n'était pas bloquée."
    except Exception as e:
        return f"Erreur iptables : {e}"


# ── Commandes système ────────────────────────────────────────────────────────

def cmd_temp():
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            temp = int(f.read().strip()) / 1000
        icon = "🟢" if temp < 60 else "🟠" if temp < 70 else "🔴"
        return f"{icon} <b>CPU</b>  {temp:.1f} °C"
    except Exception:
        return "Impossible de lire la température."


def cmd_disk():
    try:
        r = subprocess.run(["df", "-h", "/"], capture_output=True, text=True, timeout=5)
        lines = r.stdout.strip().splitlines()
        if len(lines) >= 2:
            parts = lines[1].split()
            total, used, avail, pct = parts[1], parts[2], parts[3], parts[4]
            pct_int = int(pct.rstrip("%"))
            icon = "🟢" if pct_int < 70 else "🟠" if pct_int < 85 else "🔴"
            return (
                f"{icon} <b>Disque /</b>\n"
                f"  Total : {total}  ·  Utilisé : {used} ({pct})  ·  Libre : {avail}"
            )
    except Exception:
        pass
    return "Impossible de lire l'espace disque."


def cmd_status():
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

    # Watch status
    if watch_active:
        mins = watch_interval // 60
        known_count = len(watch_known)
        lines.append(f"🟢 Watch ({mins} min, {known_count} hôtes)")
    else:
        lines.append("🔴 Watch (inactif)")

    # Uptime + RAM + Temp
    try:
        up = subprocess.run(["uptime", "-p"], capture_output=True, text=True, timeout=3)
        lines.append(f"\n<b>Uptime</b>  {up.stdout.strip()}")
    except Exception:
        pass
    try:
        mem = subprocess.run(["free", "-h"], capture_output=True, text=True, timeout=3)
        for line in mem.stdout.splitlines():
            if line.startswith("Mem:"):
                parts = line.split()
                lines.append(f"<b>RAM</b>  {parts[2]} / {parts[1]} utilisée")
    except Exception:
        pass
    try:
        with open("/sys/class/thermal/thermal_zone0/temp") as f:
            temp = int(f.read().strip()) / 1000
        icon = "🟢" if temp < 60 else "🟠" if temp < 70 else "🔴"
        lines.append(f"{icon} <b>CPU</b>  {temp:.1f} °C")
    except Exception:
        pass

    return "\n".join(lines)


def cmd_help():
    watch_status = ""
    if watch_active:
        mins = watch_interval // 60
        watch_status = f" (actif, {mins} min)"
    else:
        watch_status = " (inactif)"

    return (
        "<b>Commandes réseau</b>\n"
        "/scan — Scan enrichi (nmap + mDNS + NetBIOS)\n"
        f"/watch [on|off|N] — Surveillance périodique{watch_status}\n"
        "/ports &lt;ip&gt; — Ports ouverts d'un hôte\n"
        "/who &lt;ip&gt; — Fiche complète d'un hôte\n"
        "/ping &lt;ip&gt; — Ping rapide\n"
        "\n<b>Commandes honeypot</b>\n"
        "/stats — Statistiques d'attaques\n"
        "/last [N] — Dernières N tentatives (défaut 10)\n"
        "/block &lt;ip&gt; — Bloquer une IP\n"
        "/unblock &lt;ip&gt; — Débloquer une IP\n"
        "\n<b>Commandes système</b>\n"
        "/temp — Température CPU\n"
        "/disk — Espace disque\n"
        "/status — Services + uptime + RAM + temp\n"
        "/help — Cette aide\n"
        "\n<i>⚡ = MAC aléatoire (appareil mobile)</i>"
    )


# ── Helpers internes ──────────────────────────────────────────────────────────

def _get_local_network():
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
        mask  = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        ip_int = (int(ip_parts[0]) << 24 | int(ip_parts[1]) << 16 |
                  int(ip_parts[2]) << 8  | int(ip_parts[3]))
        net_int = ip_int & mask
        net_ip  = ".".join(str((net_int >> s) & 0xFF) for s in (24, 16, 8, 0))
        return f"{net_ip}/{prefix}"
    except Exception:
        return None


def _get_local_ip():
    try:
        out = subprocess.run(
            ["ip", "-4", "addr", "show", IFACE],
            capture_output=True, text=True, timeout=5,
        ).stdout
        match = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/", out)
        return match.group(1) if match else None
    except Exception:
        return None


def _parse_nmap(output):
    hosts = []
    cur = {}
    for line in output.splitlines():
        if "Nmap scan report for" in line:
            if cur.get("ip") and cur.get("up"):
                hosts.append(cur)
            cur = {}
            rest = line.replace("Nmap scan report for", "").strip()
            m = re.match(r"^(.+?)\s+\((\d[\d.]+)\)$", rest)
            if m:
                cur["name"] = m.group(1)
                cur["ip"]   = m.group(2)
            else:
                cur["ip"] = rest
        elif "Host is up" in line and cur.get("ip"):
            cur["up"] = True
            m = re.search(r"\(([\d.]+)s latency\)", line)
            if m:
                ms = float(m.group(1)) * 1000
                cur["latency"] = f"{ms:.1f} ms"
        elif "MAC Address:" in line and cur.get("ip"):
            m = re.match(r"MAC Address: ([0-9A-Fa-f:]+)\s+\((.+)\)", line)
            if m:
                cur["mac"]    = m.group(1).lower()
                cur["vendor"] = m.group(2)
    if cur.get("ip") and cur.get("up"):
        hosts.append(cur)
    return hosts


def _sort_ips(hosts):
    def key(h):
        try:
            return tuple(int(p) for p in h["ip"].split("."))
        except Exception:
            return (0, 0, 0, 0)
    return sorted(hosts, key=key)


# ── Boucle principale ─────────────────────────────────────────────────────────

COMMANDS_SIMPLE = {
    "/scan":   cmd_scan,
    "/status": cmd_status,
    "/help":   cmd_help,
    "/stats":  cmd_stats,
    "/temp":   cmd_temp,
    "/disk":   cmd_disk,
}

COMMANDS_WITH_ARGS = {
    "/ports":   cmd_ports,
    "/who":     cmd_who,
    "/ping":    cmd_ping,
    "/watch":   cmd_watch,
    "/last":    cmd_last,
    "/block":   cmd_block,
    "/unblock": cmd_unblock,
}

LOADING_MSG = {
    "/scan":    "Scan réseau en cours (nmap + mDNS + NetBIOS)...",
    "/watch":   "Configuration du watch...",
    "/status":  "Vérification des services...",
    "/ports":   "Scan des ports en cours...",
    "/who":     "Analyse de l'hôte en cours...",
    "/ping":    "Ping en cours...",
    "/stats":   "Chargement des statistiques...",
    "/last":    "Lecture des logs...",
    "/block":   "Mise à jour iptables...",
    "/unblock": "Mise à jour iptables...",
}


def main():
    if not TOKEN or not CHAT_ID:
        print("TELEGRAM_TOKEN ou TELEGRAM_CHAT_ID manquant dans settings.conf")
        return

    # Restaurer l'état du watch
    _watch_load_state()
    if watch_active:
        print(f"Watch restauré — scan toutes les {watch_interval // 60} min")
        _schedule_next_watch()

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

                if chat_id != CHAT_ID:
                    continue

                parts = text.split(None, 1)
                cmd   = parts[0].split("@")[0].lower() if parts else ""
                args  = parts[1] if len(parts) > 1 else ""

                if cmd in COMMANDS_SIMPLE:
                    loading = LOADING_MSG.get(cmd)
                    if loading:
                        send(f"⏳ {loading}", chat_id=chat_id)
                    reply = COMMANDS_SIMPLE[cmd]()
                    send(reply, chat_id=chat_id)
                elif cmd in COMMANDS_WITH_ARGS:
                    loading = LOADING_MSG.get(cmd)
                    if loading:
                        send(f"⏳ {loading}", chat_id=chat_id)
                    reply = COMMANDS_WITH_ARGS[cmd](args)
                    send(reply, chat_id=chat_id)

        except Exception:
            time.sleep(5)


if __name__ == "__main__":
    main()
