#!/usr/bin/env python3
"""
backup-db-honeypot — Bot Telegram interactif
Long-polling sur l'API Telegram, répond aux commandes envoyées depuis le chat autorisé.

Commandes :
  /scan          Scan réseau enrichi (nmap + mDNS + NetBIOS + MAC analysis)
  /ports <ip>    Scan des ports ouverts d'un hôte
  /who <ip>      Fiche complète d'un hôte
  /status        État des services honeypot
  /help          Liste des commandes
"""
import os, re, subprocess, time, concurrent.futures
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
    # Telegram limite à 4096 caractères par message
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
    """Découpe un message long en chunks sans couper au milieu d'une ligne."""
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
    """Résout un nom mDNS (.local) via avahi-resolve-address."""
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
    """Résout mDNS pour une liste d'IPs en parallèle."""
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
    """Scan NetBIOS via nbtscan — retourne {ip: name}."""
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

    # Fallback : nmblookup pour les IPs sans résultat nbtscan
    return results


def _resolve_nmblookup(ip):
    """Résout un nom NetBIOS via nmblookup -A (fallback unitaire)."""
    try:
        r = subprocess.run(
            ["nmblookup", "-A", ip],
            capture_output=True, text=True, timeout=5,
        )
        for line in r.stdout.splitlines():
            # Format: "\tNAME           <00>  -         B <ACTIVE>"
            m = re.match(r"\s+(\S+)\s+<00>\s+", line)
            if m:
                name = m.group(1)
                if name != "IS~" and not name.startswith("__"):
                    return name
    except Exception:
        pass
    return None


def _is_mac_random(mac):
    """Détecte une MAC localement administrée (randomisée).
    Le bit 1 du premier octet (bit "locally administered") est à 1."""
    if not mac:
        return False
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0x02)
    except Exception:
        return False


# ── Commandes ─────────────────────────────────────────────────────────────────

def cmd_scan():
    """Scan réseau enrichi : nmap + mDNS + NetBIOS + analyse MAC."""
    network = _get_local_network()
    if not network:
        return "Impossible de déterminer le réseau local."

    # 1. Scan nmap
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-R", "--host-timeout", "3s", network],
            capture_output=True, text=True, timeout=90,
        )
    except FileNotFoundError:
        return "nmap non installé."
    except subprocess.TimeoutExpired:
        return "Scan expiré (timeout 90 s)."

    hosts = _parse_nmap(result.stdout)
    if not hosts:
        return f"Aucun hôte trouvé sur <code>{network}</code>."

    # 2. Résolutions de noms en parallèle
    ips = [h["ip"] for h in hosts]
    mdns_names   = _resolve_mdns_batch(ips)
    netbios_names = _resolve_netbios_batch(network)

    # 3. Enrichir les hôtes
    for h in hosts:
        ip = h["ip"]
        names = []
        if h.get("name"):         names.append(h["name"])
        if ip in mdns_names:       names.append(mdns_names[ip])
        if ip in netbios_names:    names.append(netbios_names[ip])
        # Dédupliquer (mDNS et DNS peuvent donner le même)
        seen = set()
        unique = []
        for n in names:
            key = n.lower().rstrip(".")
            if key not in seen:
                seen.add(key)
                unique.append(n)
        h["names"] = unique
        h["mac_random"] = _is_mac_random(h.get("mac", ""))

    # 4. Formatage
    lines = [
        f"<b>Scan réseau</b>  <code>{network}</code>",
        f"<i>{len(hosts)} hôte(s)</i>\n",
    ]
    for h in _sort_ips(hosts):
        ip = h["ip"]

        # Ligne IP + noms
        name_str = ""
        if h["names"]:
            name_str = "  " + "  /  ".join(f"<b>{n}</b>" for n in h["names"])
        lines.append(f"<code>{ip}</code>{name_str}")

        # Ligne détails : vendor · MAC · latence · flag random
        details = []
        if h.get("vendor"):
            details.append(h["vendor"])
        if h.get("mac"):
            mac_str = f'<code>{h["mac"]}</code>'
            if h["mac_random"]:
                mac_str += " ⚡"
            details.append(mac_str)
        if h.get("latency"):
            details.append(h["latency"])
        if details:
            lines.append("    " + "  ·  ".join(details))

        lines.append("")

    lines.append("<i>⚡ = MAC aléatoire (appareil mobile probable)</i>")
    return "\n".join(lines).rstrip()


def cmd_ports(args):
    """Scan des ports ouverts d'un hôte spécifique."""
    ip = args.strip()
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return "Usage : <code>/ports 192.168.1.42</code>"

    try:
        result = subprocess.run(
            ["nmap", "-T4", "--top-ports", "200", "-sV", "--version-intensity", "0",
             "--host-timeout", "15s", ip],
            capture_output=True, text=True, timeout=60,
        )
    except subprocess.TimeoutExpired:
        return f"Scan de <code>{ip}</code> expiré."

    # Parse les ports ouverts
    ports = []
    for line in result.stdout.splitlines():
        m = re.match(r"^(\d+)/(tcp|udp)\s+(open)\s+(.+)$", line)
        if m:
            ports.append({
                "port":    m.group(1),
                "proto":   m.group(2),
                "service": m.group(4).strip(),
            })

    if not ports:
        return f"<code>{ip}</code> — aucun port ouvert trouvé (top 200)."

    lines = [f"<b>Ports ouverts</b>  <code>{ip}</code>\n"]
    for p in ports:
        lines.append(f"  <code>{p['port']}/{p['proto']}</code>  {p['service']}")
    return "\n".join(lines)


def cmd_who(args):
    """Fiche complète d'un hôte : tous les noms, MAC, vendor, ports."""
    ip = args.strip()
    if not ip or not re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
        return "Usage : <code>/who 192.168.1.42</code>"

    lines = [f"<b>Fiche hôte</b>  <code>{ip}</code>\n"]

    # 1. Résolution de noms
    names = []
    mdns = _resolve_mdns(ip)
    if mdns:
        names.append(f"mDNS: {mdns}")
    netbios = _resolve_nmblookup(ip)
    if netbios:
        names.append(f"NetBIOS: {netbios}")
    # Reverse DNS
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

    # 2. MAC + vendor via ARP + nmap
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

    # 3. Ping latence
    try:
        ping = subprocess.run(["ping", "-c", "3", "-W", "2", ip],
                              capture_output=True, text=True, timeout=10)
        m = re.search(r"= ([\d.]+)/([\d.]+)/([\d.]+)", ping.stdout)
        if m:
            lines.append(f"<b>Latence</b>  min {m.group(1)} / avg {m.group(2)} / max {m.group(3)} ms")
    except Exception:
        pass

    # 4. Ports ouverts (top 100, rapide)
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

    # Uptime et mémoire
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

    return "\n".join(lines)


def cmd_help():
    return (
        "<b>Commandes disponibles</b>\n\n"
        "/scan — Scan réseau (IP, noms, MAC, fabricant, latence)\n"
        "/ports &lt;ip&gt; — Ports ouverts d'un hôte\n"
        "/who &lt;ip&gt; — Fiche complète d'un hôte\n"
        "/status — État des services + uptime + RAM\n"
        "/help — Cette aide\n\n"
        "<i>⚡ = MAC aléatoire (appareil mobile)</i>"
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
        mask  = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        ip_int = (int(ip_parts[0]) << 24 | int(ip_parts[1]) << 16 |
                  int(ip_parts[2]) << 8  | int(ip_parts[3]))
        net_int = ip_int & mask
        net_ip  = ".".join(str((net_int >> s) & 0xFF) for s in (24, 16, 8, 0))
        return f"{net_ip}/{prefix}"
    except Exception:
        return None


def _parse_nmap(output):
    """Parse nmap -sn → liste de dicts {ip, name?, latency?, mac?, vendor?}."""
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
    """Trie les hôtes (dicts) par ordre d'adresse IP."""
    def key(h):
        try:
            return tuple(int(p) for p in h["ip"].split("."))
        except Exception:
            return (0, 0, 0, 0)
    return sorted(hosts, key=key)


# ── Boucle principale ─────────────────────────────────────────────────────────

# Commandes sans argument
COMMANDS_SIMPLE = {
    "/scan":   cmd_scan,
    "/status": cmd_status,
    "/help":   cmd_help,
}

# Commandes avec argument (le reste du message après la commande)
COMMANDS_WITH_ARGS = {
    "/ports": cmd_ports,
    "/who":   cmd_who,
}

LOADING_MSG = {
    "/scan":   "Scan réseau en cours (nmap + mDNS + NetBIOS)...",
    "/status": "Vérification des services...",
    "/ports":  "Scan des ports en cours...",
    "/who":    "Analyse de l'hôte en cours...",
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

                if chat_id != CHAT_ID:
                    continue

                # Parser commande + arguments
                parts = text.split(None, 1)
                cmd   = parts[0].split("@")[0].lower() if parts else ""
                args  = parts[1] if len(parts) > 1 else ""

                if cmd in COMMANDS_SIMPLE:
                    loading = LOADING_MSG.get(cmd, "...")
                    if loading:
                        send(f"⏳ {loading}", chat_id=chat_id)
                    reply = COMMANDS_SIMPLE[cmd]()
                    send(reply, chat_id=chat_id)
                elif cmd in COMMANDS_WITH_ARGS:
                    loading = LOADING_MSG.get(cmd, "...")
                    if loading:
                        send(f"⏳ {loading}", chat_id=chat_id)
                    reply = COMMANDS_WITH_ARGS[cmd](args)
                    send(reply, chat_id=chat_id)

        except Exception:
            time.sleep(5)


if __name__ == "__main__":
    main()
