<div align="center">

# backup-db-honeypot

**Honeypot réseau sur Raspberry Pi · Faux serveur de base de données · Alertes Telegram**

![Platform](https://img.shields.io/badge/platform-Raspberry%20Pi%20Zero%202W-c51a4a?logo=raspberrypi&logoColor=white)
![OS](https://img.shields.io/badge/OS-Raspberry%20Pi%20OS%20Lite%2064--bit-c51a4a?logo=raspberrypi&logoColor=white)
![OpenCanary](https://img.shields.io/badge/powered%20by-OpenCanary-ff6600)
![Python](https://img.shields.io/badge/python-3.11%2B-3776ab?logo=python&logoColor=white)
![Telegram](https://img.shields.io/badge/alertes-Telegram-26a5e4?logo=telegram&logoColor=white)

</div>

---

## Présentation

La Pi se présente sur le réseau comme un **serveur HP ProLiant** (`Hewlett Packard` via MAC spoofing) nommé **OPENDBBACKUP01**, exposant une fausse interface **Grafana v12.2.1**.

Toute tentative d'intrusion est loggée et envoyée en temps réel sur **Telegram** avec géolocalisation IP. Un rapport quotidien résume les attaques de la journée.

> **Usage défensif / éducatif — ne jamais exposer les credentials dans un repo public**

---

## Services exposés

| Port | Service | Rôle |
|------|---------|------|
| 21 | FTP (leurre) | Capture tentatives FTP |
| 22 | SSH (leurre) | Capture brute force SSH |
| 80 | HTTP Grafana | Fausse page login — capture credentials |
| 3306 | MySQL (leurre) | Faux serveur MySQL 5.7.32 |
| 6379 | Redis (leurre) | Faux Redis |
| 47832 | **SSH réel** | Accès admin caché |

---

## Fonctionnalités

- Alertes Telegram temps réel avec géolocalisation IP (ip-api.com)
- Rapport quotidien automatique : stats, top IPs, top passwords
- **Bot Telegram interactif** — commandes `/scan`, `/status`, `/help` depuis le chat
- Page Grafana pixel-perfect avec vrais assets SVG
- Détection de scans de ports via iptables
- MAC spoofing HP ProLiant (`Hewlett Packard`)
- NetBIOS hostname `OPENDBBACKUP01` via Samba/nmbd
- `ip.ignorelist` dynamique rechargée au boot
- Logs JSON avec rotation 90 jours
- Accès admin via SSH sur port obscur ou ZeroTier

---

## Matériel requis

- Raspberry Pi Zero 2W (ou Pi 3 / 4 / 5)
- Carte SD 16 Go minimum (32 Go recommandé)
- Raspberry Pi OS Lite 64-bit (Trixie recommandé)

---

## Installation rapide

```bash
git clone https://github.com/csamon/backup-db-honeypot.git
cd backup-db-honeypot
cp config/settings.conf.example config/settings.conf
nano config/settings.conf          # Remplis token Telegram, SSH port, etc.
sudo bash install.sh
```

Voir [docs/INSTALL.md](docs/INSTALL.md) pour l'installation manuelle étape par étape.

---

## Configuration

```bash
cp config/settings.conf.example config/settings.conf
nano config/settings.conf
```

| Variable | Description |
|----------|-------------|
| `TELEGRAM_TOKEN` | Token du bot Telegram |
| `TELEGRAM_CHAT_ID` | ID du chat de réception des alertes |
| `SSH_PORT` | Port SSH réel (défaut : 47832) |
| `MAC_SPOOF_ENABLED` | Activer l'usurpation MAC HP ProLiant |
| `MAC_SPOOF_ADDRESS` | Adresse MAC à usurper |
| `NETBIOS_NAME` | Nom NetBIOS visible sur le réseau |
| `ZEROTIER_NETWORK_ID` | Réseau ZeroTier pour accès distant (optionnel) |

> `config/settings.conf` est chiffré via **git-crypt** — illisible sur GitHub sans la clé.
> Voir [docs/SECRETS.md](docs/SECRETS.md) pour gérer la clé et déchiffrer sur une nouvelle machine.

---

## Bot Telegram

Le bot écoute en permanence les commandes envoyées dans le chat autorisé.

| Commande | Description |
|----------|-------------|
| `/scan` | Scan nmap du réseau local — IP, hostname, fabricant, adresse MAC, latence |
| `/status` | État de chaque service systemd (opencanary, bot, mac-spoof…) |
| `/help` | Liste des commandes disponibles |

Exemple de réponse `/scan` :
```
Scan réseau  192.168.1.0/24
8 hôte(s) trouvé(s)

192.168.1.1  router.local
    Teltonika Networks  ·  3c:d9:2b:a4:7e:21  ·  2.3 ms

192.168.1.42  nas.local
    Synology  ·  00:11:32:aa:bb:cc  ·  1.1 ms
...
```

> Seul le `CHAT_ID` configuré dans `settings.conf` peut déclencher des commandes.

---

## Accès admin

```bash
# SSH direct
ssh -p 47832 admin@<IP_DE_LA_PI>

# Via ZeroTier
ssh -p 47832 admin@<IP_ZEROTIER>

# Urgence (sans réseau local)
# https://connect.raspberrypi.com
```

---

## Structure du projet

```
backup-db-honeypot/
├── install.sh                     Script d'installation automatique
├── config/
│   ├── settings.conf              Config réelle — chiffrée git-crypt (illisible sur GitHub)
│   ├── settings.conf.example      Template public avec valeurs génériques
│   └── opencanary.conf            Config OpenCanary (ports, services, logs)
├── scripts/
│   ├── telegram_notify.py         Alertes Telegram temps réel (stdin → Telegram)
│   ├── telegram_bot.py            Bot Telegram interactif (/scan, /status, /help)
│   ├── daily_summary.py           Rapport quotidien + reset des stats
│   ├── update_grafana_skin.py     Génère la page login Grafana pixel-perfect
│   └── update_ip_ignorelist.sh    Recharge ip.ignorelist au boot
├── systemd/
│   ├── opencanary.service
│   ├── opencanary-telegram.service
│   ├── telegram-bot.service
│   └── mac-spoof.service
└── docs/
    ├── INSTALL.md                 Installation manuelle détaillée
    └── MIGRATION_BATEAU.md        Passage sur le réseau du bord
```

---

## Documentation

| Document | Contenu |
|----------|---------|
| [docs/INSTALL.md](docs/INSTALL.md) | Installation manuelle pas à pas |
| [docs/SECRETS.md](docs/SECRETS.md) | Gestion des credentials chiffrés (git-crypt) |
| [docs/MIGRATION_BATEAU.md](docs/MIGRATION_BATEAU.md) | Migration vers le réseau du bord |

---

<div align="center">

*backup-db-honeypot · Clément Samon*

</div>
