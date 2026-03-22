# 🍯 backup-db-honeypot

Honeypot complet tournant sur Raspberry Pi Zero 2W, simulant un serveur de base de données avec monitoring Grafana.

## Présentation

La Pi se présente sur le réseau comme un **serveur HP ProLiant** (`Hewlett Packard` via MAC spoofing) nommé **OPENDBBACKUP01**, exposant une fausse interface **Grafana v12.2.1**. Toute tentative d'intrusion est loggée et envoyée en temps réel sur **Telegram**.

## Services honeypot

| Port | Service | Description |
|------|---------|-------------|
| 22 | SSH (leurre) | Capture brute force SSH |
| 21 | FTP (leurre) | Capture tentatives FTP |
| 80 | HTTP Grafana | Fausse page login Grafana — capture credentials |
| 3306 | MySQL (leurre) | Faux serveur MySQL 5.7.32 |
| 6379 | Redis (leurre) | Faux Redis |
| 47832 | SSH RÉEL | Accès admin caché |

## Fonctionnalités

- 🔔 Alertes Telegram temps réel avec géolocalisation IP
- 📊 Rapport quotidien (stats, top IPs, top passwords)
- 🌍 Cache de géolocalisation (ip-api.com)
- 🔍 Détection de scans de ports via iptables
- 🖥️ Page Grafana pixel-perfect (vrais assets SVG)
- 🎭 MAC spoofing HP ProLiant
- 📛 NetBIOS hostname via Samba/nmbd
- 🔄 ip.ignorelist dynamique au boot
- 🔐 SSH réel sur port obscur (47832)
- 📋 Logs JSON avec rotation 90 jours

## Matériel requis

- Raspberry Pi Zero 2W
- Carte SD 16 Go minimum (32 Go recommandé)
- Raspberry Pi OS Lite 64-bit (Trixie/Bookworm)

## Installation rapide

```bash
git clone https://github.com/<TON_USER>/backup-db-honeypot.git
cd backup-db-honeypot
sudo bash install.sh
```

Voir [docs/INSTALL.md](docs/INSTALL.md) pour l'installation détaillée.

## Configuration

Copie et édite le fichier de config :

```bash
cp config/settings.conf.example config/settings.conf
nano config/settings.conf
```

## Structure du projet

```
backup-db-honeypot/
├── install.sh                  # Script d'installation automatique
├── config/
│   ├── settings.conf.example   # Config à copier et remplir
│   └── opencanary.conf         # Config OpenCanary complète
├── scripts/
│   ├── telegram_notify.py      # Alertes Telegram temps réel
│   ├── daily_summary.py        # Rapport quotidien
│   └── update_ip_ignorelist.sh # MAJ ip.ignorelist dynamique
├── systemd/
│   ├── opencanary.service
│   ├── opencanary-telegram.service
│   └── mac-spoof.service
├── skins/
│   └── grafanaLogin/           # Skin Grafana (généré par update_grafana_skin.py)
└── docs/
    ├── INSTALL.md
    └── MIGRATION_BATEAU.md
```

## Accès admin

- **SSH** : `ssh -p 47832 admin@<IP>`
- **Via ZeroTier** : `ssh -p 47832 admin@<IP_ZEROTIER>`
- **Urgence** : https://connect.raspberrypi.com

## Licence

Usage privé — ne pas exposer les credentials dans un repo public.
