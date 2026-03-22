# Installation

## Prérequis

- Raspberry Pi Zero 2W (ou Pi 3/4/5)
- Raspberry Pi OS Lite 64-bit (Trixie recommandé)
- Accès SSH configuré
- Connexion internet

## Installation rapide

```bash
git clone https://github.com/<TON_USER>/backup-db-honeypot.git
cd backup-db-honeypot
cp config/settings.conf.example config/settings.conf
nano config/settings.conf   # Remplis token Telegram, WiFi, etc.
sudo bash install.sh
```

## Installation manuelle étape par étape

### 1. Dépendances système

```bash
sudo apt update
sudo apt install -y python3-pip python3-dev python3-venv libssl-dev libffi-dev iptables rsyslog samba
```

### 2. OpenCanary

```bash
sudo python3 -m venv /opt/opencanary/venv
sudo /opt/opencanary/venv/bin/pip install opencanary
sudo /opt/opencanary/venv/bin/opencanaryd --copyconfig
```

### 3. Configuration

```bash
sudo cp config/opencanary.conf /etc/opencanaryd/opencanary.conf
```

### 4. Scripts

```bash
sudo cp scripts/telegram_notify.py /opt/opencanary/
sudo cp scripts/daily_summary.py /opt/opencanary/
sudo cp scripts/update_grafana_skin.py /opt/opencanary/
sudo cp scripts/update_ip_ignorelist.sh /usr/local/bin/opencanary-update-ip.sh
sudo chmod +x /usr/local/bin/opencanary-update-ip.sh
sudo cp config/settings.conf /opt/opencanary/settings.conf
```

### 5. Skin Grafana

```bash
sudo python3 /opt/opencanary/update_grafana_skin.py
```

### 6. iptables legacy (pour module portscan)

```bash
sudo update-alternatives --set iptables /usr/sbin/iptables-legacy
sudo update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy
```

### 7. Services systemd

```bash
sudo cp systemd/opencanary.service /etc/systemd/system/
sudo cp systemd/opencanary-telegram.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable opencanary opencanary-telegram
sudo systemctl start opencanary opencanary-telegram
```

### 8. MAC Spoofing (optionnel)

```bash
sudo cp systemd/mac-spoof.service /etc/systemd/system/
# Édite l'adresse MAC dans le fichier si besoin
sudo systemctl enable mac-spoof
sudo systemctl start mac-spoof
```

### 9. NetBIOS hostname (optionnel)

Édite `/etc/samba/smb.conf`, section `[global]` :

```ini
netbios name = OPENDBBACKUP01
server string = Open Database Backup Service
wins support = yes
```

```bash
sudo systemctl enable nmbd
sudo systemctl disable smbd
sudo systemctl restart nmbd
```

### 10. Rotation des logs

```bash
sudo cp /dev/stdin /etc/logrotate.d/opencanary << 'EOF'
/var/log/opencanary.log {
    daily
    rotate 90
    compress
    missingok
    notifempty
    postrotate
        systemctl restart opencanary > /dev/null 2>&1 || true
    endscript
}
EOF
```

### 11. Cron rapport quotidien

```bash
(crontab -l; echo "0 8 * * * /opt/opencanary/venv/bin/python3 /opt/opencanary/daily_summary.py") | crontab -
```

## Vérification

```bash
sudo systemctl status opencanary
sudo systemctl status opencanary-telegram
sudo ss -tlnp | grep twistd
sudo tail -f /var/log/opencanary.log
```
