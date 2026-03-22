#!/bin/bash
# ============================================================
# backup-db-honeypot — Script d'installation automatique
# Usage : sudo bash install.sh
# ============================================================

set -e
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'

log()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn() { echo -e "${YELLOW}[!!]${NC} $1"; }
err()  { echo -e "${RED}[ERR]${NC} $1"; exit 1; }

[ "$EUID" -ne 0 ] && err "Lance ce script avec sudo"

# Vérifier la config
[ ! -f "config/settings.conf" ] && err "Copie config/settings.conf.example en config/settings.conf et remplis-le"

source config/settings.conf
[ -z "$TELEGRAM_TOKEN" ] && err "TELEGRAM_TOKEN non défini dans settings.conf"
[ -z "$TELEGRAM_CHAT_ID" ] && err "TELEGRAM_CHAT_ID non défini dans settings.conf"

log "Démarrage installation backup-db-honeypot"

# Mise à jour système
log "Mise à jour des paquets..."
apt update -qq
apt install -y python3-pip python3-dev python3-venv libssl-dev libffi-dev iptables rsyslog samba nmap -qq

# OpenCanary
log "Installation OpenCanary..."
python3 -m venv /opt/opencanary/venv
/opt/opencanary/venv/bin/pip install opencanary -q

# Config OpenCanary
log "Configuration OpenCanary..."
mkdir -p /etc/opencanaryd
sed "s/backup-db-honeypot/${NODE_ID:-backup-db-honeypot}/" config/opencanary.conf > /etc/opencanaryd/opencanary.conf

# Scripts
log "Installation des scripts..."
cp scripts/telegram_notify.py /opt/opencanary/telegram_notify.py
cp scripts/daily_summary.py /opt/opencanary/daily_summary.py
cp scripts/telegram_bot.py /opt/opencanary/telegram_bot.py
cp scripts/update_grafana_skin.py /opt/opencanary/update_grafana_skin.py
cp scripts/update_ip_ignorelist.sh /usr/local/bin/opencanary-update-ip.sh
chmod +x /usr/local/bin/opencanary-update-ip.sh

# Copier config dans /opt pour les scripts
cp config/settings.conf /opt/opencanary/settings.conf

# Skin Grafana
log "Installation skin Grafana..."
python3 /opt/opencanary/update_grafana_skin.py

# Fichier de log
touch /var/log/opencanary.log

# iptables legacy pour portscan
log "Configuration iptables..."
update-alternatives --set iptables /usr/sbin/iptables-legacy 2>/dev/null || true
update-alternatives --set ip6tables /usr/sbin/ip6tables-legacy 2>/dev/null || true

# Systemd services
log "Installation services systemd..."
cp systemd/opencanary.service /etc/systemd/system/
cp systemd/opencanary-telegram.service /etc/systemd/system/
cp systemd/telegram-bot.service /etc/systemd/system/

# MAC Spoofing
if [ "${MAC_SPOOF_ENABLED}" = "true" ]; then
    log "Configuration MAC spoofing (${MAC_SPOOF_ADDRESS})..."
    sed "s/3c:d9:2b:a4:7e:21/${MAC_SPOOF_ADDRESS}/; s/wlan0/${WIFI_INTERFACE:-wlan0}/" systemd/mac-spoof.service > /etc/systemd/system/mac-spoof.service
    systemctl enable mac-spoof
fi

# NetBIOS
if [ -n "${NETBIOS_NAME}" ]; then
    log "Configuration NetBIOS (${NETBIOS_NAME})..."
    sed -i "/\[global\]/a\\   netbios name = ${NETBIOS_NAME}\n   server string = ${NETBIOS_SERVER_STRING:-Backup Server}\n   wins support = yes" /etc/samba/smb.conf
    systemctl enable nmbd
    systemctl disable smbd 2>/dev/null || true
fi

# Logrotate
log "Configuration rotation des logs (90 jours)..."
cat > /etc/logrotate.d/opencanary << 'EOF'
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

# Cron rapport quotidien
log "Configuration cron rapport 8h..."
(crontab -l 2>/dev/null; echo "0 8 * * * /opt/opencanary/venv/bin/python3 /opt/opencanary/daily_summary.py") | crontab -

# Activer et démarrer
systemctl daemon-reload
systemctl enable opencanary opencanary-telegram telegram-bot
systemctl start opencanary
sleep 2
systemctl start opencanary-telegram
systemctl start telegram-bot

[ "${MAC_SPOOF_ENABLED}" = "true" ] && systemctl start mac-spoof
[ -n "${NETBIOS_NAME}" ] && systemctl restart nmbd

echo ""
log "Installation terminée !"
echo ""
echo "Vérification :"
systemctl is-active opencanary && echo "  opencanary : OK" || warn "  opencanary : FAILED"
systemctl is-active opencanary-telegram && echo "  opencanary-telegram : OK" || warn "  opencanary-telegram : FAILED"
systemctl is-active telegram-bot && echo "  telegram-bot : OK" || warn "  telegram-bot : FAILED"
echo ""
echo "Ports actifs :"
ss -tlnp | grep twistd
echo ""
warn "N'oublie pas de changer le mot de passe admin : passwd admin"
warn "Et de révoquer le token Telegram si exposé : @BotFather"
