#!/bin/bash
# backup-db-honeypot — MAJ dynamique de ip.ignorelist
# Récupère l'IP locale courante et met à jour opencanary.conf
# Appelé par ExecStartPre dans opencanary.service

LOCAL_IP=$(hostname -I | awk '{print $1}')
CONFIG="/etc/opencanaryd/opencanary.conf"

if [ -z "$LOCAL_IP" ]; then
    echo "Impossible de récupérer l'IP locale"
    exit 1
fi

python3 -c "
import json
with open('$CONFIG') as f:
    c = json.load(f)
c['ip.ignorelist'] = ['$LOCAL_IP', '127.0.0.1']
with open('$CONFIG', 'w') as f:
    json.dump(c, f, indent=4)
print('ip.ignorelist mis à jour : $LOCAL_IP')
"
