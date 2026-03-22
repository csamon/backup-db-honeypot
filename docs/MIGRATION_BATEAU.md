# Migration vers le réseau bateau

## Réseau cible

| Paramètre | Valeur |
|---|---|
| Réseau | 192.168.1.0/24 |
| IP fixe Pi | 192.168.1.15 |
| Gateway | 192.168.1.1 (RutC41) |
| DHCP pool | 192.168.1.150 – 192.168.1.254 |

## Étapes

### 1. Configurer l'IP fixe

```bash
sudo nano /etc/dhcpcd.conf
```

Ajouter à la fin :

```
interface wlan0
static ip_address=192.168.1.15/24
static routers=192.168.1.1
static domain_name_servers=192.168.1.1
```

### 2. Mettre à jour le SSID WiFi bateau

```bash
sudo nano /etc/NetworkManager/system-connections/NomReseauBateau.nmconnection
```

### 3. Mettre à jour ZeroTier si besoin

L'IP ZeroTier ne change pas — rien à faire.

### 4. Mettre à jour la doc

Mettre à jour `config/settings.conf` avec la nouvelle IP et le nouveau SSID.

### 5. Reboot

```bash
sudo reboot
```

Vérifier après reboot :
```bash
ip addr show wlan0
sudo systemctl status opencanary
```
