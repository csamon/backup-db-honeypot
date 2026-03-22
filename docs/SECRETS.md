# Gestion des credentials — git-crypt

`config/settings.conf` contient les credentials réels (token Telegram, mot de passe SSH, etc.).
Ce fichier est **versionné et chiffré** via [git-crypt](https://github.com/AGWA/git-crypt) :
illisible sur GitHub sans la clé, transparent en local une fois déverrouillé.

---

## Principe

```
┌─────────────────────────────────────────────────────────┐
│  En local / sur la Pi (clé présente)                    │
│  config/settings.conf  →  texte clair, éditable         │
├─────────────────────────────────────────────────────────┤
│  Sur GitHub (sans clé)                                  │
│  config/settings.conf  →  binaire chiffré, illisible    │
└─────────────────────────────────────────────────────────┘
```

---

## Setup initial (une seule fois)

### 1. Installer git-crypt

**Sur la Pi (Debian/Ubuntu) :**
```bash
sudo apt install git-crypt
```

**Sur Windows (Scoop) :**
```powershell
scoop install git-crypt
```

### 2. Initialiser git-crypt dans le repo

```bash
cd backup-db-honeypot
git-crypt init
```

### 3. Déclarer le fichier à chiffrer

Ajouter dans `.gitattributes` :
```
config/settings.conf filter=git-crypt diff=git-crypt
```

### 4. Exporter et sauvegarder la clé

```bash
git-crypt export-key ~/backup-db-honeypot.key
```

> **Sauvegarde la clé** dans un endroit sûr — sans elle, les credentials sont irrécupérables :
> - Gestionnaire de mots de passe (Bitwarden, 1Password…)
> - Clé USB chiffrée
> - Autre service de stockage privé

### 5. Retirer settings.conf du .gitignore et l'ajouter au repo

```bash
# Retirer la ligne "config/settings.conf" du .gitignore
git add config/settings.conf
git commit -m "chore: settings.conf chiffré via git-crypt"
git push
```

Sur GitHub, le fichier apparaît maintenant comme binaire chiffré.

---

## Déverrouiller sur une nouvelle machine / la Pi

```bash
# Copier la clé sur la machine cible, puis :
git-crypt unlock /chemin/vers/backup-db-honeypot.key

# Le fichier settings.conf est maintenant lisible
cat config/settings.conf
```

---

## Workflow quotidien

Une fois déverrouillé, git-crypt est transparent :

```bash
# Modifier les credentials
nano config/settings.conf

# Committer normalement — le chiffrement est automatique au push
git add config/settings.conf
git commit -m "chore: mise à jour token Telegram"
git push   # → chiffré sur GitHub
```

---

## Vérifier l'état du chiffrement

```bash
git-crypt status
# Affiche quels fichiers sont chiffrés (encrypted) ou non (not encrypted)
```

---

## Contenu de settings.conf

```bash
# ============================================================
# backup-db-honeypot — Configuration
# ============================================================

# --- Telegram ---
TELEGRAM_TOKEN="<token_bot_telegram>"
TELEGRAM_CHAT_ID="<chat_id>"

# --- Réseau ---
WIFI_SSID="<ssid_reseau>"
WIFI_INTERFACE="wlan0"
SSH_PORT="47832"

# --- MAC Spoofing ---
MAC_SPOOF_ENABLED="true"
MAC_SPOOF_ADDRESS="<adresse_mac>"

# --- NetBIOS ---
NETBIOS_NAME="OPENDBBACKUP01"
NETBIOS_SERVER_STRING="Open Database Backup Service"

# --- Honeypot ---
NODE_ID="backup-db-honeypot"

# --- ZeroTier (optionnel) ---
ZEROTIER_NETWORK_ID="<network_id>"
```
