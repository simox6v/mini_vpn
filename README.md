# Mini-VPN User-Space

Un mini-VPN user-space inspiré de WireGuard, implémenté en Python. Ce projet permet à deux pairs (client/serveur) d'échanger des données à travers un tunnel chiffré avec authentification mutuelle.

## 🚀 Démarrage Rapide

### Installation et Configuration (1 minute)

```bash
# 1. Installer les dépendances
pip install -r requirements.txt

# 2. Configurer automatiquement (génère les clés et fichiers de config)
python setup_vpn.py

# 3. Lancer le serveur (avec authentification)
python gui_server.py

# 4. Dans un autre terminal, lancer le client
python gui_client.py
```

### Utilisation :

**Serveur** :
- Identifiants par défaut : `admin` / `admin`
- ⚠️ Changez le mot de passe par défaut avec `python manage_users.py`

**Client** :
- Sélectionnez le fichier de configuration
- Cliquez sur "Se Connecter"
- Envoyez des messages via le champ de saisie

**C'est tout !** 🎉

> 📖 Pour plus de détails, consultez le [Guide de Démarrage](GUIDE_DEMARRAGE.md)

## Fonctionnalités

- ✅ Échange de pseudo-paquets chiffrés entre deux pairs
- ✅ Handshake simplifié pour authentification mutuelle
- ✅ Dérivation de clés de session sécurisée
- ✅ Chiffrement AES-GCM (chiffrement + intégrité)
- ✅ Gestion de configuration via fichiers JSON
- ✅ Support des paquets de données et keepalive
- ✅ **Interfaces graphiques séparées (serveur/client)**
- ✅ **Authentification par username/password pour le serveur**
- ✅ **Design moderne et professionnel**
- ✅ **Support Dark Mode / Light Mode**

## Architecture

Le projet est organisé en plusieurs modules :

- **`config.py`** : Gestion de la configuration (lecture des fichiers JSON)
- **`crypto.py`** : Chiffrement/déchiffrement avec AES-GCM et gestion des clés
- **`handshake.py`** : Protocole de handshake pour authentification et dérivation des clés
- **`packet.py`** : Format et gestion des pseudo-paquets VPN
- **`server.py`** : Serveur VPN qui écoute les connexions
- **`client.py`** : Client VPN qui se connecte au serveur
- **`gui_server.py`** : Interface graphique serveur avec authentification
- **`gui_client.py`** : Interface graphique client séparée
- **`auth.py`** : Système d'authentification pour le serveur
- **`theme.py`** : Gestionnaire de thèmes (Dark/Light mode)
- **`manage_users.py`** : Script de gestion des utilisateurs

## Installation

### Prérequis

- Python 3.7+
- Bibliothèque `cryptography`

### Installation des dépendances

```bash
pip install -r requirements.txt
```

Ou manuellement :

```bash
pip install cryptography
```

**Note** : tkinter est généralement inclus avec Python. Si ce n'est pas le cas, installez-le selon votre système :
- Ubuntu/Debian : `sudo apt-get install python3-tk`
- Fedora : `sudo dnf install python3-tkinter`
- macOS : tkinter est inclus avec Python
- Windows : tkinter est inclus avec Python

## Configuration

### 1. Générer les clés

Générez d'abord les paires de clés pour le serveur et le client :

```bash
python generate_keys.py
```

Exécutez cette commande deux fois pour obtenir deux paires de clés distinctes.

### 2. Configurer le serveur

Éditez `server_config.json` :

```json
{
    "private_key": "VOTRE_CLE_PRIVEE_SERVEUR",
    "virtual_ip": "10.0.0.1/24",
    "listen_port": 51820,
    "peer": {
        "public_key": "CLE_PUBLIQUE_CLIENT",
        "endpoint": "127.0.0.1:51821",
        "allowed_ips": ["10.0.0.0/24"]
    }
}
```

### 3. Configurer le client

Éditez `client_config.json` :

```json
{
    "private_key": "VOTRE_CLE_PRIVEE_CLIENT",
    "virtual_ip": "10.0.0.2/24",
    "listen_port": 51821,
    "peer": {
        "public_key": "CLE_PUBLIQUE_SERVEUR",
        "endpoint": "127.0.0.1:51820",
        "allowed_ips": ["10.0.0.0/24"]
    }
}
```

**Important** : 
- La clé publique du serveur dans `client_config.json` doit correspondre à la clé publique dérivée de la clé privée du serveur
- La clé publique du client dans `server_config.json` doit correspondre à la clé publique dérivée de la clé privée du client

## Utilisation

### Interface Graphique Serveur (Recommandé)

L'interface serveur nécessite une authentification :

```bash
# Windows
python gui_server.py
# ou double-cliquez sur launch_server.bat

# Linux/macOS
python3 gui_server.py
# ou exécutez ./launch_server.sh
```

**Authentification** :
- Identifiants par défaut : `admin` / `admin`
- ⚠️ **Changez le mot de passe par défaut** avec `python manage_users.py`

**Fonctionnalités** :
- Authentification sécurisée par username/password
- Design moderne avec Dark Mode / Light Mode
- Gestion complète du serveur VPN
- Logs en temps réel
- Informations détaillées du serveur

### Interface Graphique Client

Interface client séparée et indépendante :

```bash
# Windows
python gui_client.py
# ou double-cliquez sur launch_client.bat

# Linux/macOS
python3 gui_client.py
# ou exécutez ./launch_client.sh
```

**Fonctionnalités** :
- Design moderne avec Dark Mode / Light Mode
- Connexion au serveur VPN
- Envoi de messages chiffrés
- Réception de messages en temps réel
- Logs des événements
- Informations de connexion

### Gestion des Utilisateurs

Pour gérer les utilisateurs du serveur :

```bash
python manage_users.py
```

Options disponibles :
- Créer un utilisateur
- Changer le mot de passe
- Supprimer un utilisateur
- Lister les utilisateurs

### Ligne de commande

#### Démarrer le serveur

Dans un terminal :

```bash
python server.py server_config.json
```

#### Se connecter avec le client

Dans un autre terminal :

```bash
# Mode interactif (recommandé)
python client.py client_config.json connect

# Ou envoyer un message unique
python client.py client_config.json send "Hello, Server!"

# Ou écouter uniquement
python client.py client_config.json listen
```

#### Configuration automatique

Pour générer automatiquement les clés et fichiers de configuration :

```bash
python setup_vpn.py
```

## Format des paquets

Les paquets VPN suivent ce format :

```
[Type: 1 byte][Nonce: 12 bytes][Longueur: 4 bytes][Données chiffrées: variable]
```

Types de paquets :
- `0` : Handshake
- `1` : Données
- `2` : Keepalive

## Protocole de handshake

1. **Initiation** : Le client envoie un message contenant sa clé publique, un nonce et un timestamp
2. **Réponse** : Le serveur répond avec sa clé publique, un nonce et un timestamp
3. **Dérivation de clé** : Les deux pairs dérivent une clé de session à partir des nonces et clés publiques échangés

## Sécurité

- **Chiffrement** : AES-256-GCM (chiffrement authentifié)
- **Authentification** : Basée sur les clés publiques lors du handshake
- **Protection contre les replay attacks** : Timestamps dans les messages de handshake
- **Intégrité** : Garantie par AES-GCM (tag d'authentification)

## Limitations

Ce projet est une implémentation simplifiée à des fins éducatives :

- Pas d'interface TUN/TAP (les données ne sont pas routées automatiquement)
- Handshake simplifié (pas de rotation de clés)
- Pas de gestion avancée des sessions (pas de renégociation)
- Communication en UDP uniquement
- Pas de gestion des erreurs réseau avancée

## Améliorations possibles

- Interface TUN/TAP pour le routage automatique
- Rotation périodique des clés de session
- Support IPv6
- Gestion de plusieurs pairs simultanés
- Interface de monitoring/statistiques
- Support TCP en plus d'UDP

## Licence

Ce projet est fourni à des fins éducatives.

