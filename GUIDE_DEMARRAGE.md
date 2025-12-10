# Guide de Démarrage Rapide - Mini-VPN

Ce guide vous explique comment lancer rapidement le projet mini-VPN.

## 📋 Prérequis

- Python 3.7 ou supérieur
- Bibliothèque `cryptography`
- Bibliothèque `Pillow` (pour l'affichage des images)

## 🚀 Installation Rapide

### Étape 0 : Vérifier l'installation (Optionnel)

```bash
python check_setup.py
```

Ce script vérifie que tout est correctement installé.

### Étape 1 : Installer les dépendances

```bash
pip install -r requirements.txt
```

Ou manuellement :
```bash
pip install cryptography
```

### Étape 2 : Configuration automatique (Recommandé)

La méthode la plus simple est d'utiliser le script de configuration automatique :

```bash
python setup_vpn.py
```

Ce script va :
- ✅ Générer automatiquement les clés pour le serveur et le client
- ✅ Créer les fichiers `server_config.json` et `client_config.json`
- ✅ Configurer correctement les clés publiques dans chaque fichier

## 🎨 Méthode 1 : Interface Graphique (Recommandé)

### Windows
```bash
python gui.py
```
Ou double-cliquez sur `launch_gui.bat`

### Linux/macOS
```bash
python3 gui.py
```
Ou exécutez :
```bash
chmod +x launch_gui.sh
./launch_gui.sh
```

### Utilisation de l'interface graphique :

1. **Onglet Configuration** :
   - Si vous n'avez pas encore de fichiers de config, cliquez sur "Configurer le VPN"
   - Cela génère automatiquement les clés et fichiers de configuration

2. **Onglet Serveur** :
   - Vérifiez que le chemin du fichier de config est correct (`server_config.json`)
   - Cliquez sur "Démarrer le Serveur"
   - L'état devrait passer à "En cours d'exécution" (vert)

3. **Onglet Client** :
   - Vérifiez que le chemin du fichier de config est correct (`client_config.json`)
   - Cliquez sur "Se Connecter"
   - L'état devrait passer à "Connecté" (vert)

4. **Envoyer des messages** :
   - Dans l'onglet Client, tapez un message dans le champ "Message"
   - Cliquez sur "Envoyer" ou appuyez sur Entrée
   - Les messages reçus apparaîtront dans la zone de logs

## 💻 Méthode 2 : Ligne de Commande

### Terminal 1 : Démarrer le serveur

```bash
python server.py server_config.json
```

Vous devriez voir :
```
[Server] Initialisé sur le port 51820
[Server] IP virtuelle: 10.0.0.1/24
[Server] Clé publique: ...
[Server] En attente de connexions...
```

### Terminal 2 : Connecter le client

```bash
python client.py client_config.json connect
```

Vous devriez voir :
```
[Client] Initialisé sur le port 51821
[Client] IP virtuelle: 10.0.0.2/24
[Client] Serveur: 127.0.0.1:51820
[Client] Connexion au serveur...
[Client] Handshake complété
[Client] Session établie
```

Ensuite, vous pouvez taper des messages à envoyer au serveur.

## 🔧 Configuration Manuelle (Alternative)

Si vous préférez configurer manuellement :

### 1. Générer les clés

```bash
python generate_keys.py
```

Exécutez cette commande **deux fois** pour obtenir deux paires de clés :
- Une pour le serveur
- Une pour le client

### 2. Configurer le serveur

Éditez `server_config.json` :

```json
{
    "private_key": "VOTRE_CLE_PRIVEE_SERVEUR_ICI",
    "virtual_ip": "10.0.0.1/24",
    "listen_port": 51820,
    "peer": {
        "public_key": "CLE_PUBLIQUE_CLIENT_ICI",
        "endpoint": "127.0.0.1:51821",
        "allowed_ips": ["10.0.0.0/24"]
    }
}
```

### 3. Configurer le client

Éditez `client_config.json` :

```json
{
    "private_key": "VOTRE_CLE_PRIVEE_CLIENT_ICI",
    "virtual_ip": "10.0.0.2/24",
    "listen_port": 51821,
    "peer": {
        "public_key": "CLE_PUBLIQUE_SERVEUR_ICI",
        "endpoint": "127.0.0.1:51820",
        "allowed_ips": ["10.0.0.0/24"]
    }
}
```

**Important** : Pour obtenir la clé publique depuis une clé privée, vous pouvez utiliser :

```python
from crypto import CryptoManager
crypto = CryptoManager("VOTRE_CLE_PRIVEE_HEX")
print(crypto.get_public_key_hex())
```

## 🧪 Test Rapide

Pour tester rapidement que tout fonctionne :

1. **Terminal 1** :
   ```bash
   python server.py server_config.json
   ```

2. **Terminal 2** :
   ```bash
   python client.py client_config.json send "Hello, Server!"
   ```

Le serveur devrait recevoir et afficher le message.

## ❓ Dépannage

### Erreur : "Configuration file not found"
- Assurez-vous d'avoir exécuté `python setup_vpn.py` ou créé les fichiers de configuration manuellement

### Erreur : "Public key mismatch"
- Vérifiez que les clés publiques dans les fichiers de config correspondent bien aux clés privées
- Utilisez `python setup_vpn.py` pour régénérer automatiquement

### Erreur : "Address already in use"
- Un autre processus utilise déjà le port
- Changez le port dans les fichiers de configuration ou arrêtez l'autre processus

### Le client ne se connecte pas
- Vérifiez que le serveur est démarré
- Vérifiez que l'adresse IP et le port dans `client_config.json` sont corrects
- Vérifiez les logs pour plus d'informations

## 📝 Commandes Utiles

```bash
# Générer de nouvelles clés
python generate_keys.py

# Configuration automatique
python setup_vpn.py

# Lancer l'interface graphique
python gui.py

# Démarrer le serveur
python server.py server_config.json

# Connecter le client (mode interactif)
python client.py client_config.json connect

# Envoyer un message unique
python client.py client_config.json send "Mon message"

# Écouter uniquement
python client.py client_config.json listen
```

## 🎯 Workflow Recommandé

1. **Première utilisation** :
   ```bash
   pip install -r requirements.txt
   python setup_vpn.py
   python gui.py
   ```

2. **Utilisations suivantes** :
   ```bash
   python gui.py
   ```
   Puis utilisez l'interface graphique pour démarrer le serveur et connecter le client.

## 📚 Documentation Complète

Pour plus de détails, consultez le fichier `README.md`.

