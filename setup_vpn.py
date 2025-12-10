#!/usr/bin/env python3
"""
Script utilitaire pour configurer rapidement le VPN
Génère les clés et crée les fichiers de configuration
"""
import json
import sys
if sys.platform == 'win32':
    sys.stdout.reconfigure(encoding='utf-8')
from pathlib import Path
from crypto import CryptoManager


def generate_configs():
    """Génère les configurations pour le serveur et le client"""
    
    print("Génération des clés...")
    
    # Génère les clés pour le serveur
    server_crypto = CryptoManager()
    server_private = server_crypto.get_private_key_hex()
    server_public = server_crypto.get_public_key_hex()
    
    # Génère les clés pour le client
    client_crypto = CryptoManager()
    client_private = client_crypto.get_private_key_hex()
    client_public = client_crypto.get_public_key_hex()
    
    print(f"\n✓ Clés serveur générées")
    print(f"  Privée: {server_private[:32]}...")
    print(f"  Publique: {server_public[:32]}...")
    
    print(f"\n✓ Clés client générées")
    print(f"  Privée: {client_private[:32]}...")
    print(f"  Publique: {client_public[:32]}...")
    
    # Configuration serveur
    server_config = {
        "private_key": server_private,
        "virtual_ip": "10.0.0.1/24",
        "listen_port": 51820,
        "peer": {
            "public_key": client_public,
            "endpoint": "127.0.0.1:51821",
            "allowed_ips": ["10.0.0.0/24"]
        }
    }
    
    # Configuration client
    client_config = {
        "private_key": client_private,
        "virtual_ip": "10.0.0.2/24",
        "listen_port": 51821,
        "peer": {
            "public_key": server_public,
            "endpoint": "127.0.0.1:51820",
            "allowed_ips": ["10.0.0.0/24"]
        }
    }
    
    # Écrit les fichiers de configuration
    server_path = Path("server_config.json")
    client_path = Path("client_config.json")
    
    if server_path.exists() or client_path.exists():
        response = input("\n⚠️  Les fichiers de configuration existent déjà. Les écraser? (o/N): ")
        if response.lower() != 'o':
            print("Annulé.")
            return
    
    with open(server_path, 'w') as f:
        json.dump(server_config, f, indent=4)
    
    with open(client_path, 'w') as f:
        json.dump(client_config, f, indent=4)
    
    print(f"\n✓ Configuration serveur sauvegardée dans {server_path}")
    print(f"✓ Configuration client sauvegardée dans {client_path}")
    print("\n" + "=" * 60)
    print("Configuration terminée!")
    print("=" * 60)
    print("\nPour démarrer:")
    print("  Terminal 1: python server.py server_config.json")
    print("  Terminal 2: python client.py client_config.json connect")
    print("=" * 60)


def main():
    """Point d'entrée principal"""
    if len(sys.argv) > 1 and sys.argv[1] in ['--help', '-h']:
        print("Usage: python setup_vpn.py")
        print("\nGénère automatiquement les clés et les fichiers de configuration")
        print("pour le serveur et le client.")
        sys.exit(0)
    
    try:
        generate_configs()
    except KeyboardInterrupt:
        print("\n\nAnnulé par l'utilisateur.")
        sys.exit(1)
    except Exception as e:
        print(f"\nErreur: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

