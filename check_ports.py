#!/usr/bin/env python3
"""
Script pour vérifier si les ports du VPN sont disponibles
"""
import socket
import sys
from config import VPNConfig


def check_port(port, name):
    """Vérifie si un port est disponible"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.bind(('127.0.0.1', port))
        sock.close()
        print(f"✓ Port {port} ({name}) : Disponible")
        return True
    except OSError as e:
        if hasattr(e, 'winerror') and e.winerror == 10048:
            print(f"✗ Port {port} ({name}) : OCCUPÉ")
            print(f"  → Un processus utilise déjà ce port")
            return False
        else:
            print(f"✗ Port {port} ({name}) : Erreur - {e}")
            return False


def main():
    """Point d'entrée principal"""
    print("=" * 60)
    print("Vérification des ports VPN")
    print("=" * 60)
    
    server_port = None
    client_port = None
    
    # Essaie de charger les ports depuis les configs
    try:
        server_config = VPNConfig("server_config.json")
        server_port = server_config.listen_port
    except:
        server_port = 51820  # Port par défaut
    
    try:
        client_config = VPNConfig("client_config.json")
        client_port = client_config.listen_port
    except:
        client_port = 51821  # Port par défaut
    
    print(f"\nVérification des ports configurés:")
    print(f"  Serveur: {server_port}")
    print(f"  Client: {client_port}\n")
    
    server_ok = check_port(server_port, "Serveur")
    client_ok = check_port(client_port, "Client")
    
    print("\n" + "=" * 60)
    
    if server_ok and client_ok:
        print("✓ Tous les ports sont disponibles !")
        print("\nVous pouvez démarrer le serveur et le client.")
        return 0
    else:
        print("⚠ Certains ports sont occupés")
        print("\nSolutions:")
        print("1. Fermez les instances précédentes du VPN")
        print("2. Attendez quelques secondes que les ports se libèrent")
        print("3. Changez les ports dans les fichiers de configuration")
        print("4. Sur Windows, utilisez 'netstat -ano | findstr :PORT' pour trouver")
        print("   le processus qui utilise le port")
        return 1


if __name__ == "__main__":
    sys.exit(main())

