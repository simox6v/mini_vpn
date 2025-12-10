#!/usr/bin/env python3
"""
Script de vérification de l'installation
Vérifie que toutes les dépendances sont installées et que la configuration est correcte
"""
import sys
import os
from pathlib import Path


def check_python_version():
    """Vérifie la version de Python"""
    print("✓ Vérification de la version de Python...")
    version = sys.version_info
    if version.major < 3 or (version.major == 3 and version.minor < 7):
        print(f"  ✗ Python 3.7+ requis. Version actuelle: {version.major}.{version.minor}")
        return False
    print(f"  ✓ Python {version.major}.{version.minor}.{version.micro}")
    return True


def check_dependencies():
    """Vérifie que les dépendances sont installées"""
    print("\n✓ Vérification des dépendances...")
    
    try:
        import cryptography
        print(f"  ✓ cryptography {cryptography.__version__}")
    except ImportError:
        print("  ✗ cryptography non installé")
        print("    Installez avec: pip install cryptography")
        return False
    
    try:
        import tkinter
        print("  ✓ tkinter disponible")
    except ImportError:
        print("  ⚠ tkinter non disponible (optionnel pour l'interface graphique)")
        print("    Sur Ubuntu/Debian: sudo apt-get install python3-tk")
    
    try:
        import PIL
        print(f"  ✓ Pillow {PIL.__version__}")
    except ImportError:
        print("  ✗ Pillow non installé (requis pour l'affichage des images)")
        print("    Installez avec: pip install Pillow")
        return False
    
    return True


def check_files():
    """Vérifie que les fichiers nécessaires existent"""
    print("\n✓ Vérification des fichiers...")
    
    required_files = [
        "config.py",
        "crypto.py",
        "handshake.py",
        "packet.py",
        "server.py",
        "client.py",
        "gui.py",
        "gui_client.py",
        "gui_server.py",
        "auth.py",
        "dhcp_server.py",
        "resource_manager.py",
        "theme.py"
    ]
    
    all_ok = True
    for file in required_files:
        if Path(file).exists():
            print(f"  ✓ {file}")
        else:
            print(f"  ✗ {file} manquant")
            all_ok = False
    
    return all_ok


def check_config():
    """Vérifie la configuration"""
    print("\n✓ Vérification de la configuration...")
    
    config_files = ["server_config.json", "client_config.json"]
    configs_exist = True
    
    for config_file in config_files:
        if Path(config_file).exists():
            print(f"  ✓ {config_file} existe")
            
            # Vérifie que le fichier est valide
            try:
                from config import VPNConfig
                config = VPNConfig(config_file)
                print(f"    - Port: {config.listen_port}")
                print(f"    - IP virtuelle: {config.virtual_ip}")
            except Exception as e:
                print(f"    ✗ Erreur dans {config_file}: {e}")
                configs_exist = False
        else:
            print(f"  ⚠ {config_file} n'existe pas")
            print(f"    Créez-le avec: python setup_vpn.py")
            configs_exist = False
    
    return configs_exist


def main():
    """Point d'entrée principal"""
    print("=" * 60)
    print("=" * 60)
    
    # Force l'encodage UTF-8 pour la console Windows
    if sys.platform == 'win32':
        sys.stdout.reconfigure(encoding='utf-8')

    all_ok = True
    
    # Vérifications
    if not check_python_version():
        all_ok = False
    
    if not check_dependencies():
        all_ok = False
    
    if not check_files():
        all_ok = False
    
    config_ok = check_config()
    
    # Résumé
    print("\n" + "=" * 60)
    if all_ok:
        if config_ok:
            print("✓ Toutes les vérifications sont passées !")
            print("\nVous pouvez maintenant lancer le projet:")
            print("  python gui.py")
        else:
            print("⚠ Installation OK, mais configuration manquante")
            print("\nPour configurer:")
            print("  python setup_vpn.py")
    else:
        print("✗ Certaines vérifications ont échoué")
        print("\nVeuillez corriger les erreurs ci-dessus")
    
    print("=" * 60)
    
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())

