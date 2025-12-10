#!/usr/bin/env python3
"""
Script pour générer des paires de clés pour le mini-VPN
"""
import sys
from crypto import CryptoManager


def generate_keypair():
    """Génère une paire de clés"""
    crypto = CryptoManager()
    return crypto.get_private_key_hex(), crypto.get_public_key_hex()


def main():
    """Génère des clés et les affiche"""
    if len(sys.argv) > 1 and sys.argv[1] == "--help":
        print("Usage: python generate_keys.py")
        print("\nGénère une paire de clés (privée et publique) pour le VPN")
        sys.exit(0)
    
    private_key, public_key = generate_keypair()
    
    print("=" * 60)
    print("Clés générées:")
    print("=" * 60)
    print(f"\nClé privée:\n{private_key}")
    print(f"\nClé publique:\n{public_key}")
    print("\n" + "=" * 60)
    print("\n⚠️  IMPORTANT: Gardez votre clé privée secrète!")
    print("=" * 60)


if __name__ == "__main__":
    main()

