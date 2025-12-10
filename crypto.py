"""
Module de chiffrement pour le mini-VPN
Utilise AES-GCM pour le chiffrement et l'intégrité
"""
import os
import hashlib
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend
from typing import Tuple, Optional
import secrets


class CryptoManager:
    """Gestionnaire de chiffrement pour le VPN"""
    
    # Taille des clés en bytes
    KEY_SIZE = 32  # 256 bits pour AES-256
    NONCE_SIZE = 12  # 96 bits pour AES-GCM
    
    def __init__(self, private_key: Optional[bytes] = None):
        """
        Initialise le gestionnaire de chiffrement
        
        Args:
            private_key: Clé privée en bytes (si None, génère une nouvelle clé)
        """
        if private_key is None:
            self.private_key = secrets.token_bytes(self.KEY_SIZE)
        else:
            if isinstance(private_key, str):
                # Si c'est une string hex, la convertir
                self.private_key = bytes.fromhex(private_key)
            else:
                self.private_key = private_key
        
        if len(self.private_key) != self.KEY_SIZE:
            raise ValueError(f"Private key must be {self.KEY_SIZE} bytes")
        
        # Dérive la clé publique (simplifié: hash de la clé privée)
        self.public_key = self._derive_public_key(self.private_key)
    
    @staticmethod
    def _derive_public_key(private_key: bytes) -> bytes:
        """Dérive une clé publique depuis la clé privée (simplifié)"""
        h = hashlib.sha256()
        h.update(b"public_key_derivation")
        h.update(private_key)
        return h.digest()
    
    def get_public_key(self) -> bytes:
        """Retourne la clé publique"""
        return self.public_key
    
    def get_public_key_hex(self) -> str:
        """Retourne la clé publique en hexadécimal"""
        return self.public_key.hex()
    
    def get_private_key_hex(self) -> str:
        """Retourne la clé privée en hexadécimal"""
        return self.private_key.hex()
    
    def derive_session_key(self, peer_public_key: bytes, handshake_data: bytes) -> bytes:
        """
        Dérive une clé de session depuis les clés publiques et les données de handshake
        
        Args:
            peer_public_key: Clé publique du pair
            handshake_data: Données du handshake (nonce, etc.)
        
        Returns:
            Clé de session de 32 bytes
        """
        # Combine les clés publiques et les données de handshake
        shared_secret = self._compute_shared_secret(peer_public_key)
        
        # Utilise HKDF pour dériver la clé de session
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=self.KEY_SIZE,
            salt=handshake_data[:16],  # Utilise les premiers 16 bytes du handshake comme salt
            info=b"mini_vpn_session_key",
            backend=default_backend()
        )
        
        return hkdf.derive(shared_secret)
    
    def _compute_shared_secret(self, peer_public_key: bytes) -> bytes:
        """
        Calcule un secret partagé (simplifié: XOR des clés publiques)
        Dans un vrai VPN, on utiliserait ECDH ou similaire
        """
        if isinstance(peer_public_key, str):
            peer_public_key = bytes.fromhex(peer_public_key)
        
        # Pour simplifier, on fait un XOR des clés publiques
        # Dans un vrai système, on utiliserait ECDH
        shared = bytearray(self.KEY_SIZE)
        for i in range(min(len(self.public_key), len(peer_public_key), self.KEY_SIZE)):
            shared[i] = self.public_key[i] ^ peer_public_key[i]
        
        # Hash pour obtenir une taille fixe
        h = hashlib.sha256()
        h.update(shared)
        return h.digest()
    
    def encrypt(self, plaintext: bytes, session_key: bytes, associated_data: bytes = b"") -> Tuple[bytes, bytes]:
        """
        Chiffre des données avec AES-GCM
        
        Args:
            plaintext: Données à chiffrer
            session_key: Clé de session
            associated_data: Données associées (non chiffrées mais authentifiées)
        
        Returns:
            Tuple (nonce, ciphertext+tag)
        """
        if len(session_key) != self.KEY_SIZE:
            raise ValueError(f"Session key must be {self.KEY_SIZE} bytes")
        
        # Génère un nonce aléatoire
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        
        # Chiffre avec AES-GCM
        aesgcm = AESGCM(session_key)
        ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data)
        
        return nonce, ciphertext
    
    def decrypt(self, nonce: bytes, ciphertext: bytes, session_key: bytes, associated_data: bytes = b"") -> bytes:
        """
        Déchiffre des données avec AES-GCM
        
        Args:
            nonce: Nonce utilisé pour le chiffrement
            ciphertext: Données chiffrées (incluant le tag d'authentification)
            session_key: Clé de session
            associated_data: Données associées (non chiffrées mais authentifiées)
        
        Returns:
            Données déchiffrées
        
        Raises:
            ValueError: Si l'authentification échoue
        """
        if len(session_key) != self.KEY_SIZE:
            raise ValueError(f"Session key must be {self.KEY_SIZE} bytes")
        
        if len(nonce) != self.NONCE_SIZE:
            raise ValueError(f"Nonce must be {self.NONCE_SIZE} bytes")
        
        # Déchiffre avec AES-GCM
        aesgcm = AESGCM(session_key)
        try:
            plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")

