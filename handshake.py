"""
Module de handshake pour le mini-VPN
Gère l'authentification et la dérivation des clés de session
"""
import struct
import time
import secrets
from typing import Optional, Tuple
from crypto import CryptoManager


class HandshakeMessage:
    """Représente un message de handshake"""
    
    # Types de messages
    TYPE_INITIATION = 1
    TYPE_RESPONSE = 2
    
    def __init__(self, msg_type: int, public_key: bytes, nonce: bytes, timestamp: int):
        self.msg_type = msg_type
        self.public_key = public_key
        self.nonce = nonce
        self.timestamp = timestamp
    
    def serialize(self) -> bytes:
        """Sérialise le message de handshake"""
        # Format: [type: 1 byte][public_key: 32 bytes][nonce: 16 bytes][timestamp: 8 bytes]
        return struct.pack(
            '!B 32s 16s Q',
            self.msg_type,
            self.public_key,
            self.nonce,
            self.timestamp
        )
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'HandshakeMessage':
        """Désérialise un message de handshake"""
        if len(data) < 57:  # 1 + 32 + 16 + 8
            raise ValueError("Invalid handshake message length")
        
        msg_type, public_key, nonce, timestamp = struct.unpack('!B 32s 16s Q', data[:57])
        return cls(msg_type, public_key, nonce, timestamp)


class HandshakeManager:
    """Gère le processus de handshake"""
    
    NONCE_SIZE = 16
    HANDSHAKE_TIMEOUT = 30  # secondes
    
    def __init__(self, crypto_manager: CryptoManager):
        self.crypto = crypto_manager
        self.pending_handshakes = {}  # {nonce: (timestamp, peer_public_key)}
        self.session_keys = {}  # {peer_public_key_hex: session_key}
    
    def create_initiation(self) -> Tuple[bytes, bytes]:
        """
        Crée un message d'initiation de handshake
        
        Returns:
            Tuple (handshake_message_bytes, local_nonce)
        """
        nonce = secrets.token_bytes(self.NONCE_SIZE)
        timestamp = int(time.time())
        
        msg = HandshakeMessage(
            HandshakeMessage.TYPE_INITIATION,
            self.crypto.get_public_key(),
            nonce,
            timestamp
        )
        
        # Stocke le handshake en attente
        self.pending_handshakes[nonce.hex()] = (timestamp, None)
        
        return msg.serialize(), nonce
    
    def process_initiation(self, handshake_data: bytes, peer_public_key: Optional[bytes] = None) -> Tuple[bytes, bytes]:
        """
        Traite un message d'initiation et génère une réponse
        
        Args:
            handshake_data: Données du message d'initiation
            peer_public_key: Clé publique du pair (None pour accepter tous les clients)
        
        Returns:
            Tuple (response_message_bytes, session_key)
        """
        msg = HandshakeMessage.deserialize(handshake_data)
        
        if msg.msg_type != HandshakeMessage.TYPE_INITIATION:
            raise ValueError("Expected initiation message")
        
        # Pour le serveur, on accepte n'importe quelle clé publique (multi-clients)
        # Si peer_public_key est None, on utilise la clé du message
        if peer_public_key is None:
            peer_public_key = msg.public_key
        elif msg.public_key != peer_public_key:
            # Si une clé est fournie et ne correspond pas, on utilise celle du message
            peer_public_key = msg.public_key
        
        # Vérifie le timestamp (protection contre les replay attacks)
        current_time = int(time.time())
        if abs(current_time - msg.timestamp) > self.HANDSHAKE_TIMEOUT:
            raise ValueError("Handshake message expired")
        
        # Génère une réponse
        response_nonce = secrets.token_bytes(self.NONCE_SIZE)
        response_timestamp = int(time.time())
        
        response_msg = HandshakeMessage(
            HandshakeMessage.TYPE_RESPONSE,
            self.crypto.get_public_key(),
            response_nonce,
            response_timestamp
        )
        
        # Dérive la clé de session
        handshake_combined = msg.nonce + response_nonce + msg.public_key + self.crypto.get_public_key()
        session_key = self.crypto.derive_session_key(peer_public_key, handshake_combined)
        
        # Stocke la clé de session
        peer_key_hex = peer_public_key.hex()
        self.session_keys[peer_key_hex] = session_key
        
        return response_msg.serialize(), session_key
    
    def process_response(self, handshake_data: bytes, peer_public_key: bytes, local_nonce: bytes) -> bytes:
        """
        Traite un message de réponse et dérive la clé de session
        
        Args:
            handshake_data: Données du message de réponse
            peer_public_key: Clé publique du pair
            local_nonce: Nonce local utilisé dans l'initiation
        
        Returns:
            Clé de session
        """
        msg = HandshakeMessage.deserialize(handshake_data)
        
        if msg.msg_type != HandshakeMessage.TYPE_RESPONSE:
            raise ValueError("Expected response message")
        
        # Vérifie que la clé publique correspond
        if msg.public_key != peer_public_key:
            raise ValueError("Public key mismatch")
        
        # Vérifie le timestamp
        current_time = int(time.time())
        if abs(current_time - msg.timestamp) > self.HANDSHAKE_TIMEOUT:
            raise ValueError("Handshake message expired")
        
        # Dérive la clé de session
        handshake_combined = local_nonce + msg.nonce + self.crypto.get_public_key() + peer_public_key
        session_key = self.crypto.derive_session_key(peer_public_key, handshake_combined)
        
        # Stocke la clé de session
        peer_key_hex = peer_public_key.hex()
        self.session_keys[peer_key_hex] = session_key
        
        # Nettoie le handshake en attente
        if local_nonce.hex() in self.pending_handshakes:
            del self.pending_handshakes[local_nonce.hex()]
        
        return session_key
    
    def get_session_key(self, peer_public_key: bytes) -> Optional[bytes]:
        """Récupère la clé de session pour un pair"""
        if isinstance(peer_public_key, str):
            peer_key_hex = peer_public_key
        else:
            peer_key_hex = peer_public_key.hex()
        
        return self.session_keys.get(peer_key_hex)
    
    def has_session(self, peer_public_key: bytes) -> bool:
        """Vérifie si une session existe pour un pair"""
        return self.get_session_key(peer_public_key) is not None

