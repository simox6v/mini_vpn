"""
Module de gestion des pseudo-paquets pour le mini-VPN
Gère l'encapsulation et le format des paquets
"""
import struct
from typing import Optional, Tuple
from crypto import CryptoManager


class PacketType:
    """Types de paquets"""
    HANDSHAKE = 0
    DATA = 1
    KEEPALIVE = 2


class VPNPacket:
    """Représente un pseudo-paquet VPN"""
    
    # Tailles fixes
    HEADER_SIZE = 1 + 12 + 4  # type (1) + nonce (12) + data_len (4)
    
    def __init__(self, packet_type: int, nonce: bytes, ciphertext: bytes):
        """
        Crée un paquet VPN
        
        Args:
            packet_type: Type de paquet (PacketType)
            nonce: Nonce utilisé pour le chiffrement
            ciphertext: Données chiffrées (incluant le tag d'authentification)
        """
        self.packet_type = packet_type
        self.nonce = nonce
        self.ciphertext = ciphertext
    
    def serialize(self) -> bytes:
        """
        Sérialise le paquet pour transmission
        
        Format: [type: 1 byte][nonce: 12 bytes][data_len: 4 bytes][ciphertext: variable]
        """
        data_len = len(self.ciphertext)
        header = struct.pack('!B 12s I', self.packet_type, self.nonce, data_len)
        return header + self.ciphertext
    
    @classmethod
    def deserialize(cls, data: bytes) -> 'VPNPacket':
        """
        Désérialise un paquet depuis des données reçues
        
        Args:
            data: Données brutes reçues
        
        Returns:
            VPNPacket désérialisé
        
        Raises:
            ValueError: Si les données sont invalides
        """
        if len(data) < cls.HEADER_SIZE:
            raise ValueError("Packet too short")
        
        packet_type, nonce, data_len = struct.unpack('!B 12s I', data[:cls.HEADER_SIZE])
        
        if len(data) < cls.HEADER_SIZE + data_len:
            raise ValueError("Incomplete packet")
        
        ciphertext = data[cls.HEADER_SIZE:cls.HEADER_SIZE + data_len]
        
        return cls(packet_type, nonce, ciphertext)
    
    def decrypt(self, crypto: CryptoManager, session_key: bytes, associated_data: bytes = b"") -> bytes:
        """
        Déchiffre le contenu du paquet
        
        Args:
            crypto: Instance de CryptoManager
            session_key: Clé de session
            associated_data: Données associées pour l'authentification
        
        Returns:
            Données déchiffrées
        """
        return crypto.decrypt(self.nonce, self.ciphertext, session_key, associated_data)


class PacketManager:
    """Gère la création et le traitement des paquets"""
    
    def __init__(self, crypto_manager: CryptoManager):
        self.crypto = crypto_manager
    
    def create_data_packet(self, plaintext: bytes, session_key: bytes) -> VPNPacket:
        """
        Crée un paquet de données chiffré
        
        Args:
            plaintext: Données à encapsuler
            session_key: Clé de session
        
        Returns:
            VPNPacket chiffré
        """
        # Utilise le type de paquet comme données associées
        associated_data = struct.pack('!B', PacketType.DATA)
        nonce, ciphertext = self.crypto.encrypt(plaintext, session_key, associated_data)
        
        return VPNPacket(PacketType.DATA, nonce, ciphertext)
    
    def create_handshake_packet(self, handshake_data: bytes) -> VPNPacket:
        """
        Crée un paquet de handshake (non chiffré pour l'instant)
        
        Args:
            handshake_data: Données du handshake
        
        Returns:
            VPNPacket de handshake
        """
        # Pour simplifier, on envoie le handshake en clair
        # Dans un vrai système, on pourrait utiliser une clé pré-partagée
        nonce = b'\x00' * 12  # Nonce nul pour les handshakes
        return VPNPacket(PacketType.HANDSHAKE, nonce, handshake_data)
    
    def create_keepalive_packet(self, session_key: bytes) -> VPNPacket:
        """
        Crée un paquet keepalive pour maintenir la connexion
        
        Args:
            session_key: Clé de session
        
        Returns:
            VPNPacket keepalive
        """
        plaintext = b"KEEPALIVE"
        associated_data = struct.pack('!B', PacketType.KEEPALIVE)
        nonce, ciphertext = self.crypto.encrypt(plaintext, session_key, associated_data)
        
        return VPNPacket(PacketType.KEEPALIVE, nonce, ciphertext)
    
    def process_packet(self, packet: VPNPacket, session_key: Optional[bytes] = None) -> Tuple[int, bytes]:
        """
        Traite un paquet reçu
        
        Args:
            packet: Paquet à traiter
            session_key: Clé de session (requise pour DATA et KEEPALIVE)
        
        Returns:
            Tuple (packet_type, payload)
        """
        if packet.packet_type == PacketType.HANDSHAKE:
            return (PacketType.HANDSHAKE, packet.ciphertext)
        
        elif packet.packet_type == PacketType.DATA:
            if session_key is None:
                raise ValueError("Session key required for data packet")
            associated_data = struct.pack('!B', PacketType.DATA)
            plaintext = packet.decrypt(self.crypto, session_key, associated_data)
            return (PacketType.DATA, plaintext)
        
        elif packet.packet_type == PacketType.KEEPALIVE:
            if session_key is None:
                raise ValueError("Session key required for keepalive packet")
            associated_data = struct.pack('!B', PacketType.KEEPALIVE)
            plaintext = packet.decrypt(self.crypto, session_key, associated_data)
            return (PacketType.KEEPALIVE, plaintext)
        
        else:
            raise ValueError(f"Unknown packet type: {packet.packet_type}")

