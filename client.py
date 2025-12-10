#!/usr/bin/env python3
"""
Client VPN - Se connecte au serveur et établit un tunnel chiffré
"""
import socket
import sys
import time
from config import VPNConfig
from crypto import CryptoManager
from handshake import HandshakeManager
from packet import PacketManager, PacketType, VPNPacket


class VPNClient:
    """Client VPN qui se connecte au serveur"""
    
    def __init__(self, config_path: str):
        """Initialise le client avec la configuration"""
        self.config = VPNConfig(config_path)
        self.crypto = CryptoManager(self.config.private_key)
        self.handshake = HandshakeManager(self.crypto)
        self.packet_manager = PacketManager(self.crypto)
        
        # Socket UDP pour la communication
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Permet la réutilisation de l'adresse pour éviter l'erreur "port déjà utilisé"
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except:
            pass  # Certains systèmes peuvent ne pas supporter SO_REUSEADDR pour UDP
        
        try:
            self.sock.bind(('0.0.0.0', self.config.listen_port))
        except OSError as e:
            error_code = getattr(e, 'winerror', None)
            if error_code == 10048:  # Windows: port déjà utilisé
                # Essaie de bind sur un port aléatoire
                try:
                    self.sock.bind(('0.0.0.0', 0))
                    actual_port = self.sock.getsockname()[1]
                    print(f"[Client] Port {self.config.listen_port} occupé, utilisation du port {actual_port}")
                except:
                    raise OSError(f"Impossible de trouver un port disponible: {e}")
            elif error_code == 10013:  # Windows: accès refusé (permissions)
                raise OSError(f"Permissions insuffisantes pour utiliser le port {self.config.listen_port}. "
                            f"Le port peut être bloqué par le pare-feu ou nécessiter des privilèges administrateur.")
            else:
                raise
        self.sock.settimeout(5.0)
        
        self.server_address = self.config.get_peer_address()
        self.server_public_key_bytes = bytes.fromhex(self.config.peer_public_key)
        self.assigned_ip = None  # IP attribuée par le serveur DHCP
        
        print(f"[Client] Initialisé sur le port {self.config.listen_port}")
        print(f"[Client] IP virtuelle configurée: {self.config.virtual_ip}")
        print(f"[Client] Serveur: {self.server_address[0]}:{self.server_address[1]}")
        print(f"[Client] Clé publique: {self.crypto.get_public_key_hex()}")
    
    def connect(self):
        """Établit une connexion avec le serveur"""
        print(f"[Client] Connexion au serveur {self.server_address[0]}:{self.server_address[1]}...")
        
        # Initie le handshake
        try:
            handshake_data, local_nonce = self.handshake.create_initiation()
            handshake_packet = self.packet_manager.create_handshake_packet(handshake_data)
        except Exception as e:
            return False, f"Erreur préparation handshake: {e}"
        
        print("[Client] Envoi du handshake...")
        try:
            self.sock.sendto(handshake_packet.serialize(), self.server_address)
        except Exception as e:
            return False, f"Erreur envoi paquet: {e}"
        
        # Attend la réponse
        try:
            data, addr = self.sock.recvfrom(4096)
            
            if addr != self.server_address:
                print(f"[Client] Réponse reçue d'une adresse non autorisée: {addr}")
                return False, f"Réponse source inconnue: {addr}"
            
            try:
                response_packet = VPNPacket.deserialize(data)
            except Exception as e:
                return False, f"Paquet invalide: {e}"
            
            if response_packet.packet_type != PacketType.HANDSHAKE:
                print(f"[Client] Réponse invalide: type {response_packet.packet_type}")
                return False, f"Type de réponse invalide: {response_packet.packet_type}"
            
            # Extrait l'IP attribuée depuis la réponse
            response_data = response_packet.ciphertext
            
            # La réponse du handshake est de taille fixe (57 bytes)
            # Le serveur ajoute l'IP après le handshake: [Handshake 57b][\x00][IP][\x00]
            HANDSHAKE_SIZE = 57
            
            if len(response_data) >= HANDSHAKE_SIZE:
                handshake_response = response_data[:HANDSHAKE_SIZE]
                # S'il y a des données supplémentaires, c'est l'IP
                if len(response_data) > HANDSHAKE_SIZE:
                    ip_part = response_data[HANDSHAKE_SIZE:]
                    self.assigned_ip = ip_part.strip(b'\x00').decode('utf-8')
                    print(f"[Client] IP attribuée par le serveur: {self.assigned_ip}")
                else:
                    self.assigned_ip = None
            else:
                return False, f"Réponse handshake trop courte: {len(response_data)} bytes"
            
            # Traite la réponse du handshake
            session_key = self.handshake.process_response(
                handshake_response,
                self.server_public_key_bytes,
                local_nonce
            )
            
            print("[Client] Handshake complété")
            print("[Client] Session établie")
            if self.assigned_ip:
                print(f"[Client] IP virtuelle: {self.assigned_ip}/24")
            return True, "Connexion établie"
        
        except socket.timeout:
            print("[Client] Timeout: le serveur n'a pas répondu")
            return False, "Timeout: Le serveur ne répond pas. Vérifiez qu'il est démarré et que le pare-feu n'est pas bloquant."
        except Exception as e:
            print(f"[Client] Erreur lors du handshake: {e}")
            return False, f"Erreur communication: {e}"
    
    def send_data(self, data: bytes):
        """Envoie des données au serveur"""
        if not self.handshake.has_session(self.server_public_key_bytes):
            print("[Client] Aucune session active. Connectez-vous d'abord.")
            return False
        
        try:
            session_key = self.handshake.get_session_key(self.server_public_key_bytes)
            packet = self.packet_manager.create_data_packet(data, session_key)
            self.sock.sendto(packet.serialize(), self.server_address)
            return True
        except Exception as e:
            print(f"[Client] Erreur lors de l'envoi: {e}")
            return False
    
    def listen(self):
        """Écoute les paquets du serveur"""
        print("[Client] En attente de données du serveur...")
        self.sock.settimeout(1.0)
        
        try:
            while True:
                try:
                    data, addr = self.sock.recvfrom(65535)
                    
                    if addr != self.server_address:
                        continue
                    
                    packet = VPNPacket.deserialize(data)
                    
                    if packet.packet_type == PacketType.DATA:
                        self.handle_data_packet(packet)
                    elif packet.packet_type == PacketType.KEEPALIVE:
                        self.handle_keepalive(packet)
                
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[Client] Erreur lors de la réception: {e}")
        
        except KeyboardInterrupt:
            print("\n[Client] Arrêt demandé...")
    
    def handle_data_packet(self, packet: VPNPacket):
        """Traite un paquet de données reçu"""
        try:
            session_key = self.handshake.get_session_key(self.server_public_key_bytes)
            packet_type, plaintext = self.packet_manager.process_packet(packet, session_key)
            
            print(f"[Client] Données reçues ({len(plaintext)} bytes): {plaintext[:50]}...")
        
        except Exception as e:
            print(f"[Client] Erreur lors du déchiffrement: {e}")
    
    def handle_keepalive(self, packet: VPNPacket):
        """Traite un paquet keepalive"""
        try:
            session_key = self.handshake.get_session_key(self.server_public_key_bytes)
            self.packet_manager.process_packet(packet, session_key)
        except Exception as e:
            print(f"[Client] Erreur lors du traitement du keepalive: {e}")
    
    def send_keepalive(self):
        """Envoie un paquet keepalive"""
        if not self.handshake.has_session(self.server_public_key_bytes):
            return
        
        try:
            session_key = self.handshake.get_session_key(self.server_public_key_bytes)
            packet = self.packet_manager.create_keepalive_packet(session_key)
            self.sock.sendto(packet.serialize(), self.server_address)
        except Exception as e:
            print(f"[Client] Erreur lors de l'envoi du keepalive: {e}")
    
    def close(self):
        """Ferme la connexion"""
        if self.sock:
            self.sock.close()
        print("[Client] Connexion fermée")


def main():
    """Point d'entrée principal"""
    if len(sys.argv) < 2:
        print("Usage: python client.py <config_file> [command]")
        print("Commands:")
        print("  connect  - Se connecter au serveur")
        print("  send <data> - Envoyer des données")
        print("  listen   - Écouter les données du serveur")
        sys.exit(1)
    
    config_path = sys.argv[1]
    command = sys.argv[2] if len(sys.argv) > 2 else "connect"
    
    try:
        client = VPNClient(config_path)
        
        if command == "connect":
            success, msg = client.connect()
            if success:
                # Après connexion, on peut écouter
                print("\n[Client] Mode interactif. Tapez 'quit' pour quitter.")
                print("[Client] Les données reçues seront affichées automatiquement.")
                
                import threading
                listen_thread = threading.Thread(target=client.listen, daemon=True)
                listen_thread.start()
                
                # Boucle interactive pour envoyer des données
                while True:
                    try:
                        user_input = input("\n[Client] Entrez des données à envoyer (ou 'quit'): ")
                        if user_input.lower() == 'quit':
                            break
                        if user_input:
                            client.send_data(user_input.encode())
                    except KeyboardInterrupt:
                        break
                
                client.close()
            else:
                print(f"[Client] Échec de la connexion: {msg}")
        
        elif command == "send":
            if len(sys.argv) < 4:
                print("Usage: python client.py <config_file> send <data>")
                sys.exit(1)
            
            success, msg = client.connect()
            if success:
                data = sys.argv[3].encode()
                client.send_data(data)
                time.sleep(0.5)  # Attend un peu pour recevoir une réponse
                client.close()
            else:
                print(f"[Client] Échec de la connexion: {msg}")
        
        elif command == "listen":
            success, msg = client.connect()
            if success:
                client.listen()
            else:
                print(f"[Client] Échec de la connexion: {msg}")
        
        else:
            print(f"Commande inconnue: {command}")
            sys.exit(1)
    
    except Exception as e:
        print(f"Erreur: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()

