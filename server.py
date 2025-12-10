#!/usr/bin/env python3
"""
Serveur VPN - Écoute les connexions et gère le tunnel chiffré
"""
import socket
import sys
import threading
import time
from typing import Dict
from config import VPNConfig
from crypto import CryptoManager
from handshake import HandshakeManager
from packet import PacketManager, PacketType, VPNPacket
import json


class VPNServer:
    """Serveur VPN qui écoute et gère les connexions"""
    
    def __init__(self, config_path: str):
        """Initialise le serveur avec la configuration"""
        self.config = VPNConfig(config_path)
        self.crypto = CryptoManager(self.config.private_key)
        self.handshake = HandshakeManager(self.crypto)
        self.packet_manager = PacketManager(self.crypto)
        
        # Socket UDP pour la communication
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Permet la réutilisation de l'adresse pour éviter l'erreur "port déjà utilisé"
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(('0.0.0.0', self.config.listen_port))
        except OSError as e:
            if e.winerror == 10048:  # Windows: port déjà utilisé
                raise OSError(f"Le port {self.config.listen_port} est déjà utilisé. "
                            f"Arrêtez l'instance précédente ou changez le port dans la configuration.")
            else:
                raise
        self.sock.settimeout(1.0)  # Timeout pour permettre l'arrêt propre
        
        self.running = False
        self.peer_address = None
        self.peer_public_key_bytes = bytes.fromhex(self.config.peer_public_key)
        
        # Gestion des clients connectés (plusieurs clients possibles)
        self.connected_clients: Dict[str, Dict] = {}  # {client_id: {addr, ip, public_key}}
        
        print(f"[Server] Initialisé sur le port {self.config.listen_port}")
        print(f"[Server] IP virtuelle: {self.config.virtual_ip}")
        print(f"[Server] Clé publique: {self.crypto.get_public_key_hex()}")
    
    def start(self):
        """Démarre le serveur"""
        self.running = True
        print(f"[Server] En attente de connexions...")
        
        try:
            while self.running:
                try:
                    data, addr = self.sock.recvfrom(65535)
                    # Debug print to verify connectivity
                    print(f"[Server DEBUG] Reçu paquet de {addr} ({len(data)} bytes)")
                    self.handle_packet(data, addr)
                except socket.timeout:
                    continue
                except Exception as e:
                    print(f"[Server] Erreur lors de la réception: {e}")
        except KeyboardInterrupt:
            print("\n[Server] Arrêt demandé...")
        finally:
            self.stop()
    
    def handle_packet(self, data: bytes, addr: tuple):
        """Traite un paquet reçu"""
        try:
            packet = VPNPacket.deserialize(data)
            
            if packet.packet_type == PacketType.HANDSHAKE:
                self.handle_handshake(packet, addr)
            elif packet.packet_type == PacketType.DATA:
                self.handle_data_packet(packet, addr)
            elif packet.packet_type == PacketType.KEEPALIVE:
                self.handle_keepalive(packet, addr)
            else:
                print(f"[Server] Type de paquet inconnu: {packet.packet_type}")
        
        except Exception as e:
            print(f"[Server] Erreur lors du traitement du paquet: {e}")
    
    def handle_handshake(self, packet: VPNPacket, addr: tuple):
        """Traite un message de handshake"""
        print(f"[Server] Handshake reçu de {addr}")
        
        try:
            handshake_data = packet.ciphertext
            # Extrait la clé publique du client depuis le handshake
            from handshake import HandshakeMessage
            client_msg = HandshakeMessage.deserialize(handshake_data)
            client_public_key = client_msg.public_key
            client_id = client_public_key.hex()
            
            # DHCP désactivé
            assigned_ip = "0.0.0.0"
            
            # Traite le handshake (None pour accepter n'importe quel client)
            response_data, session_key = self.handshake.process_initiation(
                handshake_data,
                None  # None = accepte tous les clients
            )
            
            # Ajoute l'IP attribuée à la réponse (séparée par \x00)
            response_with_ip = response_data + b'\x00' + assigned_ip.encode() + b'\x00'
            
            # Envoie la réponse
            response_packet = self.packet_manager.create_handshake_packet(response_with_ip)
            self.sock.sendto(response_packet.serialize(), addr)
            
            # Enregistre le client
            self.connected_clients[client_id] = {
                'addr': addr,
                'ip': assigned_ip,
                'public_key': client_public_key
            }
            self.peer_address = addr  # Pour compatibilité
            
            print(f"[Server] Handshake complété avec {addr}")
            print(f"[Server] Session établie")
        
        except Exception as e:
            print(f"[Server] Erreur lors du handshake: {e}")
            import traceback
            traceback.print_exc()
    
    def handle_data_packet(self, packet: VPNPacket, addr: tuple):
        """Traite un paquet de données"""
        # Trouve le client correspondant
        client_id = None
        for cid, client_info in self.connected_clients.items():
            if client_info['addr'] == addr:
                client_id = cid
                break
        
        if not client_id:
            print(f"[Server] Paquet reçu d'un client non connecté: {addr}")
            return
        
        client_info = self.connected_clients[client_id]
        client_public_key = client_info['public_key']
        
        if not self.handshake.has_session(client_public_key):
            print(f"[Server] Paquet de données reçu mais pas de session active")
            return
        
        try:
            session_key = self.handshake.get_session_key(client_public_key)
            packet_type, plaintext = self.packet_manager.process_packet(packet, session_key)
            
            # Gère les requêtes spéciales
            # Gère les requêtes spéciales
            is_json_request = False
            try:
                decoded_text = plaintext.decode('utf-8')
                if decoded_text.strip().startswith('{') and decoded_text.strip().endswith('}'):
                    try:
                        request = json.loads(decoded_text)
                        is_json_request = True
                    except:
                        is_json_request = False
            except:
                is_json_request = False

            if is_json_request and isinstance(request, dict):
                try:
                    if request.get('type') == 'get_resources':
                        # Envoie la liste des ressources
                        print("[Server] Demande de liste des ressources reçue")
                        from resource_manager import ResourceManager
                        rm = ResourceManager()
                        resources = rm.list_resources()
                        response = json.dumps({'type': 'resources_list', 'resources': resources}).encode('utf-8')
                        self.send_data_to_client(client_id, response)
                        return
                    
                    elif request.get('type') == 'get_resource':
                        print(f"[Server] Demande de ressource {request.get('resource_id')} reçue")
                        # Envoie le contenu d'une ressource
                        from resource_manager import ResourceManager
                        import base64
                        
                        resource_id = request.get('resource_id')
                        rm = ResourceManager()
                        
                        # Récupère la ressource sans verrouillage
                        resource_info = rm.get_resource(resource_id, client_id)
                        
                        if resource_info:
                            try:
                                # Lit le fichier
                                file_path = resource_info['path']
                                with open(file_path, 'rb') as f:
                                    content = f.read()
                                
                                # Limite la taille totale (10MB)
                                MAX_TOTAL_SIZE = 10 * 1024 * 1024
                                if len(content) > MAX_TOTAL_SIZE:
                                    error_msg = f"Fichier trop volumineux ({len(content)//1024}KB > 10MB). Max 10MB."
                                    response = json.dumps({
                                        'type': 'resource_error',
                                        'error': error_msg
                                    }).encode('utf-8')
                                    self.send_data_to_client(client_id, response)
                                    return

                                # Configuration du chunking
                                # 32KB binaire -> ~43KB Base64 (Safe pour UDP 64KB)
                                CHUNK_SIZE = 32 * 1024
                                
                                if len(content) <= CHUNK_SIZE:
                                    # Petit fichier: envoi simple
                                    content_b64 = base64.b64encode(content).decode('ascii')
                                    response = json.dumps({
                                        'type': 'resource_content',
                                        'resource_id': resource_id,
                                        'filename': resource_info['original_name'],
                                        'file_type': resource_info['type'],
                                        'content': content_b64
                                    }).encode('utf-8')
                                    self.send_data_to_client(client_id, response)
                                else:
                                    # Grand fichier: envoi par morceaux
                                    total_chunks = (len(content) + CHUNK_SIZE - 1) // CHUNK_SIZE
                                    print(f"[Server] Envoi de {resource_info['original_name']} en {total_chunks} morceaux")
                                    
                                    # 1. Envoie l'initialisation
                                    init_packet = json.dumps({
                                        'type': 'resource_transfer_init',
                                        'resource_id': resource_id,
                                        'filename': resource_info['original_name'],
                                        'file_type': resource_info['type'],
                                        'total_size': len(content),
                                        'total_chunks': total_chunks
                                    }).encode('utf-8')
                                    self.send_data_to_client(client_id, init_packet)
                                    
                                    # 2. Envoie les morceaux
                                    import time
                                    for i in range(total_chunks):
                                        chunk = content[i*CHUNK_SIZE : (i+1)*CHUNK_SIZE]
                                        chunk_b64 = base64.b64encode(chunk).decode('ascii')
                                        
                                        chunk_packet = json.dumps({
                                            'type': 'resource_chunk',
                                            'resource_id': resource_id,
                                            'chunk_index': i,
                                            'content': chunk_b64
                                        }).encode('utf-8')
                                        
                                        self.send_data_to_client(client_id, chunk_packet)
                                        # Petite pause pour éviter de saturer le buffer UDP
                                        time.sleep(0.005)
                                    
                                    print(f"[Server] Transfert de {resource_info['original_name']} terminé")

                            except Exception as e:
                                print(f"[Server ERROR] Erreur lecture fichier: {e}")
                                response = json.dumps({
                                    'type': 'resource_error',
                                    'error': str(e)
                                }).encode('utf-8')
                                self.send_data_to_client(client_id, response)
                        else:
                            print(f"[Server] Ressource introuvable: {resource_id}")
                            response = json.dumps({
                                'type': 'resource_error',
                                'error': "Ressource indisponible"
                            }).encode('utf-8')
                        
                        self.send_data_to_client(client_id, response)
                        return
                except Exception as e:
                    print(f"[Server ERROR] Erreur traitement requête JSON: {e}")
            
            print(f"[Server] Données reçues de {client_info['ip']} ({len(plaintext)} bytes): {plaintext[:50]}...")
        
        except Exception as e:
            print(f"[Server] Erreur lors du déchiffrement: {e}")
    
    def send_data_to_client(self, client_id: str, data: bytes):
        """Envoie des données à un client spécifique"""
        if client_id not in self.connected_clients:
            return False
        
        client_info = self.connected_clients[client_id]
        client_public_key = client_info['public_key']
        
        if not self.handshake.has_session(client_public_key):
            return False
        
        try:
            session_key = self.handshake.get_session_key(client_public_key)
            packet = self.packet_manager.create_data_packet(data, session_key)
            self.sock.sendto(packet.serialize(), client_info['addr'])
            return True
        except Exception as e:
            print(f"[Server] Erreur lors de l'envoi: {e}")
            return False
    
    def handle_keepalive(self, packet: VPNPacket, addr: tuple):
        """Traite un paquet keepalive"""
        # Trouve le client correspondant
        client_id = None
        for cid, client_info in self.connected_clients.items():
            if client_info['addr'] == addr:
                client_id = cid
                break
        
        if not client_id:
            return
        
        client_info = self.connected_clients[client_id]
        client_public_key = client_info['public_key']
        
        if not self.handshake.has_session(client_public_key):
            return
        
        try:
            session_key = self.handshake.get_session_key(client_public_key)
            self.packet_manager.process_packet(packet, session_key)
            # Keepalive reçu, pas besoin de réponse
        except Exception as e:
            print(f"[Server] Erreur lors du traitement du keepalive: {e}")
    
    def send_data(self, data: bytes):
        """Envoie des données au client"""
        if not self.peer_address:
            print("[Server] Aucun client connecté")
            return
        
        if not self.handshake.has_session(self.peer_public_key_bytes):
            print("[Server] Aucune session active")
            return
        
        try:
            session_key = self.handshake.get_session_key(self.peer_public_key_bytes)
            packet = self.packet_manager.create_data_packet(data, session_key)
            self.sock.sendto(packet.serialize(), self.peer_address)
        except Exception as e:
            print(f"[Server] Erreur lors de l'envoi: {e}")
    
    def stop(self):
        """Arrête le serveur"""
        self.running = False
        if self.sock:
            self.sock.close()
        print("[Server] Serveur arrêté")


def main():
    """Point d'entrée principal"""
    if len(sys.argv) != 2:
        print("Usage: python server.py <config_file>")
        sys.exit(1)
    
    config_path = sys.argv[1]
    
    try:
        server = VPNServer(config_path)
        server.start()
    except Exception as e:
        print(f"Erreur: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()

