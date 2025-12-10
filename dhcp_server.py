"""
Serveur DHCP simplifié pour attribution automatique d'IPs
"""
import threading
import time
from typing import Dict, Optional
from ipaddress import IPv4Address, IPv4Network


class DHCPServer:
    """Serveur DHCP simplifié pour le VPN"""
    
    def __init__(self, network: str = "10.0.0.0/24", start_ip: str = "10.0.0.10", end_ip: str = "10.0.0.254"):
        """
        Initialise le serveur DHCP
        
        Args:
            network: Réseau CIDR (ex: "10.0.0.0/24")
            start_ip: Première IP à attribuer
            end_ip: Dernière IP à attribuer
        """
        self.network = IPv4Network(network, strict=False)
        self.start_ip = IPv4Address(start_ip)
        self.end_ip = IPv4Address(end_ip)
        
        # Pool d'IPs disponibles
        self.available_ips = []
        self.leased_ips: Dict[str, Dict] = {}  # {client_id: {ip, timestamp, expires}}
        
        # Initialise le pool d'IPs
        self._init_ip_pool()
        
        # Thread lock pour la sécurité
        self.lock = threading.Lock()
        
        # Durée de bail par défaut (en secondes)
        self.lease_time = 3600  # 1 heure
    
    def _init_ip_pool(self):
        """Initialise le pool d'IPs disponibles"""
        for ip in self.network.hosts():
            if self.start_ip <= ip <= self.end_ip:
                self.available_ips.append(str(ip))
        
        # Trie les IPs
        self.available_ips.sort(key=lambda x: IPv4Address(x))
        print(f"[DHCP] Pool initialisé: {len(self.available_ips)} IPs disponibles")
    
    def request_ip(self, client_id: str) -> Optional[str]:
        """
        Demande une IP pour un client
        
        Args:
            client_id: Identifiant unique du client (peut être la clé publique)
        
        Returns:
            IP attribuée ou None si aucune IP disponible
        """
        with self.lock:
            # Vérifie si le client a déjà une IP active
            if client_id in self.leased_ips:
                lease = self.leased_ips[client_id]
                if time.time() < lease['expires']:
                    # Renouvelle le bail
                    lease['expires'] = time.time() + self.lease_time
                    lease['timestamp'] = time.time()
                    print(f"[DHCP] IP renouvelée pour {client_id}: {lease['ip']}")
                    return lease['ip']
                else:
                    # Le bail a expiré, libère l'IP
                    self._release_ip(lease['ip'])
                    del self.leased_ips[client_id]
            
            # Attribue une nouvelle IP
            if not self.available_ips:
                print(f"[DHCP] Aucune IP disponible pour {client_id}")
                return None
            
            ip = self.available_ips.pop(0)
            self.leased_ips[client_id] = {
                'ip': ip,
                'timestamp': time.time(),
                'expires': time.time() + self.lease_time
            }
            
            print(f"[DHCP] IP attribuée à {client_id}: {ip}")
            return ip
    
    def release_ip(self, client_id: str) -> bool:
        """
        Libère une IP attribuée à un client
        
        Args:
            client_id: Identifiant du client
        
        Returns:
            True si l'IP a été libérée
        """
        with self.lock:
            if client_id in self.leased_ips:
                ip = self.leased_ips[client_id]['ip']
                self._release_ip(ip)
                del self.leased_ips[client_id]
                print(f"[DHCP] IP libérée pour {client_id}: {ip}")
                return True
            return False
    
    def _release_ip(self, ip: str):
        """Libère une IP dans le pool"""
        if ip not in self.available_ips:
            self.available_ips.append(ip)
            self.available_ips.sort(key=lambda x: IPv4Address(x))
    
    def get_client_ip(self, client_id: str) -> Optional[str]:
        """Récupère l'IP d'un client s'il en a une"""
        with self.lock:
            if client_id in self.leased_ips:
                lease = self.leased_ips[client_id]
                if time.time() < lease['expires']:
                    return lease['ip']
            return None
    
    def cleanup_expired_leases(self):
        """Nettoie les baux expirés"""
        with self.lock:
            current_time = time.time()
            expired_clients = []
            
            for client_id, lease in self.leased_ips.items():
                if current_time >= lease['expires']:
                    expired_clients.append(client_id)
            
            for client_id in expired_clients:
                lease = self.leased_ips[client_id]
                self._release_ip(lease['ip'])
                del self.leased_ips[client_id]
                print(f"[DHCP] Bail expiré pour {client_id}, IP libérée")
    
    def get_lease_info(self, client_id: str) -> Optional[Dict]:
        """Récupère les informations de bail d'un client"""
        with self.lock:
            if client_id in self.leased_ips:
                lease = self.leased_ips[client_id].copy()
                lease['remaining_time'] = max(0, lease['expires'] - time.time())
                return lease
            return None
    
    def get_statistics(self) -> Dict:
        """Retourne les statistiques du serveur DHCP"""
        with self.lock:
            return {
                'total_ips': len(self.available_ips) + len(self.leased_ips),
                'available_ips': len(self.available_ips),
                'leased_ips': len(self.leased_ips),
                'active_clients': len(self.leased_ips)
            }

