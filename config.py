"""
Module de configuration pour le mini-VPN
Gère la lecture des fichiers de configuration
"""
import json
from typing import Dict, Any
from pathlib import Path


class VPNConfig:
    """Classe pour gérer la configuration d'un peer VPN"""
    
    def __init__(self, config_path: str):
        """
        Charge la configuration depuis un fichier JSON
        
        Format attendu:
        {
            "private_key": "clé privée en hex",
            "public_key": "clé publique en hex (optionnel, dérivée de private_key)",
            "virtual_ip": "10.0.0.x/24",
            "listen_port": 51820,
            "peer": {
                "public_key": "clé publique du pair",
                "endpoint": "ip:port",
                "allowed_ips": ["10.0.0.0/24"]
            }
        }
        """
        self.config_path = Path(config_path)
        self.config = self._load_config()
        self._validate_config()
    
    def _load_config(self) -> Dict[str, Any]:
        """Charge le fichier de configuration"""
        if not self.config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {self.config_path}")
        
        with open(self.config_path, 'r') as f:
            return json.load(f)
    
    def _validate_config(self):
        """Valide la configuration"""
        required_fields = ['private_key', 'virtual_ip', 'listen_port']
        for field in required_fields:
            if field not in self.config:
                raise ValueError(f"Missing required field: {field}")
        
        if 'peer' not in self.config:
            raise ValueError("Missing 'peer' configuration")
        
        peer_required = ['public_key', 'endpoint']
        for field in peer_required:
            if field not in self.config['peer']:
                raise ValueError(f"Missing required peer field: {field}")
    
    @property
    def private_key(self) -> str:
        """Retourne la clé privée"""
        return self.config['private_key']
    
    @property
    def public_key(self) -> str:
        """Retourne la clé publique (si fournie, sinon dérivée)"""
        return self.config.get('public_key', '')
    
    @property
    def virtual_ip(self) -> str:
        """Retourne l'IP virtuelle"""
        return self.config['virtual_ip']
    
    @property
    def listen_port(self) -> int:
        """Retourne le port d'écoute"""
        return self.config['listen_port']
    
    @property
    def peer_public_key(self) -> str:
        """Retourne la clé publique du pair"""
        return self.config['peer']['public_key']
    
    @property
    def peer_endpoint(self) -> str:
        """Retourne l'endpoint du pair (ip:port)"""
        return self.config['peer']['endpoint']
    
    @property
    def peer_allowed_ips(self) -> list:
        """Retourne les IPs autorisées du pair"""
        return self.config['peer'].get('allowed_ips', [])
    
    def get_peer_address(self) -> tuple:
        """Retourne l'adresse du pair sous forme de tuple (ip, port)"""
        endpoint = self.peer_endpoint
        if ':' in endpoint:
            ip, port = endpoint.rsplit(':', 1)
            return (ip, int(port))
        else:
            raise ValueError(f"Invalid endpoint format: {endpoint}")

