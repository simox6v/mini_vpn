"""
Gestionnaire de ressources partagées avec verrouillage
Un seul utilisateur peut consulter une ressource à la fois
"""
import os
import json
import time
import threading
import shutil
from pathlib import Path
from typing import Dict, Optional, List
from datetime import datetime


class ResourceManager:
    """Gestionnaire de ressources partagées"""
    
    def __init__(self, resources_dir: str = "shared_resources"):
        """
        Initialise le gestionnaire de ressources
        
        Args:
            resources_dir: Répertoire contenant les ressources partagées
        """
        self.resources_dir = Path(resources_dir)
        self.resources_dir.mkdir(exist_ok=True)
        
        # Fichier de métadonnées
        self.metadata_file = self.resources_dir / "metadata.json"
        self.lock_file = self.resources_dir / "locks.json"
        
        # Charger les métadonnées
        self.metadata = self._load_metadata()
        self.locks: Dict[str, Dict] = self._load_locks()
        
        # Thread lock
        self.lock = threading.Lock()
        
        # Timeout de verrouillage (en secondes)
        self.lock_timeout = 300  # 5 minutes
    
    def _load_metadata(self) -> Dict:
        """Charge les métadonnées des ressources"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_metadata(self):
        """Sauvegarde les métadonnées"""
        with open(self.metadata_file, 'w') as f:
            json.dump(self.metadata, f, indent=4)
    
    def _load_locks(self) -> Dict:
        """Charge les verrous"""
        if self.lock_file.exists():
            try:
                with open(self.lock_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_locks(self):
        """Sauvegarde les verrous"""
        with open(self.lock_file, 'w') as f:
            json.dump(self.locks, f, indent=4)
    
    def add_resource(self, file_path: str, description: str = "") -> Optional[str]:
        """
        Ajoute une ressource au système
        
        Args:
            file_path: Chemin vers le fichier à ajouter
            description: Description de la ressource
        
        Returns:
            ID de la ressource ou None en cas d'erreur
        """
        source_path = Path(file_path)
        if not source_path.exists():
            return None
        
        with self.lock:
            # Génère un ID unique
            resource_id = f"res_{int(time.time())}_{len(self.metadata)}"
            
            # Copie le fichier dans le répertoire de ressources
            dest_path = self.resources_dir / source_path.name
            
            # Si le fichier existe déjà, ajoute un suffixe
            counter = 1
            while dest_path.exists():
                stem = source_path.stem
                suffix = source_path.suffix
                dest_path = self.resources_dir / f"{stem}_{counter}{suffix}"
                counter += 1
            
            shutil.copy2(source_path, dest_path)
            
            # Enregistre les métadonnées
            self.metadata[resource_id] = {
                'filename': dest_path.name,
                'original_name': source_path.name,
                'path': str(dest_path),
                'size': dest_path.stat().st_size,
                'description': description,
                'added_at': datetime.now().isoformat(),
                'type': self._get_file_type(dest_path)
            }
            
            self._save_metadata()
            print(f"[ResourceManager] Ressource ajoutée: {resource_id} - {dest_path.name}")
            return resource_id
    
    def _get_file_type(self, file_path: Path) -> str:
        """Détermine le type de fichier"""
        suffix = file_path.suffix.lower()
        if suffix in ['.txt', '.md']:
            return 'text'
        elif suffix in ['.jpg', '.jpeg', '.png', '.gif', '.bmp']:
            return 'image'
        elif suffix == '.pdf':
            return 'pdf'
        else:
            return 'other'
    
    def list_resources(self) -> List[Dict]:
        """Liste toutes les ressources disponibles"""
        with self.lock:
            resources = []
            for resource_id, info in self.metadata.items():
                resource_info = info.copy()
                resource_info['id'] = resource_id
                # Logique de verrouillage désactivée à la demande de l'utilisateur
                resource_info['locked'] = False
                resources.append(resource_info)
            return resources
    
    def lock_resource(self, resource_id: str, user_id: str) -> bool:
        """
        Verrouille une ressource pour un utilisateur (DÉSACTIVÉ)
        """
        return True
    
    def unlock_resource(self, resource_id: str, user_id: str) -> bool:
        """
        Déverrouille une ressource (DÉSACTIVÉ)
        """
        return True
    
    def get_resource(self, resource_id: str, user_id: str) -> Optional[Dict]:
        """
        Récupère une ressource (sans verrouillage)
        """
        with self.lock:
            if resource_id not in self.metadata:
                return None
            
            info = self.metadata[resource_id].copy()
            info['id'] = resource_id
            info['path'] = self.metadata[resource_id]['path']
            
            # Vérifie que le fichier existe toujours
            file_path = Path(info['path'])
            if not file_path.exists():
                return None
            
            return info
    
    def _cleanup_expired_locks(self):
        """Nettoie les verrous expirés"""
        current_time = time.time()
        expired_locks = []
        
        for resource_id, lock_info in self.locks.items():
            if current_time - lock_info['timestamp'] > self.lock_timeout:
                expired_locks.append(resource_id)
        
        for resource_id in expired_locks:
            del self.locks[resource_id]
            print(f"[ResourceManager] Verrou expiré pour {resource_id}")
        
        if expired_locks:
            self._save_locks()
    
    def remove_resource(self, resource_id: str) -> bool:
        """Supprime une ressource"""
        with self.lock:
            if resource_id not in self.metadata:
                return False
            
            # Déverrouille si nécessaire
            if resource_id in self.locks:
                del self.locks[resource_id]
            
            # Supprime le fichier
            file_path = Path(self.metadata[resource_id]['path'])
            if file_path.exists():
                file_path.unlink()
            
            # Supprime les métadonnées
            del self.metadata[resource_id]
            
            self._save_metadata()
            self._save_locks()
            print(f"[ResourceManager] Ressource supprimée: {resource_id}")
            return True

