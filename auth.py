"""
Module d'authentification pour le serveur VPN
Gère les utilisateurs et mots de passe
"""
import json
import hashlib
import secrets
from pathlib import Path
from typing import Optional


class AuthManager:
    """Gestionnaire d'authentification"""
    
    def __init__(self, auth_file: str = "server_auth.json"):
        """
        Initialise le gestionnaire d'authentification
        
        Args:
            auth_file: Chemin vers le fichier de stockage des authentifications
        """
        self.auth_file = Path(auth_file)
        self.users = self._load_users()
    
    def _load_users(self) -> dict:
        """Charge les utilisateurs depuis le fichier"""
        if self.auth_file.exists():
            try:
                with open(self.auth_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_users(self):
        """Sauvegarde les utilisateurs dans le fichier"""
        with open(self.auth_file, 'w') as f:
            json.dump(self.users, f, indent=4)
    
    def _hash_password(self, password: str, salt: Optional[str] = None) -> tuple:
        """
        Hash un mot de passe avec un salt
        
        Returns:
            Tuple (hash_hex, salt_hex)
        """
        if salt is None:
            salt = secrets.token_hex(16)
        else:
            salt = salt
        
        # Utilise PBKDF2 pour le hashing
        h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return h.hex(), salt
    
    def create_user(self, username: str, password: str) -> bool:
        """
        Crée un nouvel utilisateur
        
        Args:
            username: Nom d'utilisateur
            password: Mot de passe
        
        Returns:
            True si créé avec succès, False si l'utilisateur existe déjà
        """
        if username in self.users:
            return False
        
        password_hash, salt = self._hash_password(password)
        self.users[username] = {
            'password_hash': password_hash,
            'salt': salt
        }
        self._save_users()
        return True
    
    def verify_user(self, username: str, password: str) -> bool:
        """
        Vérifie les identifiants d'un utilisateur
        
        Args:
            username: Nom d'utilisateur
            password: Mot de passe
        
        Returns:
            True si les identifiants sont corrects
        """
        if username not in self.users:
            return False
        
        user_data = self.users[username]
        password_hash, _ = self._hash_password(password, user_data['salt'])
        
        return password_hash == user_data['password_hash']
    
    def change_password(self, username: str, old_password: str, new_password: str) -> bool:
        """
        Change le mot de passe d'un utilisateur
        
        Args:
            username: Nom d'utilisateur
            old_password: Ancien mot de passe
            new_password: Nouveau mot de passe
        
        Returns:
            True si le changement a réussi
        """
        if not self.verify_user(username, old_password):
            return False
        
        password_hash, salt = self._hash_password(new_password)
        self.users[username] = {
            'password_hash': password_hash,
            'salt': salt
        }
        self._save_users()
        return True
    
    def delete_user(self, username: str) -> bool:
        """
        Supprime un utilisateur
        
        Args:
            username: Nom d'utilisateur
        
        Returns:
            True si supprimé avec succès
        """
        if username not in self.users:
            return False
        
        del self.users[username]
        self._save_users()
        return True
    
    def list_users(self) -> list:
        """Retourne la liste des utilisateurs"""
        return list(self.users.keys())
    
    def user_exists(self, username: str) -> bool:
        """Vérifie si un utilisateur existe"""
        return username in self.users


def create_default_admin():
    """Crée un utilisateur admin par défaut"""
    auth = AuthManager()
    if not auth.user_exists("admin"):
        auth.create_user("admin", "admin")
        print("Utilisateur admin créé (username: admin, password: admin)")
        print("⚠️  Changez le mot de passe par défaut pour la sécurité!")

