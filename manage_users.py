#!/usr/bin/env python3
"""
Script de gestion des utilisateurs pour le serveur VPN
"""
import sys
from auth import AuthManager


def print_menu():
    """Affiche le menu principal"""
    print("\n" + "=" * 60)
    print("Gestion des Utilisateurs - Mini-VPN Server")
    print("=" * 60)
    print("1. Créer un utilisateur")
    print("2. Changer le mot de passe")
    print("3. Supprimer un utilisateur")
    print("4. Lister les utilisateurs")
    print("5. Quitter")
    print("=" * 60)


def create_user(auth_manager):
    """Crée un nouvel utilisateur"""
    print("\n--- Créer un utilisateur ---")
    username = input("Nom d'utilisateur: ")
    
    if auth_manager.user_exists(username):
        print(f"✗ L'utilisateur '{username}' existe déjà")
        return
    
    password = input("Mot de passe: ")
    confirm_password = input("Confirmer le mot de passe: ")
    
    if password != confirm_password:
        print("✗ Les mots de passe ne correspondent pas")
        return
    
    if auth_manager.create_user(username, password):
        print(f"✓ Utilisateur '{username}' créé avec succès")
    else:
        print(f"✗ Erreur lors de la création de l'utilisateur")


def change_password(auth_manager):
    """Change le mot de passe d'un utilisateur"""
    print("\n--- Changer le mot de passe ---")
    username = input("Nom d'utilisateur: ")
    
    if not auth_manager.user_exists(username):
        print(f"✗ L'utilisateur '{username}' n'existe pas")
        return
    
    old_password = input("Ancien mot de passe: ")
    new_password = input("Nouveau mot de passe: ")
    confirm_password = input("Confirmer le nouveau mot de passe: ")
    
    if new_password != confirm_password:
        print("✗ Les mots de passe ne correspondent pas")
        return
    
    if auth_manager.change_password(username, old_password, new_password):
        print(f"✓ Mot de passe changé avec succès pour '{username}'")
    else:
        print(f"✗ Erreur: ancien mot de passe incorrect ou erreur lors du changement")


def delete_user(auth_manager):
    """Supprime un utilisateur"""
    print("\n--- Supprimer un utilisateur ---")
    username = input("Nom d'utilisateur à supprimer: ")
    
    if not auth_manager.user_exists(username):
        print(f"✗ L'utilisateur '{username}' n'existe pas")
        return
    
    confirm = input(f"Êtes-vous sûr de vouloir supprimer '{username}'? (o/N): ")
    if confirm.lower() != 'o':
        print("Annulé")
        return
    
    if auth_manager.delete_user(username):
        print(f"✓ Utilisateur '{username}' supprimé avec succès")
    else:
        print(f"✗ Erreur lors de la suppression")


def list_users(auth_manager):
    """Liste les utilisateurs"""
    print("\n--- Liste des utilisateurs ---")
    users = auth_manager.list_users()
    
    if not users:
        print("Aucun utilisateur trouvé")
    else:
        print(f"Nombre d'utilisateurs: {len(users)}")
        for i, username in enumerate(users, 1):
            print(f"  {i}. {username}")


def main():
    """Point d'entrée principal"""
    auth_manager = AuthManager()
    
    while True:
        print_menu()
        choice = input("\nChoix: ").strip()
        
        if choice == "1":
            create_user(auth_manager)
        elif choice == "2":
            change_password(auth_manager)
        elif choice == "3":
            delete_user(auth_manager)
        elif choice == "4":
            list_users(auth_manager)
        elif choice == "5":
            print("\nAu revoir!")
            break
        else:
            print("✗ Choix invalide")
        
        input("\nAppuyez sur Entrée pour continuer...")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrompu par l'utilisateur")
        sys.exit(0)

