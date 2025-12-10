#!/usr/bin/env python3
"""
Interface graphique pour le mini-VPN
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import sys
from pathlib import Path
from config import VPNConfig
from crypto import CryptoManager
from handshake import HandshakeManager
from packet import PacketManager, PacketType, VPNPacket
import socket
import time


class VPNGUI:
    """Interface graphique principale pour le VPN"""
    
    def __init__(self, root):
        self.root = root
        self.root.title("Mini-VPN - Interface Graphique")
        self.root.geometry("900x700")
        
        # Variables d'état
        self.server_running = False
        self.client_connected = False
        self.server_thread = None
        self.client_thread = None
        self.log_queue = queue.Queue()
        
        # Composants VPN
        self.server_instance = None
        self.client_instance = None
        self.server_config = None
        self.client_config = None
        
        # Créer l'interface
        self.create_widgets()
        
        # Démarrer le traitement des logs
        self.process_log_queue()
    
    def create_widgets(self):
        """Crée les widgets de l'interface"""
        # Frame principal avec onglets
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Onglet Serveur
        server_frame = ttk.Frame(notebook)
        notebook.add(server_frame, text="Serveur")
        self.create_server_tab(server_frame)
        
        # Onglet Client
        client_frame = ttk.Frame(notebook)
        notebook.add(client_frame, text="Client")
        self.create_client_tab(client_frame)
        
        # Onglet Configuration
        config_frame = ttk.Frame(notebook)
        notebook.add(config_frame, text="Configuration")
        self.create_config_tab(config_frame)
        
        # Zone de logs (en bas)
        log_frame = ttk.LabelFrame(self.root, text="Logs")
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=10,
            wrap=tk.WORD,
            state=tk.DISABLED
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Barre de statut
        self.status_bar = ttk.Label(
            self.root,
            text="Prêt",
            relief=tk.SUNKEN,
            anchor=tk.W
        )
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
    
    def create_server_tab(self, parent):
        """Crée l'onglet serveur"""
        # Frame de configuration
        config_frame = ttk.LabelFrame(parent, text="Configuration")
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(config_frame, text="Fichier de config:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.server_config_path = tk.StringVar(value="server_config.json")
        ttk.Entry(config_frame, textvariable=self.server_config_path, width=40).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(config_frame, text="Parcourir", command=self.browse_server_config).grid(row=0, column=2, padx=5, pady=5)
        
        # Frame d'état
        status_frame = ttk.LabelFrame(parent, text="État du Serveur")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.server_status_label = ttk.Label(status_frame, text="Arrêté", foreground="red")
        self.server_status_label.pack(pady=10)
        
        # Frame de contrôle
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.server_start_btn = ttk.Button(
            control_frame,
            text="Démarrer le Serveur",
            command=self.start_server,
            width=20
        )
        self.server_start_btn.pack(side=tk.LEFT, padx=5)
        
        self.server_stop_btn = ttk.Button(
            control_frame,
            text="Arrêter le Serveur",
            command=self.stop_server,
            state=tk.DISABLED,
            width=20
        )
        self.server_stop_btn.pack(side=tk.LEFT, padx=5)
        
        # Informations du serveur
        info_frame = ttk.LabelFrame(parent, text="Informations")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.server_info_text = scrolledtext.ScrolledText(info_frame, height=8, wrap=tk.WORD, state=tk.DISABLED)
        self.server_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_client_tab(self, parent):
        """Crée l'onglet client"""
        # Frame de configuration
        config_frame = ttk.LabelFrame(parent, text="Configuration")
        config_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(config_frame, text="Fichier de config:").grid(row=0, column=0, sticky=tk.W, padx=5, pady=5)
        self.client_config_path = tk.StringVar(value="client_config.json")
        ttk.Entry(config_frame, textvariable=self.client_config_path, width=40).grid(row=0, column=1, padx=5, pady=5)
        ttk.Button(config_frame, text="Parcourir", command=self.browse_client_config).grid(row=0, column=2, padx=5, pady=5)
        
        # Frame d'état
        status_frame = ttk.LabelFrame(parent, text="État de la Connexion")
        status_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.client_status_label = ttk.Label(status_frame, text="Déconnecté", foreground="red")
        self.client_status_label.pack(pady=10)
        
        # Frame de contrôle
        control_frame = ttk.Frame(parent)
        control_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.client_connect_btn = ttk.Button(
            control_frame,
            text="Se Connecter",
            command=self.connect_client,
            width=20
        )
        self.client_connect_btn.pack(side=tk.LEFT, padx=5)
        
        self.client_disconnect_btn = ttk.Button(
            control_frame,
            text="Se Déconnecter",
            command=self.disconnect_client,
            state=tk.DISABLED,
            width=20
        )
        self.client_disconnect_btn.pack(side=tk.LEFT, padx=5)
        
        # Frame d'envoi de données
        send_frame = ttk.LabelFrame(parent, text="Envoyer des Données")
        send_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(send_frame, text="Message:").pack(side=tk.LEFT, padx=5, pady=5)
        self.message_entry = ttk.Entry(send_frame, width=40)
        self.message_entry.pack(side=tk.LEFT, padx=5, pady=5)
        self.message_entry.bind('<Return>', lambda e: self.send_message())
        
        ttk.Button(send_frame, text="Envoyer", command=self.send_message).pack(side=tk.LEFT, padx=5, pady=5)
        
        # Informations du client
        info_frame = ttk.LabelFrame(parent, text="Informations")
        info_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.client_info_text = scrolledtext.ScrolledText(info_frame, height=8, wrap=tk.WORD, state=tk.DISABLED)
        self.client_info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_config_tab(self, parent):
        """Crée l'onglet de configuration"""
        # Frame de génération de clés
        key_frame = ttk.LabelFrame(parent, text="Génération de Clés")
        key_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Button(
            key_frame,
            text="Générer de Nouvelles Clés",
            command=self.generate_keys
        ).pack(pady=10)
        
        # Frame de configuration automatique
        setup_frame = ttk.LabelFrame(parent, text="Configuration Automatique")
        setup_frame.pack(fill=tk.X, padx=10, pady=5)
        
        ttk.Label(
            setup_frame,
            text="Génère automatiquement les clés et crée les fichiers de configuration"
        ).pack(pady=5)
        
        ttk.Button(
            setup_frame,
            text="Configurer le VPN",
            command=self.setup_vpn
        ).pack(pady=10)
        
        # Frame d'affichage des clés
        display_frame = ttk.LabelFrame(parent, text="Clés Actuelles")
        display_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.keys_text = scrolledtext.ScrolledText(display_frame, height=15, wrap=tk.WORD, state=tk.DISABLED)
        self.keys_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Charger les clés si les configs existent
        self.refresh_keys_display()
    
    def log(self, message, level="INFO"):
        """Ajoute un message aux logs"""
        timestamp = time.strftime("%H:%M:%S")
        log_message = f"[{timestamp}] [{level}] {message}\n"
        self.log_queue.put(log_message)
    
    def process_log_queue(self):
        """Traite la queue des logs"""
        try:
            while True:
                message = self.log_queue.get_nowait()
                self.log_text.config(state=tk.NORMAL)
                self.log_text.insert(tk.END, message)
                self.log_text.see(tk.END)
                self.log_text.config(state=tk.DISABLED)
        except queue.Empty:
            pass
        
        # Planifie le prochain traitement
        self.root.after(100, self.process_log_queue)
    
    def browse_server_config(self):
        """Ouvre un dialogue pour choisir le fichier de config serveur"""
        filename = filedialog.askopenfilename(
            title="Choisir le fichier de configuration serveur",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.server_config_path.set(filename)
    
    def browse_client_config(self):
        """Ouvre un dialogue pour choisir le fichier de config client"""
        filename = filedialog.askopenfilename(
            title="Choisir le fichier de configuration client",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.client_config_path.set(filename)
    
    def start_server(self):
        """Démarre le serveur"""
        config_path = self.server_config_path.get()
        
        if not Path(config_path).exists():
            messagebox.showerror("Erreur", f"Le fichier de configuration n'existe pas: {config_path}")
            return
        
        try:
            from server import VPNServer
            
            # Charge la config d'abord pour obtenir le port en cas d'erreur
            self.server_config = VPNConfig(config_path)
            listen_port = self.server_config.listen_port
            
            self.server_instance = VPNServer(config_path)
            
            # Met à jour l'affichage
            self.update_server_info()
            
            # Démarre le serveur dans un thread séparé
            self.server_running = True
            self.server_thread = threading.Thread(target=self.server_worker, daemon=True)
            self.server_thread.start()
            
            # Met à jour l'interface
            self.server_status_label.config(text="En cours d'exécution", foreground="green")
            self.server_start_btn.config(state=tk.DISABLED)
            self.server_stop_btn.config(state=tk.NORMAL)
            
            self.log("Serveur démarré", "SERVER")
            self.status_bar.config(text="Serveur démarré")
        
        except OSError as e:
            if hasattr(e, 'winerror') and e.winerror == 10048:
                error_msg = (
                    f"Le port {listen_port} est déjà utilisé.\n\n"
                    f"Solution:\n"
                    f"1. Arrêtez le serveur précédent (bouton 'Arrêter le Serveur')\n"
                    f"2. Ou attendez quelques secondes et réessayez\n"
                    f"3. Ou changez le port dans {config_path}"
                )
                messagebox.showerror("Port déjà utilisé", error_msg)
                self.log(f"Erreur serveur: Port déjà utilisé - {e}", "ERROR")
            else:
                messagebox.showerror("Erreur", f"Impossible de démarrer le serveur: {e}")
                self.log(f"Erreur serveur: {e}", "ERROR")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de démarrer le serveur: {e}")
            self.log(f"Erreur serveur: {e}", "ERROR")
    
    def server_worker(self):
        """Worker thread pour le serveur"""
        try:
            self.server_instance.start()
        except Exception as e:
            self.log(f"Erreur dans le serveur: {e}", "ERROR")
        finally:
            self.server_running = False
            self.root.after(0, self.server_stopped)
    
    def server_stopped(self):
        """Callback quand le serveur s'arrête"""
        self.server_status_label.config(text="Arrêté", foreground="red")
        self.server_start_btn.config(state=tk.NORMAL)
        self.server_stop_btn.config(state=tk.DISABLED)
        self.log("Serveur arrêté", "SERVER")
        self.status_bar.config(text="Serveur arrêté")
    
    def stop_server(self):
        """Arrête le serveur"""
        if self.server_instance:
            self.server_instance.stop()
            self.server_running = False
            self.log("Arrêt du serveur demandé", "SERVER")
    
    def update_server_info(self):
        """Met à jour les informations du serveur"""
        if not self.server_config or not self.server_instance:
            return
        
        public_key = self.server_instance.crypto.get_public_key_hex()
        info = f"""Port d'écoute: {self.server_config.listen_port}
IP virtuelle: {self.server_config.virtual_ip}
Clé publique: {public_key[:32]}...
Endpoint pair: {self.server_config.peer_endpoint}
"""
        
        self.server_info_text.config(state=tk.NORMAL)
        self.server_info_text.delete(1.0, tk.END)
        self.server_info_text.insert(1.0, info)
        self.server_info_text.config(state=tk.DISABLED)
    
    def connect_client(self):
        """Connecte le client au serveur"""
        config_path = self.client_config_path.get()
        
        if not Path(config_path).exists():
            messagebox.showerror("Erreur", f"Le fichier de configuration n'existe pas: {config_path}")
            return
        
        try:
            from client import VPNClient
            
            self.client_instance = VPNClient(config_path)
            self.client_config = VPNConfig(config_path)
            
            # Met à jour l'affichage
            self.update_client_info()
            
            # Connecte dans un thread séparé
            self.client_thread = threading.Thread(target=self.client_connect_worker, daemon=True)
            self.client_thread.start()
            
            self.log("Tentative de connexion au serveur...", "CLIENT")
        
        except OSError as e:
            if hasattr(e, 'winerror') and e.winerror == 10048:
                error_msg = (
                    f"Le port est déjà utilisé.\n\n"
                    f"Solution:\n"
                    f"1. Fermez l'instance précédente du client\n"
                    f"2. Ou attendez quelques secondes et réessayez\n"
                    f"3. Ou changez le port dans {config_path}"
                )
                messagebox.showerror("Port déjà utilisé", error_msg)
                self.log(f"Erreur client: Port déjà utilisé - {e}", "ERROR")
            else:
                messagebox.showerror("Erreur", f"Impossible de créer le client: {e}")
                self.log(f"Erreur client: {e}", "ERROR")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de créer le client: {e}")
            self.log(f"Erreur client: {e}", "ERROR")
    
    def client_connect_worker(self):
        """Worker thread pour la connexion client"""
        try:
            if self.client_instance.connect():
                self.client_connected = True
                self.root.after(0, self.client_connected_callback)
                
                # Démarre l'écoute
                self.client_listen_thread = threading.Thread(target=self.client_listen_worker, daemon=True)
                self.client_listen_thread.start()
            else:
                self.root.after(0, self.client_connection_failed)
        except Exception as e:
            self.log(f"Erreur de connexion: {e}", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Erreur", f"Erreur de connexion: {e}"))
    
    def client_connected_callback(self):
        """Callback quand le client est connecté"""
        self.client_status_label.config(text="Connecté", foreground="green")
        self.client_connect_btn.config(state=tk.DISABLED)
        self.client_disconnect_btn.config(state=tk.NORMAL)
        self.log("Client connecté au serveur", "CLIENT")
        self.status_bar.config(text="Client connecté")
    
    def client_connection_failed(self):
        """Callback quand la connexion échoue"""
        messagebox.showerror("Erreur", "Impossible de se connecter au serveur")
        self.log("Échec de la connexion", "CLIENT")
    
    def client_listen_worker(self):
        """Worker thread pour écouter les données du serveur"""
        while self.client_connected:
            try:
                if not self.client_instance:
                    break
                
                self.client_instance.sock.settimeout(1.0)
                data, addr = self.client_instance.sock.recvfrom(4096)
                
                if addr != self.client_instance.server_address:
                    continue
                
                packet = VPNPacket.deserialize(data)
                
                if packet.packet_type == PacketType.DATA:
                    session_key = self.client_instance.handshake.get_session_key(
                        self.client_instance.server_public_key_bytes
                    )
                    if session_key:
                        packet_type, plaintext = self.client_instance.packet_manager.process_packet(packet, session_key)
                        try:
                            message = plaintext.decode('utf-8', errors='ignore')
                            self.log(f"Données reçues: {message}", "CLIENT")
                        except:
                            self.log(f"Données reçues ({len(plaintext)} bytes)", "CLIENT")
                
            except socket.timeout:
                continue
            except Exception as e:
                if self.client_connected:
                    self.log(f"Erreur lors de l'écoute: {e}", "ERROR")
    
    def disconnect_client(self):
        """Déconnecte le client"""
        self.client_connected = False
        if self.client_instance:
            self.client_instance.close()
        
        self.client_status_label.config(text="Déconnecté", foreground="red")
        self.client_connect_btn.config(state=tk.NORMAL)
        self.client_disconnect_btn.config(state=tk.DISABLED)
        self.log("Client déconnecté", "CLIENT")
        self.status_bar.config(text="Client déconnecté")
    
    def send_message(self):
        """Envoie un message au serveur"""
        if not self.client_connected or not self.client_instance:
            messagebox.showwarning("Attention", "Le client n'est pas connecté")
            return
        
        message = self.message_entry.get()
        if not message:
            return
        
        try:
            if self.client_instance.send_data(message.encode()):
                self.log(f"Message envoyé: {message}", "CLIENT")
                self.message_entry.delete(0, tk.END)
            else:
                messagebox.showerror("Erreur", "Impossible d'envoyer le message")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'envoi: {e}")
            self.log(f"Erreur d'envoi: {e}", "ERROR")
    
    def update_client_info(self):
        """Met à jour les informations du client"""
        if not self.client_config or not self.client_instance:
            return
        
        public_key = self.client_instance.crypto.get_public_key_hex()
        info = f"""Port local: {self.client_config.listen_port}
IP virtuelle: {self.client_config.virtual_ip}
Clé publique: {public_key[:32]}...
Serveur: {self.client_config.peer_endpoint}
"""
        
        self.client_info_text.config(state=tk.NORMAL)
        self.client_info_text.delete(1.0, tk.END)
        self.client_info_text.insert(1.0, info)
        self.client_info_text.config(state=tk.DISABLED)
    
    def generate_keys(self):
        """Génère de nouvelles clés"""
        try:
            crypto = CryptoManager()
            private_key = crypto.get_private_key_hex()
            public_key = crypto.get_public_key_hex()
            
            keys_info = f"""Clé privée:
{private_key}

Clé publique:
{public_key}
"""
            
            # Affiche dans une nouvelle fenêtre
            key_window = tk.Toplevel(self.root)
            key_window.title("Nouvelles Clés Générées")
            key_window.geometry("600x200")
            
            text_widget = scrolledtext.ScrolledText(key_window, wrap=tk.WORD)
            text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            text_widget.insert(1.0, keys_info)
            text_widget.config(state=tk.DISABLED)
            
            self.log("Nouvelles clés générées", "CONFIG")
            self.refresh_keys_display()
        
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la génération: {e}")
    
    def setup_vpn(self):
        """Configure automatiquement le VPN"""
        try:
            import subprocess
            result = subprocess.run(
                [sys.executable, "setup_vpn.py"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                messagebox.showinfo("Succès", "Configuration terminée avec succès!")
                self.log("Configuration VPN créée", "CONFIG")
                self.refresh_keys_display()
                
                # Met à jour les chemins de config
                self.server_config_path.set("server_config.json")
                self.client_config_path.set("client_config.json")
            else:
                messagebox.showerror("Erreur", f"Erreur lors de la configuration:\n{result.stderr}")
        
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la configuration: {e}")
    
    def refresh_keys_display(self):
        """Rafraîchit l'affichage des clés"""
        keys_info = ""
        
        # Essaie de charger les clés depuis les fichiers de config
        for config_file in ["server_config.json", "client_config.json"]:
            if Path(config_file).exists():
                try:
                    config = VPNConfig(config_file)
                    # Dérive la clé publique depuis la clé privée
                    crypto = CryptoManager(config.private_key)
                    public_key = crypto.get_public_key_hex()
                    keys_info += f"\n{config_file}:\n"
                    keys_info += f"  Clé privée: {config.private_key[:32]}...\n"
                    keys_info += f"  Clé publique: {public_key[:32]}...\n"
                except Exception as e:
                    keys_info += f"\n{config_file}: Erreur ({e})\n"
        
        if not keys_info:
            keys_info = "Aucune configuration trouvée. Utilisez 'Configurer le VPN' pour créer les fichiers."
        
        self.keys_text.config(state=tk.NORMAL)
        self.keys_text.delete(1.0, tk.END)
        self.keys_text.insert(1.0, keys_info)
        self.keys_text.config(state=tk.DISABLED)


def main():
    """Point d'entrée principal"""
    root = tk.Tk()
    app = VPNGUI(root)
    
    # Gère la fermeture propre
    def on_closing():
        if app.server_running:
            app.stop_server()
        if app.client_connected:
            app.disconnect_client()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()

