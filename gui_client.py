#!/usr/bin/env python3
"""
Interface graphique client pour le mini-VPN
Design moderne avec support dark mode
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog, Toplevel
import threading
import queue
import sys
import base64
import io
from PIL import Image, ImageTk
from pathlib import Path
from config import VPNConfig
from client import VPNClient
from packet import PacketType, VPNPacket
import socket
import time
from theme import ThemeManager, DARK_THEME, LIGHT_THEME
from resource_manager import ResourceManager


class VPNClientGUI:
    """Interface graphique client avec thème moderne"""
    
    def __init__(self, root):
        self.root = root
        self.setup_window()
        
        # Gestionnaire de thème
        self.theme_manager = ThemeManager()
        self.current_theme = DARK_THEME
        
        # Variables d'état
        self.client_connected = False
        self.client_thread = None
        self.client_listen_thread = None
        self.log_queue = queue.Queue()
        
        # Composants VPN
        self.client_instance = None
        self.client_config = None
        
        # Stockage pour les transferts par morceaux {resource_id: {meta, chunks, received_count}}
        self.incoming_transfers = {}
        
        # Gestionnaire de ressources
        self.resource_manager = ResourceManager()
        
        # Applique le thème
        self.apply_theme()
        
        # Créer l'interface
        self.create_widgets()
        
        # Démarrer le traitement des logs
        self.process_log_queue()
    
    def setup_window(self):
        """Configure la fenêtre principale"""
        self.root.title("Mini-VPN Client")
        self.root.geometry("900x700")
        self.root.minsize(700, 600)
    
    def apply_theme(self):
        """Applique le thème actuel à la fenêtre"""
        theme = self.current_theme
        self.root.config(bg=theme.get("bg_primary"))
        
        # Style pour ttk
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure les styles ttk
        style.configure('TFrame', background=theme.get("bg_primary"))
        style.configure('TLabel', background=theme.get("bg_primary"), foreground=theme.get("fg_primary"))
        style.configure('TLabelFrame', background=theme.get("bg_secondary"), foreground=theme.get("fg_primary"))
        style.configure('TLabelFrame.Label', background=theme.get("bg_secondary"), foreground=theme.get("fg_primary"))
        style.configure('TButton', padding=10)
        style.map('TButton',
                  background=[('active', theme.get("button_hover"))])
    
    def create_widgets(self):
        """Crée les widgets de l'interface"""
        theme = self.current_theme
        
        # Barre de menu
        self.create_menu_bar()
        
        # Frame principal
        main_frame = tk.Frame(self.root, bg=theme.get("bg_primary"))
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Header avec titre et statut
        header_frame = tk.Frame(main_frame, bg=theme.get("bg_secondary"), relief=tk.FLAT)
        header_frame.pack(fill=tk.X, pady=(0, 15), padx=5)
        
        title_label = tk.Label(
            header_frame,
            text="Client VPN",
            font=("Segoe UI", 16, "bold"),
            bg=theme.get("bg_secondary"),
            fg=theme.get("fg_primary")
        )
        title_label.pack(side=tk.LEFT, padx=15, pady=10)
        
        self.status_indicator = tk.Label(
            header_frame,
            text="● Déconnecté",
            font=("Segoe UI", 11),
            bg=theme.get("bg_secondary"),
            fg=theme.get("error")
        )
        self.status_indicator.pack(side=tk.RIGHT, padx=15, pady=10)
        
        # Frame de configuration
        self.create_config_section(main_frame)
        
        # Frame de contrôle
        self.create_control_section(main_frame)
        
        # Frame d'informations
        self.create_info_section(main_frame)
        
        # Frame de ressources partagées
        self.create_resources_section(main_frame)
        
        # Zone de logs
        self.create_log_section(main_frame)
        
        # Barre de statut
        self.status_bar = tk.Label(
            self.root,
            text="Prêt",
            font=("Segoe UI", 9),
            bg=theme.get("bg_secondary"),
            fg=theme.get("fg_secondary"),
            anchor=tk.W,
            relief=tk.SUNKEN
        )
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
    
    def create_menu_bar(self):
        """Crée la barre de menu"""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # Menu Vue
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Vue", menu=view_menu)
        view_menu.add_command(label="Mode Sombre", command=self.toggle_theme)
        view_menu.add_command(label="Mode Clair", command=lambda: self.set_theme("light"))
        
        # Menu Aide
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Aide", menu=help_menu)
        help_menu.add_command(label="À propos", command=self.show_about)
    
    def create_config_section(self, parent):
        """Crée la section de configuration"""
        theme = self.current_theme
        
        config_frame = tk.LabelFrame(
            parent,
            text="Configuration",
            font=("Segoe UI", 10, "bold"),
            bg=theme.get("bg_secondary"),
            fg=theme.get("fg_primary"),
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        config_frame.pack(fill=tk.X, pady=(0, 10), padx=5)
        
        inner_frame = tk.Frame(config_frame, bg=theme.get("bg_secondary"))
        inner_frame.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(
            inner_frame,
            text="Fichier de configuration:",
            font=("Segoe UI", 10),
            bg=theme.get("bg_secondary"),
            fg=theme.get("fg_primary")
        ).pack(side=tk.LEFT, padx=(0, 10))
        
        self.config_path_var = tk.StringVar(value="client_config.json")
        config_entry = tk.Entry(
            inner_frame,
            textvariable=self.config_path_var,
            font=("Segoe UI", 10),
            bg=theme.get("input_bg"),
            fg=theme.get("input_fg"),
            insertbackground=theme.get("input_fg"),
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightcolor=theme.get("input_focus"),
            highlightbackground=theme.get("input_border"),
            width=40
        )
        config_entry.pack(side=tk.LEFT, padx=(0, 10), fill=tk.X, expand=True)
        
        browse_btn = tk.Button(
            inner_frame,
            text="Parcourir",
            font=("Segoe UI", 9),
            bg=theme.get("bg_tertiary"),
            fg=theme.get("fg_primary"),
            activebackground=theme.get("border_dark"),
            relief=tk.FLAT,
            cursor="hand2",
            command=self.browse_config,
            padx=15,
            pady=5
        )
        browse_btn.pack(side=tk.LEFT)
    
    def create_control_section(self, parent):
        """Crée la section de contrôle"""
        theme = self.current_theme
        
        control_frame = tk.Frame(parent, bg=theme.get("bg_primary"))
        control_frame.pack(fill=tk.X, pady=(0, 10), padx=5)
        
        self.connect_btn = tk.Button(
            control_frame,
            text="Se Connecter",
            font=("Segoe UI", 11, "bold"),
            bg=theme.get("success"),
            fg="white",
            activebackground="#45a049",
            relief=tk.FLAT,
            cursor="hand2",
            command=self.connect_client,
            padx=20,
            pady=12
        )
        self.connect_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.disconnect_btn = tk.Button(
            control_frame,
            text="Se Déconnecter",
            font=("Segoe UI", 11, "bold"),
            bg=theme.get("error"),
            fg="white",
            activebackground="#d32f2f",
            relief=tk.FLAT,
            cursor="hand2",
            command=self.disconnect_client,
            state=tk.DISABLED,
            padx=20,
            pady=12
        )
        self.disconnect_btn.pack(side=tk.LEFT)
    
    def create_resources_section(self, parent):
        """Crée la section de ressources partagées"""
        theme = self.current_theme
        
        resources_frame = tk.LabelFrame(
            parent,
            text="Ressources Partagées",
            font=("Segoe UI", 10, "bold"),
            bg=theme.get("bg_secondary"),
            fg=theme.get("fg_primary"),
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        resources_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), padx=5)
        
        # Frame pour la liste des ressources
        list_frame = tk.Frame(resources_frame, bg=theme.get("bg_secondary"))
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Liste des ressources
        self.resources_listbox = tk.Listbox(
            list_frame,
            font=("Segoe UI", 10),
            bg=theme.get("bg_tertiary"),
            fg=theme.get("fg_primary"),
            selectbackground=theme.get("accent"),
            selectforeground="white",
            relief=tk.FLAT,
            borderwidth=0
        )
        self.resources_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        scrollbar = tk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.resources_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.resources_listbox.config(yscrollcommand=scrollbar.set)
        
        # Frame pour les boutons
        buttons_frame = tk.Frame(resources_frame, bg=theme.get("bg_secondary"))
        buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        view_btn = tk.Button(
            buttons_frame,
            text="Consulter",
            font=("Segoe UI", 9, "bold"),
            bg=theme.get("accent"),
            fg="white",
            activebackground=theme.get("accent_hover"),
            relief=tk.FLAT,
            cursor="hand2",
            command=self.view_resource,
            padx=15,
            pady=8
        )
        view_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        refresh_btn = tk.Button(
            buttons_frame,
            text="Actualiser",
            font=("Segoe UI", 9),
            bg=theme.get("bg_tertiary"),
            fg=theme.get("fg_primary"),
            activebackground=theme.get("border_dark"),
            relief=tk.FLAT,
            cursor="hand2",
            command=self.refresh_resources,
            padx=15,
            pady=8
        )
        refresh_btn.pack(side=tk.LEFT)
        
        # Variable pour stocker les ressources
        self.resources = []
    
    def create_info_section(self, parent):
        """Crée la section d'informations"""
        theme = self.current_theme
        
        info_frame = tk.LabelFrame(
            parent,
            text="Informations de Connexion",
            font=("Segoe UI", 10, "bold"),
            bg=theme.get("bg_secondary"),
            fg=theme.get("fg_primary"),
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        info_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), padx=5)
        
        self.info_text = scrolledtext.ScrolledText(
            info_frame,
            height=6,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=theme.get("bg_tertiary"),
            fg=theme.get("fg_primary"),
            insertbackground=theme.get("fg_primary"),
            relief=tk.FLAT,
            borderwidth=0,
            state=tk.DISABLED
        )
        self.info_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def create_log_section(self, parent):
        """Crée la section de logs"""
        theme = self.current_theme
        
        log_frame = tk.LabelFrame(
            parent,
            text="Journal des Événements",
            font=("Segoe UI", 10, "bold"),
            bg=theme.get("bg_secondary"),
            fg=theme.get("fg_primary"),
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        log_frame.pack(fill=tk.BOTH, expand=True, padx=5)
        
        self.log_text = scrolledtext.ScrolledText(
            log_frame,
            height=10,
            wrap=tk.WORD,
            font=("Consolas", 9),
            bg=theme.get("bg_tertiary"),
            fg=theme.get("fg_primary"),
            insertbackground=theme.get("fg_primary"),
            relief=tk.FLAT,
            borderwidth=0,
            state=tk.DISABLED
        )
        self.log_text.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
    
    def browse_config(self):
        """Ouvre un dialogue pour choisir le fichier de config"""
        filename = filedialog.askopenfilename(
            title="Choisir le fichier de configuration client",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.config_path_var.set(filename)
    
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
        
        self.root.after(100, self.process_log_queue)
    
    def connect_client(self):
        """Connecte le client au serveur"""
        config_path = self.config_path_var.get()
        
        if not Path(config_path).exists():
            messagebox.showerror("Erreur", f"Le fichier de configuration n'existe pas: {config_path}")
            return
        
        # Vérifie que c'est bien un fichier de configuration client
        try:
            test_config = VPNConfig(config_path)
            # Vérifie que le port n'est pas celui du serveur (51820)
            if test_config.listen_port == 51820:
                error_msg = (
                    f"⚠️ Attention: Le port 51820 est réservé au serveur.\n\n"
                    f"Le fichier sélectionné semble être une configuration serveur.\n"
                    f"Veuillez sélectionner le fichier 'client_config.json'"
                )
                messagebox.showerror("Mauvais fichier de configuration", error_msg)
                self.log("Erreur: Tentative d'utiliser la configuration serveur", "ERROR")
                return
        except Exception as e:
            messagebox.showerror("Erreur", f"Fichier de configuration invalide: {e}")
            self.log(f"Erreur de configuration: {e}", "ERROR")
            return
        
        try:
            self.client_instance = VPNClient(config_path)
            self.client_config = VPNConfig(config_path)
            
            self.update_client_info()
            
            self.client_thread = threading.Thread(target=self.client_connect_worker, daemon=True)
            self.client_thread.start()
            
            self.log("Tentative de connexion au serveur...", "CLIENT")
        
        except OSError as e:
            error_code = getattr(e, 'winerror', None)
            if error_code == 10048:
                error_msg = (
                    f"Le port est déjà utilisé.\n\n"
                    f"Solution:\n"
                    f"1. Fermez l'instance précédente du client\n"
                    f"2. Ou attendez quelques secondes et réessayez"
                )
                messagebox.showerror("Port déjà utilisé", error_msg)
                self.log(f"Erreur client: Port déjà utilisé - {e}", "ERROR")
            elif error_code == 10013:
                error_msg = (
                    f"Erreur de permissions sur le port.\n\n"
                    f"Le port {self.client_config.listen_port if self.client_config else 'N/A'} nécessite des privilèges administrateur ou est bloqué.\n\n"
                    f"Solutions:\n"
                    f"1. Vérifiez que le port n'est pas utilisé par un autre programme\n"
                    f"2. Changez le port dans le fichier de configuration\n"
                    f"3. Exécutez en tant qu'administrateur si nécessaire"
                )
                messagebox.showerror("Erreur de permissions", error_msg)
                self.log(f"Erreur client: Permissions refusées - {e}", "ERROR")
            else:
                messagebox.showerror("Erreur réseau", f"Impossible de créer le client: {e}")
                self.log(f"Erreur client: {e}", "ERROR")
        except ValueError as e:
            if "private_key" in str(e).lower() or "required field" in str(e).lower():
                error_msg = (
                    f"Configuration incomplète.\n\n"
                    f"Le fichier de configuration est invalide ou incomplet.\n\n"
                    f"Solution:\n"
                    f"1. Vérifiez que le fichier contient toutes les clés nécessaires\n"
                    f"2. Régénérez la configuration avec: python setup_vpn.py"
                )
                messagebox.showerror("Configuration invalide", error_msg)
                self.log(f"Erreur de configuration: {e}", "ERROR")
            else:
                messagebox.showerror("Erreur", f"Erreur de configuration: {e}")
                self.log(f"Erreur: {e}", "ERROR")
        except Exception as e:
            messagebox.showerror("Erreur", f"Impossible de créer le client: {e}")
            self.log(f"Erreur client: {e}", "ERROR")
    
    def client_connect_worker(self):
        """Worker thread pour la connexion client"""
        try:
            success, message = self.client_instance.connect()
            if success:
                self.client_connected = True
                self.root.after(0, self.client_connected_callback)
                
                # Démarre l'écoute
                self.client_listen_thread = threading.Thread(target=self.client_listen_worker, daemon=True)
                self.client_listen_thread.start()
            else:
                self.root.after(0, lambda: self.client_connection_failed(message))
        except Exception as e:
            self.log(f"Erreur de connexion: {e}", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Erreur", f"Erreur de connexion: {e}"))
        except Exception as e:
            self.log(f"Erreur de connexion: {e}", "ERROR")
            self.root.after(0, lambda: messagebox.showerror("Erreur", f"Erreur de connexion: {e}"))
    
    def client_connected_callback(self):
        """Callback quand le client est connecté"""
        self.status_indicator.config(text="● Connecté", fg=self.current_theme.get("success"))
        self.connect_btn.config(state=tk.DISABLED)
        self.disconnect_btn.config(state=tk.NORMAL)
        self.log("Client connecté au serveur", "CLIENT")
        self.status_bar.config(text="Connecté au serveur")
    
    def client_connection_failed(self, error_msg="Impossible de se connecter au serveur"):
        """Callback quand la connexion échoue"""
        messagebox.showerror("Erreur", error_msg)
        self.log(f"Échec de la connexion: {error_msg}", "CLIENT")
    def client_listen_worker(self):
        """Worker thread pour écouter les données du serveur"""
        while self.client_connected:
            try:
                if not self.client_instance:
                    break
                
                try:
                    data, addr = self.client_instance.sock.recvfrom(65535)
                except socket.timeout:
                    continue
                except OSError:
                    break
                
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
                            # Essaie de parser comme JSON (réponse du serveur)
                            import json
                            response = json.loads(plaintext.decode('utf-8'))
                            if response.get('type') == 'resources_list':
                                # Met à jour la liste des ressources
                                self.root.after(0, lambda: self.update_resources_list(response.get('resources', [])))
                                self.log(f"Liste des ressources reçue: {len(response.get('resources', []))} ressource(s)", "CLIENT")
                            
                            elif response.get('type') == 'resource_content':
                                # Affiche le contenu de la ressource (mode simple)
                                self.log(f"Ressource reçue: {response.get('filename')}", "CLIENT")
                                self.root.after(0, lambda: self.show_resource_content(response))
                            
                            elif response.get('type') == 'resource_transfer_init':
                                # Initialisation d'un transfert par morceaux
                                rid = response.get('resource_id')
                                total_chunks = response.get('total_chunks')
                                self.incoming_transfers[rid] = {
                                    'meta': response,
                                    'chunks': [None] * total_chunks,
                                    'received_count': 0
                                }
                                self.log(f"Début réception: {response.get('filename')} ({total_chunks} paquets)", "CLIENT")
                            
                            elif response.get('type') == 'resource_chunk':
                                # Réception d'un morceau
                                rid = response.get('resource_id')
                                if rid in self.incoming_transfers:
                                    idx = response.get('chunk_index')
                                    data = response.get('content')
                                    transfer = self.incoming_transfers[rid]
                                    
                                    if idx < len(transfer['chunks']) and transfer['chunks'][idx] is None:
                                        transfer['chunks'][idx] = data
                                        transfer['received_count'] += 1
                                    
                                    if transfer['received_count'] >= transfer['meta']['total_chunks']:
                                        # Tout reçu, assemblage
                                        full_b64 = "".join(transfer['chunks'])
                                        fake_resp = transfer['meta'].copy()
                                        fake_resp['content'] = full_b64
                                        del self.incoming_transfers[rid]
                                        self.log(f"Réception complète: {fake_resp.get('filename')}", "CLIENT")
                                        self.root.after(0, lambda: self.show_resource_content(fake_resp))
                                
                            elif response.get('type') == 'resource_error':
                                # Erreur lors de la récupération
                                self.log(f"Erreur ressource: {response.get('error')}", "ERROR")
                                self.root.after(0, lambda: messagebox.showerror("Erreur", f"Impossible de récupérer la ressource: {response.get('error')}"))
                                
                            else:
                                message = plaintext.decode('utf-8', errors='ignore')
                                self.log(f"Message reçu: {message}", "CLIENT")
                        except json.JSONDecodeError:
                            # Ce n'est pas du JSON, affiche comme texte
                            try:
                                message = plaintext.decode('utf-8', errors='ignore')
                                self.log(f"Message reçu: {message}", "CLIENT")
                            except:
                                self.log(f"Données reçues ({len(plaintext)} bytes)", "CLIENT")
                        except Exception as e:
                            self.log(f"Erreur traitement données: {e}", "ERROR")
                
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
        
        self.status_indicator.config(text="● Déconnecté", fg=self.current_theme.get("error"))
        self.connect_btn.config(state=tk.NORMAL)
        self.disconnect_btn.config(state=tk.DISABLED)
        self.log("Client déconnecté", "CLIENT")
        self.status_bar.config(text="Déconnecté")
    
    def refresh_resources(self):
        """Actualise la liste des ressources"""
        if not self.client_connected or not self.client_instance:
            messagebox.showwarning("Attention", "Vous devez être connecté pour voir les ressources")
            return
        
        try:
            import json
            # Envoie une requête pour obtenir la liste des ressources
            request = json.dumps({'type': 'get_resources'}).encode('utf-8')
            if self.client_instance.send_data(request):
                self.log("Demande de liste des ressources envoyée", "CLIENT")
                # La réponse sera traitée dans client_listen_worker
            else:
                messagebox.showerror("Erreur", "Impossible d'envoyer la requête")
        except Exception as e:
            self.log(f"Erreur lors de l'actualisation: {e}", "ERROR")
            messagebox.showerror("Erreur", f"Erreur: {e}")
    
    def update_resources_list(self, resources):
        """Met à jour la liste des ressources dans l'interface"""
        self.resources_listbox.delete(0, tk.END)
        self.resources = resources
        
        for resource in resources:
            display_text = f"{resource.get('original_name', 'Unknown')} ({resource.get('type', 'unknown')})"
            self.resources_listbox.insert(tk.END, display_text)
    
    def view_resource(self):
        """Consulte une ressource sélectionnée"""
        # Anti-rebond (Debounce) pour éviter les double-clics
        import time
        current_time = time.time()
        if hasattr(self, '_last_view_click') and current_time - self._last_view_click < 1.0:
            return
        self._last_view_click = current_time

        selection = self.resources_listbox.curselection()
        if not selection:
            messagebox.showwarning("Attention", "Veuillez sélectionner une ressource")
            return
        
        if not self.client_connected:
            messagebox.showwarning("Attention", "Vous devez être connecté pour consulter les ressources")
            return
        
        try:
            resource = self.resources[selection[0]]
            resource_id = resource.get('id')
            
            # Envoie la demande au serveur
            import json
            request = json.dumps({
                'type': 'get_resource',
                'resource_id': resource_id
            }).encode('utf-8')
            
            if self.client_instance.send_data(request):
                self.log(f"Demande de la ressource {resource_id} envoyée", "CLIENT")
            else:
                messagebox.showerror("Erreur", "Impossible d'envoyer la requête")
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de la consultation: {e}")
            self.log(f"Erreur: {e}", "ERROR")

    def show_resource_content(self, resource_data):
        """Affiche le contenu d'une ressource"""
        # Anti-doublon: vérifie si on a déjà ouvert cette ressource récemment
        rid = resource_data.get('resource_id')
        import time
        now = time.time()
        last_rid, last_time = getattr(self, '_last_opened_resource', (None, 0))
        
        if rid and rid == last_rid and now - last_time < 2.0:
            self.log(f"Ouverture dupliquée ignorée pour {rid}", "CLIENT")
            return
        
        self._last_opened_resource = (rid, now)

        filename = resource_data.get('filename', 'Inconnu')
        file_type = resource_data.get('file_type', 'unknown')
        content_b64 = resource_data.get('content', '')
        
        try:
            content = base64.b64decode(content_b64)
            
            # Fenêtre de visualisation
            viewer = Toplevel(self.root)
            viewer.title(f"Visualisation - {filename}")
            viewer.geometry("800x600")
            
            theme = self.current_theme
            viewer.config(bg=theme.get("bg_primary"))
            
            # Header
            header = tk.Frame(viewer, bg=theme.get("bg_secondary"))
            header.pack(fill=tk.X, padx=10, pady=10)
            
            tk.Label(
                header, 
                text=f"Ressource: {filename}", 
                font=("Segoe UI", 12, "bold"),
                bg=theme.get("bg_secondary"),
                fg=theme.get("fg_primary")
            ).pack(side=tk.LEFT)
            
            # Content
            content_frame = tk.Frame(viewer, bg=theme.get("bg_primary"))
            content_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            if file_type == 'text':
                text_area = scrolledtext.ScrolledText(
                    content_frame,
                    wrap=tk.WORD,
                    font=("Consolas", 10),
                    bg=theme.get("bg_tertiary"),
                    fg=theme.get("fg_primary")
                )
                text_area.pack(fill=tk.BOTH, expand=True)
                try:
                    text_content = content.decode('utf-8')
                    text_area.insert(1.0, text_content)
                except:
                    text_area.insert(1.0, f"Encodage non supporté. Taille: {len(content)} bytes")
                text_area.config(state=tk.DISABLED)
                
            elif file_type == 'image':
                try:
                    image_data = io.BytesIO(content)
                    image = Image.open(image_data)
                    
                    # Redimensionne si nécessaire
                    display_size = (750, 500)
                    image.thumbnail(display_size, Image.Resampling.LANCZOS)
                    
                    photo = ImageTk.PhotoImage(image)
                    
                    label = tk.Label(
                        content_frame, 
                        image=photo,
                        bg=theme.get("bg_primary")
                    )
                    label.image = photo  # Garde une référence
                    label.pack(expand=True)
                except Exception as e:
                    tk.Label(
                        content_frame, 
                        text=f"Erreur d'affichage de l'image: {e}",
                        bg=theme.get("bg_primary"),
                        fg=theme.get("error")
                    ).pack()
            elif file_type == 'pdf' or filename.lower().endswith('.pdf'):
                try:
                    import tempfile
                    import os
                    import webbrowser
                    
                    # Crée un fichier temporaire
                    fd, path = tempfile.mkstemp(suffix='.pdf')
                    try:
                        with os.fdopen(fd, 'wb') as tmp:
                            tmp.write(content)
                        
                        # Ouvre avec le lecteur par défaut
                        webbrowser.open(path)
                        
                        tk.Label(
                            content_frame, 
                            text=f"Le document PDF a été ouvert dans votre lecteur par défaut.\n\nFichier temporaire: {path}",
                            font=("Segoe UI", 11),
                            bg=theme.get("bg_primary"),
                            fg=theme.get("success"),
                            justify=tk.CENTER
                        ).pack(expand=True)
                        
                    except Exception as e:
                        tk.Label(
                            content_frame, 
                            text=f"Erreur lors de l'ouverture du PDF: {e}",
                            bg=theme.get("bg_primary"),
                            fg=theme.get("error")
                        ).pack(expand=True)
                        
                except Exception as e:
                    tk.Label(
                        content_frame, 
                        text=f"Erreur système PDF: {e}",
                        bg=theme.get("bg_primary"),
                        fg=theme.get("error")
                    ).pack(expand=True)

            else:
                tk.Label(
                    content_frame, 
                    text=f"Type de fichier non supporté pour la visualisation directe: {file_type}\nTaille: {len(content)} bytes",
                    bg=theme.get("bg_primary"),
                    fg=theme.get("fg_primary")
                ).pack(expand=True)
                
        except Exception as e:
            messagebox.showerror("Erreur", f"Erreur lors de l'affichage: {e}")
    
    def update_client_info(self):
        """Met à jour les informations du client"""
        if not self.client_config or not self.client_instance:
            return
        
        public_key = self.client_instance.crypto.get_public_key_hex()
        assigned_ip = getattr(self.client_instance, 'assigned_ip', None) or "En attente..."
        
        info = f"""Port local: {self.client_config.listen_port}
IP virtuelle configurée: {self.client_config.virtual_ip}
IP attribuée: {assigned_ip}
Clé publique: {public_key[:32]}...
Serveur: {self.client_config.peer_endpoint}
"""
        
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(1.0, info)
        self.info_text.config(state=tk.DISABLED)
        
        # Actualise automatiquement les ressources après connexion
        if self.client_connected:
            self.root.after(500, self.refresh_resources)  # Attend 500ms puis actualise
    
    def toggle_theme(self):
        """Bascule entre dark et light mode"""
        if self.current_theme.name == "Dark":
            self.set_theme("light")
        else:
            self.set_theme("dark")
    
    def set_theme(self, theme_name):
        """Change le thème"""
        if theme_name == "dark":
            self.current_theme = DARK_THEME
        else:
            self.current_theme = LIGHT_THEME
        
        self.apply_theme()
        self.recreate_widgets()
    
    def recreate_widgets(self):
        """Recrée les widgets avec le nouveau thème"""
        # Supprime tous les widgets sauf la barre de menu
        for widget in self.root.winfo_children():
            if not isinstance(widget, tk.Menu):
                widget.destroy()
        
        # Recrée l'interface
        self.create_widgets()
        
        # Met à jour les informations si le client est connecté
        if self.client_connected:
            self.update_client_info()
    
    def show_about(self):
        """Affiche la boîte de dialogue À propos"""
        messagebox.showinfo(
            "À propos",
            "Mini-VPN Client\n\n"
            "Client VPN user-space inspiré de WireGuard\n"
            "Version 1.0\n\n"
            "Développé en Python"
        )


def main():
    """Point d'entrée principal"""
    root = tk.Tk()
    app = VPNClientGUI(root)
    
    def on_closing():
        if app.client_connected:
            app.disconnect_client()
        root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()


if __name__ == "__main__":
    main()

