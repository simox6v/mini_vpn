#!/usr/bin/env python3
"""
Interface graphique serveur pour le mini-VPN
Avec authentification par username/password
"""
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import sys
from pathlib import Path
from config import VPNConfig
from server import VPNServer
from auth import AuthManager, create_default_admin
from theme import ThemeManager, DARK_THEME, LIGHT_THEME

from resource_manager import ResourceManager


class LoginWindow:
    """Fenêtre d'authentification"""
    
    def __init__(self, root, auth_manager, on_success):
        self.root = root
        self.auth_manager = auth_manager
        self.on_success = on_success
        self.authenticated = False
        
        self.setup_window()
        self.create_widgets()
        
        # Centre la fenêtre
        self.center_window()
    
    def setup_window(self):
        """Configure la fenêtre de login"""
        self.root.title("Mini-VPN Server - Authentification")
        self.root.geometry("450x380")
        self.root.resizable(False, False)
        
        # Applique le thème sombre par défaut
        theme = DARK_THEME
        self.root.config(bg=theme.get("bg_primary"))
    
    def center_window(self):
        """Centre la fenêtre sur l'écran"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def create_widgets(self):
        """Crée les widgets de l'interface de login"""
        theme = DARK_THEME
        
        # Frame principal
        main_frame = tk.Frame(self.root, bg=theme.get("bg_primary"))
        main_frame.pack(fill=tk.BOTH, expand=True, padx=40, pady=40)
        
        # Titre
        title_label = tk.Label(
            main_frame,
            text="Authentification Serveur",
            font=("Segoe UI", 18, "bold"),
            bg=theme.get("bg_primary"),
            fg=theme.get("fg_primary")
        )
        title_label.pack(pady=(0, 30))
        
        # Frame pour les champs
        fields_frame = tk.Frame(main_frame, bg=theme.get("bg_primary"))
        fields_frame.pack(fill=tk.BOTH, expand=True)
        
        # Username
        username_label = tk.Label(
            fields_frame,
            text="Nom d'utilisateur:",
            font=("Segoe UI", 10),
            bg=theme.get("bg_primary"),
            fg=theme.get("fg_primary")
        )
        username_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.username_entry = tk.Entry(
            fields_frame,
            font=("Segoe UI", 11),
            bg=theme.get("input_bg"),
            fg=theme.get("input_fg"),
            insertbackground=theme.get("input_fg"),
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightcolor=theme.get("input_focus"),
            highlightbackground=theme.get("input_border"),
            width=35
        )
        self.username_entry.pack(fill=tk.X, pady=(0, 20), ipady=10)
        self.username_entry.focus()
        
        # Password
        password_label = tk.Label(
            fields_frame,
            text="Mot de passe:",
            font=("Segoe UI", 10),
            bg=theme.get("bg_primary"),
            fg=theme.get("fg_primary")
        )
        password_label.pack(anchor=tk.W, pady=(0, 5))
        
        self.password_entry = tk.Entry(
            fields_frame,
            font=("Segoe UI", 11),
            bg=theme.get("input_bg"),
            fg=theme.get("input_fg"),
            insertbackground=theme.get("input_fg"),
            show="●",
            relief=tk.FLAT,
            borderwidth=1,
            highlightthickness=1,
            highlightcolor=theme.get("input_focus"),
            highlightbackground=theme.get("input_border"),
            width=35
        )
        self.password_entry.pack(fill=tk.X, pady=(0, 25), ipady=10)
        self.password_entry.bind('<Return>', lambda e: self.login())
        
        # Frame pour le bouton
        button_frame = tk.Frame(fields_frame, bg=theme.get("bg_primary"))
        button_frame.pack(fill=tk.X, pady=(0, 15))
        
        # Bouton de connexion
        login_btn = tk.Button(
            button_frame,
            text="Se Connecter",
            font=("Segoe UI", 12, "bold"),
            bg=theme.get("button_bg"),
            fg=theme.get("button_fg"),
            activebackground=theme.get("button_hover"),
            activeforeground=theme.get("button_fg"),
            relief=tk.FLAT,
            cursor="hand2",
            command=self.login,
            width=35,
            pady=10
        )
        login_btn.pack(fill=tk.X, ipady=15)
        
        # Message d'erreur
        self.error_label = tk.Label(
            fields_frame,
            text="",
            font=("Segoe UI", 9),
            bg=theme.get("bg_primary"),
            fg=theme.get("error"),
            wraplength=350,
            justify=tk.CENTER
        )
        self.error_label.pack(pady=(5, 0))
    
    def login(self):
        """Tente de se connecter"""
        username = self.username_entry.get()
        password = self.password_entry.get()
        
        if not username or not password:
            self.error_label.config(text="Veuillez remplir tous les champs")
            return
        
        if self.auth_manager.verify_user(username, password):
            self.authenticated = True
            # Appelle le callback qui va ouvrir la fenêtre principale
            self.on_success()
        else:
            self.error_label.config(text="Nom d'utilisateur ou mot de passe incorrect")
            self.password_entry.delete(0, tk.END)


class VPNServerGUI:
    """Interface graphique serveur avec thème moderne"""
    
    def __init__(self, root):
        self.root = root
        self.setup_window()
        
        # Gestionnaire de thème
        self.theme_manager = ThemeManager()
        self.current_theme = DARK_THEME
        
        # Variables d'état
        self.server_running = False
        self.server_thread = None
        self.log_queue = queue.Queue()
        
        # Composants VPN
        self.server_instance = None
        self.server_config = None
        

        
        # Gestionnaire de ressources
        self.resource_manager = ResourceManager()
        
        # Gestionnaire d'authentification
        self.auth_manager = AuthManager()
        
        # Applique le thème
        self.apply_theme()
        
        # Créer l'interface
        self.create_widgets()
        
        # Démarrer le traitement des logs
        self.process_log_queue()
    
    def setup_window(self):
        """Configure la fenêtre principale"""
        self.root.title("Mini-VPN Server - Administration")
        self.root.geometry("1000x750")
        self.root.minsize(800, 600)
    
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
            text="Serveur VPN",
            font=("Segoe UI", 16, "bold"),
            bg=theme.get("bg_secondary"),
            fg=theme.get("fg_primary")
        )
        title_label.pack(side=tk.LEFT, padx=15, pady=10)
        
        self.status_indicator = tk.Label(
            header_frame,
            text="● Arrêté",
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
        
        # Frame de ressources
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
        
        # Menu Administration
        admin_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Administration", menu=admin_menu)
        admin_menu.add_command(label="Changer le mot de passe", command=self.change_password_dialog)
        
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
        
        self.config_path_var = tk.StringVar(value="server_config.json")
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
        
        self.start_btn = tk.Button(
            control_frame,
            text="Démarrer le Serveur",
            font=("Segoe UI", 11, "bold"),
            bg=theme.get("success"),
            fg="white",
            activebackground="#45a049",
            relief=tk.FLAT,
            cursor="hand2",
            command=self.start_server,
            padx=20,
            pady=12
        )
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))
        
        self.stop_btn = tk.Button(
            control_frame,
            text="Arrêter le Serveur",
            font=("Segoe UI", 11, "bold"),
            bg=theme.get("error"),
            fg="white",
            activebackground="#d32f2f",
            relief=tk.FLAT,
            cursor="hand2",
            command=self.stop_server,
            state=tk.DISABLED,
            padx=20,
            pady=12
        )
        self.stop_btn.pack(side=tk.LEFT)
    
    def create_info_section(self, parent):
        """Crée la section d'informations"""
        theme = self.current_theme
        
        info_frame = tk.LabelFrame(
            parent,
            text="Informations du Serveur",
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
            height=8,
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
    
    def create_resources_section(self, parent):
        """Crée la section de gestion des ressources"""
        theme = self.current_theme
        
        resources_frame = tk.LabelFrame(
            parent,
            text="Gestion des Ressources Partagées",
            font=("Segoe UI", 10, "bold"),
            bg=theme.get("bg_secondary"),
            fg=theme.get("fg_primary"),
            relief=tk.FLAT,
            padx=10,
            pady=10
        )
        resources_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10), padx=5)
        
        # Frame pour les boutons
        buttons_frame = tk.Frame(resources_frame, bg=theme.get("bg_secondary"))
        buttons_frame.pack(fill=tk.X, padx=5, pady=5)
        
        add_btn = tk.Button(
            buttons_frame,
            text="Ajouter une Ressource",
            font=("Segoe UI", 9, "bold"),
            bg=theme.get("success"),
            fg="white",
            activebackground="#45a049",
            relief=tk.FLAT,
            cursor="hand2",
            command=self.add_resource,
            padx=15,
            pady=8
        )
        add_btn.pack(side=tk.LEFT, padx=(0, 5))
        
        refresh_btn = tk.Button(
            buttons_frame,
            text="Actualiser",
            font=("Segoe UI", 9),
            bg=theme.get("bg_tertiary"),
            fg=theme.get("fg_primary"),
            activebackground=theme.get("border_dark"),
            relief=tk.FLAT,
            cursor="hand2",
            command=self.refresh_resources_list,
            padx=15,
            pady=8
        )
        refresh_btn.pack(side=tk.LEFT)
        
        delete_btn = tk.Button(
            buttons_frame,
            text="Supprimer",
            font=("Segoe UI", 9, "bold"),
            bg=theme.get("error"),
            fg="white",
            activebackground="#d32f2f",
            relief=tk.FLAT,
            cursor="hand2",
            command=self.delete_resource,
            padx=15,
            pady=8
        )
        delete_btn.pack(side=tk.LEFT, padx=(5, 0))
        
        # Liste des ressources
        list_frame = tk.Frame(resources_frame, bg=theme.get("bg_secondary"))
        list_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
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
        
        # Charge la liste initiale
        self.refresh_resources_list()
    
    def add_resource(self):
        """Ajoute une ressource"""
        filename = filedialog.askopenfilename(
            title="Sélectionner un fichier à partager",
            filetypes=[
                ("Tous les fichiers", "*.*"),
                ("Fichiers texte", "*.txt"),
                ("Images", "*.jpg *.jpeg *.png *.gif"),
                ("PDF", "*.pdf")
            ]
        )
        
        if filename:
            try:
                resource_id = self.resource_manager.add_resource(filename)
                if resource_id:
                    messagebox.showinfo("Succès", f"Ressource ajoutée avec succès!\nID: {resource_id}")
                    self.log(f"Ressource ajoutée: {resource_id}", "RESOURCES")
                    self.refresh_resources_list()
                else:
                    messagebox.showerror("Erreur", "Impossible d'ajouter la ressource")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de l'ajout: {e}")
                self.log(f"Erreur ajout ressource: {e}", "ERROR")
    
    def delete_resource(self):
        """Supprime la ressource sélectionnée"""
        selection = self.resources_listbox.curselection()
        if not selection:
            messagebox.showwarning("Attention", "Veuillez sélectionner une ressource à supprimer")
            return
        
        if not hasattr(self, 'resources') or not self.resources:
            return
            
        index = selection[0]
        if index < len(self.resources):
            resource = self.resources[index]
            resource_id = resource['id']
            filename = resource['original_name']
            
            if messagebox.askyesno("Confirmer", f"Voulez-vous vraiment supprimer '{filename}' ?"):
                try:
                    if self.resource_manager.remove_resource(resource_id):
                        messagebox.showinfo("Succès", "Ressource supprimée")
                        self.log(f"Ressource supprimée: {filename} ({resource_id})", "RESOURCES")
                        self.refresh_resources_list()
                    else:
                        messagebox.showerror("Erreur", "Impossible de supprimer la ressource")
                except Exception as e:
                    messagebox.showerror("Erreur", f"Erreur lors de la suppression: {e}")
                    self.log(f"Erreur suppression: {e}", "ERROR")
    
    def refresh_resources_list(self):
        """Actualise la liste des ressources"""
        try:
            self.resources_listbox.delete(0, tk.END)
            self.resources = self.resource_manager.list_resources()
            
            for resource in self.resources:
                display_text = f"{resource['original_name']} ({resource['type']})"
                self.resources_listbox.insert(tk.END, display_text)
            
            self.log(f"Liste des ressources actualisée: {len(resources)} ressource(s)", "RESOURCES")
        except Exception as e:
            self.log(f"Erreur actualisation ressources: {e}", "ERROR")
    
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
            title="Choisir le fichier de configuration serveur",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if filename:
            self.config_path_var.set(filename)
    
    def log(self, message, level="INFO"):
        """Ajoute un message aux logs"""
        import time
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
    
    def start_server(self):
        """Démarre le serveur"""
        config_path = self.config_path_var.get()
        
        if not Path(config_path).exists():
            messagebox.showerror("Erreur", f"Le fichier de configuration n'existe pas: {config_path}")
            return
        
        try:
            # Charge la config d'abord pour obtenir le port en cas d'erreur
            self.server_config = VPNConfig(config_path)
            listen_port = self.server_config.listen_port
            
            # Crée l'instance du serveur
            self.server_instance = VPNServer(config_path)
            self.update_server_info()
            
            self.server_running = True
            self.server_thread = threading.Thread(target=self.server_worker, daemon=True)
            self.server_thread.start()
            
            self.status_indicator.config(text="● En cours d'exécution", fg=self.current_theme.get("success"))
            self.start_btn.config(state=tk.DISABLED)
            self.stop_btn.config(state=tk.NORMAL)
            
            self.log("Serveur démarré", "SERVER")
            self.status_bar.config(text=f"Serveur démarré sur le port {listen_port}")
        
        except OSError as e:
            if hasattr(e, 'winerror') and e.winerror == 10048:
                error_msg = (
                    f"Le port {listen_port} est déjà utilisé.\n\n"
                    f"Solution:\n"
                    f"1. Arrêtez le serveur précédent\n"
                    f"2. Ou changez le port dans {config_path}"
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
        self.status_indicator.config(text="● Arrêté", fg=self.current_theme.get("error"))
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
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
        
        self.info_text.config(state=tk.NORMAL)
        self.info_text.delete(1.0, tk.END)
        self.info_text.insert(1.0, info)
        self.info_text.config(state=tk.DISABLED)
    
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
        
        # Met à jour les informations si le serveur est démarré
        if self.server_running:
            self.update_server_info()
    
    def change_password_dialog(self):
        """Ouvre le dialogue de changement de mot de passe"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Changer le mot de passe")
        dialog.geometry("400x400")
        dialog.resizable(False, False)
        
        theme = self.current_theme
        dialog.config(bg=theme.get("bg_primary"))
        
        # Centre le dialogue
        dialog.transient(self.root)
        dialog.grab_set()
        
        # Frame principal
        frame = tk.Frame(dialog, bg=theme.get("bg_primary"), padx=30, pady=30)
        frame.pack(fill=tk.BOTH, expand=True)
        
        # Style
        lbl_font = ("Segoe UI", 10)
        entry_font = ("Segoe UI", 11)
        bg = theme.get("bg_primary")
        fg = theme.get("fg_primary")
        input_bg = theme.get("input_bg")
        input_fg = theme.get("input_fg")
        
        # Username
        tk.Label(frame, text="Nom d'utilisateur:", font=lbl_font, bg=bg, fg=fg).pack(anchor=tk.W, pady=(0, 5))
        user_entry = tk.Entry(frame, font=entry_font, bg=input_bg, fg=input_fg, relief=tk.FLAT, borderwidth=1)
        user_entry.insert(0, "admin") # Défaut
        user_entry.pack(fill=tk.X, pady=(0, 15), ipady=5)
        
        # Old Pass
        tk.Label(frame, text="Mot de passe actuel:", font=lbl_font, bg=bg, fg=fg).pack(anchor=tk.W, pady=(0, 5))
        curr_pass = tk.Entry(frame, font=entry_font, show="●", bg=input_bg, fg=input_fg, relief=tk.FLAT, borderwidth=1)
        curr_pass.pack(fill=tk.X, pady=(0, 15), ipady=5)
        
        # New Pass
        tk.Label(frame, text="Nouveau mot de passe:", font=lbl_font, bg=bg, fg=fg).pack(anchor=tk.W, pady=(0, 5))
        new_pass = tk.Entry(frame, font=entry_font, show="●", bg=input_bg, fg=input_fg, relief=tk.FLAT, borderwidth=1)
        new_pass.pack(fill=tk.X, pady=(0, 15), ipady=5)
        
        # Confirm
        tk.Label(frame, text="Confirmer le nouveau mot de passe:", font=lbl_font, bg=bg, fg=fg).pack(anchor=tk.W, pady=(0, 5))
        confirm_pass = tk.Entry(frame, font=entry_font, show="●", bg=input_bg, fg=input_fg, relief=tk.FLAT, borderwidth=1)
        confirm_pass.pack(fill=tk.X, pady=(0, 25), ipady=5)
        
        def save():
            username = user_entry.get()
            old = curr_pass.get()
            new = new_pass.get()
            conf = confirm_pass.get()
            
            if not username or not old or not new:
                messagebox.showerror("Erreur", "Veuillez remplir tous les champs", parent=dialog)
                return
            
            if new != conf:
                messagebox.showerror("Erreur", "Les nouveaux mots de passe ne correspondent pas", parent=dialog)
                return
            
            if self.auth_manager.change_password(username, old, new):
                messagebox.showinfo("Succès", "Mot de passe modifié avec succès", parent=dialog)
                dialog.destroy()
            else:
                messagebox.showerror("Erreur", "Ancien mot de passe incorrect ou utilisateur inconnu", parent=dialog)
        
        tk.Button(
            frame, 
            text="Enregistrer", 
            command=save,
            bg=theme.get("success"), 
            fg="white",
            font=("Segoe UI", 11, "bold"),
            relief=tk.FLAT,
            cursor="hand2",
            padx=20, pady=10
        ).pack(fill=tk.X)
    
    def show_about(self):
        """Affiche la boîte de dialogue À propos"""
        messagebox.showinfo(
            "À propos",
            "Mini-VPN Server\n\n"
            "Serveur VPN user-space inspiré de WireGuard\n"
            "Version 1.0\n\n"
            "Développé en Python"
        )


def main():
    """Point d'entrée principal"""
    # Crée l'utilisateur admin par défaut si nécessaire
    create_default_admin()
    
    # Fenêtre de login
    login_root = tk.Tk()
    auth_manager = AuthManager()
    main_window_opened = [False]  # Utilise une liste pour permettre la modification dans la closure
    
    def open_main_window():
        """Ouvre la fenêtre principale"""
        if main_window_opened[0]:
            return  # Évite d'ouvrir plusieurs fenêtres
        
        main_window_opened[0] = True
        
        # Ferme la fenêtre de login
        try:
            login_root.quit()
            login_root.destroy()
        except:
            pass
        
        # Ouvre la fenêtre principale
        main_root = tk.Tk()
        app = VPNServerGUI(main_root)
        
        def on_closing():
            if app.server_running:
                app.stop_server()
            main_root.destroy()
        
        main_root.protocol("WM_DELETE_WINDOW", on_closing)
        main_root.mainloop()
    
    def on_login_success():
        # Ouvre la fenêtre principale
        open_main_window()
    
    login_window = LoginWindow(login_root, auth_manager, on_login_success)
    login_root.mainloop()


if __name__ == "__main__":
    main()

