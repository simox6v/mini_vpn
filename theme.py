"""
Module de gestion des thèmes (Dark/Light mode)
"""
import tkinter as tk
from typing import Dict, Tuple


class Theme:
    """Définit les couleurs et styles pour un thème"""
    
    def __init__(self, name: str, colors: Dict[str, str]):
        self.name = name
        self.colors = colors
    
    def get(self, key: str, default: str = "#000000") -> str:
        """Récupère une couleur par clé"""
        return self.colors.get(key, default)


# Thème clair (Light Mode)
LIGHT_THEME = Theme("Light", {
    # Couleurs principales
    "bg_primary": "#FFFFFF",
    "bg_secondary": "#F5F5F5",
    "bg_tertiary": "#E8E8E8",
    "fg_primary": "#212121",
    "fg_secondary": "#424242",
    "fg_tertiary": "#757575",
    
    # Couleurs d'accent
    "accent": "#2196F3",
    "accent_hover": "#1976D2",
    "accent_light": "#E3F2FD",
    
    # Couleurs de statut
    "success": "#4CAF50",
    "success_light": "#E8F5E9",
    "warning": "#FF9800",
    "warning_light": "#FFF3E0",
    "error": "#F44336",
    "error_light": "#FFEBEE",
    "info": "#2196F3",
    "info_light": "#E3F2FD",
    
    # Bordures
    "border": "#E0E0E0",
    "border_light": "#F5F5F5",
    "border_dark": "#BDBDBD",
    
    # Textes
    "text_primary": "#212121",
    "text_secondary": "#424242",
    "text_disabled": "#BDBDBD",
    
    # Boutons
    "button_bg": "#2196F3",
    "button_fg": "#FFFFFF",
    "button_hover": "#1976D2",
    "button_disabled": "#E0E0E0",
    
    # Inputs
    "input_bg": "#FFFFFF",
    "input_fg": "#212121",
    "input_border": "#E0E0E0",
    "input_focus": "#2196F3",
})


# Thème sombre (Dark Mode)
DARK_THEME = Theme("Dark", {
    # Couleurs principales
    "bg_primary": "#1E1E1E",
    "bg_secondary": "#252526",
    "bg_tertiary": "#2D2D30",
    "fg_primary": "#CCCCCC",
    "fg_secondary": "#858585",
    "fg_tertiary": "#6A6A6A",
    
    # Couleurs d'accent
    "accent": "#007ACC",
    "accent_hover": "#005A9E",
    "accent_light": "#1E3A5F",
    
    # Couleurs de statut
    "success": "#4EC9B0",
    "success_light": "#1E3A3A",
    "warning": "#DCDCAA",
    "warning_light": "#3A3A2E",
    "error": "#F48771",
    "error_light": "#3A2E2E",
    "info": "#4FC1FF",
    "info_light": "#1E3A5F",
    
    # Bordures
    "border": "#3E3E42",
    "border_light": "#2D2D30",
    "border_dark": "#454545",
    
    # Textes
    "text_primary": "#CCCCCC",
    "text_secondary": "#858585",
    "text_disabled": "#6A6A6A",
    
    # Boutons
    "button_bg": "#007ACC",
    "button_fg": "#FFFFFF",
    "button_hover": "#005A9E",
    "button_disabled": "#3E3E42",
    
    # Inputs
    "input_bg": "#252526",
    "input_fg": "#CCCCCC",
    "input_border": "#3E3E42",
    "input_focus": "#007ACC",
})


class ThemeManager:
    """Gestionnaire de thèmes"""
    
    def __init__(self):
        self.current_theme = DARK_THEME  # Dark mode par défaut
        self.themes = {
            "light": LIGHT_THEME,
            "dark": DARK_THEME
        }
    
    def set_theme(self, theme_name: str):
        """Change le thème actuel"""
        if theme_name in self.themes:
            self.current_theme = self.themes[theme_name]
    
    def get_theme(self) -> Theme:
        """Retourne le thème actuel"""
        return self.current_theme
    
    def toggle_theme(self):
        """Bascule entre light et dark"""
        if self.current_theme.name == "Dark":
            self.set_theme("light")
        else:
            self.set_theme("dark")
    
    def apply_theme(self, widget, theme_type: str = "default"):
        """
        Applique le thème à un widget
        
        Args:
            widget: Widget tkinter
            theme_type: Type de widget (default, button, input, frame)
        """
        theme = self.get_theme()
        
        if theme_type == "button":
            widget.config(
                bg=theme.get("button_bg"),
                fg=theme.get("button_fg"),
                activebackground=theme.get("button_hover"),
                activeforeground=theme.get("button_fg"),
                relief=tk.FLAT,
                borderwidth=0,
                padx=15,
                pady=8,
                font=("Segoe UI", 9, "bold")
            )
        elif theme_type == "input":
            widget.config(
                bg=theme.get("input_bg"),
                fg=theme.get("input_fg"),
                insertbackground=theme.get("input_fg"),
                selectbackground=theme.get("accent"),
                selectforeground=theme.get("button_fg"),
                relief=tk.FLAT,
                borderwidth=1,
                highlightthickness=1,
                highlightcolor=theme.get("input_focus"),
                highlightbackground=theme.get("input_border"),
            )
        elif theme_type == "frame":
            widget.config(bg=theme.get("bg_primary"))
        else:
            widget.config(
                bg=theme.get("bg_primary"),
                fg=theme.get("fg_primary")
            )

