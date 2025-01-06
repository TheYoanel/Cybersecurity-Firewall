#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Module de protection au niveau applicatif
Protège contre les attaques web courantes (XSS, SQL Injection, etc.)
"""

import re
from typing import Dict, List, Optional
from datetime import datetime
import html

class ApplicationFirewall:
    def __init__(self):
        """
        Initialise le firewall applicatif avec les règles de sécurité
        """
        # Patterns pour la détection d'attaques
        self.sql_patterns = [
            r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION|ALTER)\b)",
            r"(--|\b(OR|AND)\b\s+\d+\s*[=<>])",
            r"('[^']*'|\b(TRUE|FALSE)\b)"
        ]
        
        self.xss_patterns = [
            r"<script.*?>",
            r"javascript:",
            r"on\w+\s*=",
            r"data:text/html"
        ]
        
        # Compilation des expressions régulières
        self.sql_regex = [re.compile(p, re.IGNORECASE) for p in self.sql_patterns]
        self.xss_regex = [re.compile(p, re.IGNORECASE) for p in self.xss_patterns]

    def inspect_request(self, request: Dict) -> bool:
        """
        Inspecte une requête HTTP pour détecter des attaques potentielles
        
        Args:
            request (Dict): Requête HTTP à analyser
            
        Returns:
            bool: True si la requête est sûre, False sinon
        """
        # Vérifie les paramètres GET et POST
        for param, value in request.get('params', {}).items():
            if not self._check_parameter(param, value):
                self._log_violation(request.get('ip', 'unknown'), 
                                 f"Paramètre suspect: {param}")
                return False

        # Vérifie les en-têtes
        for header, value in request.get('headers', {}).items():
            if not self._check_header(header, value):
                self._log_violation(request.get('ip', 'unknown'), 
                                 f"En-tête suspect: {header}")
                return False

        return True

    def _check_parameter(self, param: str, value: str) -> bool:
        """
        Vérifie un paramètre de requête pour détecter des attaques
        
        Args:
            param (str): Nom du paramètre
            value (str): Valeur du paramètre
            
        Returns:
            bool: True si le paramètre est sûr, False sinon
        """
        # Vérifie les injections SQL
        for pattern in self.sql_regex:
            if pattern.search(value):
                return False

        # Vérifie les attaques XSS
        for pattern in self.xss_regex:
            if pattern.search(value):
                return False

        return True

    def sanitize_output(self, content: str) -> str:
        """
        Nettoie le contenu avant de l'envoyer au client
        
        Args:
            content (str): Contenu à nettoyer
            
        Returns:
            str: Contenu nettoyé
        """
        # Échappe les caractères HTML
        content = html.escape(content)
        
        # Supprime les scripts potentiels
        content = re.sub(r'<script.*?>.*?</script>', '', content, 
                        flags=re.IGNORECASE | re.DOTALL)
        
        return content

    def _check_header(self, header: str, value: str) -> bool:
        """
        Vérifie les en-têtes HTTP pour détecter des attaques
        
        Args:
            header (str): Nom de l'en-tête
            value (str): Valeur de l'en-tête
            
        Returns:
            bool: True si l'en-tête est sûr, False sinon
        """
        # Vérifie les injections dans les en-têtes
        dangerous_headers = {
            'X-Forwarded-For': r'[^0-9\.,]',
            'User-Agent': r'[<>]',
            'Referer': r'javascript:'
        }

        if header in dangerous_headers:
            pattern = dangerous_headers[header]
            if re.search(pattern, value, re.IGNORECASE):
                return False

        return True

    def _log_violation(self, ip: str, message: str) -> None:
        """
        Enregistre une violation dans les logs
        
        Args:
            ip (str): IP source
            message (str): Description de la violation
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {ip}: {message}\n"
        
        with open("logs/app_attacks.log", "a") as f:
            f.write(log_entry) 