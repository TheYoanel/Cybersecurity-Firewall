#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Network Packet Filtering Module
Analyzes and filters incoming packets according to predefined rules

Module de filtrage de paquets réseau
Analyse et filtre les paquets entrants selon des règles prédéfinies
"""

import socket
import json
import struct
from typing import Dict, List, Optional
from datetime import datetime

class PacketFirewall:
    def __init__(self, rules_file: str = "config/rules.json"):
        """
        Initialize the packet firewall
        Initialise le firewall de paquets
        
        Args:
            rules_file (str): Path to JSON rules file / Chemin vers le fichier de règles JSON
        """
        self.rules = self._load_rules(rules_file)
        self.blocked_patterns: List[bytes] = []  # Malicious signatures / Signatures malveillantes
        self.allowed_ports: List[int] = []      # Allowed ports / Ports autorisés
        self.packet_counter: Dict[str, int] = {} # Statistics by IP / Statistiques par IP

    def _load_rules(self, rules_file: str) -> Dict:
        """
        Load filtering rules from JSON file
        Charge les règles de filtrage depuis un fichier JSON
        
        Args:
            rules_file (str): Path to rules file / Chemin vers le fichier de règles
            
        Returns:
            Dict: Loaded filtering rules / Règles de filtrage chargées
        """
        try:
            with open(rules_file, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            self._log_error(f"Rules file not found / Fichier de règles non trouvé: {rules_file}")
            return {}

    def analyze_packet(self, packet: bytes, src_ip: str) -> bool:
        """
        Analyze a network packet according to defined rules
        Analyse un paquet réseau selon les règles définies
        
        Args:
            packet (bytes): Packet content to analyze / Contenu du paquet à analyser
            src_ip (str): Source IP / IP source
            
        Returns:
            bool: True if packet is allowed, False if blocked
                 True si le paquet est autorisé, False sinon
        """
        # Check malicious signatures / Vérifie les signatures malveillantes
        for pattern in self.blocked_patterns:
            if pattern in packet:
                self._log_violation(src_ip, "Malicious signature detected / Signature malveillante détectée")
                return False

        # Analyze TCP/IP header / Analyse l'en-tête TCP/IP
        try:
            header = self._parse_packet_header(packet)
            if not self._check_header_rules(header):
                return False
        except Exception as e:
            self._log_error(f"Header parsing error / Erreur d'analyse d'en-tête: {str(e)}")
            return False

        return True

    def _parse_packet_header(self, packet: bytes) -> Dict:
        """
        Parse network packet header
        Analyse l'en-tête d'un paquet réseau
        
        Args:
            packet (bytes): Packet to analyze / Paquet à analyser
            
        Returns:
            Dict: Extracted header information / Informations extraites de l'en-tête
        """
        # Simplified IP header parsing / Exemple simplifié d'analyse d'en-tête IP
        version_ihl = packet[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        
        return {
            'version': version,
            'ihl': ihl,
            'total_length': struct.unpack('!H', packet[2:4])[0],
            'protocol': packet[9]
        }

    def _check_header_rules(self, header: Dict) -> bool:
        """
        Check if header complies with defined rules
        Vérifie si l'en-tête respecte les règles définies
        
        Args:
            header (Dict): Analyzed packet header / En-tête du paquet analysé
            
        Returns:
            bool: True if header is valid, False if not
                 True si l'en-tête est valide, False sinon
        """
        # Check IP version / Vérifie la version IP
        if header['version'] != 4:  # IPv4 only / IPv4 uniquement
            return False

        # Check minimum size / Vérifie la taille minimale
        if header['total_length'] < 20:
            return False

        return True

    def _log_violation(self, ip: str, message: str) -> None:
        """
        Log a security violation
        Enregistre une violation dans les logs
        
        Args:
            ip (str): Source IP / IP source
            message (str): Violation description / Description de la violation
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {ip}: {message}\n"
        
        with open("logs/packet_violations.log", "a") as f:
            f.write(log_entry) 