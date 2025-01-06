import os
import sys
import time
from collections import defaultdict
from scapy.all import sniff, IP, TCP
import ctypes

# Threshold for blocking IPs based on packet rate
# Seuil pour bloquer les IPs en fonction du taux de paquets
THRESHOLD = 40
print(f"THRESHOLD: {THRESHOLD}")


# Check for administrative privileges
# Vérifie si le script est exécuté avec les privilèges administratifs
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# Read IPs from a file
# Lit les IPs depuis un fichier
def read_ip_file(filename):
    try:
        with open(filename, "r") as file:
            ips = [line.strip() for line in file]
        return set(ips)
    except FileNotFoundError:
        # If the file doesn't exist, return an empty set
        # Si le fichier n'existe pas, renvoie un ensemble vide
        print(f"File not found: {filename}. Continuing without it.")
        return set()


# Check for Nimda worm signature
# Vérifie la signature du ver Nimda
def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        # Decode the payload safely
        # Décoder la charge utile en toute sécurité
        payload = bytes(packet[TCP].payload).decode(errors="ignore")
        return "GET /scripts/root.exe" in payload
    return False


# Log events to a file
# Journalise les événements dans un fichier
def log_event(message):
    log_folder = "logs"
    # Create a log folder if it doesn't exist
    # Crée un dossier de journalisation s'il n'existe pas
    os.makedirs(log_folder, exist_ok=True)
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S", time.localtime())
    log_file = os.path.join(log_folder, f"log_{timestamp}.txt")

    with open(log_file, "a") as file:
        # Write the log message to the file
        # Écrit le message dans le fichier de journal
        file.write(f"{message}\n")


# Packet processing callback
# Fonction de rappel pour traiter les paquets
def packet_callback(packet):
    if not packet.haslayer(IP):
        # Ignore packets without an IP layer
        # Ignore les paquets sans couche IP
        return

    src_ip = packet[IP].src

    # Check if IP is in the whitelist
    # Vérifie si l'IP est dans la liste blanche
    if src_ip in whitelist_ips:
        return

    # Check if IP is in the blacklist
    # Vérifie si l'IP est dans la liste noire
    if src_ip in blacklist_ips:
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking blacklisted IP: {src_ip}")
        return

    # Check for Nimda worm signature
    # Vérifie la signature du ver Nimda
    if is_nimda_worm(packet):
        print(f"Blocking Nimda source IP: {src_ip}")
        os.system(f"iptables -A INPUT -s {src_ip} -j DROP")
        log_event(f"Blocking Nimda source IP: {src_ip}")
        return

    # Increment packet count for this IP
    # Incrémente le nombre de paquets pour cette IP
    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval

            # Block IPs exceeding the threshold
            # Bloque les IPs dépassant le seuil
            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                os.system(f"iptables -A INPUT -s {ip} -j DROP")
                log_event(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                blocked_ips.add(ip)

        # Reset packet counts and timer
        # Réinitialise les comptes de paquets et le chronomètre
        packet_count.clear()
        start_time[0] = current_time


if __name__ == "__main__":
    if not is_admin():
        # Ensure the script is run as administrator
        # Assure que le script est exécuté en tant qu'administrateur
        print("This script requires administrative privileges. Please run as administrator.")
        sys.exit(1)

    # Import whitelist and blacklist IPs
    # Importe les IPs de la liste blanche et de la liste noire
    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    # Start sniffing packets
    # Commence à capturer les paquets
    sniff(filter="ip", prn=packet_callback)
