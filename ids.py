import os
import time
import hashlib
import smtplib
import logging
import subprocess
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from threading import Thread
from scapy.all import sniff, IP, TCP

# Configure logging
logging.basicConfig(filename='hybrid_ids.log', level=logging.INFO, format='%(asctime)s - %(message)s')

# Email Configuration
EMAIL_HOST = "sandbox.smtp.mailtrap.io"
EMAIL_PORT = 2525
EMAIL_USERNAME = "2c1d5044325903"
EMAIL_PASSWORD = "86b6f78fce1195"
EMAIL_SENDER = "nargiza@example.com"
EMAIL_RECEIVER = "suman@example.com"

# Monitored File
MONITOR_FILE = "/etc/passwd"

# Thresholds
FAILED_SSH_LIMIT = 2
FAILED_SSH_COUNT = {}
IP_BLOCK_DURATION = 60  # Block for 1 minute
BLOCKED_IPS = {}
DOS_THRESHOLD = 100  # Max packets per second
TRAFFIC_HISTORY = {}
SCAN_ATTEMPTS = {}
SCAN_TIME_WINDOW = 5  # seconds
SCAN_THRESHOLD = 5  # packets in time window

def send_alert(subject, message):
    """Send an email alert."""
    try:
        msg = MIMEMultipart()
        msg["From"] = EMAIL_SENDER
        msg["To"] = EMAIL_RECEIVER
        msg["Subject"] = subject
        msg.attach(MIMEText(message, "plain"))

        with smtplib.SMTP(EMAIL_HOST, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USERNAME, EMAIL_PASSWORD)
            server.sendmail(EMAIL_SENDER, EMAIL_RECEIVER, msg.as_string())

        logging.info(f"[ALERT] Email sent: {subject}")
    except Exception as e:
        logging.error(f"Failed to send email: {str(e)}")


def log_alert(alert_msg):
    """Log alerts to a file and print them."""
    logging.info(alert_msg)
    print(alert_msg)


def get_checksum(file_path):
    """Calculate SHA-256 checksum of a file."""
    hasher = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            hasher.update(f.read())
        return hasher.hexdigest()
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {str(e)}")
        return None


def file_integrity_monitor():
    """Monitor file integrity changes."""
    previous_hash = get_checksum(MONITOR_FILE)
    log_alert("[INFO] Monitoring file integrity...")
    
    while True:
        time.sleep(5)
        current_hash = get_checksum(MONITOR_FILE)
        if current_hash and previous_hash and current_hash != previous_hash:
            alert_msg = "[ALERT] File integrity violation detected! /etc/passwd was modified."
            log_alert(alert_msg)
            send_alert("File Integrity Alert", alert_msg)
            previous_hash = current_hash


def block_ip(ip):
    """Block an IP address temporarily."""
    if ip not in BLOCKED_IPS:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
        BLOCKED_IPS[ip] = time.time()
        log_alert(f"[INFO] Blocked IP: {ip} for {IP_BLOCK_DURATION} seconds")


def unblock_ips():
    """Unblock IPs after timeout."""
    while True:
        time.sleep(30)
        current_time = time.time()
        for ip, block_time in list(BLOCKED_IPS.items()):
            if current_time - block_time > IP_BLOCK_DURATION:
                subprocess.run(["sudo", "iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"])
                del BLOCKED_IPS[ip]
                log_alert(f"[INFO] Unblocked IP: {ip}")


def monitor_logs():
    """Monitor system logs for SSH brute-force attempts."""
    log_alert("[INFO] Starting Log Monitoring...")
    process = subprocess.Popen(['journalctl', '-f', '-n', '0', '-u', 'sshd'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    
    for line in iter(process.stdout.readline, b''):
        decoded_line = line.decode()
        if "Failed password" in decoded_line:
            ip = decoded_line.split('from ')[1].split(' ')[0]
            FAILED_SSH_COUNT[ip] = FAILED_SSH_COUNT.get(ip, 0) + 1
            if FAILED_SSH_COUNT[ip] >= FAILED_SSH_LIMIT:
                alert_msg = f"[ALERT] SSH Brute Force Detected from {ip}!"
                log_alert(alert_msg)
                send_alert("SSH Intrusion Alert", alert_msg)
                block_ip(ip)
                FAILED_SSH_COUNT[ip] = 0


def detect_reverse_shell():
    """Detect potential reverse shells."""
    log_alert("[INFO] Monitoring for Reverse Shells...")
    while True:
        result = subprocess.run(['netstat', '-antp'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        for line in result.stdout.split('\n'):
            if "ESTABLISHED" in line and any(cmd in line for cmd in ["nc", "bash", "sh", "python", "perl"]):
                alert_msg = f"[ALERT] Possible Reverse Shell Detected: {line}"
                log_alert(alert_msg)
                send_alert("Reverse Shell Alert", alert_msg)
                ip = line.split()[4].split(':')[0]
                block_ip(ip)
        time.sleep(5)


def detect_nmap_scan(packet):
    """Detect Nmap scans with improved accuracy."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        current_time = time.time()

        if src_ip not in SCAN_ATTEMPTS:
            SCAN_ATTEMPTS[src_ip] = []

        SCAN_ATTEMPTS[src_ip].append(current_time)

        # Remove old scan attempts outside the time window
        SCAN_ATTEMPTS[src_ip] = [t for t in SCAN_ATTEMPTS[src_ip] if current_time - t <= SCAN_TIME_WINDOW]

        if len(SCAN_ATTEMPTS[src_ip]) > SCAN_THRESHOLD:
            alert_msg = f"[ALERT] Nmap Scan Detected from {src_ip}!"
            log_alert(alert_msg)
            send_alert("Nmap Scan Alert", alert_msg)
            block_ip(src_ip)
            SCAN_ATTEMPTS[src_ip] = []  # Reset count after blocking


def detect_dos_attack(packet):
    """Detect DoS attacks."""
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        TRAFFIC_HISTORY[src_ip] = TRAFFIC_HISTORY.get(src_ip, 0) + 1
        if TRAFFIC_HISTORY[src_ip] > DOS_THRESHOLD:
            alert_msg = f"[ALERT] DoS Attack Detected from {src_ip}!"
            log_alert(alert_msg)
            send_alert("DoS Attack Alert", alert_msg)
            block_ip(src_ip)
            TRAFFIC_HISTORY[src_ip] = 0


def network_monitor():
    """Monitor network traffic."""
    log_alert("[INFO] Starting Network Monitoring...")
    sniff(prn=lambda packet: (detect_nmap_scan(packet), detect_dos_attack(packet)), store=False)


if __name__ == "__main__":
    Thread(target=file_integrity_monitor, daemon=True).start()
    Thread(target=monitor_logs, daemon=True).start()
    Thread(target=unblock_ips, daemon=True).start()
    Thread(target=detect_reverse_shell, daemon=True).start()
    Thread(target=network_monitor, daemon=True).start()
    
    log_alert("[INFO] Hybrid IDS is running...")
    while True:
        time.sleep(60)
