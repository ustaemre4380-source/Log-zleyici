#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
========================================================================================
 Project Name : LogSentinel Ultimate SIEM & SOC Engine
 Author       : H3XTOR (Emre Usta)
 Description  : Kurumsal düzeyde log analizi, tehdit avcılığı, otomatik iptables simülasyonu,
                Discord bildirimleri, GeoIP analizleri, SQLite kalıcı depolama ve 
                gelişmiş Rich terminal arayüzünü birleştiren kapsamlı güvenlik aracı.
========================================================================================
"""

import time
import re
import sqlite3
import threading
import random
import argparse
import csv
import json
import os
import sys
import logging
from datetime import datetime
from collections import defaultdict

try:
    from rich.console import Console
    from rich.layout import Layout
    from rich.panel import Panel
    from rich.table import Table
    from rich.live import Live
    from rich.text import Text
except ImportError:
    print("[HATA] 'rich' kütüphanesi yüklü değil. Lütfen 'pip install rich' komutu ile kurun.")
    sys.exit(1)

console = Console()

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(filename="logsentinel_system.log", level=logging.INFO, format=LOG_FORMAT)

class DatabaseManager:
    def __init__(self, db_name="log_verileri.db"):
        self.db_name = db_name
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        with self.lock:
            with sqlite3.connect(self.db_name) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS alerts (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp TEXT,
                        threat_type TEXT,
                        ip_address TEXT,
                        target_user TEXT,
                        attempt_count INTEGER,
                        country TEXT,
                        status TEXT
                    )
                """)
                
                try:
                    conn.execute("ALTER TABLE alerts ADD COLUMN country TEXT")
                except sqlite3.OperationalError:
                    pass

                conn.execute("""
                    CREATE TABLE IF NOT EXISTS firewall_bans (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        ip_address TEXT UNIQUE,
                        banned_at TEXT,
                        reason TEXT,
                        action_taken TEXT
                    )
                """)
                try:
                    conn.execute("ALTER TABLE firewall_bans ADD COLUMN action_taken TEXT")
                except sqlite3.OperationalError:
                    pass

    def log_alert(self, threat_type, ip, user, count, country="Bilinmiyor", status="KARANTİNADA"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        with self.lock:
            with sqlite3.connect(self.db_name) as conn:
                conn.execute(
                    """INSERT INTO alerts 
                       (timestamp, threat_type, ip_address, target_user, attempt_count, country, status) 
                       VALUES (?, ?, ?, ?, ?, ?, ?)""",
                    (timestamp, threat_type, ip, user, count, country, status)
                )
                conn.execute(
                    """INSERT OR IGNORE INTO firewall_bans 
                       (ip_address, banned_at, reason, action_taken) 
                       VALUES (?, ?, ?, ?)""",
                    (ip, timestamp, threat_type, "IPTABLES_DROP_SIM")
                )
        logging.warning(f"KRİTİK TEHDİT: {threat_type} | IP: {ip} | Kullanıcı: {user} | Ülke: {country}")

    def get_recent_alerts(self, limit=12):
        with self.lock:
            with sqlite3.connect(self.db_name) as conn:
                cursor = conn.execute(
                    "SELECT timestamp, threat_type, ip_address, target_user, attempt_count, country, status FROM alerts ORDER BY id DESC LIMIT ?",
                    (limit,)
                )
                return cursor.fetchall()

    def get_stats(self):
        with self.lock:
            with sqlite3.connect(self.db_name) as conn:
                total_alerts = conn.execute("SELECT COUNT(*) FROM alerts").fetchone()[0]
                unique_ips = conn.execute("SELECT COUNT(DISTINCT ip_address) FROM alerts").fetchone()[0]
                total_bans = conn.execute("SELECT COUNT(*) FROM firewall_bans").fetchone()[0]
                return total_alerts, unique_ips, total_bans

    def export_report_json(self, filename="logsentinel_rapor.json"):
        with self.lock:
            with sqlite3.connect(self.db_name) as conn:
                conn.row_factory = sqlite3.Row
                alerts = [dict(row) for row in conn.execute("SELECT * FROM alerts").fetchall()]
                bans = [dict(row) for row in conn.execute("SELECT * FROM firewall_bans").fetchall()]
                
                report = {
                    "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "total_alerts": len(alerts),
                    "total_bans": len(bans),
                    "alerts": alerts,
                    "bans": bans
                }
                with open(filename, "w", encoding="utf-8") as f:
                    json.dump(report, f, indent=4, ensure_ascii=False)
        console.print(f"\n[bold cyan][*] Kurumsal güvenlik raporu {filename} olarak dışa aktarıldı abi![/]")

class GeoIPIntelligence:
    def __init__(self):
        self.country_cache = {
            "192.168.1.50": "Yerel Ağ (LAN)",
            "10.0.0.15": "Türkiye (TR)",
            "172.16.4.88": "Rusya (RU)",
            "45.33.32.156": "Amerika (US)",
            "203.0.113.42": "Çin (CN)",
            "185.220.101.5": "Almanya (DE)"
        }

    def get_country(self, ip):
        return self.country_cache.get(ip, "Bilinmeyen (XX)")

class NotificationEngine:
    def __init__(self, webhook_url=None):
        self.webhook_url = webhook_url

    def send_alert(self, threat_type, ip, country, count):
        if not self.webhook_url:
            return
        payload = {
            "content": f"🚨 **LOGSENTINEL SECURITY ALERT** 🚨\n"
                       f"• **Tehdit:** `{threat_type}`\n"
                       f"• **Kaynak IP:** `{ip}` ({country})\n"
                       f"• **Deneme:** `{count}`\n"
                       f"• **Aksiyon:** `IP Karantinada (DROP)`"
        }
        try:
            import urllib.request
            req = urllib.request.Request(
                self.webhook_url,
                data=json.dumps(payload).encode('utf-8'),
                headers={'Content-Type': 'application/json'}
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception as e:
            logging.error(f"Webhook gönderilemedi: {e}")

LOG_PATTERNS = {
    "SSH Brute-Force": re.compile(
        r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3}) port \d+ ssh2"
    ),
    "Sudo Auth Hatası": re.compile(
        r"sudo:\s+pam_unix.*authentication failure.*rhost=(?P<ip>\S*)\s+user=(?P<user>\S+)?"
    ),
    "Web SQL Injection": re.compile(
        r"GET .*(?:SELECT.*FROM|UNION.*SELECT|OR 1=1).*(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    ),
    "Path Traversal": re.compile(
        r"GET .*(?:\.\./\.\./etc/passwd).*from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
    ),
    "Port Scan / SYN Flood": re.compile(
        r"\[UFW BLOCK\].*SRC=(?P<ip>\d{1,3}(?:\.\d{1,3}){3}).*DPT=(?P<port>\d+)"
    )
}

class ThreatDetector:
    def __init__(self, db_manager, notifier, geoip, threshold=3, time_window=15):
        self.db = db_manager
        self.notifier = notifier
        self.geoip = geoip
        self.threshold = threshold
        self.time_window = time_window
        self.failed_attempts = defaultdict(list)
        self.banned_ips = set()
        self.total_scanned = 0
        self.last_raw_log = "Sistem aktif, log akışı taranıyor..."

    def analyze_line(self, line):
        self.total_scanned += 1
        self.last_raw_log = line
        
        for threat_type, pattern in LOG_PATTERNS.items():
            match = pattern.search(line)
            if match:
                data = match.groupdict()
                ip = data.get("ip") or "127.0.0.1"
                user = data.get("user") or "root/system"
                
                if ip in self.banned_ips:
                    return
                
                self._handle_ip_threat(ip, threat_type, user)

    def _handle_ip_threat(self, ip, threat_type, user):
        current_time = time.time()
        self.failed_attempts[ip] = [t for t in self.failed_attempts[ip] if current_time - t < self.time_window]
        self.failed_attempts[ip].append(current_time)
        attempt_count = len(self.failed_attempts[ip])

        if attempt_count >= self.threshold:
            self.banned_ips.add(ip)
            country = self.geoip.get_country(ip)
            self.db.log_alert(threat_type, ip, user, attempt_count, country, "IPTABLES DROP")
            self.notifier.send_alert(threat_type, ip, country, attempt_count)
            self.failed_attempts[ip].clear()

def generate_dashboard(detector, db_manager):
    layout = Layout()
    layout.split(
        Layout(name="header", size=3),
        Layout(name="stats", size=5),
        Layout(name="main"),
        Layout(name="footer", size=3)
    )

    header_text = Text("LOGSENTINEL ULTIMATE v5.0 - ENTERPRISE SOC & SOAR PLATFORM", style="bold cyan", justify="center")
    layout["header"].update(Panel(header_text, border_style="cyan"))

    total_alerts, unique_ips, total_bans = db_manager.get_stats()
    stats_table = Table.grid(expand=True)
    stats_table.add_column(justify="center", ratio=1)
    stats_table.add_column(justify="center", ratio=1)
    stats_table.add_column(justify="center", ratio=1)
    stats_table.add_column(justify="center", ratio=1)

    stats_table.add_row(
        Panel(f"[bold cyan]{detector.total_scanned}[/]\n[dim cyan]Taranan Satır[/]", border_style="cyan"),
        Panel(f"[bold cyan]{total_alerts}[/]\n[dim cyan]Kritik Tehdit[/]", border_style="cyan"),
        Panel(f"[bold cyan]{total_bans}[/]\n[dim cyan]Karantinadaki IP[/]", border_style="cyan"),
        Panel(f"[bold cyan]log_verileri.db[/]\n[dim cyan]SIEM Storage[/]", border_style="cyan")
    )
    layout["stats"].update(stats_table)

    alert_table = Table(title="Log Verileri - Aktif Tehdit ve GeoIP Karantina Matrisi", expand=True, border_style="cyan")
    alert_table.add_column("Saat", style="cyan", width=10)
    alert_table.add_column("Tehdit / Saldırı Türü", style="bright_cyan")
    alert_table.add_column("Kaynak IP", style="bold cyan")
    alert_table.add_column("Konum (GeoIP)", style="cyan")
    alert_table.add_column("Hedef", style="cyan")
    alert_table.add_column("Deneme", justify="center", style="bright_cyan")
    alert_table.add_column("Güvenlik Durumu", justify="right", style="bold cyan")

    recent_alerts = db_manager.get_recent_alerts(10)
    if not recent_alerts:
        alert_table.add_row("-", "Sistem Güvenli: Tehdit algılanmadı...", "-", "-", "-", "-", "-")
    else:
        for row in recent_alerts:
            alert_table.add_row(row[0][11:], row[1], row[2], row[5], row[3], str(row[4]), row[6])

    layout["main"].update(Panel(alert_table, border_style="cyan"))

    footer_text = Text(f"Canlı Log İnceleme: {detector.last_raw_log[:85]}...", style="dim cyan")
    layout["footer"].update(Panel(footer_text, title="Canlı SOC Akışı (Çıkış için CTRL+C)", border_style="cyan"))

    return layout

def simulate_log_activity(log_file_path):
    sample_ips = ["192.168.1.50", "10.0.0.15", "172.16.4.88", "45.33.32.156", "203.0.113.42", "185.220.101.5"]
    users = ["admin", "root", "postgres", "ubuntu", "www-data"]
    attack_types = [
        lambda ip, u: f"Nov 12 23:10:01 server sshd[1234]: Failed password for invalid user {u} from {ip} port 54321 ssh2\n",
        lambda ip, u: f"Nov 12 23:10:02 server webserver: GET /index.php?id=1 UNION SELECT null,null FROM users FROM {ip}\n",
        lambda ip, u: f"Nov 12 23:10:03 server webserver: GET /../../etc/passwd HTTP/1.1 from {ip}\n",
        lambda ip, u: f"Nov 12 23:10:04 server kernel: [UFW BLOCK] IN=eth0 OUT= SRC={ip} DST=192.168.1.10 PROTO=TCP SPT=45123 DPT=22\n"
    ]
    
    if not os.path.exists(log_file_path):
        open(log_file_path, "w").close()

    while True:
        time.sleep(random.uniform(0.4, 1.0))
        ip = random.choice(sample_ips)
        user = random.choice(users)
        log_generator = random.choice(attack_types)
        log_line = log_generator(ip, user)
        
        with open(log_file_path, "a", encoding="utf-8") as f:
            f.write(log_line)

def tail_f(log_file_path, detector):
    while True:
        try:
            with open(log_file_path, "r", encoding="utf-8", errors="ignore") as f:
                f.seek(0, 2)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)
                        continue
                    detector.analyze_line(line.strip())
        except FileNotFoundError:
            time.sleep(0.5)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LogSentinel Ultimate Enterprise SIEM & SOC Engine")
    parser.add_argument("--log", default="auth_test.log", help="Taranacak log dosyası yolu")
    parser.add_argument("--threshold", type=int, default=3, help="Brute-force eşik değeri")
    parser.add_argument("--webhook", default=None, help="Discord Webhook URL adresi")
    parser.add_argument("--export-json", action="store_true", help="Güvenlik raporunu JSON olarak dışa aktar")
    args = parser.parse_args()

    db_manager = DatabaseManager("log_verileri.db")

    if args.export_json:
        db_manager.export_report_json()
        sys.exit(0)

    notifier = NotificationEngine(args.webhook)
    geoip = GeoIPIntelligence()
    detector = ThreatDetector(db_manager, notifier, geoip, threshold=args.threshold, time_window=15)

    threading.Thread(target=simulate_log_activity, args=(args.log,), daemon=True).start()
    threading.Thread(target=tail_f, args=(args.log, detector), daemon=True).start()

    console.print(f"[bold cyan][*] LogSentinel Ultimate SOC motoru başlatıldı. Veriler 'log_verileri.db' içinde işleniyor abi.[/]")
    
    try:
        with Live(generate_dashboard(detector, db_manager), refresh_per_second=4, screen=True) as live:
            while True:
                time.sleep(0.25)
                live.update(generate_dashboard(detector, db_manager))
    except KeyboardInterrupt:
        console.print("\n[bold cyan][*] LogSentinel güvenle kapatıldı. Tüm güvenlik kayıtları güvende abi.[/]")