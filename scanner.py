import socket
import threading
import queue
import sys
import time
import re
import logging
from datetime import datetime
from ipaddress import ip_address, AddressValueError

# --- LEGAL DISCLAIMER & CONFIGURATION ---
LEGAL_DISCLAIMER = """
╔════════════════════════════════════════════════════════════════╗
║                    ⚠️  LEGAL DISCLAIMER ⚠️                     ║
║                                                                ║
║ Port scanning without explicit authorization from the system  ║
║ owner is ILLEGAL and may violate computer fraud laws.         ║
║                                                                ║
║ Use this tool ONLY on:                                        ║
║ • Systems you own                                             ║
║ • Systems you have explicit written permission to test       ║
║ • Designated testing environments (e.g., scanme.nmap.org)    ║
║                                                                ║
║ Unauthorized scanning may result in:                         ║
║ • Criminal prosecution                                        ║
║ • Civil liability                                             ║
║ • Network bans                                                ║
║                                                                ║
║ By proceeding, you agree you have authorization to scan.     ║
╚════════════════════════════════════════════════════════════════╝
"""

# --- SETTINGS (Engineering Part) ---
print_lock = threading.Lock()
target_ports = queue.Queue()
open_ports_log = []
scan_stopped = False

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('scan.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# --- VALIDATION FUNCTIONS ---
def is_valid_ip(ip_string):
    """Validate if string is a valid IP address."""
    try:
        ip_address(ip_string)
        return True
    except AddressValueError:
        return False

def is_private_ip(ip_string):
    """Check if IP is in private range."""
    try:
        ip = ip_address(ip_string)
        return ip.is_private
    except AddressValueError:
        return False

def sanitize_hostname(hostname):
    """Sanitize hostname input to prevent injection attacks."""
    # Allow only alphanumeric, dots, hyphens, and underscores
    if not re.match(r'^[a-zA-Z0-9._-]+$', hostname):
        return None
    if len(hostname) > 255:
        return None
    return hostname

# --- THE SCANNING LOGIC ---
def port_scan(target, port, timeout=3):
    """
    Scan a single port on the target.
    
    Args:
        target: Target IP address
        port: Port number to scan
        timeout: Socket timeout in seconds
    """
    try:
        # Create a socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        
        # Try to connect
        result = sock.connect_ex((target, port))
        
        if result == 0:
            with print_lock:
                print(f"[+] Port {port:5d} is OPEN")
                open_ports_log.append(port)
                logger.info(f"Open port found: {port}")
        
        sock.close()
            
    except socket.timeout:
        logger.debug(f"Timeout on port {port}")
    except socket.error as e:
        logger.debug(f"Socket error on port {port}: {str(e)}")
    except Exception as e:
        logger.error(f"Unexpected error on port {port}: {str(e)}")

# --- THE ROBOT MANAGER (Threader) ---
def worker(target_ip):
    """Worker thread that processes port scanning tasks."""
    global scan_stopped
    
    while not scan_stopped:
        try:
            # Get a port number with timeout
            port = target_ports.get(timeout=1)
            
            if port is None:  # Sentinel value to stop
                break
            
            port_scan(target_ip, port)
            target_ports.task_done()
            
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Worker thread error: {str(e)}")

# --- UTILITY FUNCTIONS ---
def get_service_name(port):
    """Get common service name for a port."""
    common_ports = {
        21: "FTP",
        22: "SSH",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        445: "SMB",
        3306: "MySQL",
        3389: "RDP",
        5432: "PostgreSQL",
        5900: "VNC",
        8080: "HTTP-Alt",
        8443: "HTTPS-Alt"
    }
    return common_ports.get(port, "Unknown")

def format_report(target_host, target_ip, start_time, end_time):
    """Generate a formatted security report."""
    duration = end_time - start_time
    report = f"""
{'='*60}
                    SECURITY SCAN REPORT
{'='*60}

Target Host:        {target_host}
Target IP:          {target_ip}
Scan Start Time:    {start_time}
Scan End Time:      {end_time}
Duration:           {duration:.2f} seconds
Total Ports Scanned: 500
Ports Per Second:   {500/duration:.2f}

{'='*60}
                      OPEN PORTS FOUND
{'='*60}

"""
    if not open_ports_log:
        report += "No open ports detected.\n"
    else:
        report += f"Total Open Ports: {len(open_ports_log)}\n\n"
        report += f"{'Port':<8} {'Service':<15}\n"
        report += "-" * 30 + "\n"
        for port in sorted(open_ports_log):
            service = get_service_name(port)
            report += f"{port:<8} {service:<15}\n"
    
    report += "\n" + "="*60 + "\n"
    report += "DISCLAIMER: This scan was performed with authorization.\n"
    report += "="*60 + "\n"
    
    return report

# --- MAIN CONTROL CENTER ---
# Replace the main section (after line 212) with this:

if __name__ == "__main__":
    try:
        print(LEGAL_DISCLAIMER)
        consent = input("\nDo you have authorization to scan this target? (yes/no): ").lower().strip()
        if consent != "yes":
            print("Scan cancelled.")
            sys.exit(1)
        
        print("\n" + "-" * 50)
        print("      PYTHON PORTS SCANNER (MULTI-THREADED)")
        print("-" * 50)
        
        target_input = input("\nTarget IP/Hostname (default: scanme.nmap.org): ").strip()
        
        if target_input == "":
            target_host = "scanme.nmap.org"
        else:
            target_host = sanitize_hostname(target_input)
            if not target_host:
                print("Error: Invalid hostname format.")
                sys.exit(1)

        try:
            target_ip = socket.gethostbyname(target_host)
            print(f"\n✓ Resolved {target_host} → {target_ip}")
        except socket.gaierror:
            print(f"Error: Could not resolve hostname '{target_host}'")
            sys.exit(1)
        
        if not is_valid_ip(target_ip):
            print(f"Error: Invalid IP address '{target_ip}'")
            sys.exit(1)
        
        if is_private_ip(target_ip):
            confirm = input(f"  {target_ip} is a private IP. Continue? (yes/no): ").lower().strip()
            if confirm != "yes":
                print("Scan cancelled.")
                sys.exit(0)

        # NEW: Ask user for port range
        print("\n" + "-" * 50)
        print("Port Range Options:")
        print("1. Quick scan (1-500)")
        print("2. Common ports (1-1024)")
        print("3. Extended scan (1-5000)")
        print("4. All ports (1-65535) - VERY SLOW")
        print("5. Custom range")
        print("-" * 50)
        
        choice = input("\nSelect scan type (1-5): ").strip()
        
        if choice == "1":
            start_port, end_port = 1, 500
            scan_label = "ports 1-500 (Quick)"
        elif choice == "2":
            start_port, end_port = 1, 1024
            scan_label = "ports 1-1024 (Well-known)"
        elif choice == "3":
            start_port, end_port = 1, 5000
            scan_label = "ports 1-5000 (Extended)"
        elif choice == "4":
            confirm = input("  This will take 10-30 MINUTES. Continue? (yes/no): ").lower().strip()
            if confirm != "yes":
                print("Scan cancelled.")
                sys.exit(0)
            start_port, end_port = 1, 65535
            scan_label = "ports 1-65535 (All)"
        elif choice == "5":
            try:
                start_port = int(input("Start port (1-65535): ").strip())
                end_port = int(input("End port (1-65535): ").strip())
                if not (1 <= start_port <= 65535 and 1 <= end_port <= 65535 and start_port <= end_port):
                    print("Invalid port range.")
                    sys.exit(1)
                scan_label = f"ports {start_port}-{end_port} (Custom)"
            except ValueError:
                print("Invalid input.")
                sys.exit(1)
        else:
            print("Invalid choice.")
            sys.exit(1)

        total_ports = end_port - start_port + 1
        
        print(f"\n Scanning Target: {target_ip}")
        print(f" Scanning {scan_label} with 100 threads...")
        print(f"⏱  Total ports: {total_ports}\n")

        start_time = time.time()
        
        threads = []
        for i in range(100):
            t = threading.Thread(target=worker, args=(target_ip,), daemon=True)
            t.start()
            threads.append(t)

        # Fill queue with custom port range
        for port in range(start_port, end_port + 1):
            target_ports.put(port)

        try:
            target_ports.join()
        except KeyboardInterrupt:
            print("\n\n  Scan interrupted!")
            scan_stopped = True

        end_time = time.time()

        print("\n" + "-" * 50)
        print("✓ Scan Complete!")
        
        report = format_report(target_host, target_ip, 
                              datetime.fromtimestamp(start_time).strftime('%Y-%m-%d %H:%M:%S'),
                              datetime.fromtimestamp(end_time).strftime('%Y-%m-%d %H:%M:%S'))
        
        try:
            with open("scan_report.txt", "w") as f:
                f.write(report)
            import os
            os.chmod("scan_report.txt", 0o600)
            print(report)
            print(f"✓ Report saved to 'scan_report.txt'")
        except IOError as e:
            print(f"Error writing report: {str(e)}")

        print("-" * 50 + "\n")

    except KeyboardInterrupt:
        print("\n\n  Interrupted by user.")
        sys.exit(0)
    except Exception as e:
        print(f"\n Fatal Error: {str(e)}")
        sys.exit(1)