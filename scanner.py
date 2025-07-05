#!/usr/bin/env python3

import socket
import threading
from queue import Queue
import argparse
from datetime import datetime
import re
from urllib.parse import urlparse
import ssl # Import the SSL module

# A lock for synchronized printing to the console
print_lock = threading.Lock()

def analyze_banner(banner, is_ssl):
    """
    Analyzes a banner (or certificate info) to infer service, version, and OS.
    Now handles both plain text and SSL certificate data.
    """
    if not banner:
        return "Unknown Service", "Unknown Version", "Unknown OS", ""

    # If we connected via SSL, the 'banner' is actually certificate info
    if is_ssl:
        service = "SSL/TLS"
        version = "Unknown"
        os_guess = "Unknown"
        
        # Try to find a Common Name from the certificate subject
        cn_match = re.search(r"'commonName':\s*'([^']*)'", banner)
        if cn_match:
            version = f"Certificate for {cn_match.group(1)}"

        # Check for HTTP headers in the response after the handshake
        if "HTTP/" in banner:
            service = "HTTPS"
            server_match = re.search(r'Server:\s*([\w.\-/]+)', banner, re.IGNORECASE)
            if server_match:
                version += f" (Server: {server_match.group(1)})"
        
        return service, version, os_guess, banner
    
    # --- Fallback to original plain-text banner analysis ---
    
    # SSH: Example: SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
    ssh_pattern = re.search(r'SSH-([\d.]+)-OpenSSH_([\w.]+)\s*(.*)', banner, re.IGNORECASE)
    if ssh_pattern:
        service = "SSH"
        version = f"OpenSSH {ssh_pattern.group(2)} (Protocol {ssh_pattern.group(1)})"
        os_info = ssh_pattern.group(3) if ssh_pattern.group(3) else "Linux/Unix-like"
        return service, version, os_info, banner

    # FTP: Example: 220 ProFTPD 1.3.7a Server
    ftp_pattern = re.search(r'FTPD\s+([\d.\w]+)', banner, re.IGNORECASE)
    if ftp_pattern:
        service = "FTP"
        version = f"ProFTPD {ftp_pattern.group(1)}"
        return service, version, "Likely Unix/Linux", banner

    # HTTP: Example: Server: nginx/1.18.0 (Ubuntu)
    http_server_pattern = re.search(r'Server:\s*([\w.\-/]+)\s*(?:\((.*?)\))?', banner, re.IGNORECASE)
    if http_server_pattern:
        service = "HTTP"
        version = http_server_pattern.group(1)
        os_info = http_server_pattern.group(2) if http_server_pattern.group(2) else "Unknown"
        return service, version, os_info, banner
    
    if "400 The plain HTTP request was sent to HTTPS port" in banner:
        return "HTTPS", "Nginx (likely)", "Unknown", banner

    return "Unknown Service", banner[:60].replace('\n', ' ').replace('\r', ''), "Unknown", banner

def probe_port(target_ip, port, target_host):
    """
    Probes a port, attempting an SSL/TLS handshake first, then falling back to plain text.
    Returns a tuple: (banner_string, is_ssl_boolean).
    """
    # --- 1. Attempt SSL/TLS Connection First ---
    try:
        # Create a default SSL context. This provides good security defaults.
        context = ssl.create_default_context()
        context.check_hostname = False # We are not verifying the host, just connecting
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((target_ip, port), timeout=2) as sock:
            # Wrap the socket with SSL. The handshake happens here.
            # server_hostname is crucial for SNI (Server Name Indication) to work correctly
            with context.wrap_socket(sock, server_hostname=target_host) as ssock:
                cert = ssock.getpeercert()
                banner = str(cert) # Use the certificate info as the banner
                
                # For HTTPS, we can send a request to get more info (like server headers)
                if port == 443:
                    ssock.sendall(f'HEAD / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n'.encode())
                    try:
                        http_response = ssock.recv(1024).decode('utf-8', errors='ignore')
                        banner += "\n--- HTTP Response ---\n" + http_response.split('\r\n')[0]
                        server_header = re.search(r'Server:\s*(.*)', http_response, re.IGNORECASE)
                        if server_header:
                            banner += f"\nServer: {server_header.group(1)}"
                    except socket.timeout:
                        pass # No HTTP response, that's fine
                return banner, True # Success, return certificate info and is_ssl=True
    except (ssl.SSLError, ConnectionResetError):
        # This means the port is likely not SSL/TLS. We fall through to the plain text check.
        pass
    except (socket.timeout, ConnectionRefusedError):
        # Port is closed or unreachable
        return None, False
    except Exception:
        # Other SSL/socket errors, we'll just try plain text
        pass

    # --- 2. Fallback to Plain Text Banner Grabbing ---
    try:
        with socket.create_connection((target_ip, port), timeout=2) as sock:
            # For some services (like HTTP), we need to send data to get a response
            if port == 80:
                 sock.sendall(f'HEAD / HTTP/1.1\r\nHost: {target_host}\r\nConnection: close\r\n\r\n'.encode())
            
            banner = sock.recv(1024).decode('utf-8', errors='ignore')
            return banner, False # Success, return plain banner and is_ssl=False
    except (socket.timeout, ConnectionRefusedError, ConnectionResetError):
        return None, False # No banner received or connection failed
    except Exception:
        return None, False

def scan_port(target_ip, port, target_host):
    """
    Scans a single port on the target IP using the advanced probe.
    """
    try:
        # First, a quick check to see if the port is open at all
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as pre_check_sock:
            pre_check_sock.settimeout(1)
            if pre_check_sock.connect_ex((target_ip, port)) != 0:
                return # Port is closed, no need to probe further

        # Port is open, let's probe it
        banner, is_ssl = probe_port(target_ip, port, target_host)
        
        if banner is not None:
            service, version, os_guess, raw_banner = analyze_banner(banner, is_ssl)
            with print_lock:
                ssl_tag = " (SSL/TLS)" if is_ssl else ""
                print(f"[+] Port {port:<5} is OPEN{ssl_tag}")
                print(f"    {'Service:':<10} {service}")
                print(f"    {'Version:':<10} {version}")
                print(f"    {'OS Guess:':<10} {os_guess}")
                # Clean up raw banner for printing
                cleaned_banner = raw_banner.replace('\n', ' ').replace('\r', '').strip()
                print(f"    {'Raw Info:':<10} {cleaned_banner[:100]}")
                print("-" * 60)
                
    except Exception as e:
        with print_lock:
            # This might happen for various reasons, good to log it
            print(f"[-] Error scanning port {port}: {e}")

def worker(q, target_ip, target_host):
    """ The worker thread function. Gets a port from the queue and scans it. """
    while not q.empty():
        port = q.get()
        scan_port(target_ip, port, target_host)
        q.task_done()

def parse_ports(port_string):
    """ Parses a port string like "80,443,1000-1024" into a list of integers. """
    ports = set()
    if not port_string:
        return sorted([21, 22, 25, 80, 110, 143, 443, 3306, 3389, 8080, 8443])
    parts = port_string.split(',')
    for part in parts:
        part = part.strip()
        if '-' in part:
            try:
                start, end = map(int, part.split('-'))
                ports.update(range(start, end + 1))
            except ValueError:
                print(f"[-] Invalid port range: {part}")
        else:
            try:
                ports.add(int(part))
            except ValueError:
                print(f"[-] Invalid port number: {part}")
    return sorted(list(ports))

def main():
    parser = argparse.ArgumentParser(description="Advanced Python Port Scanner with SSL/TLS detection.")
    parser.add_argument("target", help="The target IP address or hostname to scan.")
    parser.add_argument("-p", "--ports", help="Ports to scan (e.g., '80,443', '1-1024'). Defaults to common ports.")
    parser.add_argument("-t", "--threads", type=int, default=100, help="Number of threads to use (default: 100).")
    args = parser.parse_args()

    raw_target = args.target
    parsed_url = urlparse(raw_target if '://' in raw_target else f"http://{raw_target}")
    target_host = parsed_url.netloc or parsed_url.path
    
    print("=" * 60)
    print("      Advanced Python Port Scanner (with SSL/TLS)")
    print("=" * 60)

    try:
        target_ip = socket.gethostbyname(target_host)
    except socket.gaierror:
        print(f"[-] Cannot resolve hostname: {target_host}")
        return

    print(f"[*] Scanning Target: {target_host} ({target_ip})")
    ports_to_scan = parse_ports(args.ports)
    print(f"[*] Scanning {len(ports_to_scan)} port(s) with {args.threads} threads.")
    print("-" * 60)

    q = Queue()
    for port in ports_to_scan:
        q.put(port)
    
    start_time = datetime.now()
    for _ in range(args.threads):
        thread = threading.Thread(target=worker, args=(q, target_ip, target_host))
        thread.daemon = True
        thread.start()
    
    q.join()
    end_time = datetime.now()
    print("-" * 60)
    print(f"[*] Scan Completed in: {end_time - start_time}")
    print("=" * 60)

if __name__ == "__main__":
    main()