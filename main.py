import socket
import whois

def scan_ports(target, ports=[21, 22, 23, 25, 53, 80, 110, 443]):
    print(f"\n[+] Scanning {target}...")
    try:
        ip = socket.gethostbyname(target)
    except socket.gaierror:
        print("[!] Invalid domain or IP")
        return

    print(f"[+] Resolved {target} to {ip}\n")

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1)
        result = s.connect_ex((ip, port))
        if result == 0:
            print(f"[OPEN] Port {port}")
        s.close()

def whois_lookup(target):
    print(f"\n[+] Fetching WHOIS information for {target}...")
    try:
        domain_info = whois.whois(target)
        print("\n[+] WHOIS Info:")
        print(domain_info)
    except Exception as e:
        print(f"[!] Error fetching WHOIS info: {e}")

if __name__ == "__main__":
    target = input("Enter a domain or IP to scan: ")
    scan_ports(target)
    whois_lookup(target)
