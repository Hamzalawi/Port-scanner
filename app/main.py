from argument import argument
from ICMP_ping_scan import icmp_scan
from arp_scan import arp_scan
from tcp_scan import tcp_connect_scan, tcp_syn_scan, tcp_ack_scan
from display import display_icmp, display_arp, display_tcp

import sys

def main():

    args= argument()
    target = args.target
    scan_type = args.scan
    ports = args.ports

    print(f"[*] Starting {scan_type.upper()} scan against {target}...")

    match scan_type:
        case 'arp':
            display_arp(arp_scan(target))
        
        case 'ping':
            display_icmp(icmp_scan(target))

        case "connect":
            results = tcp_connect_scan(target, ports)
            display_tcp(results)

        case "syn":
            results = tcp_syn_scan(target, ports)
            display_tcp(results)

        case "ack":
            results = tcp_ack_scan(target, ports)
            display_tcp(results)

        case _:
            print("[-] Error: Unrecognized scan type.")
            sys.exit(1)

if __name__ == "__main__":

    try:
        main()
    except KeyboardInterrupt:
        print("\n[*] Scan aborted by user.")
        sys.exit(0)

    except PermissionError:
        print("\n[-] Permission denied. SYN, ACK, and ARP scans require root/sudo privileges.")
        sys.exit(1)