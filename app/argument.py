import argparse

def port_parser(str_port):
    ret_list = []

    port_parts = str_port.split(',')
   
    for p in port_parts:
        p = p.strip()
        if '-' in p:
            start, end = p.split('-') 
            ret_list.extend(range(int(start), int(end) + 1))
        else:
            ret_list.append(int(p))
            
    return sorted(list(set(ret_list)))
def argument():
    parser = argparse.ArgumentParser(description="A port scanner in python")
    
    # -t / --target: Required, accepts a string (IP or CIDR)
    parser.add_argument(
        "-t", "--target",
        required=True,
        help="Target IP address or CIDR range (e.g., 192.168.1.1 or 192.168.1.0/24)"
    )

    # -s / --scan: Optional, restricted to specific choices, defaults to 'connect'
    parser.add_argument(
        "-s", "--scan",
        choices=["arp", "ping", "syn", "connect", "ack"],
        default="connect",
        help="The type of scan to perform. Allowed values: arp, ping, syn, connect, ack.\n(default: %(default)s)"
    )

    # -p / --ports: Optional, defaults to all TCP ports
    parser.add_argument(
        "-p", "--ports",
        type=str,
        default="1-65535", 
        help="Ports to scan. Formats: '80', '80,443', or '1-1024' or combinations like '80,1-5'.\n(default: %(default)s)"
    )

    args = parser.parse_args()

    args.ports = port_parser(args.ports)
    return args
