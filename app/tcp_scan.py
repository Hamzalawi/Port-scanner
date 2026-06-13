from socket import socket, connect_ex, AF_inet, SOCK_STREAM
from scapy.all import sr, IP, TCP

def tcp_connect_scan(target, ports):    # should change this fucntion to be able to spoof source ip addresse and source port 
    L = list()
    for p in ports:
    
        sock= socket(AF_inet, SOCK_STREAM)
        code = sock.connect_ex(target, p)
        sock.settimeout(2.0)

        match code:
            case 0:
                L.append({"port": p, "status": "open"})
            case 111:
                L.append({"port": p, "status": "close"})
            case 110:
                L.append({"port": p, "status": "filetered"})
        
    return L


def tcp_syn_scan(target, ports):

   ans, unans= sr(IP(dst = target)/TCP(dport = ports, flags="S"))


