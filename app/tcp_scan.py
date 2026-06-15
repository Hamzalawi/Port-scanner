from socket import socket, AF_INET  , SOCK_STREAM
from scapy.all import sr, IP, TCP
import subprocess

def tcp_connect_scan(target, ports):   # should change this fucntion to be able to spoof source ip addresse and source port 

    L = list()
    for p in ports:
    
        sock= socket(AF_INET, SOCK_STREAM)
        sock.settimeout(2.0)

        code = sock.connect_ex((target, p))

        match code:
            case 0:
                L.append({"port": p, "status": "open"})

            case 111:
                L.append({"port": p, "status": "close"})

            case 110:
                L.append({"port": p, "status": "filtered"})
        
            case _:
                L.append({"port": p, "status": "failed to connect"})
    
        sock.close()
    return L


def tcp_syn_scan(target, ports):   # Should be able to change source port and why not destination port
   
    try:
        subprocess.run(["sudo", "iptables", "-A", "INPUT", "-p", "tcp", "-s", target, "-j", "DROP"])

        ans, unans= sr(IP(dst = target)/TCP(dport = ports, flags="S"))
        L  = list()

        for s,r in ans:

            if r[TCP].flags == "R":
                L.append({"port": r[TCP].sport, "status": "close"})
                
            elif r[TCP].flags == "SA":
                L.append({"port": r[TCP].sport, "status": "open"})

        for us in unans:
            L.append({"port": us[TCP].dport, "status": "filtered"})

    
    finally:
        subprocess.run(["sudo", "iptables", "-D", "INPUT", "-p", "tcp", "-s", target, "-j", "DROP"])
    
    return L


def tcp_ack_scan(target, ports):

    ans, unans= sr(IP(dst = target)/TCP(dport = ports, flags="A"))
    L = list()

    for s,r in ans:

            if r[TCP].flags == "R":
                L.append({"port": r[TCP].sport, "status": "unfiltered"})

    for us in unans:
            L.append({"port": us[TCP].dport, "status": "filtered"})

    return L