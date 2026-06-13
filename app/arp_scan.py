from scapy.all import Ether,ARP, srp

def arp_scan(target)->list:

    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=target), timeout=2)

    L=list()
    for s,r in ans:
        L.append({"IP": r[ARP].psrc, "MAC":r[ARP].hwsrc })
        
    return L

