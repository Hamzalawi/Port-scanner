from scapy.all import sr, ICMP, IP

def icmp_scan(target):
    
    ans, unans= sr(IP(dst = target)/ICMP(type = 8), timeout = 3)
    L=list()
    for s,r in ans:

        if r[ICMP].type == 0 :
            L.append({"ip": r[IP].src, "TTL": r[IP].ttl, "status": "Alive"})

        elif r[ICMP].type == 3:
            L.append({"ip": r[IP].src, "TTL":None, "status": "Unreachable"})

    for us in unans:
        L.append({"ip": us[IP].dst, "TTL": None, "status": "No response"})

    return L

