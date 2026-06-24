def affiche(l):

    if not l: 
        print("host not found")

    else:
        for d in l: 

            for k,v in d.items():
                print(f"{k}: {v}")


def display_icmp(l):
    
    print("ICMP scan results:")
    affiche(l)
    print("_______________________________________________________________________________________________________________")


def display_tcp(l) :

    print("TCP scan results:")
    affiche(l)



def display_arp(l):

    print("arp scan results:")
    affiche(l)
    print("_______________________________________________________________________________________________________________")


