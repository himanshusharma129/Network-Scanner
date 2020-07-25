import scapy.all as scapy
import argparse
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target", dest="target",help="Target IP/Range")
    options = parser.parse_args()
    return options

def scan(ip):
    arp_req = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_req_broadcast = broadcast/arp_req
    ans_list = scapy.srp(arp_req_broadcast, timeout=2, verbose=False)[0]

    client_list=[]
    for element in ans_list:
        #print(element[1].psrc + "\t\t"+element[1].hwsrc)
        client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
        client_list.append(client_dict)
    return client_list
def printing(result):
    print("________________________________________________")
    print("\t\t Simple Network Scanner")
    print("________________________________________________")

    print("IP\t\t\t MAC Address")
    print("________________________________________________")
    for client in result:
        print(client["ip"]+"\t\t"+client["mac"])

options = get_args()

scanning = scan(options.target)
printing(scanning)
