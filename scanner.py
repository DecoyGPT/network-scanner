from scapy.all import ARP, Ether, srp

def scan(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

def print_result(results):
    print("IP" + " "*18+"MAC")
    for device in results:
        print("{:20}{}".format(device['ip'], device['mac']))

# replace '192.168.1.1/24' with your network address
network = "192.168.1.1/24"
devices = scan(network)
print_result(devices)
