from flask import Flask, render_template
from scapy.all import ARP, Ether, srp

app = Flask(__name__)

def scan(ip):
    arp = ARP(pdst=ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp

    result = srp(packet, timeout=3, verbose=0)[0]

    devices = []
    for sent, received in result:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

@app.route("/")
def index():
    # replace '192.168.1.1/24' with your network address
    network = "192.168.1.1/24"
    devices = scan(network)
    return render_template('index.html', devices=devices)

if __name__ == "__main__":
    app.run(debug=True)
