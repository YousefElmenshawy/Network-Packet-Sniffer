from scapy.layers.inet import  IP, TCP, UDP
from scapy.all import sniff
from scapy.all import Raw # for displaying data packet payload section
def main():
  print(" Packet sniffing...")
  sniff(prn = sniff_Packet, store = 0)



def sniff_Packet(pkt):
    if IP in pkt :
        src = pkt[IP].src # source IP address of the packet
        dst = pkt[IP].dst # destination IP address of the packet
        protocol = pkt[IP].proto # Protocol used in the data packet transfer
        print(f"Packet from {src} to {dst} using protocol {protocol}")
        if TCP in pkt : # Check if the packet is using TCP (connection involved) or UDP (Faster with no connection )
            print(f"  TCP ports: {pkt[TCP].sport} --> {pkt[TCP].dport} ")
        elif UDP in pkt :
            print(f" UDP ports: {pkt[UDP].sport}  --> {pkt[UDP].dport}")

        if Raw in pkt :
            try:
                data = pkt[Raw].load.decode(errors = "ignore")
                print(f"  Payload: {data}")
            except Exception as e:
                print(f"Couldnt decode data/Payload: {e}")






if  __name__ == "__main__":
    main()



