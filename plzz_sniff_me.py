from scapy.all import sniff, IP, TCP, UDP 

def packet_callback(packet):

    if IP in packet:
        ip_layer = packet[IP]
        print(f"Source IP: {ip_layer.src}")
        print(f"Destination Ip: {ip_layer.dst}")


        if TCP in packet:
            print("Protocol: TCP")
            tcp_layer = packet[TCP]
            print(f"Source Port: {tcp_layer.sport}")
            print(f"Destination Port: {tcp_layer.dport}")
            print(f"Payload: {bytes(tcp_layer.payload)}")

        elif UDP in packet:
            print("Protocol: UDP")
            udp_layer = packet[UDP]
            print(f"Source Port: {udp_layer.sport}")
            print(f"Destination Port: {udp_layer.dport}")
            print(f"Payload: {bytes(udp_layer.payload)}")
        print("-" * 50)

def main():
    print("Starting Packet sniffer....") 

    sniff(prn=packet_callback, store=0) 


if __name__=="__main__":
    main()              
