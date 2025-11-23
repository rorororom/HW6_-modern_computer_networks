#!/usr/bin/env python3
import sys
import os
import threading
import time
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import IP, ICMP, UDP
from scapy.layers.l2 import Ether

TARGET_DOMAIN = "trap.music"
BASE_IP = "10.13.37"

SONG_LINES = [
    "show.girl.v.etom.klube",
    "prosit.snyat.ochki",
    "nochnye.babochki.na.bloke",
    "znayut.chto.ya.psih",
    "go.hard.quick.mommy",
    "zamolchi.pls",
    "kamasutra.flow.style",
    "ya.ih.nauchil",
    "yung.rich.yung.hustle",
    "secret.victory.mode",
    "ya.ves.v.krovi",
    "da.ya.znayu.da.ya.videl",
    "kak.ona.gorit",
    "neobyknovennyy.trap",
    "o.moey.lyubvi",
    "dlya.kultury.dlya.strany",
    "obuchayu.vnukov",
    "tyanus.k.adamu",
    "klad.ubral.v.druguyu",
    "ruku.pokupaju.serdce",
    "prosto.ultrazvukom",
    "tusuyus.tam.gde.grabyat",
    "s.normalnoy.sukoy",
    "vyhodite.besy.my",
    "stantsuyem.jersey",
    "otusha.ya.voydu",
    "i.ona.voskresnet",
    "pristegnis.i.smotri",
    "kak.tebe.olesya",
    "zhopa.kazhdoy.iz.moih",
    "podrug.v.amg.obvese",
    "turn.around.let.me",
    "take.my.glock",
    "ya.presleduyu.tsel",
    "teper.s.nim.ta",
    "iz.pesni.farika",
    "pro.revolver.prra",
    "tvoy.hip.hap.chisto.ha",
    "ne.slyshala.nicho.tupey",
    "kakoy.ty.repak.esli",
    "hochesh.vykupit.moy.trek"
]

class TrapInterceptor:
    def __init__(self, iface1, iface2):
        self.iface1 = iface1
        self.iface2 = iface2
        self.running = True
        
    def get_verse_ip(self, hop_number):
        return f"{BASE_IP}.{100 + hop_number}"
        
    def find_verse_index(self, domain):
        domain_lower = domain.lower().replace('-', '.')
        for i, line in enumerate(SONG_LINES):
            if line in domain_lower or domain_lower.replace('.', '') in line.replace('.', ''):
                return i
        return -1
        
    def handle_dns_query(self, packet):
        if not packet.haslayer(DNS) or not packet.haslayer(DNSQR):
            return None
            
        query_name = packet[DNSQR].qname.decode('utf-8').rstrip('.')
        hop_number = -1
        
        if TARGET_DOMAIN in query_name:
            hop_number = len(SONG_LINES) - 1
        else:
            hop_number = self.find_verse_index(query_name)
            
        if hop_number == -1:
            return None
            
        response_ip = self.get_verse_ip(hop_number)
        
        response = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                  IP(src=packet[IP].dst, dst=packet[IP].src) / \
                  UDP(sport=packet[UDP].dport, dport=packet[UDP].sport) / \
                  DNS(id=packet[DNS].id,
                      qr=1,
                      aa=1,
                      qd=packet[DNS].qd,
                      an=DNSRR(rrname=packet[DNSQR].qname,
                              ttl=300,
                              rdata=response_ip))
        
        return response
        
    def handle_traceroute_packet(self, packet):
        if not packet.haslayer(IP):
            return None
            
        ip_layer = packet[IP]
        dest_ip = ip_layer.dst
        ttl = ip_layer.ttl
        
        if not dest_ip.startswith(BASE_IP):
            return None
        
        if ttl <= len(SONG_LINES):
            source_ip = self.get_verse_ip(ttl - 1)
            icmp_response = ICMP(type=11, code=0)
        else:
            source_ip = dest_ip
            icmp_response = ICMP(type=3, code=3)
            
        response = Ether(src=packet[Ether].dst, dst=packet[Ether].src) / \
                  IP(src=source_ip, dst=ip_layer.src) / \
                  icmp_response / \
                  Raw(bytes(packet[IP])[:28])
        
        return response
        
    def should_intercept_packet(self, packet):
        if packet.haslayer(DNS) and packet.haslayer(DNSQR):
            query_name = packet[DNSQR].qname.decode('utf-8').rstrip('.')
            if TARGET_DOMAIN in query_name or self.find_verse_index(query_name) != -1:
                return True
                
        if packet.haslayer(IP):
            dest_ip = packet[IP].dst
            if dest_ip.startswith(BASE_IP):
                return True
                
        return False
        
    def packet_handler(self, packet, out_iface):
        try:
            if self.should_intercept_packet(packet):
                response = None
                
                if packet.haslayer(DNS) and packet[DNS].qr == 0:
                    response = self.handle_dns_query(packet)
                    
                elif packet.haslayer(IP):
                    if packet.haslayer(UDP) or packet.haslayer(ICMP):
                        response = self.handle_traceroute_packet(packet)
                
                if response:
                    sendp(response, iface=out_iface, verbose=False)
                    return
                    
            sendp(packet, iface=out_iface, verbose=False)
            
        except Exception:
            try:
                sendp(packet, iface=out_iface, verbose=False)
            except:
                pass
                
    def start_sniffing(self, in_iface, out_iface):        
        def packet_callback(packet):
            if self.running:
                self.packet_handler(packet, out_iface)
                
        sniff(iface=in_iface, prn=packet_callback, store=0)
        
    def run(self):
        try:
            thread1 = threading.Thread(
                target=self.start_sniffing,
                args=(self.iface1, self.iface2),
                daemon=True
            )
            thread2 = threading.Thread(
                target=self.start_sniffing,
                args=(self.iface2, self.iface1),
                daemon=True
            )
            
            thread1.start()
            thread2.start()
            
            while True:
                time.sleep(1)
                
        except KeyboardInterrupt:
            self.running = False
            
def main():
    if len(sys.argv) != 3:
        sys.exit(1)
        
    if os.geteuid() != 0:
        sys.exit(1)
        
    interceptor = TrapInterceptor(sys.argv[1], sys.argv[2])
    interceptor.run()

if __name__ == "__main__":
    main()
