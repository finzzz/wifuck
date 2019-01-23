from scapy.all import srp, Ether, ARP
import requests
import csv
import nmap
import time
import argparse
import sys


# need root access if detail is True
# need to install nmap
def scan_devices(initial_IP="10.2.1.0", cidr="24", detail=False):
    print("scanning...")
    start = time.time()
    MAC_URL = "http://macvendors.co/api/"
    all_computer = "ff:ff:ff:ff:ff:ff"
    ans, unans = srp(Ether(dst=all_computer)/ARP(pdst=initial_IP+"/"+cidr),
                     timeout=2, verbose=False)

    new_mac_prefixes = []
    nm = nmap.PortScanner()

    with open("scan_result.csv", mode="w", newline=""):
        pass

    for _ in ans:
        ip_addrs = _[0].pdst
        mac_addrs = _[1].src
        vendor_prefix = mac_addrs[:8]

        vendor = ""
        os_guess = ""
        os_guess_acc = ""
        hostname = ""
        
        if detail:
            try:
                nm.scan(ip_addrs, '22-443', arguments="-O")
                os_guess = nm[ip_addrs]['osmatch'][0].get("name")
                os_guess_acc = nm[ip_addrs]['osmatch'][0].get("accuracy")
                hostname = nm[ip_addrs].hostname()
            except nmap.PortScannerError:
                print("need root access to predict os")
                sys.exit(1)
            except IndexError:
                pass
            except Exception as e:
                print(e)

        with open("vendor_list.csv", newline="") as rf:
            reader = csv.reader(rf)
            for row in reader:
                if row[0] == vendor_prefix:
                    vendor = row[1]
                else:
                    new_mac_prefixes.append(vendor_prefix)

        if not vendor:
            r = requests.get(MAC_URL+mac_addrs)
            response = r.json().get("result")

            vendor = response.get("company")

            if not vendor:
                vendor = "Unknown"

            with open("vendor_list.csv", mode="a", newline="") as af:
                writer = csv.writer(af, delimiter=",")
                writer.writerow([vendor_prefix, vendor])

        shorten_vendor = vendor.split()[0].split(",")[0]
        shorten_os = os_guess[:10]

        with open("scan_result.csv", mode="a", newline="") as af:
            writer = csv.writer(af, delimiter=",")
            writer.writerow([ip_addrs, mac_addrs, shorten_vendor,
                             hostname, shorten_os, os_guess_acc])

        print(f"ip={ip_addrs} mac={mac_addrs} vendor={shorten_vendor} "
              f"hostname=\"{hostname}\" os={shorten_os}~{os_guess_acc}%")

    end = time.time()
    elapsed_time = end-start
    print(f"{len(ans)} devices are found in {elapsed_time:.2f}s")


parser = argparse.ArgumentParser()
parser.add_argument('-m', '--mode', action='store_true')
args = parser.parse_args()

scan_devices(detail=args.mode)
