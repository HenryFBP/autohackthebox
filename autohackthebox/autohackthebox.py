import enum
from pprint import pprint
from typing import Optional, List, Set
from lxml import etree
from lxml import objectify
import nmap3

nmap = nmap3.Nmap()


class BoxVulnerabilityFeature(enum.Enum):
    """
    represents a specific "vulnerability feature" that a box has
    """
    SSH = "SSH"
    HTTP = "HTTP"
    HTTP_FORM = "HTTP_FORM"
    HTTP_API = "HTTP_API"
    SMB = "SMB"


class NMAPResult:
    def __init__(self, raw_xml: str):
        self.raw_xml = raw_xml
        self.data = etree.fromstring(self.raw_xml.encode('ascii'))
        self.objectified_data = objectify.fromstring(self.raw_xml.encode('ascii'))

    def extractVulnFeatures(self) -> Set[BoxVulnerabilityFeature]:
        """From my results, what vulnerable features does this scan exhibit?"""
        raise NotImplemented('lol im lazy')

    def isOnline(self) -> bool:
        return self.data.xpath('//nmaprun/host[1]/status/@state')[0] == 'up'

    def hasSSH(self) -> bool:
        return

    # def


class Box:
    def __init__(self, name: str,
                 ip: Optional[str] = None, hostname: Optional[str] = None):
        self.name = name
        self.ip = ip
        self.hostname = hostname
        self.nmap_results: List[NMAPResult] = []

    def get_ip_or_hostname(self):
        if self.ip:
            return self.ip

        if self.hostname:
            return self.hostname

        raise ValueError("Error! {} doesn't have an IP or Hostname!".format(self))

    def __repr__(self):
        return f"<Box name='{self.name}' ip='{self.ip}' hostname='{self.hostname}'>"

    def run_nmap_scan(self, args=('-sC', '-sV')):

        cmd = [nmap.nmaptool]
        cmd.extend(args)
        cmd.extend([self.get_ip_or_hostname(), '-oX', '-'])

        xml = nmap.run_command(cmd)

        self.nmap_results.append(NMAPResult(xml))

        return self.nmap_results


def hackthe(box: Box) -> Box:
    box.run_nmap_scan()

    if box.nmap_results[-1].isOnline():
        print(f"Most recent nmap scan says box {box} is online!")
    else:
        raise Exception(f"Box {box} is offline!")

    # todo do stuff based off results

    return box


# corresponds to "Horizontall" box: <https://app.hackthebox.com/machines/374>
Horizontall = Box('horizontall',
                  ip='10.10.11.105')

if __name__ == '__main__':
    hackthe(Horizontall)
    print("wow :3")
