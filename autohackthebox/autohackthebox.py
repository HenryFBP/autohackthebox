from typing import Optional, List, Set, Union

import nmap3
import lxml
from lxml import etree
from lxml import objectify

from VulnerabilityFeatures import BoxVulnerabilityFeature

nmap = nmap3.Nmap()


class NMAPResult:
    def __init__(self, raw_xml: str):
        self.raw_xml = raw_xml
        self.data: lxml.etree.Element = etree.fromstring(self.raw_xml.encode('ascii'))
        self.objectified_data: lxml.objectify.ObjectifiedElement = objectify.fromstring(self.raw_xml.encode('ascii'))

    def extractVulnFeatures(self) -> Set[BoxVulnerabilityFeature]:
        """From my results, what vulnerable features does this scan exhibit?"""
        raise NotImplemented('lol im lazy')

    def isOnline(self) -> bool:
        """Does this nmap result say host is online?"""
        state = self.data.xpath('//nmaprun/host/status/@state')

        if len(state) > 0:
            return state[0] == 'up'

        return False

    def getServices(self, service: str) -> List[lxml.etree.Element]:
        return self.data.xpath(f'//nmaprun/host/ports/port/service[@name="{service}"]')

    def getServicePort(self, service: str) -> Union[bool, int]:
        """
        :param service: Name of service, i.e. 'ssh'
        :return: Port number of service, or False if service DNE.
        """
        foo = self.getServices(service)

        if len(foo) > 0:
            port = foo[0].xpath('../@portid')[0]
            return port

        return False

    def hasSSH(self) -> Union[bool, int]:
        return self.getServicePort('ssh')

    def hasHTTPServer(self) -> Union[bool, int]:
        return self.getServicePort('http')


class Box:
    def __init__(self, name: str,
                 ip: Optional[str] = None, hostname: Optional[str] = None):
        self.name = name
        self.ip = ip
        self.hostname = hostname
        self.http_scanner = HttpScanner(self)
        self.nmap_results: List[NMAPResult] = []

    def has_nmap_results(self):
        return len(self.nmap_results) > 0

    def last_nmap_result(self):
        return self.nmap_results[-1]

    def get_ip_or_hostname(self):
        if self.ip:
            return self.ip

        if self.hostname:
            return self.hostname

        raise ValueError("Error! {} doesn't have an IP or Hostname!".format(self))

    def has_http_forms(self):
        if self.http_scanner.has_results():
            raise NotImplementedError("wowie check for le forms")

    def __repr__(self):
        return f"<Box name='{self.name}' online='{self.is_online()}' ip='{self.ip}' hostname='{self.hostname}'>"

    def run_nmap_scan(self, args=('-sC', '-sV')):

        cmd = [nmap.nmaptool]
        cmd.extend(args)
        cmd.extend([self.get_ip_or_hostname(), '-oX', '-'])

        xml = nmap.run_command(cmd)

        self.nmap_results.append(NMAPResult(xml))

        return self.nmap_results

    def is_online(self) -> bool:
        if not self.has_nmap_results():
            return False

        return self.last_nmap_result().isOnline()


class HttpScanner:
    def __init__(self, box: Box):
        self.box = box
        self.results = {}

    def has_results(self):
        return len(self.results) > 0

    def initial_scan(self):
        target = self.box.get_ip_or_hostname()

        raise NotImplementedError("lol send a get request d00d")

    def bruteforce_form(self):
        raise NotImplementedError("pee pee pu pu")


def hackthe(box: Box) -> Box:
    box.run_nmap_scan()

    if box.is_online():
        print(f"Most recent nmap scan says box {box} is online!")
    else:
        raise ConnectionError(f"Box {box} is offline!")

    if box.last_nmap_result().hasHTTPServer():
        print("target has an HTTP server!")

        if not box.http_scanner.has_results():
            box.http_scanner.initial_scan()

        box.http_scanner.bruteforce_form()

    return box


# corresponds to "Horizontall" box: <https://app.hackthebox.com/machines/374>
Horizontall = Box('horizontall',
                  ip='10.10.11.105')


def familyfriendlyWithDummyNMAPresults():
    dummyNmapResult = None
    with open('../data/Horizontall.xml', 'r') as f:
        dummyNmapResult = NMAPResult(raw_xml='\n'.join(f.readlines()))

    gay1 = dummyNmapResult.isOnline()

    gay2 = dummyNmapResult.getServices('ssh')
    gay3 = dummyNmapResult.hasHTTPServer()
    gay4 = dummyNmapResult.hasSSH()
    print(" >:3c ")


if __name__ == '__main__':
    # # debug xml section
    # familyfriendlyWithDummyNMAPresults()
    # raise Exception("familyfriendlymywummy, debug webug")

    hackthe(Horizontall)
