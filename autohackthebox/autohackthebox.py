from typing import Optional, List, Set

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
            return state[0] == 'up'  # TODO: How can I return the port? XPATH backreferences?

        return False

    def hasService(self, service: str) -> List[lxml.etree.Element]:
        return self.data.xpath('//nmaprun/host/ports/port/service[@name="{}"]'.format(service))

    def hasSSH(self) -> bool:
        foo = self.hasService('ssh')

        if len(foo) > 0:
            return True  # TODO: How can I return the port? XPATH backreferences?

        return False

    # def
    def hasHTTPServer(self):
        foo = self.hasService('http')

        if len(foo) > 0:
            return True  # TODO: How can I return the port? XPATH backreferences?

        return False


class Box:
    def __init__(self, name: str,
                 ip: Optional[str] = None, hostname: Optional[str] = None):
        self.name = name
        self.ip = ip
        self.hostname = hostname
        self.nmap_results: List[NMAPResult] = []

    def last_nmap_result(self):
        return self.nmap_results[-1]

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

    if box.last_nmap_result().isOnline():
        print(f"Most recent nmap scan says box {box} is online!")
    else:
        raise ConnectionError(f"Box {box} is offline!")

    if box.last_nmap_result().hasHTTPServer():
        print("target has an HTTP server!")
        raise NotImplementedError("TODO: send http request and search for <form> or HTTP 302s")

    return box


# corresponds to "Horizontall" box: <https://app.hackthebox.com/machines/374>
Horizontall = Box('horizontall',
                  ip='10.10.11.105')

if __name__ == '__main__':
    hackthe(Horizontall)
    print("wow :3")

    # dummyNmapResult = None
    # with open('../data/Horizontall.xml', 'r') as f:
    #     dummyNmapResult = NMAPResult(raw_xml='\n'.join(f.readlines()))
    #
    # dummyNmapResult.isOnline()
