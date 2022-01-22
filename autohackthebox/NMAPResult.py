from typing import Set, List, Union

import lxml
from lxml import etree, objectify

from VulnerabilityFeatures import BoxVulnerabilityFeature


class NMAPResult:
    def __init__(self, raw_xml: str):
        self.raw_xml = raw_xml
        self.nmap_data: lxml.etree.Element = etree.fromstring(self.raw_xml.encode('ascii'))
        self.objectified_nmap_data: lxml.objectify.ObjectifiedElement = objectify.fromstring(self.raw_xml.encode('ascii'))

    def extractFeatures(self) -> Set[BoxVulnerabilityFeature]:
        """From my results, what vulnerable features does this scan exhibit?"""
        result = self.nmap_data

        raise NotImplementedError("lazy!! >:3c ")

    def isOnline(self) -> bool:
        """Does this nmap result say host is online?"""
        state = self.nmap_data.xpath('//nmaprun/host/status/@state')

        if len(state) > 0:
            return state[0] == 'up'

        return False

    def getServices(self, service: str) -> List[lxml.etree.Element]:
        return self.nmap_data.xpath(f'//nmaprun/host/ports/port/service[@name="{service}"]')

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