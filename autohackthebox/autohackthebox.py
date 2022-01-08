from pprint import pprint
from typing import Optional, List, Set, Union, Dict

import mechanize
import nmap3
import lxml
from lxml import etree
from lxml import objectify
from mechanize import HTMLForm

from VulnerabilityFeatures import BoxVulnerabilityFeature

nmap = nmap3.Nmap()
SERVICE_NAMES = [
    'ssh', 'http',
]


def determine_form_type(f: HTMLForm) -> str:
    """
    Use "advanced logic" and "epic facts" to determine what type of form a form is... wew
    :param f:
    :return:
    """
    if 'login' in f.action:
        return 'login'

    raise NotImplementedError("Not sure what to do for this form: " + repr(f))


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
        self.http_scanner = HttpModule(self)
        self.nmap_results: List[NMAPResult] = []
        self.service_ports: Dict[str, int] = {}

    def has_nmap_results(self):
        return len(self.nmap_results) > 0

    def last_nmap_result(self):
        if self.has_nmap_results():
            return self.nmap_results[-1]

        return False

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

    def get_service_port(self, serviceName: str) -> Union[int, None]:
        return self.service_ports.get(serviceName, None)

    def run_nmap_scan(self, args=('-sC', '-sV'), import_nmap_xml_filepath: str = None):

        if import_nmap_xml_filepath:
            with open(import_nmap_xml_filepath, 'r') as f:
                nmapres = NMAPResult(f.read())
        else:
            cmd = [nmap.nmaptool]
            cmd.extend(args)
            cmd.extend([self.get_ip_or_hostname(), '-oX', '-'])

            xml = nmap.run_command(cmd)

            nmapres = NMAPResult(xml)

        self.nmap_results.append(nmapres)

        for servicename in SERVICE_NAMES:
            if nmapres.getServicePort(servicename):
                self.service_ports[servicename] = nmapres.getServicePort(servicename)

        return self.nmap_results

    def is_online(self) -> bool:
        if not self.has_nmap_results():
            return False

        return self.last_nmap_result().isOnline()


class HttpModule:
    def __init__(self, box: Box):
        self.box = box
        self.browser: mechanize.Browser = mechanize.Browser()
        self.browser.set_handle_robots(False)  # lol

    def has_results(self):
        return False  # TODO NYI

    def initial_http_scan(self):
        target = self.box.get_ip_or_hostname()
        target = "http://" + target + ":" + self.box.get_service_port('http') + "/"
        print("target={0}".format(target))

        self.browser.open(target)

    def bruteforce_login_form(self):
        if not self.has_results():
            self.initial_http_scan()

        links = self.browser.links()
        print(type(links[0]))

        forms = self.browser.forms()
        print(type(forms[0]))

        daForm: HTMLForm = forms[0]

        if not (determine_form_type(daForm) is 'login'):
            raise Exception("Cannot bruteforce this type of form: " + determine_form_type(daForm))

        print("about to bruteforce " + daForm.action)

        fuzzywuzzycandidates = ['foobar', 'god', 'admin', 'password']

        print("foo")

        raise NotImplementedError("todo finish bruteforce form")


def hackthe(box: Box) -> Box:
    # box.run_nmap_scan()

    # save time, import xml instead of running new nmap scan
    box.run_nmap_scan(import_nmap_xml_filepath='../data/DVWA.xml')

    if box.is_online():
        print(f"Most recent nmap scan says box {box} is online!")
    else:
        raise ConnectionError(f"Box {box} is offline!")

    if box.last_nmap_result().hasHTTPServer():
        print("target has an HTTP server!")

        box.http_scanner.bruteforce_login_form()

    return box


# corresponds to "Horizontall" box: <https://app.hackthebox.com/machines/374>
Horizontall = Box('horizontall',
                  ip='10.10.11.105')

DVWA = Box('dvwa',
           hostname='localhost')  # TODO can we pass port 6789?


def familyfriendlyWithDummyNMAPresults():
    with open('../data/Horizontall.xml', 'r') as f:
        dummyNmapResult = NMAPResult(raw_xml=f.read())

    gay1 = dummyNmapResult.isOnline()

    gay2 = dummyNmapResult.getServices('ssh')
    gay3 = dummyNmapResult.hasHTTPServer()
    gay4 = dummyNmapResult.hasSSH()
    print(" >:3c ")


if __name__ == '__main__':
    # # debug xml section
    # familyfriendlyWithDummyNMAPresults()
    # raise Exception("familyfriendlymywummy, debug webug")

    # hackthe(Horizontall)
    hackthe(DVWA)
