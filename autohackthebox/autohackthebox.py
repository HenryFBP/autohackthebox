from typing import Optional



class Box:
    def __init__(self, ip: Optional[str] = None, hostname: Optional[str] = None):
        self.ip = ip
        self.hostname = hostname


class GenericFuzzer:
    def __init__(self, target: str):
        self.target = target


class SubdomainFuzzer(GenericFuzzer):
    pass


class HTTPResponse:
    pass


class NMAPResult:
    pass


def hackthe(b: Box) -> Box:
    nmap_results = 'squoobar'

    # decide how to proceed based on nmap

    if nmap_results[80]:
        # send exploratory http reqeust
        print("wow http! :)")


Horizontall = Box(ip='10.10.11.105')  # corresponds to "Horizontall" box: <https://app.hackthebox.com/machines/374>

if __name__ == '__main__':
    hackthe(Horizontall)
    print("wow :3")
