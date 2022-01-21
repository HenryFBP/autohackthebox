from autohackthebox.potatomodule import hackthe, Box
import argparse

if __name__ == '__main__':

    parser = argparse.ArgumentParser()

    parser.add_argument('host', help="The host to attack.", default=None)

    args = parser.parse_args()

    if args.host:
        print("Attacking " + args.host)
        daBox = Box(name=args.host, hostname=args.host)
        hackthe(daBox)
        exit(0)
    else:
        print("No arguments supplied. Hacking example boxes.")

    # # debug xml section
    # familyfriendlyWithDummyNMAPresults()
    # raise Exception("familyfriendlymywummy, debug webug")

    # corresponds to "Horizontall" box: <https://app.hackthebox.com/machines/374>
    Horizontall = Box('horizontall',
                      ip='10.10.11.105')

    DVWA = Box('dvwa',
               hostname='localhost')  # TODO can we pass port 6789?

    # NOTE: If you're trying to bruteforce DVWA box, you must first set up the database manually by going to:
    # http://localhost:6789/setup.php

    # hackthe(Horizontall)
    hackthe(DVWA)
