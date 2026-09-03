#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import ipaddress
import mailparser
import geoip2.database
from tinyscript import *


__author__ = "Alexandre D'Hondt"
__version__ = "1.2"
__copyright__ = "A. D'Hondt"
__license__ = "agpl-3.0"
__doc__ = """
This tool loads an email and parses the receivers, indicating where the found IP addresses originate from.
"""
__examples__ = ["message.eml"]


IP_REGEX = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
MMDB_PATH = "GeoLite2-City.mmdb"  # Download from MaxMind and set path here


def parse_eml(eml):
    ips = []
    found = False
    logger.debug("Parsing receivers...")
    with geoip2.database.Reader(MMDB_PATH) as reader:
        for receiver in eml.received:
            for addr in IP_REGEX.findall(receiver.get('raw', "")):
                addr = ipaddress.ip_address(addr)
                if str(addr) in ips:
                    continue
                ips.append(str(addr))
                logger.debug("Found: {}{}".format(addr, ["", " (private)"][addr.is_private]))
                if not addr.is_private:
                    s, found = str(addr), True
                    try:
                        d = reader.city(s)
                        if d.city.name:
                            s += "\n{: <9}: {}".format("City", d.city.name)
                        if d.country.name:
                            s += "\n{: <9}: {}".format("Country", d.country.name)
                        if d.continent.name:
                            s += "\n{: <9}: {}".format("Continent", d.continent.name)
                        if d.location.latitude and d.location.longitude:
                            s += "\nLocation : Lat {} Lon {}".format(
                                d.location.latitude, d.location.longitude)
                            if d.location.time_zone:
                                s += " ({})".format(d.location.time_zone)
                    except geoip2.errors.AddressNotFoundError:
                        s += "\n(No geolocation data found)"
                    logger.info(s)
    if not found:
        logger.warning("No public IP addresses found in email headers.")


def valid_eml(filename):
    try:
        with open(filename) as f:
            eml = mailparser.parse_from_file_obj(f)
        return eml
    except Exception as e:
        raise argparse.ArgumentTypeError("Invalid or unreadable .eml file: {}".format(e))


if __name__ == '__main__':
    parser.add_argument("eml", type=valid_eml, help="email file")
    initialize()
    parse_eml(args.eml)