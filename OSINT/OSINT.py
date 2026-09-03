#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import argparse
import ipaddress
import os
import re
import mailparser
import geoip2.database
from tinyscript import *


__author__ = "Alexandre D'Hondt (Original Author), Vian (Modified)"
__version__ = "1.3"
__copyright__ = "Copyright (c) A. D'Hondt (Original Work), Vian (Modifications)"
__license__ = "AGPL-3.0"
__doc__ = """
Email OSINT & Header Analyzer
=============================
Original script by Alexandre D'Hondt.
Modifications made by Vian under the GNU Affero General Public License v3.0 (AGPL-3.0):
  - Added device, OS, and mail client header signature extraction (User-Agent, X-Mailer, X-Originating-IP).
  - Added graceful fallback handling when 'GeoLite2-City.mmdb' is not found in the script directory.
  - Updated output formatting and logging for CLI inspection.

This tool loads an email (.eml), parses network hops (IP addresses), geolocates public routing relays,
and extracts client device/software metadata.
"""

IP_REGEX = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')
MMDB_PATH = "GeoLite2-City.mmdb"

# Specific email headers that leak user device and software metadata
DEVICE_HEADERS = [
    'user-agent',
    'x-mailer',
    'x-operating-system',
    'x-originating-ip',
    'x-client-os',
    'x-device-type'
]


def extract_device_signatures(eml):
    """Parses email headers for client software, OS, and device identifiers."""
    logger.info("\n=== Device & Client Identification ===")
    found_device_info = False

    # Normalize headers dictionary to lowercase keys
    headers = {k.lower(): v for k, v in eml.headers.items()}

    for header_name in DEVICE_HEADERS:
        if header_name in headers:
            found_device_info = True
            value = headers[header_name]
            logger.info(f"{header_name.title(): <20}: {value}")

    if not found_device_info:
        logger.warning("No explicit device or X-Mailer headers found in this email.")


def parse_eml(eml):
    """Parses email routing hops and geolocates public IP addresses."""
    # 1. Extract device signatures
    extract_device_signatures(eml)

    ips = []
    found = False
    logger.info("\n=== Received IP Hops & Geolocation ===")

    # 2. Verify availability of MaxMind database
    db_available = os.path.exists(MMDB_PATH)
    if not db_available:
        logger.warning(f"Database file '{MMDB_PATH}' not found. Skipping geolocation lookups.")

    reader = geoip2.database.Reader(MMDB_PATH) if db_available else None

    try:
        for receiver in eml.received:
            for addr in IP_REGEX.findall(receiver.get('raw', "")):
                addr = ipaddress.ip_address(addr)
                if str(addr) in ips:
                    continue
                ips.append(str(addr))

                if not addr.is_private:
                    s, found = str(addr), True

                    if reader:
                        try:
                            d = reader.city(s)
                            if d.city.name:
                                s += f"\n{'City': <9}: {d.city.name}"
                            if d.country.name:
                                s += f"\n{'Country': <9}: {d.country.name}"
                            if d.continent.name:
                                s += f"\n{'Continent': <9}: {d.continent.name}"
                            if d.location.latitude and d.location.longitude:
                                s += f"\nLocation : Lat {d.location.latitude} Lon {d.location.longitude}"
                                if d.location.time_zone:
                                    s += f" ({d.location.time_zone})"
                        except geoip2.errors.AddressNotFoundError:
                            s += "\n(No geolocation data found)"

                    logger.info(s)
    finally:
        if reader:
            reader.close()

    if not found:
        logger.warning("No public IP addresses found in email headers.")


def valid_eml(filename):
    """Validates and parses the input file into a mailparser object."""
    try:
        with open(filename) as f:
            eml = mailparser.parse_from_file_obj(f)
        return eml
    except Exception as e:
        raise argparse.ArgumentTypeError(f"Invalid or unreadable .eml file: {e}")


if __name__ == '__main__':
    parser.add_argument("eml", type=valid_eml, help="email file")
    initialize()
    parse_eml(args.eml)