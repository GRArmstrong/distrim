# -*- coding: utf-8 -*-
## This file is part of DistrIM.
##
## DistrIM is a DHT-based network for secured messaging.
##
##     Author: Graham Armstrong
## Student ID: 11004764
##      Email: graham.armstrong@northumbria.ac.uk
##
## Product for CM0645 Individual Project, academic year 2014/15.
##
## This product has been developed in partial fulfilment of the regulations
## governing the award of the Degree of BSc (Honours) Computer Science
## at the University of Northumbria at Newcastle.


"""
    Miscelaneous Utility functions.
"""


from netifaces import gateways, interfaces, ifaddresses, AF_INET

from ..assets.errors import InvalidIPAddressError, NetInterfaceError


def parse_ip(str_ip):
    """
    Format string IP address into python objects.

    Takes a string representing an IPv4 address in the format
    "255.255.255.255:25525" and returns the four octets as a tuple of ints and
    the port as an int, such that "255.255.255.255:25525" becomes
    ((255,255,2552,255),25525).

    :param str_ip: String representation of the IP address.
    """
    ip, seperator, port = str_ip.partition(':')
    ip_address = tuple([int(x) for x in ip.split('.')])
    port = int(port)

    # Validation
    for octet in ip_address:
        if octet < 0 or octet > 255:
            raise InvalidIPAddressError(
                "Invalid IP address, bad octet in %s" % (str_ip,))
    if port < 1 or port > 65535:
        raise InvalidIPAddressError(
            "Invalid IP address, invalid port %d" % (port,))
    return ip_address, int(port)


def get_local_ip(address_type=AF_INET):
    """
    Determine local IP address of node from its interface IP.


    :param address_type: Any address type from the `AF_*` values in the
        `netifaces` module. Default `AF_INET` for IPv4 addresses.
    """
    default_gateway = gateways().get('default')
    if not default_gateway:
        raise NetInterfaceError("No default gateway found.")

    gateway_ip, interface = default_gateway.get(address_type)
    for addresses in ifaddresses(interface).get(address_type):
        if addresses.get('addr')[:3] == gateway_ip[:3]:
            return addresses.get('addr')
