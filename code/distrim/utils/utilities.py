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


from os import urandom
from random import randint
from argparse import ArgumentTypeError

from Crypto.PublicKey import RSA
from netifaces import gateways, ifaddresses, AF_INET

from .config import CFG_SALT_LEN_MIN, CFG_SALT_LEN_MAX
from ..assets.errors import (InvalidIPAddressError, NetInterfaceError,
                             CipherError)


class CipherWrap(object):
    """
    Wrap an RSA Cipher Instance
    """
    def __init__(self, cipher):
        """
        :param cipher: An RSA key, or an RSA instance.
        """
        if isinstance(cipher, basestring):
            try:
                self.rsa_instance = RSA.importKey(cipher)
            except (IndexError, ValueError):
                raise CipherError("Not a valid cipher string.")
        elif isinstance(cipher, RSA._RSAobj):
            self.rsa_instance = cipher
        else:
            raise CipherError("Not a valid cipher.")
        self._has_private = self.rsa_instance.has_private()

    def export(self, text=False, key_type=0):
        """
        Export the RSA key as a string.

        By default, this just exports a public key in DER format for use in
        fingers.

        If the private key is requested when this instance only has a public
        key, then a :class:`CipherError` is thrown.

        :param text: If True, format the string for humans.
        :param key_type: Key type to export. If 0, public; if 1, private; if 2,
            export public and private key.
        :return: The exported key.
        """
        fmt = 'PEM' if text else 'DER'
        if key_type == 0:
            return self.rsa_instance.publickey().exportKey(format=fmt)
        elif key_type == 1:
            if not self._has_private:
                raise CipherError("Requested non-existant private key.")
            return self.rsa_instance.exportKey(format=fmt)
        elif key_type == 2:
            if not self._has_private:
                raise CipherError("Requested non-existant private key.")
            return (self.rsa_instance.publickey().exportKey(format=fmt),
                    self.rsa_instance.exportKey(format=fmt))
        else:
            raise ValueError("Value for param 'key_type' must be in [0, 1, 2]")

    def encrypt(self, data):
        """
        Encrypt a packet of data.

        Note that this data must be a string no longer than 128 bytes.

        :param data: The data to encrypt.
        :return: The encrypted data.
        """
        if not isinstance(data, basestring):
            raise CipherError("Can only encrypt ")
        if len(data) > 128:
            raise CipherError("RSA Can't encrypt longer than 128 bytes")
        return self.rsa_instance.encrypt(data, None)[0]

    def decrypt(self, data):
        """
        Decrypt a packet of data.

        :param data: The data to decrypt.
        :return: The decrypted data.
        """
        if not self._has_private:
            raise CipherError("Can't decrypt, no private key!")
        return self.rsa_instance.decrypt(data)


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


def split_address(address):
    """
    Transform IPv4 address and port into a `string` and `int` tuple.

    :param address: The string format of the input address.
    :return: tuple of string of the IP or hostname, and port as an int.
    """
    parts = address.partition(':')

    if not parts[1]:
        return parts[0], None
    try:
        vals = parts[0], int(parts[2])
        return vals
    except ValueError:
        msg = ("'%s' is not a valid integer in address '%s'"
               % (parts[2], address))
        raise ArgumentTypeError(msg)


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


def generate_padding(min_length=CFG_SALT_LEN_MIN, max_length=CFG_SALT_LEN_MAX):
    """
    Create a padding string for use in a cryptographic message

    Generate a random string, of random characters, of a random length for
    padding secure messages.

    :param min_length: Minimum length of the padding.
    :param max_length: Maximum length of the padding.
    :return: The padding.
    """
    return urandom(randint(min_length, max_length))


def split_chunks(seq, part_size=128):
    """
    Split a sequence into parts.

    :param seq: The sequence to split.
    :param part_size: Size of the parts.
    :return: Generator function that yields chunks.
    """
    for idx in xrange(0, len(seq), part_size):
        yield seq[idx:idx+part_size]


def format_elapsed(delta):
    """
    Format a :class:`datetime.timedelta` object into a string.
    """
    hours, rem_secs = divmod(delta.seconds, 60*60)
    mins, secs = divmod(rem_secs, 60)
    if delta.days:
        return "%d days, %dh %dm %ds" % (delta.days, hours, mins, secs)
    else:
        return "%dh %dm %ds" % (hours, mins, secs)
