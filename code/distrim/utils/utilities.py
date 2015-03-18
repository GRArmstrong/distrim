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

import socket
import struct

from os import urandom
from random import randint
from argparse import ArgumentTypeError

from Crypto.PublicKey import RSA
from netifaces import gateways, ifaddresses, AF_INET

from .config import (CFG_SALT_LEN_MIN, CFG_SALT_LEN_MAX, CFG_TIMEOUT,
                     CFG_STRUCT_FMT)
from ..assets.errors import (InvalidIPAddressError, NetInterfaceError,
                             CipherError, SockWrapError)


class SocketWrapper(object):
    """
    Socket interface for communication with foreign nodes.

    This class wraps around a :class:`socket.socket` object. It provides the
    ability to send and receive packed data, packing it with the length to
    ensure all data is received.

    If the socket is not connected, use the :func:`connect` method to establish
    the connection.
    """
    def __init__(self, sock=None, remote_address=None, timeout=CFG_TIMEOUT):
        """
        Create the wrapper for the sockets.

        Note: You can pass in a socket or an address, if you pass in a
        connected socket, the remote address will be ignored.

        :param sock: the `socket` object. If None, a socket is created using
            the default values.
        :param remote_address: IP and Port of the remote host.
        :param timeout: the timeout value of the socket, how long it will pend
            waiting for a remote response.
        """
        if not sock:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock = sock
        self.remote_address = remote_address
        self.sock.settimeout(timeout)

    def _test_connection(self):
        """Test if connected, raise exception if not."""
        if not self.is_connected():
            raise SockWrapError("Can't use socket, it's not connected.")

    def is_connected(self):
        """
        Determines if the socket is connected or not.
        :return: True if it is, False if it isn't.
        """
        try:
            self.sock.getpeername()
            return True
        except socket.error:
            return False

    def connect(self, remote_address=None):
        """
        Connect the socket to the remote address.

        :param remote_address: IP and Port of the remote host.
        """
        if self.is_connected():
            return

        try:
            if remote_address:
                self.sock.connect(remote_address)
            elif self.remote_address:
                self.sock.connect(self.remote_address)
            else:
                raise SockWrapError("Connect to what? No remote address.")
        except (socket.error, socket.timeout):
            raise SockWrapError("Failure to connect.")

    def close(self):
        """
        Close connection with the foreign node.
        """
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
            self.sock.close()
        except socket.error as exc:
            raise SockWrapError("Error closing socket: %s" % exc.message)

    def recieve(self, read_length=1024):
        """
        Receive data from a foreign node via its socket.

        :param read_length: How many bytes to read at a time.
        """
        self._test_connection()
        received_data = ''
        try:
            length = struct.unpack(CFG_STRUCT_FMT, self.sock.recv(4))[0]
            while length > len(received_data):
                stream_out = self.sock.recv(read_length)
                received_data += stream_out
        except (socket.error, socket.timeout):
            raise SockWrapError("Error attempting to receive data.")
        return received_data

    def send(self, data):
        """
        Send data to the foreign node via its socket.

        :param data: The data packet to send.
        """
        self._test_connection()
        length = struct.pack(CFG_STRUCT_FMT, len(data))
        package = length + data
        sent_len = 0
        try:
            while sent_len < len(package):
                sent_len += self.sock.send(package)
        except (socket.error, socket.timeout):
            raise SockWrapError("Error attempting to data data.")


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
