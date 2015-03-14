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
    Finger Space, stores information about other nodes
"""

import random

from hashlib import md5
from threading import Semaphore
from Crypto.PublicKey import RSA

from .assets.errors import (HashMissmatchError, FingerSpaceError,
                            FingerError)


class Finger(object):
    """
    A container class that represents the information identifying a particular
    Node in the network.

    Three attributes are stored:
     - The IP address of the node.
     - The listening port of node.
     - The public key of the node.

    These are the attributes needed for communication between nodes.

    On instantiation, an optional identifier value can also be passed in which
    is tested to ensure authenticity.
    """
    def __init__(self, ip_address, listening_port, public_key, ident=''):
        """
        :param ip_address: IP address of the node.
        :param listening_port: Listening port of the node.
        :param public_key: Public key of the node.
        :param ident: Hash value representing the identity of the node.
        """
        new_ident = generate_hash(ip_address, listening_port, public_key)
        if ident and (ident != new_ident):
            raise HashMissmatchError(ip_address, listening_port,
                                     new_ident, ident)
        self.ident = new_ident
        self.addr = ip_address
        self.port = listening_port
        self.key = public_key

    def __eq__(self, other):
        """
        Check if this finger is equal to another.

        :param other: The other finger.
        """
        if type(other) is not Finger:
            return False

        try:
            if self.ident == other.ident \
               and self.addr == other.addr \
               and self.port == other.port \
               and self.key == other.key:
                return True
        except Exception:
            pass
        return False


    def get_connection_info(self):
        """
        Fetch IP address and listening port of this finger.

        :return: IP address, and Listening Port.
        """
        return self.addr, self.port

    def get_cipher(self):
        """
        Get an RSA cipher for message encryption.

        Returns an instance of an RSA cipher of the Public Key of this Node.

        :return: RSA Public Key instance.
        """
        return RSA.importKey(self.key)


class FingerSpace(object):
    """
    The FingerSpace class is responsible for storing information about nodes.
    Access to the Key Space is managed through this class.
    """
    def __init__(self):
        """No parameters are needed"""
        self.access = Semaphore()
        self._keyspace = {}
        random.seed()

    def get(self, ident):
        """
        Retrieve a Node Finger with the ident.

        :param ident: ident of the Finger to fetch.
        :return: Finger of the node, or `None` if node not found.
        """
        with self.access:
            return self._keyspace.get(h2i(ident), None)

    def put(self, ip_address, listening_port, public_key, existing_ident=''):
        """
        Place a new node into the Finger Space.

        Expect a :class:`FingerError` exception be raised if the data passed
        in is not valid. Also expect a :class:`HashMissmatchError` exception
        if the generated ident does not match one passed in, do try to pass
        this data in to maintain integrity.

        :param ip_address: IP address of the node.
        :param listening_port: Listening port of the node.
        :param public_key: Public Key of the node in binary format.
        """
        new_finger = Finger(ip_address, listening_port,
                            public_key, existing_ident)
        with self.access:
            self._keyspace[h2i(new_finger.ident)] = new_finger

    def remove(self, ident):
        """
        Delete a Node Finger from the FingerSpace

        :param ident: ident of the Finger to remove.
        """
        try:
            with self.access:
                self._keyspace.pop(h2i(ident))
            return True
        except KeyError:
            return False

    def get_random_fingers(self, number):
        """
        Get random fingers.

        :param number: How many fingers to return.
        """
        with self.access:
            idents = self._keyspace.keys()
            if not self._keyspace:
                raise FingerSpaceError("DHT is empty.")

        if number < 1:
            raise ValueError("Number of keys must be positive")
        if len(idents) < number:
            number = len(idents)

        route = []

        with self.access:
            for _ in xrange(number):
                key = random.choice(idents)
                route.append((key, self._keyspace[key]))
                idents.remove(key)
        return route


def generate_hash(ip_address, listening_port, public_key):
    """
    Creates the identifying hash.

    The hash is generated using the md5 function. The IP address, listening
    port, and the public key are concatenated together into a single string.
    The string is hashed using the md5 function.

    For demonstration purposes the length of the hash is reduced to 2 bytes.

    :param ip_address: IP address of the node.
    :param listening_port: Listening port of the node.
    :param public_key: Public Key of the node in binary format.

    :returns: String representation of an MD5 hex hash.
    """
    finger_type_test(ip_address, listening_port, public_key)
    concated = "%s%d%s" % (ip_address, listening_port, public_key)
    ash = md5(concated)
    return ash.hexdigest()[:4]


def finger_type_test(ip_address, listening_port, public_key):
    """
    Tests three values for correct type and format.

    :param ip_address: IP address of the node.
    :param listening_port: Listening port of the node.
    :param public_key: Public Key of the node.

    :return: True if parameters are valid, else raises a `FingerError`
        exception.
    """
    # Test Types
    if type(ip_address) is not str:
        raise FingerError("ip_address must be a string")
    if type(listening_port) is not int:
        raise FingerError("listening_port must be an int")
    if type(public_key) is not str:
        raise FingerError("public_key must be a string")

    # Test values
    if len(ip_address.split('.')) != 4:
        raise FingerError("Invalid IPv4 address: '%s'" % (ip_address,))
    if listening_port > 65535 or listening_port < 1:
        raise FingerError("invalid port number '%d'. " % (listening_port,)
                          + "Must be between 1 and 65535")

    if public_key.startswith('-----BEGIN'):
        raise FingerError("public_key must be in binary format")

    try:
        RSA.importKey(public_key)
    except (ValueError, IndexError) as exc:
        raise FingerError("public_key is not valid:\n%s" % exc.message)

    return True


def h2i(hex_string):
    """
    Converts a hexadecimal string into an integer.

    For example: '2e' -> 46

    This is used since the key for entries in the fingerspace is the Finger
    ident represented as a number.

    :return: integer representation of hex string
    """
    return int(hex_string, 16)
