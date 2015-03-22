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
from .utils.utilities import SocketWrapper, CipherWrap


class Finger(object):
    """
    Contains identifying information unique to a single node.

    This class represents the information identifying a particular Node in the
    network. Provides some functionalty for connecting and communicating with
    the node.

    Four attributes are stored:
     - The ident of the node.
     - The IP address of the node.
     - The listening port of node.
     - The public key of the node.

    These are the attributes needed for communication between nodes.

    On instantiation, an optional identifier value can also be passed in; the
    ident is calculated anyway but if given then it can be validated for
    authenticity.
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
        self.addr = ip_address
        self.port = listening_port
        self.key = public_key
        self.ident = new_ident
        # Combined values
        self.address = (self.addr, self.port)
        self.values = (self.addr, self.port, self.key)
        self.all = (self.addr, self.port, self.key, self.ident)

    def __eq__(self, other):
        """
        Check if this finger is equal to another.

        :param other: The other finger.
        """
        # Type check, attribute check
        if isinstance(other, Finger) and self.__dict__ == other.__dict__:
            return True
        return False

    def __repr__(self):
        """
        Representation of this object by text.
        """
        return "<Fingerspace.Finger %s @ %s:%d>" % (self.ident, self.addr,
                                                    self.port)

    def get_socket(self):
        """
        Get a socket object connected to this node.
        """
        return SocketWrapper(remote_address=self.address)

    def get_cipher(self):
        """
        Get an RSA cipher for message encryption.

        Returns an instance of an RSA cipher of the Public Key of this Node.

        :return: RSA Public Key instance.
        """
        return CipherWrap(self.key)


class FingerSpace(object):
    """
    The FingerSpace class is responsible for storing information about nodes.
    Access to the Key Space is managed through this class.
    """
    def __init__(self, parent_log, local_finger):
        """
        :param parent_log: logger object from Node instance.
        :param local_finger: The finger for this node.
        """
        self.log = parent_log.getChild(__name__.rpartition('.')[2])
        self.local_finger = local_finger
        self.access = Semaphore()
        self._keyspace = {}
        random.seed()

        # Some nice stats
        self.count_added = 0
        self.count_removed = 0

    def __len__(self):
        """FingerSpace length, the number of keys stored"""
        with self.access:
            return len(self._keyspace)

    def import_nodes(self, nodes_list):
        """
        Import a list of nodes.

        Receives a list of tuples, typically from a foreign node exporting
        their list, and adds those nodes to the FingerSpace.

        Data is expected to be (ip address, port, public key[, ident])
        The ident is optional.

        :param nodes: List of nodes.
        """
        for values in nodes_list:
            try:
                self.put(*values)  # Star-input allows us to use 3 or 4 args
            except FingerError as exc:
                self.log.error("Error importing finger: %s", exc.message)

    def export_nodes(self):
        """
        Export a list of all nodes.

        Exports a list of all nodes in tuple format for serialising and sending
        to foreign nodes.

        Data is exported as (ip address, port, public key, ident)

        :return: A list of tuples with the data from the 'all' attribute.
        """
        with self.access:
            return [finger.all for finger in self._keyspace.itervalues()]

    def get_all(self):
        """
        Gets a list of all fingers.
        """
        with self.access:
            return self._keyspace.values()

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
        finger = Finger(ip_address, listening_port,
                        public_key, existing_ident)

        if self.local_finger == finger:
            self.log.warning("Can't place local finger in FingerSpace")
            return

        ident = h2i(finger.ident)
        with self.access:
            if ident not in self._keyspace:
                self._keyspace[ident] = finger
                self.count_added += 1
            else:
                if not self._keyspace[ident] == finger:
                    self.log.warning(
                        "Attempted adding non-matching finger with matching "
                        + "ident %s.", finger.ident)

    def remove(self, ident):
        """
        Delete a Node Finger from the FingerSpace

        :param ident: ident of the Finger to remove.
        :return: True if succesfully removed, false if otherwise.
        """
        try:
            with self.access:
                self._keyspace.pop(h2i(ident))
            self.count_removed += 1
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
                route.append(self._keyspace[key])
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
    if not isinstance(ip_address, str):
        raise FingerError("ip_address must be a string")
    if not isinstance(listening_port, int):
        raise FingerError("listening_port must be an int")
    if not isinstance(public_key, str):
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
        key = RSA.importKey(public_key)
        if key.has_private():
            raise FingerError("!!!This is a private key, not public!!!")
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
