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

# Python testing module:
#    http://docs.python-guide.org/en/latest/writing/tests/

"""
    Protocol tests, ensures the protocol is handled as we expect.
"""


import unittest

import socket
import pickle

from Crypto.PublicKey import RSA

from ..protocol import Protocol, ConnectionHandler
from ..fingerspace import Finger
from ..utils.utilities import SocketWrapper, CipherWrap
from ..assets.errors import ProtocolError


class ProtocolTest(unittest.TestCase):
    """Tests the :class:`Protocol` class."""
    def test_protocol_definition(self):
        """
        Sanity test for the class :class:`Protocol`.
        """
        # Combine known attributes in the class
        attrs = [attr for attr in dir(Protocol) if not attr.startswith('_')]
        attrs.remove('ALL')
        attrs.sort()  # Get Protocol message list alphabetically.

        # Create an instance of that class for attribute checking
        proc = Protocol()

        remaining_attributes = [atr for atr in attrs]
        found_attribute_vals = []

        # Test that all attributes are in ALL
        self.assertTrue(len(Protocol.ALL) == len(remaining_attributes))

        for idx, attribute in enumerate(attrs):
            value = proc.__getattribute__(attribute)
            self.assertEqual(Protocol.ALL[idx], value)
            found_attribute_vals.append(value)
            remaining_attributes.remove(attribute)

        self.assertTrue(len(remaining_attributes) == 0)

        # Test that attributes are valid for the protocol
        for attribute in found_attribute_vals:
            self.assertEqual(len(attribute), 4)
            self.assertEqual(attribute.upper(), attribute)
            self.assertIn(attribute, Protocol.ALL)


class MockSock(object):
    """Emulates a socket object"""
    def __init__(self):
        self.data = ''

    def send(self, data):
        self.data = data

    def receive(self):
        val = self.data
        self.data == ''
        return val


class ConnectionHandlerTests(unittest.TestCase):
    """Test the abstract ConnectionHandler class"""
    def setUp(self):
        self.handle = ConnectionHandler()
        self.handle.conn = MockSock()
        local_keys = RSA.generate(1024)
        self.handle.local_keys = CipherWrap(local_keys)
        pubkey = self.handle.local_keys.export()
        self.handle.foreign_key = CipherWrap(pubkey)
        self.handle.local_finger = Finger('192.168.0.1', 2345, pubkey)
        # with open("./testdata_fingerspace.pickle") as handle:
        #     fingers = pickle.load(handle)
        # foreign_finger = fingers[0]
        # self.handle.foreign_finger = Finger(*foreign_finger)

    def test_pack_unpack_procedure(self):
        """
        Tests the :func:`fetch` and :method:`send` methods of
        :class:`SocketWrapper`.
        """
        test_params = {'testcase': 'this dict'}
        self.handle.send(Protocol.Ping, test_params)
        message_type, params = self.handle.receive()
        self.assertEqual(message_type, Protocol.Ping)
        self.assertDictEqual(params, test_params)


class WrapperInvalidTests(unittest.TestCase):

    def test_send_invalid_data(self):
        """
        Ensure that sending invalid data causes an error.
        """
        handle = ConnectionHandler()
        self.assertRaises(ProtocolError, handle.send, *("Send", {}))
        self.assertRaises(ProtocolError, handle.send, *(Protocol.Message,
                                                        "Hello error!"))

    def test_receive_invalid_data(self):
        """
        Ensure that receiving invalid data causes an error.
        """
        handle = ConnectionHandler()
        handle.conn = MockSock()

        local_keys = RSA.generate(1024)
        handle.local_keys = CipherWrap(local_keys)

        handle.conn.send("subbers")
        self.assertRaises(ProtocolError, handle.receive)

        handle.conn.send('')
        self.assertRaises(ProtocolError, handle.receive)
