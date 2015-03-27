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
from mock import Mock
from itertools import product

import pickle

from ..protocol import (Protocol, ConnectionHandler, IncomingConnection,
                        MessageHandler)
from ..fingerspace import Finger
from ..assets.errors import ProtocolError, ProcedureError
from ..utils.utilities import CipherWrap


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
    """Emulates a SocketWrapper object"""
    def __init__(self):
        self.data = ''

    def send(self, data):
        self.data = data

    def receive(self):
        val = self.data
        self.data == ''
        return val


class ConnHandleInit(ConnectionHandler):
    """Extends the abstract class ConnectionHandler with an init method"""
    def __init__(self, local_keys, local_finger, foreign_finger):
        self.local_keys = local_keys
        self.local_finger = local_finger
        self.foreign_finger = foreign_finger
        self.foreign_key = foreign_finger.get_cipher()
        self.log = Mock()


class ConnectionHandlerFuncTests(unittest.TestCase):
    """Test the functions of the abstract ConnectionHandler class"""
    def setUp(self):
        test_data_path = (__file__.rpartition('/')[0]
                          + "/_testdata_protocol.pickle")
        with open(test_data_path) as handle:
            test_data = pickle.load(handle)
        self.nodes = []  # Gives 5 test nodes
        for val in test_data:
            keys = CipherWrap(val['priv'])
            finger = Finger(val['ip'], val['port'], val['pub'])
            self.nodes.append((keys, finger))

    def test_testdata_integrity(self):
        """Ensure our test data is valid"""
        for keys, finger in self.nodes:
            self.assertEqual(keys.export(), finger.key)

    def test_encrypt_decypt(self):
        """Test the encryption and decryption using public-private keys"""
        from itertools import product
        test_data_1 = "Data length 32 repeated 64 times" * 64  # 2048 bytes
        test_data_2 = "Data leng 32 repeated 512 times." * 512  # 16384 bytes
        for idx, (data_a, data_b) in enumerate(
                product(self.nodes, self.nodes), 1):
            node_a = ConnHandleInit(data_a[0], data_a[1], data_b[1])
            node_b = ConnHandleInit(data_b[0], data_b[1], data_a[1])

            cryptic = node_a.foreign_key.encrypt(test_data_1)
            decryptic = node_b.local_keys.decrypt(cryptic)
            self.assertEqual(test_data_1, decryptic)

            cryptic = node_a.foreign_key.encrypt(test_data_2)
            decryptic = node_b.local_keys.decrypt(cryptic)
            self.assertEqual(test_data_2, decryptic)

    def test_package_unpack(self):
        """Test the packaging and unpackaging of pickled data"""
        test_data_1 = "Data length 32 repeated 64 times" * 64  # 2048 bytes
        test_data_2 = "Data leng 32 repeated 512 times." * 512  # 16384 bytes
        test_dict_1 = {'td': test_data_1}
        test_dict_2 = {'td': test_data_2}
        for idx, (data_a, data_b) in enumerate(
                product(self.nodes, self.nodes), 1):
            print 'Pair #%d' % (idx,)
            node_a = ConnHandleInit(data_a[0], data_a[1], data_b[1])
            node_b = ConnHandleInit(data_b[0], data_b[1], data_a[1])

            cryptic = node_a.package(Protocol.Message, test_dict_1)
            foreign, msg, decryptic = node_b.unpack(cryptic)
            self.assertEqual(Protocol.Message, msg)
            self.assertEqual(test_data_1, decryptic['td'])

            cryptic = node_a.package(Protocol.Message, test_dict_2)
            foreign, msg, decryptic = node_b.unpack(cryptic)
            self.assertEqual(Protocol.Message, msg)
            self.assertEqual(test_data_2, decryptic['td'])

    def test_send_invalid_data(self):
        """Ensure that sending invalid data causes an error."""
        data_a, data_b = self.nodes[0:2]
        con = ConnHandleInit(data_a[0], data_a[1], data_b[1])
        self.assertRaises(ProtocolError, con.send, *("Send", {}))
        self.assertRaises(AttributeError, con.send, *(Protocol.Message,
                                                      "Hello error!"))

    def test_verification_message(self):
        """Ensure that messages are verified properly."""
        data_a, data_b = self.nodes[0:2]
        con = ConnHandleInit(data_a[0], data_a[1], data_b[1])

        self.assertRaises(ProtocolError, con._verify_message, 'Tim', {})
        self.assertRaises(ProcedureError, con._verify_message,
                          Protocol.Ping, {}, Protocol.Pong)
        self.assertRaises(ProtocolError, con._verify_message, Protocol.Ping,
                          {'tim': 'bob'})


class MessageHandlingTests(unittest.TestCase):
    """Test the functions of the MessageHandler class"""
    def setUp(self):
        test_data_path = (__file__.rpartition('/')[0]
                          + "/_testdata_protocol.pickle")
        with open(test_data_path) as handle:
            test_data = pickle.load(handle)
        self.nodes = []  # Gives 5 test nodes
        for val in test_data:
            finger = Finger(val['ip'], val['port'], val['pub'])
            keys = CipherWrap(val['priv'])  # Private Key
            self.nodes.append((finger, keys))  # self.nodes structure

    def test_initial_pack(self):
        """Test direct message passing"""
        for idx, ((fng_a, key_a), (fng_b, key_b)) in enumerate(
                product(self.nodes, self.nodes), 1):
            node_a = MessageHandler(Mock(), None, fng_a, key_a)
            node_b = IncomingConnection(Mock(), None, fng_a.address,
                                        None, fng_b, key_b)

            test_msg = "The quick brown fox jumped over the lazy dog."

            cryptic_data = node_a._build_message(fng_b, test_msg)

            cipher = CipherWrap(key_b.export(True, 1))
            # unpacked = cipher.decrypt(cryptic_data)
            # obj = pickle.loads(unpacked)
            unpacked = node_b._peel_onion_layer(cryptic_data)
            # self.assertEqual(test_msg, obj['MESSAGE'])
            self.assertEqual(test_msg, unpacked['MESSAGE'])
