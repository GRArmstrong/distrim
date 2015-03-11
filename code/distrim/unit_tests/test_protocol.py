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
import struct
from threading import Thread

from ..protocol import Protocol, SocketWrapper
from ..assets.errors import ProtocolError

class ProtocolTest(unittest.TestCase):

    def test_protocol_definition(self):
        """
        Sanity test for the class :class:`Protocol`.
        """
        # Combine known attributes in the class
        attrs = [attr for attr in dir(Protocol) if not attr.startswith('_')]
        attrs.remove('ALL')
        attrs.sort()

        # Create an instance of that class for attribute checking
        proc = Protocol()

        remaining_attributes = [atr for atr in attrs]
        found_attribute_vals = []

        # Test that all attributes are in ALL
        self.assertTrue(len(Protocol.ALL) == len(remaining_attributes))

        for idx, attribute in enumerate(attrs):
            value = proc.__getattribute__(attribute)
            #self.assertIn(value, Protocol.ALL)
            self.assertEqual(Protocol.ALL[idx], value)
            found_attribute_vals.append(value)
            remaining_attributes.remove(attribute)

        self.assertTrue(len(remaining_attributes) == 0)

        # Test that attributes are valid for the protocol
        for attribute in found_attribute_vals:
            self.assertEqual(len(attribute), 4)
            self.assertEqual(attribute.upper(), attribute)
            self.assertIn(attribute, Protocol.ALL)


class WrapperTest(unittest.TestCase):

    def setUp(self):
        """
        Setup to execute before each test.
        """
        from time import sleep
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('localhost', 0))
        self.listener.listen(0)
        listen_thread = Thread(target=self._listen)
        listen_thread.start()

        sleep(0.1)  # Momentary pause while the listening socket becomes ready

        self.foreign = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.foreign.connect(('localhost', self.listener.getsockname()[1]))
        listen_thread.join()

    def _listen(self):
        """
        In a seperate thread, await a connection
        """
        self.local, address = self.listener.accept()

    def tearDown(self):
        """
        Cleanup after each test.
        """
        self.foreign.shutdown(socket.SHUT_RD)
        self.foreign.close()
        self.listener.shutdown(socket.SHUT_RD)
        self.listener.close()
        self.local.shutdown(socket.SHUT_RD)
        self.local.close()

    def test_receive(self):
        """
        Receive basic data.
        """
        test_str = "Testing String 123. Testing String ABC."
        wrapper = SocketWrapper(self.local, None, None, timeout=3)
        data_len = struct.pack(">L", len(test_str))
        package = data_len + test_str
        self.foreign.sendall(package)
        self.assertEqual(wrapper._sock_receive(), test_str)

        # Test big data with 79872 bytes transfered
        big_data = test_str * 2048
        data_len = struct.pack(">L", len(big_data))
        package = data_len + big_data
        self.foreign.sendall(package)
        self.assertEqual(wrapper._sock_receive(), big_data)

    def test_send(self):
        """
        Send basic data
        """
        test_str = "Testing String 123. Testing String ABC."
        wrapper = SocketWrapper(self.local, None, None, timeout=3)
        wrapper._sock_send(test_str)
        fetched = self.foreign.recv(1024)
        length = struct.unpack(">L", fetched[:4])[0]
        self.assertEqual(length, len(fetched[4:]))

    def test_send_receive(self):
        """
        Test two sockets sending and receiving
        """
        w_local = SocketWrapper(self.local, None, None, timeout=5)
        w_foreign = SocketWrapper(self.foreign, None, None, timeout=5)

        test_str = "Testing String 123. Testing String ABC."
        w_foreign._sock_send(test_str)
        w_local._sock_send(test_str)
        self.assertEqual(w_foreign._sock_receive(), test_str)
        self.assertEqual(w_local._sock_receive(), test_str)

    def test_pack_unpack_procedure(self):
        """
        Tests the :method:`fetch` and :method:`send` methods of
        :class:`SocketWrapper`.
        """
        from Crypto.PublicKey import RSA

        local_keys = RSA.generate(1024)
        local_pubkey = local_keys.publickey()

        w_local = SocketWrapper(self.local, None, local_keys, timeout=5)
        w_foreign = SocketWrapper(self.foreign, None, None, timeout=5)
        w_foreign.foreign_key = local_pubkey

        test_params = {'testcase': 'this dict'}
        w_foreign.send(Protocol.Ping, test_params)
        message_type, params = w_local.fetch()
        self.assertEqual(message_type, Protocol.Ping)
        self.assertDictEqual(params, test_params)


class WrapperInvalidTests(unittest.TestCase):

    def test_send_invalid_data(self):
        """
        Ensure that sending invalid data causes an error.
        """
        wrap = SocketWrapper(socket.socket(), None, None)
        self.assertRaises(ProtocolError, wrap.send, *("Send", {}))
        self.assertRaises(ProtocolError, wrap.send, *(Protocol.Message,
                                                      "Hello error!"))

    def test_receive_invalid_data(self):
        """
        Ensure that receiving invalid data causes an error.
        """
        from Crypto.PublicKey import RSA

        def sub_func1():
            return "subbers"

        def sub_func2():
            return None

        local_keys = RSA.generate(1024)
        wrap = SocketWrapper(socket.socket(), None, local_keys)
        wrap._sock_receive = sub_func1
        self.assertRaises(ProtocolError, wrap.fetch)

        wrap._sock_receive = sub_func2
        self.assertRaises(ProtocolError, wrap.fetch)
