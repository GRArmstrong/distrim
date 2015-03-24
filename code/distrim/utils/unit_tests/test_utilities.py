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
    Test cases for utility functions.
"""


import unittest

import socket
import struct
from time import sleep
from threading import Thread
from argparse import ArgumentTypeError
from Crypto.PublicKey import RSA

from ...assets.errors import InvalidIPAddressError, CipherError, SockWrapError

from ..utilities import (SocketWrapper, CipherWrap, parse_ip, split_address,
                         generate_padding, split_chunks, format_elapsed)


class SocketWrapperListenTest(unittest.TestCase):
    """Tests the :class:`SocketWrapper` class with a listener that creates
    a local socket."""
    def setUp(self):
        """
        Setup to execute before each test.
        """
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
        self.foreign.shutdown(socket.SHUT_RDWR)
        self.foreign.close()
        self.listener.shutdown(socket.SHUT_RDWR)
        self.listener.close()
        self.local.shutdown(socket.SHUT_RDWR)
        self.local.close()

    def test_receive(self):
        """
        Receive basic data.
        """
        test_str = "Testing String 123. Testing String ABC."
        wrapper = SocketWrapper(sock=self.local, timeout=3)
        data_len = struct.pack(">L", len(test_str))
        package = data_len + test_str
        self.foreign.sendall(package)
        self.assertEqual(wrapper.receive(), test_str)

        # Test big data with 79872 bytes transfered
        big_data = test_str * 2048
        data_len = struct.pack(">L", len(big_data))
        package = data_len + big_data
        self.foreign.sendall(package)
        self.assertEqual(wrapper.receive(), big_data)

    def test_send(self):
        """
        Send basic data
        """
        test_str = "Testing String 123. Testing String ABC."
        wrapper = SocketWrapper(sock=self.local, timeout=3)
        wrapper.send(test_str)
        fetched = self.foreign.recv(1024)
        length = struct.unpack(">L", fetched[:4])[0]
        self.assertEqual(length, len(fetched[4:]))

    def test_send_receive(self):
        """
        Test two sockets sending and receiving
        """
        w_local = SocketWrapper(sock=self.local, timeout=3)
        w_foreign = SocketWrapper(sock=self.foreign, timeout=3)

        test_str = "Testing String 123. Testing String ABC."
        w_foreign.send(test_str)
        w_local.send(test_str)
        self.assertEqual(w_foreign.receive(), test_str)
        self.assertEqual(w_local.receive(), test_str)


class SocketWrapperConnTest(unittest.TestCase):
    """Tests the :class:`SocketWrapper` class with a listener only."""
    def setUp(self):
        """
        Setup to execute before each test.
        """
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('localhost', 0))
        self.listener.listen(0)
        self.addr = self.listener.getsockname()
        self.listen_thread = Thread(target=self._listen)
        self.listen_thread.start()

    def _listen(self):
        """
        In a seperate thread, await a connection
        """
        self.sock, address = self.listener.accept()

    def tearDown(self):
        """
        Cleanup after each test.
        """
        try:
            self.listener.shutdown(socket.SHUT_RDWR)
            self.listener.close()
        except socket.error:
            pass

    def test_init_none(self):
        """Init with nothing."""
        wrap = SocketWrapper()
        self.assertFalse(wrap.is_connected())
        wrap.connect(self.addr)
        self.listen_thread.join()
        self.assertTrue(wrap.is_connected())
        wrap2 = SocketWrapper(self.sock)
        self.assertTrue(wrap2.is_connected())

        test_str = "Testing String 123. Testing String ABC."
        wrap.send(test_str)
        wrap2.send(test_str)
        self.assertEqual(wrap.receive(), test_str)
        self.assertEqual(wrap2.receive(), test_str)

        wrap.close()
        wrap2.close()
        self.assertFalse(wrap.is_connected())
        self.assertFalse(wrap2.is_connected())

    def test_init_sock(self):
        """init with a socket"""
        wrap = SocketWrapper(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        self.assertFalse(wrap.is_connected())
        wrap.connect(self.addr)
        self.listen_thread.join()
        self.assertTrue(wrap.is_connected())
        wrap.close()

    def test_init_addr(self):
        """init with an address"""
        wrap = SocketWrapper(remote_address=self.addr)
        self.assertFalse(wrap.is_connected())
        wrap.connect()
        wrap.connect()  # Attempting to connect while connected is harmless
        self.listen_thread.join()
        self.assertTrue(wrap.is_connected())
        wrap.close()

    def test_close_error(self):
        """test errors when closing"""
        wrap = SocketWrapper(timeout=1)
        wrap.connect(self.addr)
        self.listen_thread.join()
        self.listener.close()
        with self.assertRaises(SockWrapError) as exc:
            wrap.receive()
        self.assertEqual(exc.exception.message,
                         "Error attempting to receive data.")


class SocketWrapperNoSockTest(unittest.TestCase):
    """Tests the :class:`SocketWrapper` class without external sockets."""
    def test_no_remote_addr(self):
        """Test no remote address"""
        wrap = SocketWrapper()
        with self.assertRaises(SockWrapError) as exc:
            wrap.connect()
        self.assertEqual(exc.exception.message,
                         "Connect to what? No remote address.")

    def test_not_connected(self):
        """Test no remote address"""
        wrap = SocketWrapper()
        with self.assertRaises(SockWrapError) as exc:
            wrap.send("Message")
        self.assertEqual(exc.exception.message,
                         "Can't use socket, it's not connected.")

        with self.assertRaises(SockWrapError) as exc:
            wrap.receive()
        self.assertEqual(exc.exception.message,
                         "Can't use socket, it's not connected.")


class TestCipherWrap(unittest.TestCase):
    """Tests the :class:`CipherWrap` class."""
    def test_public(self):
        """Test init and export functions with public key"""
        pk1 = RSA.generate(1024).publickey()  # _RSAobj Instance
        pk2 = pk1.exportKey()  # Text Format
        pk3 = pk1.exportKey(format='DER')  # Binary Format

        cw1 = CipherWrap(pk1)
        cw2 = CipherWrap(pk2)
        cw3 = CipherWrap(pk3)

        # We expect the instance to be created without error
        self.assertIsInstance(cw1, CipherWrap)
        self.assertIsInstance(cw2, CipherWrap)
        self.assertIsInstance(cw3, CipherWrap)

        self.assertEqual(cw1.export(), cw2.export())
        self.assertEqual(cw1.export(), cw3.export())
        self.assertEqual(pk2, cw1.export(text=True))
        self.assertEqual(pk3, cw1.export())
        self.assertFalse(cw1._has_private)
        self.assertFalse(cw2._has_private)
        self.assertFalse(cw3._has_private)

    def test_private(self):
        """Test init and export functions with private key"""
        pk1 = RSA.generate(1024)  # _RSAobj Instance
        pk2 = pk1.exportKey()  # Text Format
        pk3 = pk1.exportKey(format='DER')  # Binary Format

        tup1 = (pk1.publickey().exportKey(format='DER'),
                pk1.exportKey(format='DER'))

        tup2 = (pk1.publickey().exportKey(format='PEM'),
                pk1.exportKey(format='PEM'))

        # We expect the instance to be created without error
        cw1 = CipherWrap(pk1)
        cw2 = CipherWrap(pk2)
        cw3 = CipherWrap(pk3)
        self.assertTrue(cw1._has_private)
        self.assertTrue(cw2._has_private)
        self.assertTrue(cw3._has_private)

        self.assertEqual(cw1.export(), cw2.export())
        self.assertEqual(cw1.export(), cw3.export())
        self.assertEqual(tup1, cw3.export(key_type=2))
        self.assertEqual(tup2, cw3.export(text=True, key_type=2))

    def test_encrypt_decrypt(self):
        """Test the encryption and decryption methods"""
        keys = RSA.generate(1024)  # _RSAobj Instance
        private = CipherWrap(keys)
        public = CipherWrap(private.export())

        test_data = "This was a failure test who knows what."
        crypted = public.encrypt(test_data)
        self.assertEqual(private.decrypt(crypted), test_data)

    def test_encrypt_decrypt_big(self):
        """Test the encryption and decryption methods"""
        keys = RSA.generate(1024)  # _RSAobj Instance
        private = CipherWrap(keys)
        public = CipherWrap(private.export())

        test_data = "Data leng 32 repeated 2048 times" * 2048  # 65536 bytes
        crypted = public.encrypt(test_data)
        self.assertEqual(private.decrypt(crypted), test_data)

    def test_invalid_init(self):
        """Test exceptions when creating an instance"""
        with self.assertRaises(CipherError) as exc:
            CipherWrap("NO TIMMY! DON'T DO THAT!")
        self.assertEqual(exc.exception.message, "Not a valid cipher string.")

        with self.assertRaises(CipherError) as exc:
            CipherWrap(('well this is an error',))
        self.assertEqual(exc.exception.message, "Not a valid cipher.")

    def test_invalid_input(self):
        """Test exceptions when using an instance"""
        private = CipherWrap(RSA.generate(1024))
        public = CipherWrap(private.export())

        for _kt in [1, 2]:
            with self.assertRaises(CipherError) as exc:
                public.export(key_type=_kt)
            self.assertEqual(exc.exception.message,
                             "Requested non-existant private key.")

        for _kt in [-1, 3, '0']:
            with self.assertRaises(ValueError) as exc:
                public.export(key_type=_kt)
            self.assertEqual(exc.exception.message,
                             "Value for param 'key_type' must be in [0, 1, 2]")

        with self.assertRaises(CipherError) as exc:
            public.decrypt('anything')
        self.assertEqual(exc.exception.message,
                         "Can't decrypt, no private key!")


class TestParseIP(unittest.TestCase):
    """Tests the Parse IP function"""
    def test_valid_ip(self):
        """Expect success"""
        self.assertEqual(((192, 168, 3, 4), 81), parse_ip("192.168.3.4:81"))

    def test_invalid_ip(self):
        """Expect failure"""
        self.assertRaises(InvalidIPAddressError, parse_ip, "192.999.0.1:82")


class TestAddressSplit(unittest.TestCase):
    """Tests the address split function"""
    def test_valid(self):
        """Expect success"""
        valid_tests = [
            ("localhost", ("localhost", None)),
            ("192.168.0.6", ("192.168.0.6", None)),
            ("localhost:2000", ("localhost", 2000)),
            ("192.168.0.5:3000", ("192.168.0.5", 3000)),
            ("stevie-bob:99999", ("stevie-bob", 99999)),
        ]
        for test_data, expected in valid_tests:
            self.assertEqual(split_address(test_data), expected)

    def test_invalid(self):
        """Expect failure"""
        invalid_tests = [
            "barry:brought:bacon",
            "192.168.0.1:default",
            "anything::"
            "hostname:"
        ]
        for test_data in invalid_tests:
            self.assertRaises(ArgumentTypeError, split_address, test_data)


class TestPadding(unittest.TestCase):
    """Tests the padding function"""
    def test_padding(self):
        """Test the padding function for correct output"""
        len_min = 64
        len_max = 1024
        test_values = [generate_padding() for cnt in xrange(50)]
        for value in test_values:
            self.assertGreaterEqual(len(value), len_min)
            self.assertLessEqual(len(value), len_max)


class TestSplitChunks(unittest.TestCase):
    """Tests the split chunks function"""
    def test_split(self):
        """Test the values in each part of the split list"""
        test = "This string will be split."
        expected = ["This ", "strin", "g wil", "l be ", "split", "."]
        results = []
        for result in split_chunks(test, 5):
            results.append(result)
        self.assertListEqual(results, expected)

    def test_lengths(self):
        """Ensure the lengths are what we expect."""
        test_list = range(1048641)  # 1024*1024 + 65
        chunks = split_chunks(test_list, 1024)
        self.assertEqual(1025, len(list(chunks)))
        for idx, chunk_gen in enumerate(chunks):
            chunk = list(chunk_gen)
            start = idx * 1024
            if idx == 1024:
                end = 1048640
                self.assertEqual(1024, len(65))
            else:
                end = start + 1023
                self.assertEqual(1024, len(chunk))
            self.assertEqual(start, chunk[0])
            self.assertEqual(end, chunk[-1])


class TestTimeDeltaFormat(unittest.TestCase):
    """Test timedelta utility function :func:`format_elapsed`"""
    def test_format(self):
        """Test it formats correctly"""
        from datetime import timedelta

        # days, seconds, microseconds, milliseconds, minutes, hours
        test_cases = [
            ((0, 34, 0, 0, 15, 0), "0h 15m 34s"),
            ((0, 0, 0, 0, 0, 0), "0h 0m 0s"),
            ((1, 0, 0, 0, 0, 0), "1 days, 0h 0m 0s"),
            ((1, 12, 0, 0, 55, 9), "1 days, 9h 55m 12s"),
        ]

        for params, expected in test_cases:
            tdo = timedelta(*params)
            self.assertEqual(expected, format_elapsed(tdo))
