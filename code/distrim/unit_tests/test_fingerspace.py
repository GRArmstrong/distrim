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

# pylint: disable=protected-access

"""
    Protocol tests, ensures the protocol is handled as we expect.
"""


import unittest
import itertools
import socket

from threading import Thread
from mock import Mock
from Crypto.PublicKey import RSA

from ..utils.utilities import SocketWrapper
from ..fingerspace import (FingerSpace, Finger, generate_hash,
                           finger_type_test, h2i)
from ..assets.errors import FingerSpaceError, FingerError, HashMissmatchError


def a2b(ascii_key):
    """Transforms ASCII public key into a binary one"""
    key = RSA.importKey(ascii_key)
    return key.exportKey(format='DER')


class FunctionTests(unittest.TestCase):
    """
    Checks that the hash function used to assign node IDs is predictable
    """
    def test_hash_ident(self):
        """Test valid data when hasing the ident."""
        addr = '192.168.5.35'
        port = 6050
        pub_key = """-----BEGIN PUBLIC KEY-----
            MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+J6zqvL6MHP1Fpn7hmP3xQV/z
            FaZ6p2puVJBaMhwLCh4zTbYlyo/J19Spc9+uqmcFE0z4QEN3AjRdSXvgRH4Qdvvh
            pc9b47cYAUnDd27QIZ/U/FvTcb+Fjhhb3zb+FFvykzGO1YobhaYXQKlnZuFiBq2Z
            JJrG7JW3onqtfHFi4wIDAQAB
            -----END PUBLIC KEY-----"""
        expected = "0f54"

        bin_key = a2b(pub_key)

        result = generate_hash(addr, port, bin_key)
        self.assertEqual(expected, result)

    def test_finger_type_test(self):
        """Tests the :func:`finger_type_test` function."""
        addr = '192.168.5.35'
        port = 6050
        pub_key = """-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC+J6zqvL6MHP1Fpn7hmP3xQV/z
FaZ6p2puVJBaMhwLCh4zTbYlyo/J19Spc9+uqmcFE0z4QEN3AjRdSXvgRH4Qdvvh
pc9b47cYAUnDd27QIZ/U/FvTcb+Fjhhb3zb+FFvykzGO1YobhaYXQKlnZuFiBq2Z
JJrG7JW3onqtfHFi4wIDAQAB
-----END PUBLIC KEY-----"""

        bin_key = a2b(pub_key)

        self.assertTrue(finger_type_test(addr, port, bin_key))

        # Types
        with self.assertRaises(FingerError) as exc:
            finger_type_test(192, 6050, bin_key)
        self.assertEqual("ip_address must be a string", exc.exception.message)

        with self.assertRaises(FingerError) as exc:
            finger_type_test('192.168.5.35', '6050', bin_key)
        self.assertEqual("listening_port must be an int",
                         exc.exception.message)

        with self.assertRaises(FingerError) as exc:
            finger_type_test('192.168.5.35', 6050, (bin_key,))
        self.assertEqual("public_key must be a string", exc.exception.message)

        # Values
        with self.assertRaises(FingerError) as exc:
            finger_type_test('localhost', 6050, bin_key)
        self.assertEqual("Invalid IPv4 address: 'localhost'",
                         exc.exception.message)

        with self.assertRaises(FingerError) as exc:
            finger_type_test('192.168.5.35', -6050, bin_key)
        self.assertEqual("invalid port number '-6050'. Must be between"
                         + " 1 and 65535", exc.exception.message)

        with self.assertRaises(FingerError) as exc:
            finger_type_test('192.168.5.35', 6050, pub_key)
        self.assertEqual("public_key must be in binary format",
                         exc.exception.message)

        with self.assertRaises(FingerError) as exc:
            finger_type_test('192.168.5.35', 6050, 'pub_key')
        self.assertTrue(
            exc.exception.message.startswith("public_key is not valid:"))

        private_key = RSA.generate(1024).exportKey(format='DER')
        with self.assertRaises(FingerError) as exc:
            finger_type_test('192.168.5.35', 6050, private_key)
        self.assertTrue(exc.exception.message ==
                        "!!!This is a private key, not public!!!")

    def test_hex_to_int(self):
        """Tests the h2i function"""
        self.assertEquals(h2i('2a'), 42)
        self.assertEquals(h2i('2e'), 46)
        self.assertEquals(h2i('3f2a'), 16170)
        self.assertRaises(ValueError, h2i, 'qa3edsv')
        self.assertRaises(TypeError, h2i, None)


class FingerTests(unittest.TestCase):
    """Test valid creation of a :class:`Finger` object."""
    def test_valid_finger(self):
        """Create fingers with valid data"""
        pubkey = RSA.generate(1024).publickey().exportKey(format='DER')
        obj = Finger('192.168.0.1', 2000, pubkey)
        self.assertIsInstance(obj, Finger)

    def test_invalid_finger(self):
        """Create fingers with invalid data, expect exceptions"""
        pubkey = RSA.generate(1024).publickey()
        valid_key = pubkey.exportKey(format='DER')
        invalid_key = pubkey.exportKey()

        ips = ['192.168.0.1', None, '', 'localhost', (192, 168, 0, 1)]
        ports = [2000, None, '', '2050', 9999999, -2000]
        keys = [valid_key, None, '', '2050', invalid_key]

        vals = list(itertools.product(ips, ports, keys))

        vals.remove(('192.168.0.1', 2000, valid_key))

        for addr, port, key in vals:
            # with self.assertRaises(FingerError):
            #     Finger(addr, port, key)
            #     print addr, port
            self.assertRaises(FingerError, Finger, addr, port, key)

    def test_hash_mismatch(self):
        """Tests invalid hash"""
        pubkey = RSA.generate(1024).publickey().exportKey(format='DER')
        self.assertRaises(HashMissmatchError, Finger, '192.168.0.1',
                          2050, pubkey, 'Invalid Hash')

    def test_get_cipher(self):
        """Tests the :func:`get_cipher` method :class:`Finger`"""
        from ..utils.utilities import CipherWrap
        keys = CipherWrap(RSA.generate(1024))
        pubkey = keys.export()
        obj = Finger('192.168.0.1', 2000, pubkey)

        test_data = "This is a beep boop"
        cipher = obj.get_cipher()
        enc_data = cipher.encrypt(test_data)
        self.assertEqual(keys.decrypt(enc_data), test_data)


class FingerSocketTest(unittest.TestCase):
    """Tests the :func:`get_socket` method of :class:`Finger`."""
    def setUp(self):
        """
        Setup to execute before each test.
        """
        from time import sleep
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind(('localhost', 0))
        self.listener.listen(0)
        self.listen_thread = Thread(target=self._listen)
        self.listen_thread.start()

        sleep(0.1)  # Momentary pause while the listening socket becomes ready

        pubkey = RSA.generate(1024).publickey().exportKey(format='DER')
        port = self.listener.getsockname()[1]
        self.finger = Finger('127.0.0.1', port, pubkey)

    def _listen(self):
        """
        In a seperate thread, await a connection
        """
        local, address = self.listener.accept()
        self.local = SocketWrapper(local)

    def tearDown(self):
        """
        Cleanup after each test.
        """
        self.listener.shutdown(socket.SHUT_RDWR)
        self.listener.close()
        self.local.close()

    def test_get_socket(self):
        """
        Receive basic data.
        """
        sock = self.finger.get_socket()
        sock.connect()
        self.listen_thread.join()
        data = '12345678'
        sock.send(data)
        self.assertEqual(self.local.receive(8), data)
        sock.close()


class FingerSpaceTests(unittest.TestCase):
    """Tests the FingerSpace class itself"""
    def setUp(self):
        """Load in test data"""
        import cPickle as pickle
        test_data_path = (__file__.rpartition('/')[0]
                          + '/_testdata_fingerspace.pickle')
        with open(test_data_path) as hand:
            nodes = pickle.load(hand)
        self.local_finger = Finger(*nodes[0])
        self.test_node_list = nodes[1:]
        self.mock_log = Mock()

    def tearDown(self):
        """Test our mock_log each time"""
        self.mock_log.getChild.assert_called_with('fingerspace')

    def test_init_add(self):
        """Initilise and add data"""
        fs1 = FingerSpace(self.mock_log, self.local_finger)
        for addr, port, key in self.test_node_list:
            fs1.put(addr, port, key)

        fs2 = FingerSpace(self.mock_log, self.local_finger)
        for addr, port, key in self.test_node_list:
            ident = generate_hash(addr, port, key)
            fs2.put(addr, port, key, ident)

    def test_add_invalid(self):
        """Tests invalid hash error"""
        invalid_hash = "This is an invalid hash"

        fsi = FingerSpace(self.mock_log, self.local_finger)
        for addr, port, key in self.test_node_list:
            with self.assertRaises(HashMissmatchError):
                fsi.put(addr, port, key, invalid_hash)

    def test_add_valid_duplicate(self):
        """Tests when adding identicle fingers, second is ignored"""
        fsi = FingerSpace(self.mock_log, self.local_finger)
        addr, port, key = self.test_node_list[0]
        self.assertEqual(len(fsi), 0)
        fsi.put(addr, port, key)
        self.assertEqual(len(fsi), 1)
        fsi.put(addr, port, key)
        self.assertEqual(len(fsi), 1)

    def test_add_invalid_duplicate(self):
        """Tests when two different fingers have same hash, logs warning"""
        fsi = FingerSpace(self.mock_log, self.local_finger)
        addr, port, key = self.test_node_list[0]
        bad_finger = Finger(addr, port, key)
        bad_finger.addr = '0.0.0.0'
        bad_finger.port = 0
        fsi._keyspace[h2i(bad_finger.ident)] = bad_finger
        self.assertEqual(fsi.log.warning.call_count, 0)
        fsi.put(addr, port, key)
        self.assertEqual(fsi.log.warning.call_count, 1)

    def test_add_self(self):
        """Tests that it's considered an error """
        fsi = FingerSpace(self.mock_log, self.local_finger)
        addr, port, key = self.local_finger.values
        fsi.put(addr, port, key)
        self.assertEqual(fsi.log.warning.call_count, 1)

    def test_single_finger(self):
        """Tests adding, getting, and removing a Finger"""
        addr, port, key = self.test_node_list[0]
        finger = Finger(addr, port, key)
        ident = finger.ident
        fsi = FingerSpace(self.mock_log, self.local_finger)

        fsi.put(addr, port, key)
        self.assertTrue(len(fsi._keyspace.keys()) == 1)
        self.assertEqual(finger, fsi._keyspace[h2i(ident)])

        self.assertEqual(fsi.get(ident), finger)

        self.assertTrue(fsi.remove(ident))
        self.assertTrue(len(fsi._keyspace.keys()) == 0)

    def test_empty(self):
        """Tests an empty FingerSpace"""
        fsi = FingerSpace(self.mock_log, self.local_finger)
        self.assertEqual(fsi.get('abcd'), None)
        self.assertFalse(fsi.remove('abcd'))
        self.assertRaises(FingerSpaceError, fsi.get_random_fingers, 1)

    def test_path(self):
        """Test ability for path creation"""
        fsi = FingerSpace(self.mock_log, self.local_finger)
        for addr, port, key in self.test_node_list:
            fsi.put(addr, port, key)

        all_fingers = [x[1] for x in fsi._keyspace.items()]

        lengths = [1, 2, 5, 10, 14]
        for length in lengths:
            path = fsi.get_random_fingers(length)
            self.assertEqual(len(path), length)
            for finger in path:
                self.assertIn(finger, all_fingers)

        self.assertRaises(ValueError, fsi.get_random_fingers, 0)

        path = fsi.get_random_fingers(5000)
        self.assertEqual(len(path), len(self.test_node_list))

    def test_import_and_export(self):
        """Tests importing and exporting values."""
        fs1 = FingerSpace(self.mock_log, self.local_finger)
        for values in self.test_node_list:
            fs1.put(*values)

        expected = [Finger(*node).all for node in self.test_node_list]
        gotten = fs1.export_nodes()
        expected.sort()
        gotten.sort()
        self.assertListEqual(gotten, expected)
        fs2 = FingerSpace(self.mock_log, self.local_finger)
        fs2.import_nodes(expected)
        self.assertDictEqual(fs1._keyspace, fs2._keyspace)
        self.assertFalse(self.mock_log.warning.called)

    def test_get_all(self):
        """Test the get_all function"""
        fsi = FingerSpace(self.mock_log, self.local_finger)
        for addr, port, ident in self.test_node_list:
            fsi.put(addr, port, ident)

        fingers = fsi.get_all()
        expected = [Finger(*pars) for pars in self.test_node_list]

        for finger in expected:
            out = fsi.get(finger.ident)
            self.assertIn(out, fingers)
