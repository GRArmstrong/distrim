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
from Crypto.PublicKey import RSA

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
        expected = "70e0"

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


class FingerSpaceTests(unittest.TestCase):
    """Tests the FingerSpace class itself"""
    def setUp(self):
        """Load in test data"""
        if not hasattr(self, 'test_node_list'):
            import cPickle as pickle
            test_data_path = (__file__.rpartition('/')[0]
                              + '/testdata_fingerspace.pickled.bin')
            with open(test_data_path) as hand:
                self.test_node_list = pickle.load(hand)

    def test_init_add(self):
        """Initilise and add data"""
        fs1 = FingerSpace()
        for addr, port, key in self.test_node_list:
            fs1.put(addr, port, key)

        fs2 = FingerSpace()
        for addr, port, key in self.test_node_list:
            ident = generate_hash(addr, port, key)
            fs2.put(addr, port, key, ident)

    def test_add_invalid(self):
        """Tests invalid hash error"""
        invalid_hash = "This is an invalid hash"

        fsi = FingerSpace()
        for addr, port, key in self.test_node_list:
            with self.assertRaises(HashMissmatchError):
                fsi.put(addr, port, key, invalid_hash)

    def test_single_finger(self):
        """Tests adding, getting, and removing a Finger"""
        addr, port, key = self.test_node_list[0]
        finger = Finger(addr, port, key)
        ident = finger.ident
        fsi = FingerSpace()

        fsi.put(addr, port, key)
        self.assertTrue(len(fsi._keyspace.keys()) == 1)
        self.assertEqual(finger, fsi._keyspace[h2i(ident)])

        self.assertEqual(fsi.get(ident), finger)

        self.assertTrue(fsi.remove(ident))
        self.assertTrue(len(fsi._keyspace.keys()) == 0)

    def test_empty(self):
        """Tests an empty FingerSpace"""
        fsi = FingerSpace()
        self.assertEqual(fsi.get('abcd'), None)
        self.assertFalse(fsi.remove('abcd'))
        self.assertRaises(FingerSpaceError, fsi.get_random_fingers, 1)

    def test_path(self):
        """Test ability for path creation"""
        fsi = FingerSpace()
        for addr, port, key in self.test_node_list:
            fsi.put(addr, port, key)

        lengths = [1, 2, 5, 10, 15]
        for length in lengths:
            path = fsi.get_random_fingers(length)
            self.assertEqual(len(path), length)
            for finger in path:
                self.assertIn(finger, fsi._keyspace.items())

        self.assertRaises(ValueError, fsi.get_random_fingers, 0)

        path = fsi.get_random_fingers(5000)
        self.assertEqual(len(path), len(self.test_node_list))
