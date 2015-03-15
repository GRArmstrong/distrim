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

from argparse import ArgumentTypeError
from Crypto.PublicKey import RSA

from ...assets.errors import InvalidIPAddressError, CipherError

from ..utilities import (CipherWrap, parse_ip, split_address, generate_padding,
                         split_chunks, format_elapsed)


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
        """Expect success"""
        test = "This string will be split."
        expected = ["This ", "strin", "g wil", "l be ", "split", "."]
        results = []
        for result in split_chunks(test, 5):
            results.append(result)
        self.assertListEqual(results, expected)


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
