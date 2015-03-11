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
from ...assets.errors import InvalidIPAddressError

from ..utilities import parse_ip, split_address, generate_padding, split_chunks


class TestParseIP(unittest.TestCase):

    def test_valid_ip(self):
        self.assertEqual(((192,168,3,4),81), parse_ip("192.168.3.4:81"))

    def test_invalid_ip(self):
        self.assertRaises(InvalidIPAddressError, parse_ip, "192.999.0.1:82")


class TestAddressSplit(unittest.TestCase):

    def test_valid(self):
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
        invalid_tests = [
            "barry:brought:bacon",
            "192.168.0.1:default",
            "anything::"
            "hostname:"
        ]
        for test_data in invalid_tests:
            self.assertRaises(ArgumentTypeError, split_address, test_data)        


class TestPadding(unittest.TestCase):

    def test_padding(self):
        len_min = 64
        len_max = 1024
        test_values = [generate_padding() for cnt in xrange(50)]
        for value in test_values:
            self.assertGreaterEqual(len(value), len_min)
            self.assertLessEqual(len(value), len_max)

class TestSplitChunks(unittest.TestCase):

    def test_split(self):
        test = "This string will be split."
        expected = ["This ", "strin", "g wil", "l be ", "split", "."]
        results = []
        for result in split_chunks(test, 5):
            results.append(result)
        self.assertListEqual(results, expected)
