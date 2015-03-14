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

from ..utilities import (parse_ip, split_address, generate_padding,
                         split_chunks, format_elapsed)


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
