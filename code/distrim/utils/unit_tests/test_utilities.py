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
    Initial Execution Tests
"""


import unittest


from ..utilities import parse_ip

from ...assets.errors import InvalidIPAddressError


class TestParseIP(unittest.TestCase):

    def test_valid_ip(self):
        self.assertEqual(((192,168,3,4),81), parse_ip("192.168.3.4:81"))

    def test_invalid_ip(self):
        self.assertRaises(InvalidIPAddressError, parse_ip, "192.999.0.1:82")

