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


"""
    Errors, a collection of custom exception types.
"""


class InvalidIPAddressError(ValueError):
    pass


class NetInterfaceError(Exception):
    pass


class HashMissmatchError(Exception):

    def __init__(self, addr, port, hash_gen, hash_bad):
        super(HashMissmatchError, self).__init__(
            "%s:%d == %s, not %s" % (addr, port, hash_gen, hash_bad))

class FingerSpaceError(ValueError):
    pass

class ProtocolError(Exception):
    pass
