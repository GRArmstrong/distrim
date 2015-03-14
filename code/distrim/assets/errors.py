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
    """Raised if two idents, which should match, do not."""
    def __init__(self, addr, port, hash_gen, hash_bad):
        """
        :param addr: Node address.
        :param port: Node Port.
        :param hash_gen: Generated ident.
        :param hash_bad: Given ident.
        """
        super(HashMissmatchError, self).__init__(
            "%s:%d == %s, but given %s." % (addr, port, hash_gen, hash_bad))


class FingerSpaceError(ValueError):
    pass


class ProtocolError(Exception):
    """Raised during communications if invalid data is sent or received."""


class ProcedureError(ProtocolError):
    """Raised during communications if data sent at incorrect time."""


class FingerError(Exception):
    """Raised by creating a finger with invalid data"""
