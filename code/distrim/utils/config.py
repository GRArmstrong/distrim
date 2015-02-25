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
    Configuration
"""

DATA = 5

def genconf():
    global DATA
    DATA += 1
    return "Generated Config %d" % (DATA,)


VALUE = genconf()



CFG = {
    'localhost': "127.0.0.1",
    'listening_port': 2000,
    'listening_queue': 5,
    'thread_pool_length': 8,
}
