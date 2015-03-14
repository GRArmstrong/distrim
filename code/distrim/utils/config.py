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
    Default DistrIM Configuration and Constants.
"""


# Node
CFG_LISTENING_PORT = 2000

# Connection Manager
CFG_LISTENING_QUEUE = 8
CFG_THREAD_POOL_LENGTH = 8

# Crypto
CFG_KEY_LENGTH = 1024

# Protocol
CFG_PICKLE_PROTOCOL = 2
CFG_STRUCT_FMT = ">L"
CFG_CRYPT_CHUNK_SIZE = 128

# Salting
CFG_SALT_LEN_MIN = 64
CFG_SALT_LEN_MAX = 512

# Logging
CFG_LOGGER_PORT = 1999
