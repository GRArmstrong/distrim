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
    Entry point.
"""


from Crypto.PublicKey import RSA

from .connections import ConnectionsManager
from .fingerspace import Finger, FingerSpace

from .utils.config import CFG_LISTENING_PORT, CFG_LOGGER_PORT, CFG_KEY_LENGTH
from .utils.logger import create_logger
from .utils.utilities import get_local_ip


class Node(object):

    def __init__(self, local_ip, local_port=CFG_LISTENING_PORT,
                 remote_ip='', remote_port=0, log_ip='',
                 log_port=CFG_LOGGER_PORT):
        """
        A node within the peer-to-peer network.

        :param local_ip: IP address of this node.
        :param local_port: Listening port of this node.
        :param remote_ip: IP address of a remote note to bootstrap against.
        :param remote_port: Listening port of the remote node.
        :param log_ip: IP address of a remote logger.
        :param log_port: Port of the remote logger.
        """
        self.connections_manager = ConnectionsManager(local_ip, local_port)

        # Cryptographic Settings
        #https://pythonhosted.org/pycrypto/
        self.crypto_key = RSA.generate(CFG_KEY_LENGTH)
        self.public_key = self.crypto_key.publickey()

        # Identity
        self.finger = Finger(local_ip, local_port,
                             self.public_key.exportKey(format='DER'))

        # Get Logging!
        #__name__ is distrim.node
        self.log = create_logger(__name__, log_ip, log_port,
                                 ident=self.finger.ident)
        self.log.info("Node IP address: %s" % (local_ip,))

    def start(self):
        #self.server.start()
        print "Node started..."

    def stop(self):
        print "Node Stopping..."

    def run_command(self, command_string):
        print "Node received: ", command_string

    def destroy(self):
        pass

    def send_message(self, recipient, message):
        """
        Do the thing
        """
        raise NotImplementedError
        #msg = 


