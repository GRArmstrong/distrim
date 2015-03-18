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
    A DistrIM Node.
"""


from Crypto.PublicKey import RSA
from datetime import datetime as dto

from .connections import ConnectionsManager
from .fingerspace import Finger, FingerSpace

from .utils.config import CFG_LISTENING_PORT, CFG_LOGGER_PORT, CFG_KEY_LENGTH
from .utils.logger import create_logger
from .utils.utilities import CipherWrap


class Node(object):
    """
    Representation of a single Node in the DistrIM network.
    """
    def __init__(self, local_ip, local_port=CFG_LISTENING_PORT,  log_ip='',
                 log_port=CFG_LOGGER_PORT):
        """
        A node within the peer-to-peer network.

        :param local_ip: IP address of this node.
        :param local_port: Listening port of this node.
        :param log_ip: IP address of a remote logger.
        :param log_port: Port of the remote logger.
        """
        self.local_ip = local_ip
        self.local_port = local_port
        # Cryptographic Settings
        # https://pythonhosted.org/pycrypto/
        crypto_key = RSA.generate(CFG_KEY_LENGTH)
        self.keys = CipherWrap(crypto_key)

        # Identity
        self.finger = Finger(local_ip, local_port,
                             self.keys.export(text=False, key_type=0))

        # Get Logging!
        # __name__ is distrim.node
        self.log = create_logger(__name__, log_ip, log_port,
                                 ident=self.finger.ident)

        self.fingerspace = FingerSpace(self.log, self.finger)
        self.conn_manager = ConnectionsManager(self.log, local_ip, local_port,
                                               self.fingerspace, self.finger,
                                               self.keys)

    def start(self, remote_ip='', remote_port=CFG_LISTENING_PORT):
        """
        :param remote_ip: IP address of a remote note to bootstrap against.
        :param remote_port: Listening port of the remote node.
        """
        self.log.info("Node starting at %s:%d", self.local_ip, self.local_port)
        self.start_time = dto.now()
        self.conn_manager.start()
        if remote_ip:
            self.log.info("Boostrapping to %s:%d", remote_ip, remote_port)
            self.conn_manager.bootstrap(remote_ip, remote_port)

    def stop(self):
        self.log.info("Node Stopping...")
        self.conn_manager.stop()

    def send_message(self, recipient, message):
        """
        Do the thing
        """
        raise NotImplementedError
