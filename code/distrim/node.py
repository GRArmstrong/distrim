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


from .connections import ConnectionsManager

from .utils.config import CFG
from .utils.logger import log
from .utils.utilities import get_local_ip


class Node(object):

    def __init__(self, local_ip=''):
        """
        Entry point for the program.

        Initiates the application with the parameters passed in.
        """
        print "__name__", __name__
        if not local_ip:
            local_ip = get_local_ip()

        log("Node IP address: %s" % (local_ip,))
        self.connections_manager = ConnectionsManager(CFG['localhost'],
                                                      CFG['listening_port'])
        #https://pythonhosted.org/pycrypto/

    def start(self):
        #self.server.start()
        print "Node started..."

    def stop(self):
        print "Node Stopping..."

    def run_command(self, command_string):
        print "Node received: ", command_string

    def destroy(self):
        pass




class Message(object):

    def __init__(self, message_type, payload):
        self.message_type = message_type
        self.payload = payload
