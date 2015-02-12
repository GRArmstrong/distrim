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


from gevent.server import StreamServer

from .utils.config import CFG_FINAL as CFG
from .utils.logger import log



class Node(object):

    def __init__(self):
        """
        Entry point for the program.

        Initiates the application with the parameters passed in.
        """

        # ArgParse docs: https://docs.python.org/dev/library/argparse.html
        print "oops"

        log("Listening for connections from %s:%d", CFG['localhost'],
            CFG['listening_port'])
        self.server = StreamServer((CFG['localhost'], CFG['listening_port']),
                                   handle)

    def start(self):
        #self.server.start()
        print "Node started..."

    def run_command(self, command_string):
        print "Node received: ", command_string

    def destroy(self):
        pass


def handle():
    print("MAKE IT RAIN")



class Message(object):

    def __init__(self, message_type, payload):
        self.message_type = message_type
        self.payload = payload
