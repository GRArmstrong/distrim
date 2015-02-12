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
    Entry point to DistrIM, this should be executed on the command line within
    the Python environment. 
"""


import argparse

from distrim.node import Node
from distrim.assets.text import CMD_DESCRIPTION, CMD_EPILOG


def init():
    """
    Entry point for the program.

    Initiates the application and fetches any configuration from the program
    arguments.
    """

    # ArgParse docs: https://docs.python.org/dev/library/argparse.html
    parser = argparse.ArgumentParser(
        description=CMD_DESCRIPTION, epilog=CMD_EPILOG,
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('remote_ip', help='IP of bootstrap node')
    parser.add_argument('remote_port', help='Listening port of remote node')
    
    args = parser.parse_args()
    
    node = Node()
    node.start()

    while True:
        option = raw_input("DistrIM> ")
        if option.lower() in ['quit', 'exit']:
            break
        node.run_command(option)

    print "Exiting..."
    node.destroy()
    print "Node stopped, end."


# Program entry point
if __name__ == '__main__':
    init()
