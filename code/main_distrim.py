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

from distrim.ui_cl import CommandLineInterface
from distrim.assets.text import CMD_DESCRIPTION, CMD_EPILOG
from distrim.utils.utilities import get_local_ip


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

    local_ip = get_local_ip()
    if not local_ip:
        print "IP Address of this node could not be determined."
        local_ip = raw_input("IP of node: ")

    cli = CommandLineInterface()
    cli.enter()
    # Remains in enter() loop until program exit
    print "End, program exit."


# Program entry point
if __name__ == '__main__':
    init()
