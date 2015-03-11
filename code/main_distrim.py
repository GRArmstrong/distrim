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

from distrim.ui_cl import run_application
from distrim.assets.text import CMD_DESCRIPTION, CMD_EPILOG
from distrim.utils.utilities import split_address


def init():
    """
    Entry point for the DistrIM application.

    Takes arguments from the command line and creates a Command Line Interface
    with a DistrIM node.
    """
    # ArgParse docs: https://docs.python.org/dev/library/argparse.html
    parser = argparse.ArgumentParser(
        description=CMD_DESCRIPTION, epilog=CMD_EPILOG,
        formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('-p', '--listen-on', type=int,
                        help='listening port for this node')
    parser.add_argument('-b', '--bootstrap', type=split_address,
                        help='Address for a bootstrap node in form IP:Port.')
    parser.add_argument('-l', '--logger', type=split_address,
                        help='Address for a remote logger in form IP:Port.')

    args = parser.parse_args()
    run_application(args.__dict__)


# Program entry point
if __name__ == '__main__':
    init()
