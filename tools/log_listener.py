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
    Log listener, outputs log messages from multiple nodes.
"""


import argparse
import socket
import cPickle
import logging
import struct


RECEIVE_SIZE = 2048


def init():
    """
    Entry point for the program.

    Initiates the application and fetches any configuration from the program
    arguments.
    """
    parser = argparse.ArgumentParser(
        description="Listens to log output from DistrIM nodes.")
    parser.add_argument('ip_addr', help='IP to receive on')
    parser.add_argument('port', type=int, help='Port to receive on')
    parser.add_argument('--debug', help='Show DEBUG messages.',
                        dest='debug', action='store_true')

    args = parser.parse_args()

    try:
        listen(args.ip_addr, args.port, show_debug=args.debug)
    except KeyboardInterrupt:
        pass

    print "\nListening program has exited."


def listen(addr, port, show_debug=False):
    """
    Listen and print
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((addr, port))
    print "Listening on %s:%d ..." % (addr, port)

    log = logging.getLogger()

    fmt_str = (" %(addr)s | [%(asctime)s] [%(levelname)s] "
               "<%(threadName)s>: %(message)s")
    formatter = logging.Formatter(fmt=fmt_str, datefmt="%I:%M:%S")

    stream = logging.StreamHandler()
    if show_debug:
        stream.setLevel(logging.DEBUG)
    else:
        stream.setLevel(logging.INFO)
    stream.setFormatter(formatter)
    
    log.addHandler(stream)

    while True:
        data, addr = sock.recvfrom(RECEIVE_SIZE)
        #print '*', data[:4], '*'
        data_length = struct.unpack(">L", data[:4])[0]
        try:
            obj = cPickle.loads(data[4:data_length + 4])
        except EOFError:
            print(" !!! Logging error, failed to receive message from %s"
                  % (addr[0]))
            continue
        record = logging.makeLogRecord(obj)
        record.addr = addr[0]
        log.handle(record)
        # print addr, record


# Program entry point
if __name__ == '__main__':
    init()
