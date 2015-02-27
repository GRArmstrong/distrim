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
    Logging
"""


import logging

from logging.handlers import DatagramHandler


def create_logger(name, remote_ip='', remote_port=1999, show_debug=True):
    """
    Spawns a Python logger to output application messages.

    :param name: Logger name.
    :param remote_ip: If defined, log output will be logged to a remote server.
    :param remote_port: Port on remote server to send log messages to.

    :return: An instance of ``logging.Logger``.
    """
    new_logger = logging.Logger(name)

    level = logging.DEBUG if show_debug else logging.INFO
    new_logger.setLevel(level)
    
    fmt_str = "[%(asctime)s] [%(levelname)s] <%(threadName)s>: %(message)s"
    formatter = logging.Formatter(fmt=fmt_str, datefmt="%I:%M:%S")

    stream = logging.StreamHandler()
    stream.setLevel(level)
    stream.setFormatter(formatter)
    
    new_logger.addHandler(stream)

    if remote_ip:
        remote_handler = DatagramHandler(remote_ip, remote_port)
        new_logger.addHandler(remote_handler)

    return new_logger
