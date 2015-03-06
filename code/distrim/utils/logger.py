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


class CustomUDPHandler(DatagramHandler):
    """
    An extension of DatagramHandler that allows extra information to be passed
    onto the listening server.
    """

    def __init__(self, host, port, record_additions={}):
        super(CustomUDPHandler, self).__init__(host, port)
        self.record_additions = record_additions

    def handle(self, record):
        for key, value in self.record_additions.iteritems():
            if key in record.__dict__:
                raise AttributeError(
                    "Attempt to overwrite attribute %s in record." % (key,))
            record.__setattr__(key, value)
        super(CustomUDPHandler, self).handle(record)


def create_logger(name, log_ip='', log_port=1999, show_debug=True, ident=''):
    """
    Spawns a Python logger to output application messages.

    Places log information into StdOut, if `remote_ip` is set then those
    messages are sent to a remote server.

    :param name: Logger name.
    :param remote_ip: If defined, log output will be logged to a remote server.
    :param remote_port: Port on remote server to send log messages to.
    :param show_debug: Determine effective level, `True` is DEBUG, `False` is
        INFO.
    :param ident: Unique ident for this node.

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

    if log_ip:
        extra = {'ident': ident}
        remote_handler = CustomUDPHandler(log_ip, log_port, extra)
        new_logger.addHandler(remote_handler)

    return new_logger
