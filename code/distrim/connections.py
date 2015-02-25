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
    Connections Manager,
"""

import socket

from threading import Thread
from thread_pool import ThreadPool

from .utils.config import CFG
from .utils.logger import log


class ConnectionsManager(object):

    def __init__(self, localhost, port):
        self.localhost = localhost
        self.port = port
        self.listener = Listener(self, localhost, port)
        self.pool = ThreadPool(CFG['thread_pool_length'])

    def start(self):
        self.listener.start()

    def accept_new_connetion(self, sock, address):
        """
        Handle incoming connections

        :param sock: The socket of the incoming connection.
        :param address: Address of the connecting node.
        """
        # Needham–Schroeder–Lowe
        # Connection Procedure, handshake
        data_in = read_socket(sock)


class Listener(object):

    def __init__(self, manager, localhost, port):
        self.manager = manager
        self.localhost = localhost
        self.port = port
        self.thread = Thread(target=self._listen, name='Thread-Listener')
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self._bind_and_listen()
        log("Listening for connections on %s:%d", self.localhost, self.port)
        self.running = True
        self.thread.start()

    def stop(self):
        # Stop accepting incoming connections
        self.socket.shutdown(socket.SHUT_RD)
        self.running = False

    def _bind_and_listen(self):
        """
        Bind socket to listening address

        """
        self.sock.bind((self.localhost, self.port))
        self.listen(CFG['listening_queue'])

    def _listen(self):
        """
        Listen for incoming connections.

        This method is the target of `self.thread`
        """
        while self.running:
            sock, addr = self.socket.accept()
            self.manager.accept_new_connetion(sock, addr)

        self.socket.close()



def read_socket(socket, read_length=1024):
    """
    Read data from a socket.

    :param socket: The socket object to read from.
    :param read_length: How many bytes to read at a time.
    """
    received_data = []
    while True:
        stream_out = socket.recv(read_length)
        if stream_out:
            received_data.append(stream_out)
        else:
            break
    return received_data.join('')
