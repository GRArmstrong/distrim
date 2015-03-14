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
    Connections Manager
"""


import socket

from time import sleep
from threading import Thread
from thread_pool import ThreadPool

from .utils.config import CFG_THREAD_POOL_LENGTH, CFG_LISTENING_QUEUE


class ConnectionsManager(object):
    """
    The ConnectionsManager class is responsible for all incoming connections
    from other nodes.
    """
    def __init__(self, localhost, port):
        self.local_ip = localhost
        self.port = port
        self._pool = ThreadPool(CFG_THREAD_POOL_LENGTH)

        # Listener
        self._thread = Thread(target=self._listen, name='Thread-Listener')
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Cleaner
        self._cleaner = Thread(target=self._cleaning, name='Thread-Cleaner')

        # Some nice stats, because why not
        self.count_conn_success = 0
        self.count_conn_failure = 0

    def start(self):
        self.sock.bind((self.localhost, self.port))
        self.sock.listen(CFG_LISTENING_QUEUE)
        log.info("Listening for connections on %s:%d", self.localhost,
                 self.port)
        self._running = True
        self._thread.start()
        self._cleaner.start()

    def stop(self):
        self._sock.shutdown(socket.SHUT_RD)
        self._running = False

    def pool_new_connection(self, sock, address):
        """
        Handle incoming connection, puts socket into seperate thread.
        """
        self._pool.add_task(self.accept_new_connetion, sock, address)

    def accept_new_connetion(self, sock, address):
        """
        Handle incoming connections

        :param sock: The socket of the incoming connection.
        :param address: Address of the connecting node.
        """
        # Needham–Schroeder–Lowe
        # Connection Procedure, handshake
        # data_in = read_socket(sock)
        try:
            # TODO: Stuff
            sock.close()
        except Exception as exc:
            self.log.error("Exception occured during connection with %s:\n%s",
                           address, exc.message)
            return False
        return True

    def _listen(self):
        """
        Listen for incoming connections.

        This method is the target of `self._thread`
        """
        while self._running:
            sock, addr = self.sock.accept()
            self.pool_new_connection(sock, addr)

        self.sock.close()
        self.log.debug("Listening thread stopped.")

    def _cleaning(self):
        """
        Removes completed connection results from the thread pool.

        This method is the target of `self._cleaner`
        """
        while self._running:
            result = self._pool.get_task()
            if result:
                self.count_conn_success += 1
            else:
                self.count_conn_failure += 1

            # It'll be satisfactory for the time being to pend on get_task
            # Hopefully errors will be rare
            try:
                while not self._pool.err_queue.empty():
                    self._pool.err_queue.get_nowait()
            except Exception:
                pass
        self.log.debug("Cleaning thread stopped.")


