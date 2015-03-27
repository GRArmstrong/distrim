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
import traceback

from time import sleep
from threading import Thread
from thread_pool import ThreadPool

from .protocol import IncomingConnection, MessageHandler, Boostrapper
from .utils.config import CFG_THREAD_POOL_LENGTH, CFG_LISTENING_QUEUE


class ConnectionsManager(object):
    """
    The ConnectionsManager class is responsible for all incoming connections
    from other nodes.
    """
    def __init__(self, parent_log, local_ip, local_port,
                 fingerspace, finger, keys):
        """
        :param parent_log:
        """
        self.log = parent_log.getChild(__name__.rpartition('.')[2])
        self.local_ip = local_ip
        self.local_port = local_port
        self.fingerspace = fingerspace
        self.local_finger = finger
        self.local_keys = keys

        # Listener
        self._pool = ThreadPool(CFG_THREAD_POOL_LENGTH)
        self._thread = Thread(target=self._listen, name='Thread-Listener')
        self._thread.daemon = True
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Cleaner
        self._cleaner = Thread(target=self._cleaning, name='Thread-Cleaner')
        self._cleaner.daemon = True

        # Some nice stats, because why not
        self.count_conn_success = 0
        self.count_conn_failure = 0

    def start(self):
        self._running = True
        self._sock.bind((self.local_ip, self.local_port))
        self._sock.listen(CFG_LISTENING_QUEUE)
        self._thread.start()
        self._cleaner.start()
        self.log.info("Listening for connections on %s:%d", self.local_ip,
                      self.local_port)

    def stop(self):
        self._running = False
        try:
            self._sock.shutdown(socket.SHUT_RD)
            self._sock.close()
        except socket.error:
            pass
        while not self._pool.out_queue.empty():
            sleep(0.2)

    def bootstrap(self, remote_ip, remote_port):
        """
        Establish the first connection in the network.
        """
        connection = Boostrapper(self.log, self.fingerspace, self.local_finger,
                                 self.local_keys)
        connection.bootstrap((remote_ip, remote_port))

    def send_message(self, recipient, message):
        """
        Send a message via relays.

        :param recipient: Finger of the node to send the message to.
        :param message: Plaintext message to send.
        """
        postman = MessageHandler(
            self.log, self.fingerspace, self.local_finger, self.local_keys)
        postman.send_message(recipient, message)

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
        try:
            print 'New Connection from:', address
            connection = IncomingConnection(
                self.log, sock, address, self.fingerspace, self.local_finger,
                self.local_keys)
            connection.handle()
            connection.close()
        except Exception as exc:  # pylint: disable=broad-except
            traceback.print_exc()
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
            sock, addr = self._sock.accept()
            self.pool_new_connection(sock, addr)
        self.log.debug("Listening thread stopped.")

    def _cleaning(self):
        """
        Removes completed connection results from the thread pool.

        This method is the target of `self._cleaner`
        """
        while self._running:
            result = self._pool.get_task()
            try:
                self._pool.out_queue.task_done()
            except ValueError:
                self.log.error("_pool.out_queue error")
            if result:
                self.count_conn_success += 1
            else:
                self.count_conn_failure += 1

            # It'll be satisfactory for the time being to pend on get_task
            # Hopefully errors will be rare
            try:
                while not self._pool.err_queue.empty():
                    self._pool.err_queue.get_nowait()
            except Exception as exc:  # pylint: disable=broad-except
                self.log.error("Cleaning errors: %s", exc.message)
                pass
        self.log.debug("Cleaning thread stopped.")
