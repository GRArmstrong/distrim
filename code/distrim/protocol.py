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
    Protocol, handlers for connections with other nodes
"""

from hashlib import md5

import socket
import struct
import cPickle as pickle
from cPickle import UnpicklingError

from .fingerspace import Finger
from .assets.errors import ProtocolError, ProcedureError
from .utils.config import (CFG_PICKLE_PROTOCOL, CFG_STRUCT_FMT,
                           CFG_CRYPT_CHUNK_SIZE, CFG_TIMEOUT)
from .utils.utilities import (SocketWrapper, CipherWrap, generate_padding,
                              split_chunks)


class Protocol(object):
    """
    Protocol Message Definitions.

    Protocol messages should be in alphabetic order and the values should be
    4 characters in length.
    """
    Announce = "ANNO"
    Message = "MESG"
    Ping = "PING"
    Pong = "PONG"
    Relay = "RELY"
    Welcome = "WELC"
    ALL = [Announce, Message, Ping, Pong, Relay, Welcome]


class ConnectionHandler(object):
    """
    An abstract class with common connection functionality.

    ConnectionHandler holds some common functionality used for the connection
    of nodes to one another.

    Messages can be sent between the local node and the foreign node through an
    instance of this class. The instance will take care of pickling and
    encrypting the messages. Transmission is achieved by a SocketWrapper.

    Pickled messages are created with the *cPickle* module.

    When the message is unpickled, a tuple of length 4 will be attained with
    the following attributes:

     - The sender's information.
     - The message type.
     - The message parameters.
     - The padding.

    The sender's information will contain the sender's finger and any nonces
    used for the transaction which are checked for consistency. The padding
    is used for cryptographic scrambling and is discarded.
    """
    def receive(self, expected=None):
        """
        Receive a message from the foreign node.

        :return: A message type, and its parameters
        """
        cryptic_data = self.conn.receive()  # Receive foreign data
        # self.log.debug("cryptic length receive: %d", len(cryptic_data))
        self.log.debug("cryptic length rec: %d", len(cryptic_data))
        self.log.debug("rec crypt: %s", md5(cryptic_data).hexdigest())

        data = ''
        # print self.local_keys.export(text=True)
        for piece in split_chunks(cryptic_data, CFG_CRYPT_CHUNK_SIZE):
            data += self.local_keys.decrypt(piece)  # Decrypt it

        self.log.debug("data length rec: %d", len(data))
        # with open("/tmp/rec", 'w') as handle:
        #     handle.write(data)

        self.log.debug("rec: %s", md5(data[0:600]).hexdigest())
        try:
            msg = pickle.loads(data)  # Build object
        except UnpicklingError as exc:
            raise ProtocolError("Couldn't de-serialise: %s" % (exc.message,))

        self._verify_sender(msg[0])
        self._verify_message(msg, expected)

        if expected:
            return msg[2]
        else:
            return msg[1], msg[2]

    def send(self, message_type, parameters):
        """
        Construct a message and send it to a foreign node.

        :param message_type: Type of message from the Protocol class.
        :param parameters: Parameters of the message, as a dict.
        """
        if message_type not in Protocol.ALL:
            raise ProtocolError("Invalid protocol message type '%s'"
                                % (message_type,))
        if type(parameters) is not dict:
            raise ProtocolError("Message parameters must be in a dictionary.")

        msg = (self.local_finger.all, message_type,
               parameters, generate_padding())
        # TODO: Node data
        data = pickle.dumps(msg, protocol=CFG_PICKLE_PROTOCOL)
        self.log.debug("data length send: %d", len(data))
        self.log.debug("send: %s", md5(data[0:600]).hexdigest())

        cryptic_data = ''
        for piece in split_chunks(data, CFG_CRYPT_CHUNK_SIZE):
            cryptic_data += self.foreign_key.encrypt(piece)
        self.log.debug("cryptic length send: %d", len(cryptic_data))
        self.log.debug("send crypt: %s", md5(cryptic_data).hexdigest())
        self.conn.send(cryptic_data)

    def _verify_sender(self, sender_info):
        # TODO: Improve
        self.foreign_finger = Finger(*sender_info)

    def _verify_message(self, msg, expected):
        """Check message for consistency"""
        # Test that the structure we receive is what we expect
        if type(msg) is not tuple and len(msg) != 4:
            raise ProtocolError("Received object is not a tuple as expected")

        sender, message, params = msg[:3]

        if msg[1] not in Protocol.ALL:
            raise ProtocolError("Received message not valid protocol")

        if expected and expected != msg[1]:
            raise ProcedureError("Expected message type '%s' but got '%s'" %
                                 (expected, msg[1]))

        if type(msg[2]) is not dict:
            raise ProtocolError("Received message params not valid dict.")

    def close(self):
        """
        Terminate the connection
        """
        self.conn.close()


class Boostrapper(ConnectionHandler):
    """
    Handle bootstrap and rendezvous.

    Protocol Handler specialised for bootstrapping and rendezvousing with
    other nodes in the network.
    """
    def __init__(self, log, fingerspace, local_finger, local_keys):
        """
        :param timeout: Timeout time for socket.
        """
        self.log = log.getChild('bootstrapper')
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = SocketWrapper(sock)
        self.fingerspace = fingerspace
        self.local_finger = local_finger
        self.local_keys = local_keys

    def bootstrap(self, remote_address):
        """
        Perform bootstrap procedure.

        The very first action a node will perform is its bootstrap procedure,
        during which the node will rendezvous with a bootstrap node, an
        existing node in the network, and attain a list of nodes.

        :param remote_address: IP and Port tuple of bootstrap node.
        """
        self.conn.connect(remote_address)
        self.log.info("Bootstrap connection established.")
        boot_package = pickle.dumps(self.local_finger.all,
                                    protocol=CFG_PICKLE_PROTOCOL)
        self.conn.send(boot_package)
        self.log.info("Bootstrap package sent.")
        # Expect back a welcome message.
        received = self.receive(Protocol.Welcome)
        # We will add your technological distinctiveness to our own.
        self.fingerspace.put(*self.foreign_finger.all)
        nodes_list = received.get('NODES')
        if nodes_list:
            self.fingerspace.import_nodes(nodes_list)
        self.log.info("SUCCESS! Rendezvous occured.")

    def announce(self):
        """
        Make presence of this node known to others.
        """
        for finger in self.fingerspace.get_all():
            self.log.info("Announce to %s" % finger)


class IncomingConnection(ConnectionHandler):
    """
    Protocol Handler for communication with foreign nodes.

    The methods of this class define procedures for dealing with connections
    from foreign nodes.
    """
    def __init__(self, log, sock, addr, fingerspace, local_finger, local_keys):
        """
        :param sock: The socket object.
        """
        self.log = log.getChild("incoming@%s" % (addr[0],))
        print 'logger name', self.log.name
        self.conn = SocketWrapper(sock)
        self.fingerspace = fingerspace
        self.local_finger = local_finger
        self.local_keys = local_keys

    def _is_bootstrap_request(self, data):
        """ Try and unpickle """
        try:
            obj = pickle.loads(data)
            assert isinstance(obj, tuple)
            assert len(obj) == 4
            self.foreign_finger = Finger(*obj)
            self.log.info("New node joining network with ID: %s", obj[-1])
            return True
        except Exception:  # pylint: disable=broad-except
            return False

    def _rendezvous(self):
        """
        Accept node into the network.
        """
        self.fingerspace.put(*self.foreign_finger.all)
        self.log.info("Sending welcome message.")
        self.foreign_key = self.foreign_finger.get_cipher()
        parameters = {'NODES': self.fingerspace.export_nodes()}
        self.send(Protocol.Welcome, parameters)

    def handle(self):
        """ """
        data = self.conn.receive()
        if self._is_bootstrap_request(data):
            self._rendezvous()
            return
        # message = decode(data)

    def auth(self):
        self.conn.receive_stuff()


class OutgoingConnection(ConnectionHandler):
    """
    Protocol Handler for outgoing communication with foreign nodes.

    The methods of this class define procedures for dealing with connections
    established locally to transmit to foreign nodes.
    """
    def __init__(self, finger):
        """
        :param finger: Finger of the node to connect to.
        """
