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


import struct
import cPickle as pickle
from cPickle import UnpicklingError

from .assets.errors import ProtocolError
from .utils.config import (CFG_PICKLE_PROTOCOL, CFG_STRUCT_FMT,
                           CFG_CRYPT_CHUNK_SIZE)
from .utils.utilities import generate_padding, split_chunks


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
    ALL = [Announce, Message, Ping, Pong, Relay]


class SocketWrapper(object):
    """
    Interface for communicating with foreign nodes.

    This class wraps around a :class:`socket.socket` object that is initialised
    and connected to a foreign node. Messages can be sent between the local
    node  and the foreign node through an instance of this class. The instance
    will take care of pickling and encrypting the messages.

    Pickled messages are created with the *cPickle* module, the first
    four bytes of a pickled message represent the length of the string
    representing the pickled object.

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
    def __init__(self, sock, address, local_key, timeout=15):
        """
        Create the wrapper for the sockets.

        :param sock: the `socket` object.
        """
        #TODO: Clean up parameters
        self.sock = sock
        self.address = address
        self.local_key = local_key
        self.sock.settimeout(timeout)

    def _sock_receive(self, read_length=1024):
        """
        Receive data from a foreign node via its socket.

        :param read_length: How many bytes to read at a time.
        """
        received_data = ''
        length = struct.unpack(CFG_STRUCT_FMT, self.sock.recv(4))[0]
        while length > len(received_data):
            stream_out = self.sock.recv(read_length)
            received_data += stream_out
        return received_data

    def _sock_send(self, data):
        """
        Send data to the foreign node via its socket.

        :param data: The data packet to send.
        """
        length = struct.pack(CFG_STRUCT_FMT, len(data))
        package = length + data
        self.sock.sendall(package)

    def _fetch(self):
        """
        Receive a message from the foreign node.

        :return: A message type, and its parameters
        """
        cryptic_data = self._sock_receive()  # Receive foreign data
        data = ''
        for piece in split_chunks(cryptic_data, CFG_CRYPT_CHUNK_SIZE):
            data += self.local_key.decrypt(piece)  # Decrypt it
        msg = pickle.loads(data)  # Build object

        # Test that the structure we receive is what we expect
        if type(msg) is not tuple and len(msg) != 4:
            raise ProtocolError("Received object is not a tuple as expected")

        #self._verify_sender(msg[0])

        if msg[1] not in Protocol.ALL:
            raise ProtocolError("Received message not valid protocol")

        if type(msg[2]) is not dict:
            raise ProtocolError("Received message params not valid dict.")

        return msg[1], msg[2]

    def fetch(self):
        """
        Error handler for the :method:`_fetch` method.

        :return: A message type, and its parameters
        """
        try:
            return self._fetch()
        except UnpicklingError as exc:
            raise ProtocolError("Couldn't de-serialise: %s" % (exc.message,))
        except Exception as exc:
            raise ProtocolError("Unknown: %s" % (exc.message,))

    def send(self, message_type, parameters):
        """
        Construct a message and send it to a foreign node.

        :param message_type: Type of message from the Protocol class.
        :param parameters: Parameters of the message, as a dict.
        """
        if not message_type in Protocol.ALL:
            raise ProtocolError("Invalid protocol message type '%s'"
                                % (message_type,))
        if type(parameters) is not dict:
            raise ProtocolError("Message parameters must be in a dictionary.")

        msg = (None, message_type, parameters, generate_padding())
        # TODO: Node data
        data = pickle.dumps(msg, protocol=CFG_PICKLE_PROTOCOL)
        cryptic_data = ''
        for piece in split_chunks(data, CFG_CRYPT_CHUNK_SIZE):
            cryptic_data += self.foreign_key.encrypt(piece, None)[0]
        self._sock_send(cryptic_data)

