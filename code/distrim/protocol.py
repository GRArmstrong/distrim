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

import pickle
# import cPickle as pickle
from cPickle import UnpicklingError

from .fingerspace import Finger
from .assets.errors import ProtocolError, ProcedureError, AuthError
from .utils.config import CFG_PICKLE_PROTOCOL
from .utils.utilities import SocketWrapper, generate_padding


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
    def __init__(self):
        raise NotImplementedError("ConnectionHandler is abstract!")

    def send(self, message_type, parameters):
        """
        Construct a message and send it.
        """
        self._verify_message(message_type, parameters)
        cryptic_data = self.package(message_type, parameters)
        self.conn.send(cryptic_data)

    def receive(self, expected=None):
        """
        Receive a message from the foreign node.

        :return: A message type, and its parameters
        """
        cryptic_data = self.conn.receive()  # Receive foreign data

        try:
            foreign, message_type, parameters = self.unpack(cryptic_data)
        except ValueError:
            raise ProtocolError("Error unpacking received data.")
        self._verify_foreign(foreign)
        self._verify_message(message_type, parameters, expected)
        return message_type, parameters

    def package(self, message_type, parameters):
        """
        Construct a message for sending to a foreign node.

        :param message_type: Type of message from the Protocol class.
        :param parameters: Parameters of the message, as a dict.
        """
        if message_type not in Protocol.ALL:
            raise ProtocolError("Invalid protocol message type '%s'"
                                % (message_type,))
        if type(parameters) is not dict:
            raise ProtocolError("Message parameters must be in a dictionary.")

        msg = (self.local_finger.all, message_type, parameters)

        data = pickle.dumps(msg, protocol=CFG_PICKLE_PROTOCOL)
        data_pack = data + generate_padding()

        self.log.debug("Sen DataPack %s", md5(data_pack).hexdigest())
        cryptic_data = self.foreign_key.encrypt(data_pack)
        self.log.debug("Sen Cryptic %s", md5(cryptic_data).hexdigest())
        return cryptic_data

    def unpack(self, cryptic_data):
        """
        Unpack data sent to this node by a foreign node.
        """
        self.log.debug("Rec Cryptic %s", md5(cryptic_data).hexdigest())
        data = self.local_keys.decrypt(cryptic_data)
        self.log.debug("Rec Data %s", md5(data).hexdigest())

        try:
            foreign, msg_type, params = pickle.loads(data)
        except UnpicklingError as exc:
            self.log.error("Unpickling error, %s", exc.message)
            self.log.error("Decrypted hash: %s", md5(data).hexdigest())
            raise ProtocolError("Couldn't de-serialise: %s" % (exc.message,))
        except ValueError:
            print ' ======= VALUE ERROR =========='
            print 'data', data
            print ' ======= =========== =========='
            raise
        return foreign, msg_type, params

    def _verify_foreign(self, sender_info):
        """Verify the foreign node"""
        sender_finger = Finger(*sender_info)
        try:
            if self.foreign_finger != sender_finger:
                self.log.warning("Authentication error with %s",
                                 self.foreign_finger.ident)
                raise AuthError("Info of foreign not match of locally stored")
        except AttributeError:
            self.log.debug("Unknown connection, authenticating now...")
            self.foreign_finger = sender_finger
            self.foreign_key = sender_finger.get_cipher()
            self.fingerspace.put(*sender_info)

    def _verify_message(self, msg_type, parameters, expected=None):
        """Check message for consistency"""
        if msg_type not in Protocol.ALL:
            raise ProtocolError("Received message not valid protocol")

        if expected and expected != msg_type:
            raise ProcedureError("Expected message type '%s' but got '%s'" %
                                 (expected, msg_type))

        for key in parameters.keys():
            if key.upper() != key:
                raise ProtocolError("Invalid key in parameters '%s'." % (key,))

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
        self.conn = SocketWrapper()
        self.fingerspace = fingerspace
        self.local_finger = local_finger
        self.local_keys = local_keys

    def _setup(self, foreign_info):
        """
        Set necessary local variables after initial connection.

        Since little is known about the foreign node prior to the creation of
        this object, it's necessary to fill in information about the foreign
        node before two-way message passing can happen.
        """
        self.foreign_finger = Finger(*foreign_info)
        self.foreign_key = self.foreign_finger.get_cipher()
        self.fingerspace.put(*self.foreign_finger.all)

    def _init_connection(self, remote_address):
        """
        Establish connection and setup this object.
        """
        self.conn.connect(remote_address)
        self.log.info("Bootstrap connection established.")
        boot_package = pickle.dumps(self.local_finger.all,
                                    protocol=CFG_PICKLE_PROTOCOL)
        self.conn.send(boot_package)
        self.log.info("Bootstrap package sent.")

        # Expect back a welcome message.
        cryptic_data = self.conn.receive()  # Receive foreign data
        foreign, message_type, parameters = self.unpack(cryptic_data)
        if message_type != Protocol.Welcome:
            raise ProcedureError("Expected welcome from bootstrap node.")
        self._setup(foreign)
        return parameters

    def bootstrap(self, remote_address):
        """
        Perform bootstrap procedure.

        The very first action a node will perform is its bootstrap procedure,
        during which the node will rendezvous with a bootstrap node, an
        existing node in the network, and attain a list of nodes.

        :param remote_address: IP and Port tuple of bootstrap node.
        """
        welcome_params = self._init_connection(remote_address)
        # We will add your technological distinctiveness to our own.
        nodes_list = welcome_params.get('NODES')
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
        foreign, msg_type, parameters = self.unpack(data)
        self._verify_foreign(foreign)
        self._verify_message(msg_type, parameters, None)
        if msg_type == Protocol.Relay:
            self.handle_relay(parameters)
        # message = decode(data)

    def handle_relay(self, params):
        package = params.get('PACKAGE')
        unpacked = self._peel_onion_layer(package)
        if unpacked.get('RECIPIENT') == self.local_finger.ident:
            print 'Message Received: ', unpacked.get('MESSAGE')
            return
        else:
            addr, port, key, ident = unpacked.get('NEXT')
            self.fingerspace.put(addr, port, key, ident)
            next_finger = self.fingerspace.get(ident)
            self.log.info("Relaying message from %s to %s",
                          self.foreign_finger.ident, next_finger.ident)
            out = MessageHandler(
                self.log, self.fingerspace, self.local_finger,
                self.local_keys, next_finger)
            out.connect()
            out.relay(unpacked.get('PACKAGE'))

    def _peel_onion_layer(self, package):
        data = self.local_keys.decrypt(package)
        next_layer = pickle.loads(data)
        return next_layer


class MessageHandler(ConnectionHandler):
    """
    Protocol Handler for outgoing communication with foreign nodes.

    The methods of this class define procedures for dealing with connections
    established locally to transmit to foreign nodes.
    """
    def __init__(self, log, fingerspace, local_finger, local_keys,
                 foreign_finger=None):
        """
        :param finger: Finger of the node to connect to.
        """
        self.log = log.getChild("outgoing")
        self.conn = SocketWrapper()
        self.fingerspace = fingerspace
        self.local_finger = local_finger
        self.local_keys = local_keys
        self.foreign_finger = foreign_finger
        if foreign_finger:
            self.foreign_key = foreign_finger.get_cipher()

    def connect(self, remote_address=None):
        """Establish connection with foreign node"""
        if remote_address:
            self.conn.connect(remote_address)
        elif self.foreign_finger:
            self.conn.connect(self.foreign_finger.address)
        else:
            raise ProtocolError("No address to connect to.")

    def send_message(self, recipient, message):
        """
        Send message.
        """
        final_pack = self._build_message(recipient, message)
        next_node, params = self._build_onion(recipient, final_pack)
        print 'next ident', next_node.ident
        self.foreign_finger = next_node
        self.foreign_key = next_node.get_cipher()
        self.connect()
        self.send(Protocol.Relay, params)

    def _build_onion(self, recipient, package):
        """
        Construct the onion package
        """
        next_node = recipient
        path = self.fingerspace.get_random_fingers(3)
        try:
            path.remove(recipient)
        except ValueError:
            pass  # We won't route a message to the recipient

        print "Path Length of", len(path)

        for idx, finger in enumerate(path):
            contents = {
                'NEXT': recipient.all if idx == 0 else path[idx-1].all,
                'PACKAGE': package
            }
            print 'Path', idx, finger.ident
            cipher = finger.get_cipher()
            package = cipher.encrypt(
                pickle.dumps(contents, CFG_PICKLE_PROTOCOL))
            next_node = finger

        params = {'PACKAGE': package}
        return next_node, params

    def _build_message(self, recipient, message):
        """
        Construct the final message package received by the recipient.

        :param recipient: Finger of the recipient.
        :param message: Textual message for the recipient to receive.
        """
        contents = {
            'MESSAGE': message,
            'RECIPIENT': recipient.ident,
            'SENDER': self.local_finger.all,
        }
        data = pickle.dumps(contents, CFG_PICKLE_PROTOCOL)

        cipher = recipient.get_cipher()
        cryptic_data = cipher.encrypt(data)
        return cryptic_data

    def relay(self, package):
        params = {'PACKAGE': package}
        self.send(Protocol.Relay, params)
