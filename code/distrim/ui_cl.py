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
    Command Line User Interface
"""

import traceback

from .node import Node
from .utils.utilities import get_local_ip


COMMANDS = [
    (('help', 'h'), "Print this message."),
    (('print', 'p'), "Print some information."),
    (('send', 's'), "Send message to node."),
    (('quit', 'q'), "Stop this node and exit."),
]


class CommandLineInterface(object):

    def __init__(self, node_params):
        self.node = Node(**node_params)
        self.prompt = "> "
        self._handlers = {
            'help': self.cmd_help,
            'print': self.cmd_print,
            'send': self.cmd_send,
            'quit': self.cmd_quit,
        }

    def enter(self):
        """
        Start node and accept commands in a loop.
        """
        self.node.start()
        self.running = True
        while self.running:
            self.accept_commands()

    def accept_commands(self):
        """
        Prompt for command input and execute command.
        """
        command = self.get_command()
        try:
            self.exec_command(command)
        except KeyboardInterrupt:
            print "\n *** KeyboardInterrupt: Command interrupted! ***"
        except Exception:
            print traceback.format_exc()

    def get_command(self):
        """
        Receive input from the command prompt.
        """
        command = ''
        try:
            while not command:
                command = raw_input(self.prompt)
            return command
        except KeyboardInterrupt:
            print "\n *** KeyboardInterrupt: Shutting down! ***"
            self.running = False
            self.node.stop()

    def exec_command(self, command):
        """
        Parse command and attempt to execute it.
        """
        print "exec command: ", command
        cmd, handle, params = self.parse_command(command)
        if not handle:
            print "No such command '%s'." % (cmd,)
            return
        else:
            handle(params)

    def parse_command(self, command):
        comm, part, params = command.partition(' ')
        for cmd in COMMANDS:
            if comm.lower() in cmd[0]:
                # Return: (long command name, handler)
                return cmd[0][0], self._handlers[cmd[0][0]], params
        return comm, None, None

    # ========== Command Handlers ==========
    def cmd_help(self, params):
        print "DistrIM Commands"
        for (longname, shortname), descrption in COMMANDS:
            print "\t%s, \t%s: \t%s" % (longname, shortname, descrption)

    def cmd_print(self, params):
        options = ['crypto-keys', 'fingers', 'node-info', 'node-stats']
        if not params.lower() in options:
            if params:
                print "No such option '%s'" % (params,)
            print "\033[1mPossible options:\033[0m\n ", '\n  '.join(options)

        params = params.lower()

        if params == 'crypto-keys':
            print "\033[1mNode Keys...\033[0m"
            print self.node.crypto_key.exportKey()
            print self.node.public_key.exportKey()

        if params == 'fingers':
            print "\033[1mFinger Table...\033[0m"
            fingers = self.node.finger_table.get_all()
            for ident, finger in fingers.iteritems():
                print " %s) %s:%d" % (ident, finger.addr, finger.port)

        if params == 'node-info':
            finger = self.node.finger
            print "\033[1mNode Information...\033[0m"
            print "    Hash:", finger.ident 
            print " Node IP:", "%s:%d" % (finger.addr, finger.port)
            pubkey = finger.get_cipher().exportKey()
            print " Pub-Key:", pubkey.replace('\n', '\n' + ' ' * 10)

        if params == 'node-stats':
            print 'To be implemented...'


    def cmd_send(self, params):
        print 'To be implemented...'
        raise NotImplementedError

    def cmd_quit(self, params):
        print "Shutting down..."
        self.node.stop()
        self.running = False


def run_application(args):
    """
    Entry point for the program.

    Initiates the application and fetches any configuration from the program
    arguments.

    :param args: Arguments collected by :module:`argparse`.
    """
    local_ip = get_local_ip()
    if not local_ip:
        print "WARNING: IP Address of this node could not be determined."
        local_ip = raw_input("IP of this node: ")

    params = {'local_ip': local_ip}
    if args.get('listen_on'):
        params['local_port'] = args['listen_on']
    if args.get('bootstrap'):
        params['remote_ip'] = args['bootstrap'][0]
        if args['bootstrap'][1]:
            params['remote_port'] = args['bootstrap'][1]
    if args.get('logger'):
        params['log_ip'] = args['logger'][0]
        if args['logger'][1]:
            params['log_port'] = args['logger'][1]

    cli = CommandLineInterface(params)
    cli.enter()
