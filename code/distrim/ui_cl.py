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


from .node import Node


COMMANDS = [
    (('help', 'h'), "Print this message."),
    (('send', 's'), "Send message to node."),
    (('quit', 'q'), "Stop this node and exit."),
]


class CommandLineInterface(object):

    def __init__(self):
        self.node = Node()
        self.prompt = "> "
        self._handlers = {
            'help': self.cmd_help,
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
    def cmd_quit(self, params):
        print "Shutting down..."
        self.node.stop()
        self.running = False

    def cmd_help(self, params):
        print "DistrIM Commands"
        for (longname, shortname), descrption in COMMANDS:
            print "\t%s, \t%s: \t%s" % (longname, shortname, descrption)

    def cmd_send(self, params):
        raise NotImplementedError
