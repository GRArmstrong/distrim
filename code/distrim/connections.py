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


from gevent.server import StreamServer

from .config import CFG_FINAL as CFG
from .logger import log


class TaskManager(object):

    def __init__(self):
        self.tasks = []

    def add_task(self, task, period, *args, **kwargs):
        self.tasks.add()

    def run(self):
        #start thread