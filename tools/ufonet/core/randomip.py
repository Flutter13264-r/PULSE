#!/usr/bin/env python3 
# -*- coding: utf-8 -*-"
"""
This file is part of the UFONet project, https://ufonet.03c8.net


"""
from random import randrange

class RandomIP(object):
    """
    Class to generate random valid IP's
    """
    def _generateip(self, string):
        notvalid = [10, 127, 169, 172, 192]
        first = randrange(1, 256)
        while first is notvalid:
            first = randrange(1, 256)
        _ip = ".".join([str(first), str(randrange(1, 256)),
        str(randrange(1, 256)), str(randrange(1, 256))])
        return _ip
