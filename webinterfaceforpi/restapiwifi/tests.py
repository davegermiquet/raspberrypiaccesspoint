# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.test import TestCase

from .models import *


# Create your tests here.

class ModelTestCase(TestCase):
    def setUp(selfs):
        pass

    def testFindWifiNetworks(self):
        self.wifi_networks = WifiNetworks()
