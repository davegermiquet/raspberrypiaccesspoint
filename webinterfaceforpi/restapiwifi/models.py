# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.db import models

class NetworkDevice(models.Model):
    device = models.CharField(max_length=100, blank=False)
    
class WifiNetworks(models.Model):
    wifissid = models.CharField(max_length=100, blank=True, default='')
    wifikey_mgmt = models.CharField(max_length=100, blank=True, default='')
    wifipsk =  models.CharField(max_length=100, blank=True, default='')

class TypeOfNetwork(models.Model):
    network_type =  models.CharField(max_length=100, blank=True, default='')

class Routes(models.Model):
    route_type =  models.CharField(max_length=100, blank=True, default='')


