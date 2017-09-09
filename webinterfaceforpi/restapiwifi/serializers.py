from rest_framework import serializers
from  restapiwifi.models import NetworkDevice, WifiNetworks, TypeOfNetwork, Routes


class NetworkDeviceSerializer(serializer.Serializer):
     id = serializers.IntegerField(read_only=True)
     device = serializers.CharField(required=True, allow_blank=False, max_length=100)

