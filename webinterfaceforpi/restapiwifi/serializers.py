from rest_framework import serializers
from  restapiwifi.models import NetworkDevice, WifiNetworks, Routes


class NetworkDeviceSerializer(serializers.ModelSerializer):
    class Meta:
        model = NetworkDevice
        fields = ('id', 'device')


class WifiNetworksSerializer(serializers.ModelSerializer):
    class Meta:
        model = WifiNetworks
        fields = ('id', 'wifissid', "wifipsk", "wifi_keymgmt")


class TypeOfNetworkSerialzier(serializers.ModelSerializer): d


class RouteSerializer(serializers.ModelSerializer):
    class Meta:
        model = Routes
        fields = ('id', 'route_type')
