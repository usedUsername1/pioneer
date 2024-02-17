class DeviceObject:
    def __init__(self, name, description, overridable) -> None:
        self._name = name
        self._description = description
        self._overridable = overridable

class NetworkObject(DeviceObject):
    def __init__(self, name, description, overridable, network_address_value, network_address_description, network_address_type, overridable_object) -> None:
        super().__init__(name, description, overridable)
        self._network_address_value = network_address_value
        self._network_address_description = network_address_description
        self._network_address_type = network_address_type
    
    def process_network_object(self):
        pass


class NetworkGroupObject(DeviceObject):
    def __init__(self, name, description, overridable, members) -> None:
        super().__init__(name, description, overridable)
        self._members = members

    def process_group_object(self):
        pass
    