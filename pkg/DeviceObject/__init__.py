class ObjectContainer:
    def __init__(self, name, parent, security_device_name, member_objects = None) -> None:
        self._name = name
        self._parent = parent
        self._security_device_name = security_device_name
        self._member_objects = member_objects

    def set_member_objects(self, member_objects):
        self._member_objects = member_objects

class DeviceObject:
    def __init__(self, name, description, is_overridable, object_container_name = None) -> None:
        self._name = name
        self._description = description
        self._is_overridable = is_overridable
        self._object_container_name = object_container_name
    
    def get_name(self):
        return self._name
    
    def get_description(self):
        return self._description
    
    def get_override_bool(self):
        return self._is_overridable
    
    def get_object_container_name(self):
        return self._object_container_name
    

class NetworkObject(DeviceObject):
    def __init__(self, name, description, is_overridable, network_address_value, network_address_type) -> None:
        super().__init__(name, description, is_overridable)
        self._network_address_value = network_address_value
        self._network_address_type = network_address_type

    def get_network_address_value(self):
        return self._network_address_value

    def get_network_address_type(self):
        return self._network_address_type

class NetworkGroupObject(DeviceObject):
    def __init__(self, name, description, is_overridable, members) -> None:
        super().__init__(name, description, is_overridable)
        self._members = members
    
    def get_members(self):
        return self._members

    