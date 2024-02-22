
class Object:
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

class GroupObject(Object):
    def __init__(self, name, description, is_overridable, members) -> None:
        super().__init__(name, description, is_overridable)
        self._members = members
    
    def get_members(self):
        return self._members
    
class NetworkObject(Object):
    def __init__(self, name, description, is_overridable, network_address_value, network_address_type) -> None:
        super().__init__(name, description, is_overridable)
        self._network_address_value = network_address_value
        self._network_address_type = network_address_type

    def get_network_address_value(self):
        return self._network_address_value

    def get_network_address_type(self):
        return self._network_address_type

class NetworkGroupObject(GroupObject):
    pass


class SecurityZone(Object):
    def __init__(self, name, description, is_overridable, object_container_name=None) -> None:
        super().__init__(name, description, is_overridable, object_container_name)


    