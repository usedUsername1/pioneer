
class Object:
    def __init__(self, object_info) -> None:
        self._object_info = object_info
        self._name = None
        self._description = None
        self._is_overridable = None
        self._object_container_name = None
    
    def get_name(self):
        return self._name
    
    def get_description(self):
        return self._description
    
    def get_override_bool(self):
        return self._is_overridable
    
    def get_object_container_name(self):
        return self._object_container_name

class GroupObject(Object):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)
        self._members = None
    
    def get_members(self):
        return self._members
    
class NetworkObject(Object):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)
        self._network_address_value = None
        self._network_address_type = None

    def get_network_address_value(self):
        return self._network_address_value

    def get_network_address_type(self):
        return self._network_address_type

class NetworkGroupObject(GroupObject):
    pass


# class SecurityZone(Object):
#     def __init__(self, name, description, is_overridable, object_container_name=None) -> None:
#         super().__init__(name, description, is_overridable, object_container_name)


    