import utils.helper as helper
from pkg.DeviceObject import Object, NetworkObject, GeolocationObject, CountryObject, PortObject, ICMPObject, URLObject, \
NetworkGroupObject, PortGroupObject, URLGroupObject, ScheduleObject, PolicyUserObject, URLCategoryObject, \
L7AppObject, L7AppFilterObject, L7AppGroupObject
import utils.gvars as gvars
import ipaddress
import utils.exceptions as PioneerExceptions
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')

class ObjectCache:
    def __init__(self):
        self._cache = {}

    def get_or_create(self, key, create_func):
        if key not in self._cache:
            self._cache[key] = create_func()
        return self._cache[key]

class PioneerObject(Object):
    def __init__(self, ObjectContainer, name, description, is_overridable) -> None:
        super().__init__(ObjectContainer, name, description, is_overridable)

# should the PioneerGroups also have a members python attribute which will be a list with all the 
# python object representations of the member objects?
    # if so, should members be retrieved upon the instantiation of the group object?


class PioneerNetworkObject(PioneerObject, NetworkObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        object_value = object_info[3]
        object_description = object_info[4]
        object_type = object_info[5]
        overridable_object = object_info[6]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        NetworkObject.__init__(self, object_value, object_type)
        self.set_uid(object_uid)

class PioneerNetworkGroupObject(NetworkGroupObject, PioneerObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        object_description = object_info[3]
        overridable_object = object_info[4]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        NetworkGroupObject.__init__(self)
        self.set_uid(object_uid)

class PioneerPortObject(PortObject, PioneerObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        object_protocol = object_info[3]
        source_port_number = object_info[4]
        destination_port_number = object_info[5]
        object_description = object_info[6]
        overridable_object = object_info[7]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        PortObject.__init__(self, source_port_number, destination_port_number, object_protocol)
        self.set_uid(object_uid)

class PioneerICMPObject(ICMPObject, PioneerObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        object_type = object_info[3]
        object_code = object_info[4]
        object_description = object_info[5]
        overridable_object = object_info[6]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        ICMPObject.__init__(self, object_type, object_code)
        self.set_uid(object_uid)

class PioneerPortGroupObject(PortGroupObject, PioneerObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        object_description = object_info[3]
        overridable_object = object_info[4]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        PortGroupObject.__init__(self)
        self.set_uid(object_uid)

class PioneerURLObject(URLObject, PioneerObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        url_value = object_info[3]
        overridable_object = object_info[4]
        object_description = object_info[5]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        URLObject.__init__(self, url_value)
        self.set_uid(object_uid)

class PioneerURLGroupObject(URLGroupObject, PioneerObject):
    def __init__(self, ObjectContainer, object_info) -> None:
        object_uid = object_info[0]
        object_name = object_info[1]
        object_description = object_info[3]
        overridable_object = object_info[4]
        PioneerObject.__init__(self, ObjectContainer, object_name, object_description, overridable_object)
        URLGroupObject.__init__(self)
        self.set_uid(object_uid)