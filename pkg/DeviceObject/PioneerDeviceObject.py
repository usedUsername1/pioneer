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

#TODO: class variables for the ObjectContainer?
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

#TODO: implement these classes
class PioneerPortObject(PortObject, PioneerObject):
    pass

class PioneerICMPObject(ICMPObject, PioneerObject):
    pass

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
    pass

class PioneerURLGroupObject(URLGroupObject, PioneerObject):
    pass