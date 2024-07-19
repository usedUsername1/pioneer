import utils.helper as helper
from pkg.DeviceObject import Object, NetworkObject, GeolocationObject, CountryObject, PortObject, ICMPObject, URLObject, \
NetworkGroupObject, PortGroupObject, URLGroupObject, ScheduleObject, PolicyUserObject, URLCategoryObject, \
L7AppObject, L7AppFilterObject, L7AppGroupObject
import utils.gvars as gvars
import ipaddress
import utils.exceptions as PioneerExceptions
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')