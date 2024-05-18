import utils.helper as helper
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')
from pkg.DeviceObject import Object

class SecurityZone(Object):
    def __init__(self, ObjectContainer, object_info) -> None:
        super().__init__(ObjectContainer, object_info)
    
    def set_attributes(self):
        self.set_name()

    def save(self, Database):
        ZonesTable = Database.get_security_zones_table()
        ZonesTable.insert(self.get_uid(), self.get_name(), self.get_object_container().get_uid()) 
