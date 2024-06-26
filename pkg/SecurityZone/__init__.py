import utils.helper as helper
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')

class SecurityZone():
    def __init__(self, ObjectContainer, name) -> None:
        self._ObjectContainer = ObjectContainer
        self._name = name
        self._uid = helper.generate_uid()
    
    def get_name(self):
        return self._name
    
    def get_uid(self):
        return self._uid
    
    def save(self, Database):
        ZonesTable = Database.get_security_zones_table()
        ZonesTable.insert(self._uid, self._name, self._ObjectContainer.get_uid()) 
