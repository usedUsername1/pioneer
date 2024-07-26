import utils.helper as helper
from abc import abstractmethod

# Logger for general-purpose messages
general_logger = helper.logging.getLogger('general')

class SecurityZone:
    def __init__(self, object_container, name) -> None:
        """
        Initialize a SecurityZone instance.

        Args:
            object_container (ObjectContainer): The container that holds the security zone.
            name (str): The name of the security zone.
        """
        self._object_container = object_container
        self._name = name
        self._uid = helper.generate_uid()
    
    @property
    def name(self):
        """
        Get the name of the security zone.

        Returns:
            str: The name of the security zone.
        """
        return self._name
    
    @property
    def uid(self):
        """
        Get the unique identifier (UID) of the security zone.

        Returns:
            str: The UID of the security zone.
        """
        return self._uid
    
    def save(self, db):
        """
        Save the security zone to the db.

        Args:
            db (db): The db instance where the security zone will be saved.
        """
        # Insert the security zone into the table
        db.security_zones_table.insert(self._uid, self._name, self._object_container.uid)