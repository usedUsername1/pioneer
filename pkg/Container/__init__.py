import utils.helper as helper
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')

class Container():
    """
    Represents a container in the security device context.

    Args:
        security_device (SecurityDevice): The security device associated with the container.
        name (str): The name of the container.
        parent_name (str): The name of the parent container.
    """
    
    def __init__(self, security_device, name, parent_name) -> None:
        """
        Initializes a Container object with given details.

        Args:
            security_device (SecurityDevice): The security device associated with the container.
            name (str): The name of the container.
            parent_name (str): The name of the parent container.
        """
        self._security_device = security_device
        self._name = name
        self._parent_name = parent_name
        self._parent = None
        self._uid = helper.generate_uid()

    @property
    def uid(self):
        """
        Gets the unique identifier for the container.

        Returns:
            str: The UID of the container.
        """
        return self._uid

    @uid.setter
    def uid(self, value):
        """
        Sets the unique identifier for the container.

        Args:
            value (str): The new UID for the container.
        """
        self._uid = value

    @property
    def name(self):
        """
        Gets the name of the container.

        Returns:
            str: The name of the container.
        """
        return self._name

    @name.setter
    def name(self, value):
        """
        Sets the name of the container.

        Args:
            value (str): The new name of the container.
        """
        self._name = value

    @property
    def parent_name(self):
        """
        Gets the name of the parent container.

        Returns:
            str: The name of the parent container.
        """
        return self._parent_name

    @parent_name.setter
    def parent_name(self, value):
        """
        Sets the name of the parent container.

        Args:
            value (str): The new name of the parent container.
        """
        self._parent_name = value

    @property
    def parent(self):
        """
        Gets the parent container object.

        Returns:
            Container: The parent container object.
        """
        return self._parent

    @parent.setter
    def parent(self, value):
        """
        Sets the parent container object.

        Args:
            value (Container): The new parent container object.
        """
        self._parent = value

    @property
    def security_device(self):
        """
        Gets the security device associated with the container.

        Returns:
            SecurityDevice: The security device associated with the container.
        """
        return self._security_device

    @property
    def security_device_uid(self):
        """
        Gets the UID of the associated security device.

        Returns:
            str: The UID of the associated security device.
        """
        return self._security_device.uid

    @abstractmethod
    def save(self, db):
        """
        Saves the container information to the db.

        Args:
            db (Database): The db where the container information will be saved.
        
        This method should be implemented by subclasses.
        """
        pass

class SecurityPolicyContainer(Container):
    """
    Represents a container for security policies within a security device.

    Inherits from:
        Container: The base container class for security devices.

    Args:
        security_device (SecurityDevice): The security device associated with this container.
        name (str): The name of the security policy container.
        parent_name (str): The name of the parent container.
    """
    
    def __init__(self, security_device, name, parent_name) -> None:
        """
        Initializes a SecurityPolicyContainer object with the provided details.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            name (str): The name of the security policy container.
            parent_name (str): The name of the parent container.
        """
        super().__init__(security_device, name, parent_name)

    def save(self, db):
        """
        Saves the security policy container information to the db.

        Args:
            db (Database): The db where the container information will be saved.
        
        Handles saving with consideration for the presence or absence of a parent container.
        """        
        try:
            # Attempt to insert the container with parent UID
            db.security_policy_containers_table.insert(
                self.uid, 
                self.name, 
                self.security_device_uid, 
                self.parent.uid
            )
        except AttributeError:
            # Handle the case where the parent UID is None
            db.security_policy_containers_table.insert(
                self.uid, 
                self.name, 
                self.security_device_uid, 
                None
            )

class ObjectContainer(Container):
    """
    Represents a container for objects within a security device.

    Inherits from:
        Container: The base container class for security devices.

    Args:
        security_device (SecurityDevice): The security device associated with this container.
        name (str): The name of the object container.
        parent_name (str): The name of the parent container.
    """
    
    def __init__(self, security_device, name, parent_name) -> None:
        """
        Initializes an ObjectContainer object with the provided details.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            name (str): The name of the object container.
            parent_name (str): The name of the parent container.
        """
        super().__init__(security_device, name, parent_name)

    def save(self, db):
        """
        Saves the object container information to the db.

        Args:
            db (Database): The db where the container information will be saved.
        
        Handles saving with consideration for the presence or absence of a parent container.
        """
        
        try:
            # Attempt to insert the container with parent UID
            db.object_containers_table.insert(
                self.uid, 
                self.name, 
                self.security_device_uid, 
                self.parent.uid
            )
        except AttributeError:
            # Handle the case where the parent UID is None
            db.object_containers_table.insert(
                self.uid, 
                self.name, 
                self.security_device_uid, 
                None
            )

class ZoneContainer(Container):
    """
    Represents a container for zones within a security device.

    Inherits from:
        Container: The base container class for security devices.

    Args:
        security_device (SecurityDevice): The security device associated with this container.
        name (str): The name of the zone container.
        parent_name (str): The name of the parent container.
    """
    
    def __init__(self, security_device, name, parent_name) -> None:
        """
        Initializes a ZoneContainer object with the provided details.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            name (str): The name of the zone container.
            parent_name (str): The name of the parent container.
        """
        super().__init__(security_device, name, parent_name)
    
    def save(self, db):
        """
        Saves the zone container information to the db.

        Args:
            db (Database): The db where the container information will be saved.
        
        Handles saving with consideration for the presence or absence of a parent container.
        """
        
        try:
            # Attempt to insert the container with parent UID
            db.zone_containers_table.insert(
                self.uid, 
                self.name, 
                self.security_device_uid, 
                self.parent.uid
            )
        except AttributeError:
            # Handle the case where the parent UID is None
            db.zone_containers_table.insert(
                self.uid, 
                self.name, 
                self.security_device_uid, 
                None
            )

class ManagedDeviceContainer(Container):
    """
    Represents a container for managed devices within a security device.

    Inherits from:
        Container: The base container class for security devices.

    Args:
        security_device (SecurityDevice): The security device associated with this container.
        name (str): The name of the managed device container.
        parent_name (str): The name of the parent container.
    """
    
    def __init__(self, security_device, name, parent_name) -> None:
        """
        Initializes a ManagedDeviceContainer object with the provided details.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            name (str): The name of the managed device container.
            parent_name (str): The name of the parent container.
        """
        super().__init__(security_device, name, parent_name)
    
    def save(self, db):
        """
        Saves the managed device container information to the db.

        Args:
            db (Database): The db where the container information will be saved.
        
        Handles saving with consideration for the presence or absence of a parent container.
        """
        
        try:
            # Attempt to insert the container with parent UID
            db.managed_device_containers_table.insert(
                self.uid, 
                self.name, 
                self.security_device_uid, 
                self.parent.uid
            )
        except AttributeError:
            # Handle the case where the parent UID is None
            db.managed_device_containers_table.insert(
                self.uid, 
                self.name, 
                self.security_device_uid, 
                None
            )

class NATPolicyContainer:
    pass