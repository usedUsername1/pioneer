import utils.helper as helper
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')

class Container:
    def __init__(self, SecurityDevice, container_info) -> None:
        """
        Initializes a Container object.

        Args:
            container_info: Information related to the container.
        """
        self._container_info = container_info
        self._security_device_uid = SecurityDevice.get_uid()
        self._name = None
        self._parent_name = None
        self._parent = None
        self._uid = helper.generate_uid()

    def set_name(self, name):
        """
        Sets the name of the container.

        Args:
            name (str): The name of the container.
        """
        self._name = name

    def set_parent_name(self, parent_name):
        """
        Sets the parent container of the current container.

        Args:
            parent (Container): The parent container object.
        """
        self._parent_name = parent_name
    
    def set_parent(self, parent):
        self._parent = parent
    
    def get_parent(self):
        return self._parent
    
    def set_uid(self, uid):
        self._uid = uid
    
    def get_uid(self):
        return self._uid

    def get_name(self):
        """
        Gets the name of the container.

        Returns:
            str: The name of the container.
        """
        return self._name

    def get_parent_name(self):
        """
        Get the name of the parent policy.

        Returns:
            str: Name of the parent policy.
        """
        return self._parent_name

    def get_security_device_uid(self):
        return self._security_device_uid

    @abstractmethod
    def process_container_info(self):
        """
        Processes the container information. Implemented in the children Container classes
        """
        pass

    @abstractmethod
    def is_child_container(self):
        """
        Checks if the container is a child container. Implemented in the device specific children Container classes.

        Returns:
            bool: True if the container is a child container, False otherwise.
        """
        pass

    @abstractmethod
    def save(self, Database):
        pass

class SecurityPolicyContainer(Container):
    def __init__(self, SecurityDevice, container_info) -> None:
        """
        Initializes a SecurityPolicyContainer object.

        Args:
            container_info: Information related to the security policy container.
        """
        super().__init__(SecurityDevice, container_info)

    def save(self, Database):
        SecurityPolicyContainerTable = Database.get_security_policy_containers_table()
        try:
            SecurityPolicyContainerTable.insert(self.get_uid(), self.get_name(), self.get_security_device_uid(), self.get_parent().get_uid())
        except AttributeError:
            SecurityPolicyContainerTable.insert(self.get_uid(), self.get_name(), self.get_security_device_uid(), None)

class ObjectContainer(Container):
    def __init__(self, SecurityDevice, container_info) -> None:
        """
        Initializes an ObjectPolicyContainer object.

        Args:
            container_info: Information related to the object policy container.
        """
        super().__init__(SecurityDevice, container_info)

    def save(self, Database):
        ObjectContainersTable = Database.get_object_containers_table()
        try:
            ObjectContainersTable.insert(self.get_uid(), self.get_name(), self.get_security_device_uid(), self.get_parent().get_uid())
        except AttributeError:
            ObjectContainersTable.insert(self.get_uid(), self.get_name(), self.get_security_device_uid(), None)

class VirtualContainer(Container):
    def __init__(self, SecurityDevice, container_info) -> None:
        super().__init__(SecurityDevice, container_info)
    """
    Represents a virtual container.
    """
    def __init__(self, SecurityDevice, container_info) -> None:
        """
        Initialize an Virtual Container instance.

        Parameters:
            container_info (dict): Information about the object container.
        """
        super().__init__(SecurityDevice, container_info)

    def is_child_container(self):
        """
        Check if the container is a child container.

        Returns:
            bool: Always returns False for FMC object containers.
        """
        return False

    def get_parent_name(self):
        """
        Get the name of the parent container.

        Returns:
            None: Since FMC object containers do not have parent containers, it returns None.
        """
        return None

    def set_name(self):
        name = "virtual_container"
        return super().set_name(name)

    def set_parent_name(self):
        parent_name = None
        return super().set_parent_name(parent_name)

class ZoneContainer(Container):
    def __init__(self, SecurityDevice, container_info) -> None:
        super().__init__(SecurityDevice, container_info)
    
    def save(self, Database):
        ZoneContainersTable = Database.get_zone_containers_table()
        try:
            ZoneContainersTable.insert(self.get_uid(), self.get_name(), self.get_security_device_uid(), self.get_parent().get_uid())
        except AttributeError:
            ZoneContainersTable.insert(self.get_uid(), self.get_name(), self.get_security_device_uid(), None)

class ManagedDeviceContainer(Container):
    def __init__(self, SecurityDevice, container_info) -> None:
        super().__init__(SecurityDevice, container_info)
    
    def save(self, Database):
        ManagedDeviceContainersTable = Database.get_managed_device_containers_table()
        try:
            ManagedDeviceContainersTable.insert(self.get_uid(), self.get_name(), self.get_security_device_uid(), self.get_parent().get_uid())
        except:
            ManagedDeviceContainersTable.insert(self.get_uid(), self.get_name(), self.get_security_device_uid(), None)


class NATPolicyContainer:
    pass