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
        self._parent = None
        self._uid = helper.generate_uid()

    def set_name(self, name):
        """
        Sets the name of the container.

        Args:
            name (str): The name of the container.
        """
        self._name = name

    def set_parent(self, parent):
        """
        Sets the parent container of the current container.

        Args:
            parent (Container): The parent container object.
        """
        self._parent = parent
    
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

    def get_parent(self):
        """
        Get the name of the parent policy.

        Returns:
            str: Name of the parent policy.
        """
        return self._parent

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
        SecurityPolicyContainerTable.insert(self.get_uid(), self.get_name(), self.get_security_device_uid(), self.get_parent())

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
        ObjectContainersTable.insert(self.get_uid(), self.get_name(), self.get_security_device_uid(), self.get_parent())

class NATPolicyContainer:
    pass