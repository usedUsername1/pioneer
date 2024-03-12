import utils.helper as helper
from abc import abstractmethod
general_logger = helper.logging.getLogger('general')

class Container:
    def __init__(self, container_info) -> None:
        """
        Initializes a Container object.

        Args:
            container_info: Information related to the container.
        """
        general_logger.debug("Called Container::__init__()")
        self._container_info = container_info
        self._name = None
        self._parent = None
    
    def set_name(self, name):
        """
        Sets the name of the container.

        Args:
            name (str): The name of the container.
        """
        general_logger.debug("Called Container::set_name()")
        self._name = name

    def set_parent(self, parent):
        """
        Sets the parent container of the current container.

        Args:
            parent (Container): The parent container object.
        """
        general_logger.debug("Called Container::set_parent()")
        self._parent = parent

    def get_name(self):
        """
        Gets the name of the container.

        Returns:
            str: The name of the container.
        """
        general_logger.debug("Called Container::get_name()")
        return self._name

    def get_parent_name(self):
        """
        Gets the name of the parent container.

        Returns:
            str: The name of the parent container.
        """
        general_logger.debug("Called Container::get_parent_name()")
        return self._parent.get_name()

    def get_security_device_name(self):
        """
        Gets the name of the security device associated with the container.

        Returns:
            str: The name of the security device.
        """
        general_logger.debug("Called Container::get_security_device_name()")
        return self._security_device_name

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

    def get_info(self):
        """
        Retrieves the information of a container info that is used to initialize the container.

        Returns:
            Any: Information related to the container.
        """
        general_logger.debug("Called Container::get_info()")
        return self._container_info

class SecurityPolicyContainer(Container):
    def __init__(self, container_info) -> None:
        """
        Initializes a SecurityPolicyContainer object.

        Args:
            container_info: Information related to the security policy container.
        """
        general_logger.debug("Called SecurityPolicyContainer::__init__()")
        super().__init__(container_info)

    def process_container_info(self):
        """
        Processes the security policy container information.

        Returns:
            dict: Processed information about the security policy container.
        """
        general_logger.debug("Called SecurityPolicyContainer::process_container_info()")
        try:
            container_processed_info = {
                'security_policy_container_name': self.get_name(),
                'security_policy_parent': self.get_parent_name()
            }
        
        # If the parent doesn't exist, then an Attribute Error exception will be raised
        except AttributeError:
            container_processed_info = {
                'security_policy_container_name': self.get_name(),
                'security_policy_parent': None
            }

        return container_processed_info

class ObjectPolicyContainer(Container):
    def __init__(self, container_info) -> None:
        """
        Initializes an ObjectPolicyContainer object.

        Args:
            container_info: Information related to the object policy container.
        """
        general_logger.debug("Called ObjectPolicyContainer::__init__()")
        super().__init__(container_info)
    
    def process_container_info(self):
        """
        Processes the object policy container information.

        Returns:
            dict: Processed information about the object policy container.
        """
        general_logger.debug("Called ObjectPolicyContainer::process_container_info()")
        try:
            container_processed_info = {
                'object_container_name': self.get_name(),
                'object_container_parent': self.get_parent_name()
            }
        
        except AttributeError:
            container_processed_info = {
                'object_container_name': self.get_name(),
                'object_container_parent': None
            }

        return container_processed_info

class NATPolicyContainer:
    pass