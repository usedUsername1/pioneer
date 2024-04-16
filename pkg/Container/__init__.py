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
    def save(self, database):
        pass

class SecurityPolicyContainer(Container):
    def __init__(self, container_info) -> None:
        """
        Initializes a SecurityPolicyContainer object.

        Args:
            container_info: Information related to the security policy container.
        """
        general_logger.debug("Called SecurityPolicyContainer::__init__()")
        super().__init__(container_info)

class ObjectContainer(Container):
    def __init__(self, container_info) -> None:
        """
        Initializes an ObjectPolicyContainer object.

        Args:
            container_info: Information related to the object policy container.
        """
        general_logger.debug("Called ObjectPolicyContainer::__init__()")
        super().__init__(container_info)

class NATPolicyContainer:
    pass