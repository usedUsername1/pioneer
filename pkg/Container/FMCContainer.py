from pkg.Container import SecurityPolicyContainer, ObjectContainer

#TODO: maybe use setters for setting the values in here, and use the getters from the parent class to retrieve the info. just like you do for objects
class FMCSecurityPolicyContainer(SecurityPolicyContainer):
    """
    Represents a policy container specific to the Firepower Management Center (FMC).
    """

    def __init__(self, container_info) -> None:
        """
        Initialize an FMCPolicyContainer instance.

        Parameters:
            container_info (dict): Information about the policy container.
        """
        super().__init__(container_info)

    def set_name(self):
        name = self._container_info['name']
        return super().set_name(name)

    def get_name(self):
        """
        Get the name of the policy container.

        Returns:
            str: Name of the policy container.
        """
        return self._name

    def set_parent(self):
        try:
            parent = self._container_info['metadata']['parentPolicy']['name']
        except KeyError:
            parent = None
        return super().set_parent(parent)
    
    def get_parent(self):
        """
        Get the name of the parent policy.

        Returns:
            str: Name of the parent policy.
        """
        return self._parent

    def is_child_container(self):
        """
        Check if the container is a child container.

        Returns:
            bool: True if the container is a child container, False otherwise.
        """
        return self._container_info['metadata']['inherit']

class FMCObjectContainer(ObjectContainer):
    """
    Represents an object container specific to the Firepower Management Center (FMC).
    """

    def __init__(self, container_info) -> None:
        """
        Initialize an FMCObjectContainer instance.

        Parameters:
            container_info (dict): Information about the object container.
        """
        super().__init__(container_info)

    def is_child_container(self):
        """
        Check if the container is a child container.

        Returns:
            bool: Always returns False for FMC object containers.
        """
        return False

    def get_parent(self):
        """
        Get the name of the parent container.

        Returns:
            None: Since FMC object containers do not have parent containers, it returns None.
        """
        return None

    def set_name(self):
        name = "virtual_object_container"
        return super().set_name(name)

    def set_parent(self):
        parent = None
        return super().set_parent(parent)
    