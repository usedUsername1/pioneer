from pkg.Container import SecurityPolicyContainer, ObjectContainer, VirtualContainer, ZoneContainer, ManagedDeviceContainer

#TODO: maybe use setters for setting the values in here, and use the getters from the parent class to retrieve the info. just like you do for objects
class FMCSecurityPolicyContainer(SecurityPolicyContainer):
    """
    Represents a policy container specific to the Firepower Management Center (FMC).
    """

    def __init__(self, SecurityDevice, container_info) -> None:
        """
        Initialize an FMCPolicyContainer instance.

        Parameters:
            container_info (dict): Information about the policy container.
        """
        super().__init__(SecurityDevice, container_info)

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

    def set_parent_name(self):
        try:
            parent_name = self._container_info['metadata']['parentPolicy']['name']
        except KeyError:
            parent_name = None
        return super().set_parent_name(parent_name)

    def is_child_container(self):
        """
        Check if the container is a child container.

        Returns:
            bool: True if the container is a child container, False otherwise.
        """
        return self._container_info['metadata']['inherit']

class FMCObjectContainer(ObjectContainer, VirtualContainer):
    """
    Represents an object container specific to the Firepower Management Center (FMC).
    """
    def __init__(self, SecurityDevice, container_info) -> None:
        """
        Initialize an FMCObjectContainer instance.

        Parameters:
            container_info (dict): Information about the object container.
        """
        super().__init__(SecurityDevice, container_info)

class FMCZoneContainer(ZoneContainer, VirtualContainer):
    def __init__(self, SecurityDevice, container_info) -> None:
        super().__init__(SecurityDevice, container_info)

class FMCManagedDeviceContainer(ManagedDeviceContainer, VirtualContainer):
    def __init__(self, SecurityDevice, container_info) -> None:
        super().__init__(SecurityDevice, container_info)