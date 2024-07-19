from pkg.Container import SecurityPolicyContainer, ObjectContainer, ZoneContainer, ManagedDeviceContainer

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
        self._name = container_info['name']
        self._parent_name = container_info['metadata'].get('parentPolicy', {}).get('name')
        super().__init__(SecurityDevice, self._name, self._parent_name)

class FMCObjectContainer(ObjectContainer):
    """
    Represents an object container specific to the Firepower Management Center (FMC).
    """
    def __init__(self, SecurityDevice, container_info) -> None:
        """
        Initialize an FMCObjectContainer instance.

        Parameters:
            container_info (dict): Information about the object container.
        """
        super().__init__(SecurityDevice, 'virtual_container', None)

class FMCZoneContainer(ZoneContainer):
    def __init__(self, SecurityDevice, container_entry) -> None:
        super().__init__(SecurityDevice, 'virtual_container', None)

class FMCManagedDeviceContainer(ManagedDeviceContainer):
    def __init__(self, SecurityDevice, container_entry) -> None:
        super().__init__(SecurityDevice, 'virtual_container', None)