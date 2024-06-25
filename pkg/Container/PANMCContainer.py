from pkg.Container import SecurityPolicyContainer, ObjectContainer, VirtualContainer, ZoneContainer, ManagedDeviceContainer, Container

# for PANMC, all containers are actually the same device group (except for security zones, which are stored in templates)
# create a DeviceGroup class and make all the containers inherit from it

class PANMCSecurityPolicyContainer(SecurityPolicyContainer):
    """
    Represents a policy container specific to the Firepower Management Center (PANMC).
    """
    def __init__(self, SecurityDevice, container_info) -> None:
        """
        Initialize an PANMCPolicyContainer instance.

        Parameters:
            container_info (dict): Information about the policy container.
        """
        SecurityPolicyContainer().__init__(SecurityDevice, container_info, self._name, self._parent_name)

class PANMCObjectContainer(ObjectContainer):
    """
    Represents an object container specific to the Firepower Management Center (PANMC).
    """
    def __init__(self, SecurityDevice, container_info) -> None:
        """
        Initialize an PANMCObjectContainer instance.

        Parameters:
            container_info (dict): Information about the object container.
        """
        super().__init__(SecurityDevice, container_info, container_info['name'], container_info['parent'])