from pkg.Container import SecurityPolicyContainer, ObjectContainer, ZoneContainer, ManagedDeviceContainer, Container, NATPolicyContainer

# for PANMC, all containers are actually the same device group (except for security zones, which are stored in templates)
# create a DeviceGroup class and make all the containers inherit from it

class PANMCSecurityPolicyContainer(SecurityPolicyContainer):
    """
    Represents a policy container specific to the Panorama Management Center (PANMC).
    """
    
    def __init__(self, security_device, container_info) -> None:
        """
        Initializes a PANMCSecurityPolicyContainer instance.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            container_info (dict): Information about the policy container, including its name and parent.
        """
        super().__init__(security_device, container_info['name'], container_info['parent'])

class PANMCNATContainer(NATPolicyContainer):
    """
    Represents a policy container specific to the Panorama Management Center (PANMC).
    """
    
    def __init__(self, security_device, container_info) -> None:
        """
        Initializes a PANMCNATContainer instance.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            container_info (dict): Information about the policy container, including its name and parent.
        """
        super().__init__(security_device, container_info['name'], container_info['parent'])

class PANMCObjectContainer(ObjectContainer):
    """
    Represents an object container specific to the Panorama Management Center (PANMC).
    """
    
    def __init__(self, security_device, container_info) -> None:
        """
        Initializes a PANMCObjectContainer instance.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            container_info (dict): Information about the object container, including its name and parent.
        """
        super().__init__(security_device, container_info['name'], container_info['parent'])


class PANMCSecurityZoneContainer(ZoneContainer):
    """
    Represents a security zone container specific to the Panorama Management Center (PANMC).
    """
    
    def __init__(self, security_device, container_info) -> None:
        """
        Initializes a PANMCSecurityZoneContainer instance.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            container_info (dict): Information about the security zone container, including its name and parent.
        """
        super().__init__(security_device, container_info['name'], container_info['parent'])