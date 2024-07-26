from pkg.Container import SecurityPolicyContainer, ObjectContainer, ZoneContainer, ManagedDeviceContainer
import utils.gvars as gvars
class FMCSecurityPolicyContainer(SecurityPolicyContainer):
    """
    Represents a security policy container specific to the Firepower Management Center (FMC).
    """
    
    def __init__(self, security_device, container_info) -> None:
        """
        Initializes an FMCSecurityPolicyContainer instance.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            container_info (dict): Information about the policy container, including its name and parent policy.
        """
        super().__init__(security_device, container_info['name'], container_info['metadata'].get('parentPolicy', {}).get('name'))


class FMCObjectContainer(ObjectContainer):
    """
    Represents an object container specific to the Firepower Management Center (FMC).
    """
    
    def __init__(self, security_device, container_info) -> None:
        """
        Initializes an FMCObjectContainer instance.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            container_info (dict): Information about the object container.
        """
        super().__init__(security_device, gvars.virtual_container_name, None)


class FMCZoneContainer(ZoneContainer):
    """
    Represents a zone container specific to the Firepower Management Center (FMC).
    """
    
    def __init__(self, security_device, container_entry) -> None:
        """
        Initializes an FMCZoneContainer instance.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            container_entry: Information related to the zone container.
        """
        super().__init__(security_device, gvars.virtual_container_name, None)


class FMCManagedDeviceContainer(ManagedDeviceContainer):
    """
    Represents a managed device container specific to the Firepower Management Center (FMC).
    """
    
    def __init__(self, security_device, container_entry) -> None:
        """
        Initializes an FMCManagedDeviceContainer instance.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            container_entry: Information related to the managed device container.
        """
        super().__init__(security_device, gvars.virtual_container_name, None)