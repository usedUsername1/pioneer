from abc import abstractmethod
from pkg.Container.FMCContainer import FMCSecurityPolicyContainer, FMCObjectContainer, FMCZoneContainer, FMCManagedDeviceContainer
from pkg.DeviceObject.FMCDeviceObject import FMCObject, FMCNetworkGroupObject, FMCNetworkObject, \
FMCPortObject, FMCICMPObject, FMCPortGroupObject, FMCGeolocationObject, FMCURLObject, FMCURLGroupObject, FMCScheduleObject
from pkg.Policy.FMCPolicy import FMCSecurityPolicy
from pkg.SecurityZone.FMCSecurityZone import FMCSecurityZone
from pkg.SecurityDevice import SecurityDevice 
from pkg.ManagedDevice.FMCManagedDevice import FMCManagedDevice

import utils.helper as helper
import utils.gvars as gvars

general_logger = helper.logging.getLogger('general')
  
class FMCSecurityDevice(SecurityDevice):
    """
    Represents a Cisco Firepower Management Center (FMC) security device.

    Args:
        name (str): The name of the security device.
        SecurityDeviceDatabase: The database for the security device.
        security_device_username (str): The username for accessing the security device.
        security_device_secret (str): The secret for accessing the security device.
        security_device_hostname (str): The hostname or IP address of the security device.
        security_device_port (int): The port number for connecting to the security device.
        domain (str): The domain of the security device.

    Attributes:
        _SecurityDeviceConnection: The connection to the FMC device.
    """

    def __init__(self, uid, name, SecurityDeviceDatabase, SecurityDeviceConnection):
        """
        Initializes an FMCSecurityDevice instance.

        Args:
            name (str): The name of the security device.
            SecurityDeviceDatabase: The database for the security device.
            security_device_username (str): The username for accessing the security device.
            security_device_secret (str): The secret for accessing the security device.
            security_device_hostname (str): The hostname or IP address of the security device.
            security_device_port (int): The port number for connecting to the security device.
            domain (str): The domain of the security device.
        """
        super().__init__(uid, name, SecurityDeviceDatabase, SecurityDeviceConnection)
        self._SecurityDeviceConnection = SecurityDeviceConnection
        self._network_address_objects_info = None
        self._network_group_objects_info = None
        self._geolocation_objects_info = None
        self._countries_info = None
        self._continents_info = None
        self._port_objects_info = None
        self._port_group_objects_info = None
        self._url_objects_info = None
        self._url_object_groups_info = None

    def return_security_policy_container_info(self):
        return self._SecurityDeviceConnection.policy.accesspolicy.get()

    def return_managed_device_info(self):
        return self._SecurityDeviceConnection.device.devicerecord.get()

    def return_network_object_info(self):
        return self._SecurityDeviceConnection.object.networkaddress.get()

    def return_network_group_object_info(self):
        return self._SecurityDeviceConnection.object.networkgroup.get()
    
    #TODO: should contintents and countries be imported here as well?
    # def return_geolocation_object_info(self):
    #     return self._SecurityDeviceConnection.object.geolocation.get()
        # return self._SecurityDeviceConnection.object.country.get()
        # self._SecurityDeviceConnection.object.continent.get()
    
    def return_port_object_info(self):
        return self._SecurityDeviceConnection.object.port.get()
        
    def return_port_group_object_info(self):
        return self._SecurityDeviceConnection.object.portobjectgroup.get()
        
    def return_url_object_info(self):
        return self._SecurityDeviceConnection.object.url.get()
        
    def return_url_group_object_info(self):
        return self._SecurityDeviceConnection.object.urlgroup.get()

    def return_security_zone_info(self):
        return self._SecurityDeviceConnection.object.securityzone.get()
    
    def return_schedule_object_info(self):
        return self._SecurityDeviceConnection.object.timerange.get()
    
    def return_security_policy_container(self, container_entry):
        return FMCSecurityPolicyContainer(self, container_entry)

    def return_object_container(self, container_entry):
        return FMCObjectContainer(self, container_entry)

    def return_zone_container(self, container_entry):
        return FMCZoneContainer(self, container_entry)
    
    def return_managed_device_container(self, container_entry):
        return FMCManagedDeviceContainer(self, container_entry)

    def return_managed_device(self, ManagedDeviceContainer, managed_device_entry):
        """
        Override create_managed_device method to return FMCManagedDevice instance.

        Args:
            managed_device_entry: Entry containing information about the managed device.

        Returns:
            FMCManagedDevice: Instance of FMCManagedDevice.
        """
        return FMCManagedDevice(ManagedDeviceContainer, managed_device_entry)

    def return_network_object(self, ObjectContainer, network_object_entry):
        return FMCNetworkObject(ObjectContainer, network_object_entry)
    
    def return_network_group_object(self, ObjectContainer, network_group_object_entry):
        return FMCNetworkGroupObject(ObjectContainer, network_group_object_entry)

    def return_geolocation_object(self, ObjectContainer, geolocation_object_entry):
        return FMCGeolocationObject(ObjectContainer, geolocation_object_entry)

    #TODO: the problem is ICMP objects and port objects are treated the same by FMC, there is no distinction between them.
    # we need to determine the type of the object and then call the right constructor based on the object's type
    def return_port_object(self, ObjectContainer, port_object_entry):
        if 'ICMP' in port_object_entry['type']:
            return FMCICMPObject(ObjectContainer, port_object_entry)
        else:
            return FMCPortObject(ObjectContainer, port_object_entry)

    # for FMC devices, retrieving the policies of a child container, will also return the policies
    # inherited from the parent.
    # they need to be filtered out
    def return_security_policy_info(self, SecurityPolicyContainer):
        """
        Retrieve information about security policies within a specified container.

        Args:
            policy_container_name (str): Name of the container containing the security policies.

        Returns:
            list: List of dictionaries containing information about security policies.
        """
        security_policy_container_name = SecurityPolicyContainer.get_name()
        # Execute the request to retrieve information about the security policies
        security_policies_info = self._SecurityDeviceConnection.policy.accesspolicy.accessrule.get(container_name=security_policy_container_name)
        
        # Filter out the security policies which are not part of the current container being processed
        filtered_data_gen = (entry for entry in security_policies_info if entry['metadata']['accessPolicy']['name'] == security_policy_container_name)

        # Convert generator to a list if needed
        filtered_data = list(filtered_data_gen)

        return filtered_data

    def return_port_group_object(self, ObjectContainer, port_group_object_entry):
        return FMCPortGroupObject(ObjectContainer, port_group_object_entry)

    def return_url_object(self, ObjectContainer, url_object_entry):
        return FMCURLObject(ObjectContainer, url_object_entry)

    def return_url_group_object(self, ObjectContainer, url_group_object_entry):
        return FMCURLGroupObject(ObjectContainer, url_group_object_entry)
    
    def return_security_zone(self, ZoneContainer, zone_entry):
        return FMCSecurityZone(ZoneContainer, zone_entry)

    def return_schedule_object(self, ObjectContainer, schedule_object_entry):
        return FMCScheduleObject(ObjectContainer, schedule_object_entry)

    #TODO is there anyway to put the virtual object container here?
    def return_security_policy_object(self, SecurityPolicyContainer, policy_entry):
        # return security policy object only if the current policy belongs to the current container,
        # if it belongs to another parent, skip it
        return FMCSecurityPolicy(SecurityPolicyContainer, policy_entry)

    def get_device_version(self):
        """
        Retrieve the version of the device's server.

        Returns:
            str: Version of the device's server.
        """
        # Retrieve device system information to get the server version
        device_system_info = self._SecurityDeviceConnection.system.info.serverversion.get()

        # Extract the exact info needed from the response got from the device
        device_version = device_system_info[0]['serverVersion']
        return device_version