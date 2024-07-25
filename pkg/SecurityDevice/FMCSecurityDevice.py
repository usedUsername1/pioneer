from abc import abstractmethod
from pkg.Container.FMCContainer import FMCSecurityPolicyContainer, FMCObjectContainer, FMCZoneContainer, FMCManagedDeviceContainer
from pkg.DeviceObject.FMCDeviceObject import FMCNetworkGroupObject, FMCNetworkObject, \
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
        uid (str): The unique identifier for the security device.
        name (str): The name of the security device.
        security_device_database (SecurityDeviceDatabase): The database for the security device.
        security_device_connection (SecurityDeviceConnection): The connection to the FMC device.

    Attributes:
        _security_device_connection (SecurityDeviceConnection): The connection to the FMC device.
    """

    def __init__(self, uid, name, security_device_database, security_device_connection):
        """
        Initializes an FMCSecurityDevice instance.

        Args:
            uid (str): The unique identifier for the security device.
            name (str): The name of the security device.
            security_device_database (SecurityDeviceDatabase): The database for the security device.
            security_device_connection (SecurityDeviceConnection): The connection to the FMC device.
        """
        super().__init__(uid, name, security_device_database, security_device_connection)
        self._security_device_connection = security_device_connection

    # returning container info methods
    def return_security_policy_container_info(self):
        """
        Retrieve security policy container information.

        Returns:
            dict: Information about the security policy container.
        """
        return self._security_device_connection.policy.accesspolicy.get()

    def return_managed_device_info(self):
        """
        Retrieve managed device information.

        Returns:
            dict: Information about the managed devices.
        """
        return self._security_device_connection.device.devicerecord.get()
    
    # returning container objects methods
    def return_security_policy_container(self, container_entry):
        """
        Retrieve a security policy container.

        Args:
            container_entry (dict): Entry containing information about the security policy container.

        Returns:
            FMCSecurityPolicyContainer: Instance of FMCSecurityPolicyContainer.
        """
        return FMCSecurityPolicyContainer(self, container_entry)

    def return_object_container(self, container_entry):
        """
        Retrieve an object container.

        Args:
            container_entry (dict): Entry containing information about the object container.

        Returns:
            FMCObjectContainer: Instance of FMCObjectContainer.
        """
        return FMCObjectContainer(self, container_entry)

    def return_zone_container(self, container_entry):
        """
        Retrieve a zone container.

        Args:
            container_entry (dict): Entry containing information about the zone container.

        Returns:
            FMCZoneContainer: Instance of FMCZoneContainer.
        """
        return FMCZoneContainer(self, container_entry)

    def return_managed_device_container(self, container_entry):
        """
        Retrieve a managed device container.

        Args:
            container_entry (dict): Entry containing information about the managed device container.

        Returns:
            FMCManagedDeviceContainer: Instance of FMCManagedDeviceContainer.
        """
        return FMCManagedDeviceContainer(self, container_entry)

    # returning objects info methods
    def return_network_object_info(self):
        """
        Retrieve network object information.

        Returns:
            dict: Information about the network objects.
        """
        return self._security_device_connection.object.networkaddress.get()

    def return_network_group_object_info(self):
        """
        Retrieve network group object information.

        Returns:
            dict: Information about the network group objects.
        """
        return self._security_device_connection.object.networkgroup.get()

    def return_port_object_info(self):
        """
        Retrieve port object information.

        Returns:
            dict: Information about the port objects.
        """
        return self._security_device_connection.object.port.get()

    def return_port_group_object_info(self):
        """
        Retrieve port group object information.

        Returns:
            dict: Information about the port group objects.
        """
        return self._security_device_connection.object.portobjectgroup.get()

    def return_url_object_info(self):
        """
        Retrieve URL object information.

        Returns:
            dict: Information about the URL objects.
        """
        return self._security_device_connection.object.url.get()

    def return_url_group_object_info(self):
        """
        Retrieve URL group object information.

        Returns:
            dict: Information about the URL group objects.
        """
        return self._security_device_connection.object.urlgroup.get()

    def return_security_zone_info(self):
        """
        Retrieve security zone information.

        Returns:
            dict: Information about the security zones.
        """
        return self._security_device_connection.object.securityzone.get()

    def return_schedule_object_info(self):
        """
        Retrieve schedule object information.

        Returns:
            dict: Information about the schedule objects.
        """
        return self._security_device_connection.object.timerange.get()

    def return_security_policy_info(self, security_policy_container):
        """
        Retrieve information about security policies within a specified container.

        Args:
            security_policy_container (FMCSecurityPolicyContainer): The container for the security policies.

        Returns:
            list: List of dictionaries containing information about security policies.
        """
        security_policy_container_name = security_policy_container.name
        # Execute the request to retrieve information about the security policies
        security_policies_info = self._security_device_connection.policy.accesspolicy.accessrule.get(container_name=security_policy_container_name)
        
        # Filter out the security policies which are not part of the current container being processed
        filtered_data_gen = (entry for entry in security_policies_info if entry['metadata']['accessPolicy']['name'] == security_policy_container_name)

        # Convert generator to a list if needed
        filtered_data = list(filtered_data_gen)
        return filtered_data

    # returning objects methods
    def return_managed_device(self, managed_device_container, managed_device_entry):
        """
        Retrieve a managed device.

        Args:
            managed_device_container (FMCManagedDeviceContainer): The container for the managed device.
            managed_device_entry (dict): Entry containing information about the managed device.

        Returns:
            FMCManagedDevice: Instance of FMCManagedDevice.
        """
        return FMCManagedDevice(managed_device_container, managed_device_entry)

    def return_network_object(self, object_container, network_object_entry):
        """
        Retrieve a network object.

        Args:
            object_container (FMCObjectContainer): The container for the network object.
            network_object_entry (dict): Entry containing information about the network object.

        Returns:
            FMCNetworkObject: Instance of FMCNetworkObject.
        """
        return FMCNetworkObject(object_container, network_object_entry)

    def return_network_group_object(self, object_container, network_group_object_entry):
        """
        Retrieve a network group object.

        Args:
            object_container (FMCObjectContainer): The container for the network group object.
            network_group_object_entry (dict): Entry containing information about the network group object.

        Returns:
            FMCNetworkGroupObject: Instance of FMCNetworkGroupObject.
        """
        return FMCNetworkGroupObject(object_container, network_group_object_entry)

    def return_geolocation_object(self, object_container, geolocation_object_entry):
        """
        Retrieve a geolocation object.

        Args:
            object_container (FMCObjectContainer): The container for the geolocation object.
            geolocation_object_entry (dict): Entry containing information about the geolocation object.

        Returns:
            FMCGeolocationObject: Instance of FMCGeolocationObject.
        """
        return FMCGeolocationObject(object_container, geolocation_object_entry)

    def return_port_object(self, object_container, port_object_entry):
        """
        Retrieve a port object.

        Args:
            object_container (FMCObjectContainer): The container for the port object.
            port_object_entry (dict): Entry containing information about the port object.

        Returns:
            FMCICMPObject or FMCPortObject: Instance of the appropriate port object class.
        """
        if 'ICMP' in port_object_entry['type']:
            return FMCICMPObject(object_container, port_object_entry)
        else:
            return FMCPortObject(object_container, port_object_entry)

    def return_port_group_object(self, object_container, port_group_object_entry):
        """
        Retrieve a port group object.

        Args:
            object_container (FMCObjectContainer): The container for the port group object.
            port_group_object_entry (dict): Entry containing information about the port group object.

        Returns:
            FMCPortGroupObject: Instance of FMCPortGroupObject.
        """
        return FMCPortGroupObject(object_container, port_group_object_entry)

    def return_url_object(self, object_container, url_object_entry):
        """
        Retrieve a URL object.

        Args:
            object_container (FMCObjectContainer): The container for the URL object.
            url_object_entry (dict): Entry containing information about the URL object.

        Returns:
            FMCURLObject: Instance of FMCURLObject.
        """
        return FMCURLObject(object_container, url_object_entry)

    def return_url_group_object(self, object_container, url_group_object_entry):
        """
        Retrieve a URL group object.

        Args:
            object_container (FMCObjectContainer): The container for the URL group object.
            url_group_object_entry (dict): Entry containing information about the URL group object.

        Returns:
            FMCURLGroupObject: Instance of FMCURLGroupObject.
        """
        return FMCURLGroupObject(object_container, url_group_object_entry)

    def return_security_zone(self, zone_container, zone_entry):
        """
        Retrieve a security zone.

        Args:
            zone_container (FMCZoneContainer): The container for the security zone.
            zone_entry (dict): Entry containing information about the security zone.

        Returns:
            FMCSecurityZone: Instance of FMCSecurityZone.
        """
        return FMCSecurityZone(zone_container, zone_entry)

    def return_schedule_object(self, object_container, schedule_object_entry):
        """
        Retrieve a schedule object.

        Args:
            object_container (FMCObjectContainer): The container for the schedule object.
            schedule_object_entry (dict): Entry containing information about the schedule object.

        Returns:
            FMCScheduleObject: Instance of FMCScheduleObject.
        """
        return FMCScheduleObject(object_container, schedule_object_entry)

    def return_security_policy_object(self, security_policy_container, policy_entry):
        """
        Retrieve a security policy object.

        Args:
            security_policy_container (FMCSecurityPolicyContainer): The container for the security policy.
            policy_entry (dict): Entry containing information about the security policy.

        Returns:
            FMCSecurityPolicy: Instance of FMCSecurityPolicy.
        """
        return FMCSecurityPolicy(security_policy_container, policy_entry)

    # other functions
    def get_device_version(self):
        """
        Retrieve the version of the device's server.

        Returns:
            str: Version of the device's server.
        """
        # Retrieve device system information to get the server version
        device_system_info = self._security_device_connection.system.info.serverversion.get()

        # Extract the exact info needed from the response got from the device
        device_version = device_system_info[0]['serverVersion']
        return device_version
