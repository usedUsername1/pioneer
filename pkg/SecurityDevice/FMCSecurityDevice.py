from abc import abstractmethod
from pkg.Container.FMCContainer import FMCSecurityPolicyContainer, FMCObjectContainer, FMCZoneContainer, FMCManagedDeviceContainer
from pkg.DeviceObject.FMCDeviceObject import FMCObject, FMCNetworkGroupObject, FMCNetworkObject, FMCNetworkLiteralObject, \
FMCPortObject, FMCICMPObject, FMCLiteralICMPObject, FMCPortGroupObject, FMCPortLiteralObject, FMCGeolocationObject, \
FMCContinentObject, FMCCountryObject, FMCURLObject, FMCURLLiteral, FMCURLGroupObject
from pkg.Policy.FMCPolicy import FMCSecurityPolicy
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
    def return_geolocation_object_info(self):
        return self._SecurityDeviceConnection.object.geolocation.get()
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

    # def return_security_zone_info(self):
    #     return self._SecurityDeviceConnection
    
    def return_security_policy_container(self, container_entry):
        return FMCSecurityPolicyContainer(self, container_entry)

    def return_object_container(self, container_entry):
        return FMCObjectContainer(self, container_entry)

    def return_zone_container(self, container_entry):
        return FMCZoneContainer(self, container_entry)
    
    #TODO: get the uid of the container 
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

    def return_port_object(self, ObjectContainer, port_object_entry):
        return FMCPortObject(ObjectContainer, port_object_entry)

    def return_port_group_object(self, ObjectContainer, port_group_object_entry):
        return FMCPortGroupObject(ObjectContainer, port_group_object_entry)

    def return_url_object(self, ObjectContainer, url_object_entry):
        return FMCURLObject(ObjectContainer, url_object_entry)

    def return_url_group_object(self, ObjectContainer, url_group_object_entry):
        return FMCURLGroupObject(ObjectContainer, url_group_object_entry)

    def return_security_policies_info(self, policy_container_name):
        """
        Retrieve information about security policies within a specified container.

        Args:
            policy_container_name (str): Name of the container containing the security policies.

        Returns:
            list: List of dictionaries containing information about security policies.
        """
        # Execute the request to retrieve information about the security policies
        security_policies_info = self._SecurityDeviceConnection.policy.accesspolicy.accessrule.get(container_name=policy_container_name)
        return security_policies_info
    
    def create_security_policy(self, policy_entry):
        return FMCSecurityPolicy(policy_entry)

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

    # this function is responsible for retrieving all the member objects
    # it also sets the members of a group objects to be the objects retrieved
    # what if i set the members of the object here?
    # TODO: this could probabily be rewritten in a better way. maybe moved to the SecurityDevice class directly?
    def _return_group_object_members_helper(self, group_object, object_type, group_member_objects):
        """
        Helper function to retrieve and process group member objects.

        This function extracts information about the members of a group object, including both objects and literals.
        It then sets the member names of the group object and recursively fetches objects for group members.

        Args:
            group_object: The group object for which member objects are to be retrieved.
            object_type (str): The type of objects to retrieve (e.g., 'network_objects').
            group_member_objects (list): A list to store the processed member objects.

        Returns:
            None
        """
        # Log a debug message indicating the function call

        # Initialize lists to store member names
        group_member_object_names = []
        group_member_literals_list = []
        
        # Get the information of the group object
        group_object_info = group_object.get_info()

        # Try to retrieve object members from the group object information
        try:
            object_members = group_object_info['objects']
            # Extract object names and append to the list
            for object_member in object_members:
                group_member_object_names.append(object_member['name'])
        except KeyError:
            general_logger.info("No member objects")
        
        # Try to retrieve literal members from the group object information
        try:
            literal_members = group_object_info['literals']
            # Convert literal members to objects and append to the list
            if object_type == 'network_objects':
                group_member_literals_list += FMCObject.convert_network_literals_to_objects(literal_members)
            if object_type == 'url_objects':
                group_member_literals_list += FMCObject.convert_url_literals_to_objects(literal_members)
            for literal_member in group_member_literals_list:
                group_member_object_names.append(literal_member)
        except KeyError:
            general_logger.info("No literal members")

        # Set the member names of the group object
        group_object.set_member_names(group_member_object_names)

        # Recursively fetch objects for group members if the object type is 'network_objects'
        if object_type == 'network_objects':
            # Extend the list of group member objects instead of appending
            group_member_objects.extend(self.return_network_objects(group_member_object_names))
        elif object_type == 'port_objects':
            group_member_objects.extend(self.return_port_objects(group_member_object_names))
        elif object_type == 'url_objects':
            group_member_objects.extend(self.return_url_objects(group_member_object_names))

    def return_network_objects(self, object_names):
        """
        Retrieve Python objects with information about network objects from the device.

        This method retrieves information about network objects from the device, processes it, and returns Python representations of network objects.

        Args:
            object_names (list): A list of names of network objects to retrieve.

        Returns:
            list: A list of Python representations of network objects.
        """
        # Log a debug message indicating the function call
        
        # Log an informative message about processing network objects data info
        general_logger.info("Processing network objects data info. Retrieving all objects from the database, processing them, and returning their info.")

        # Initialize an empty list to store network objects retrieved from the device
        network_objects_from_device_list = []

        # Iterate over each network object name retrieved from the database
        for network_object_name in object_names:
            # Check if the network object is a literal
            if network_object_name.startswith(gvars.network_literal_prefix):
                # Create a network literal object and append it to the list
                network_objects_from_device_list.append(FMCNetworkLiteralObject(network_object_name))
            
            # Check if the network object represents a country
            elif gvars.separator_character in network_object_name:
                country_id, country_name = network_object_name.split(gvars.separator_character)
                # Get the country object information from the countries dictionary
                country_object_info = self._countries_info.get(country_id)
                if country_object_info:
                    # Create a country object and append it to the list
                    network_objects_from_device_list.append(FMCCountryObject(country_object_info))
            
            # Handle other types of network objects
            else:
                # Check if the network object name exists in any of the dictionaries
                if network_object_name in self._network_address_objects_info:
                    # Append the network object to the list
                    network_objects_from_device_list.append(FMCNetworkObject(self._network_address_objects_info[network_object_name]))
                
                elif network_object_name in self._network_group_objects_info:
                    # Create a network group object
                    network_group_object = FMCNetworkGroupObject(self._network_group_objects_info[network_object_name])
                    # Process the group object members
                    self._return_group_object_members_helper(network_group_object, 'network_objects', network_objects_from_device_list)
                    # Append the group object to the list
                    network_objects_from_device_list.append(network_group_object)
                
                elif network_object_name in self._geolocation_objects_info:
                    # Append the geolocation object to the list
                    network_objects_from_device_list.append(FMCGeolocationObject(self._geolocation_objects_info[network_object_name]))
                
                elif network_object_name in self._continents_info:
                    # Append the continent object to the list
                    network_objects_from_device_list.append(FMCContinentObject(self._continents_info[network_object_name]))
                else:
                    # Log an error message for invalid network objects
                    general_logger.error(f"{network_object_name} is an invalid object!")
        
        # Return the list of network objects retrieved from the device
        return network_objects_from_device_list

    def return_port_objects(self, object_names):
        """
        Retrieve port objects based on the given object names.

        Parameters:
        - object_names (list): List of port object names to retrieve.

        Returns:
        - port_objects_from_device_list (list): List of port objects retrieved.
        """
        # Log a debug message indicating the function call
        
        # Log an informative message about processing network objects data info
        general_logger.info("Processing port objects data info. Retrieving all objects from the database, processing them, and returning their info.")

        # Initialize an empty list to store port objects retrieved from the device
        port_objects_from_device_list = []

        # Iterate over each port object name in the provided list
        for port_object_name in object_names:
            # Check if the port object name starts with the defined port literal prefix
            if port_object_name.startswith(gvars.port_literal_prefix):
                # Check if the port object name contains 'ICMP'
                if 'ICMP' in port_object_name:
                    # Create and append an ICMP object to the list
                    port_objects_from_device_list.append(FMCLiteralICMPObject(port_object_name))
                else:
                    # Create and append a Port Literal object to the list
                    port_objects_from_device_list.append(FMCPortLiteralObject(port_object_name))
            # Check if the port object name exists in the port objects info dictionary
            elif port_object_name in self._port_objects_info:
                # Check if the object type contains 'ICMP'
                if 'ICMP' in self._port_objects_info[port_object_name]['type']:
                    # Create and append an ICMP object to the list
                    port_objects_from_device_list.append(FMCICMPObject(self._port_objects_info[port_object_name]))
                else:
                    # Create and append a Port object to the list
                    port_objects_from_device_list.append(FMCPortObject(self._port_objects_info[port_object_name]))
            # Check if the port object name exists in the port group objects info dictionary
            elif port_object_name in self._port_group_objects_info:
                # Create a Port Group object
                port_group_object = FMCPortGroupObject(self._port_group_objects_info[port_object_name])
                # Helper function to retrieve members of port group object
                self._return_group_object_members_helper(port_group_object, 'port_objects', port_objects_from_device_list)
                # Append the port group object to the list
                port_objects_from_device_list.append(port_group_object)
        
        # Return the list of port objects retrieved from the device
        return port_objects_from_device_list

    def return_url_objects(self, object_names):
        """
        Retrieve URL objects based on the given object names.

        Parameters:
        - object_names (list): List of URL object names to retrieve.

        Returns:
        - url_objects_from_device_list (list): List of URL objects retrieved.
        """
        # Log a debug message indicating the function call
        
        # Log an informative message about processing URL objects data info
        general_logger.info("Processing URL objects data info. Retrieving all objects from the database, processing them, and returning their info.")

        # Initialize an empty list to store URL objects retrieved from the device
        url_objects_from_device_list = []

        # Iterate over each URL object name in the provided list
        for url_object_name in object_names:
            # Check if the URL object name starts with the defined URL literal prefix
            if url_object_name.startswith(gvars.url_literal_prefix):
                # Create and append a URL Literal object to the list
                url_objects_from_device_list.append(FMCURLLiteral(url_object_name))
            # Check if the URL object name exists in the URL objects info dictionary
            elif url_object_name in self._url_objects_info:
                # Create and append a URL object to the list
                url_objects_from_device_list.append(FMCURLObject(self._url_objects_info[url_object_name]))
            # Check if the URL object name exists in the URL object groups info dictionary
            elif url_object_name in self._url_object_groups_info:
                # Create a URL Group object
                url_group_object = FMCURLGroupObject(self._url_object_groups_info[url_object_name])
                # Helper function to retrieve members of URL group object
                self._return_group_object_members_helper(url_group_object, 'url_objects', url_objects_from_device_list)
                # Append the URL group object to the list
                url_objects_from_device_list.append(url_group_object)
        
        # Return the list of URL objects retrieved from the device
        return url_objects_from_device_list