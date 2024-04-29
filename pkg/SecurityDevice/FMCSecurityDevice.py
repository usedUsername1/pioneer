from abc import abstractmethod
from pkg.Container.FMCContainer import FMCSecurityPolicyContainer, FMCObjectContainer
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

    def create_managed_device(self, managed_device_entry):
        """
        Override create_managed_device method to return FMCManagedDevice instance.

        Args:
            managed_device_entry: Entry containing information about the managed device.

        Returns:
            FMCManagedDevice: Instance of FMCManagedDevice.
        """
        return FMCManagedDevice(self, managed_device_entry)

    def return_security_policy_container(self, container_name):
        acp_info = self._SecurityDeviceConnection.policy.accesspolicy.get(name=container_name)
        return FMCSecurityPolicyContainer(self, acp_info)

    def return_objects_container(self):
        container_info = "DUMMY_CONTAINER"
        dummy_container = FMCObjectContainer(self, container_info)
        return dummy_container
    
    def get_policies_info(self, policy_type):
        match policy_type:
            case "security_policy":
                pass
            case "nat_policy":
                pass

    def get_managed_devices_info(self):
        """
        Retrieve information about managed devices.

        Returns:
            list: List of dictionaries containing information about managed devices.
        """
        # Execute the request to retrieve information about the devices
        managed_devices = self._SecurityDeviceConnection.device.devicerecord.get()
        return managed_devices

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
    
    # This function returns Python network objects back to the caller.
    # for the objects stored in the database, it checks where they are exactly located on the Security Device
    # if "example" is a network address, it will stop processing and then it will return a network address object
    def fetch_objects_info(self, object_type):
        """
        This function fetches information about different types of objects from the security device based on the specified object type.
        It checks if the information has already been fetched to avoid redundant API calls.
        If the information is not already available, it fetches it from the device and converts it into dictionaries for efficient lookup.

        Args:
            object_type (str): Type of objects to fetch information for.

        Returns:
            None
        """
        # Fetch information for network objects
        if object_type == 'network_objects':
            # Fetch network address objects if not already fetched
            if not self._network_address_objects_info:
                self._network_address_objects_info = self._SecurityDeviceConnection.object.networkaddress.get()
                # Convert the fetched information into a dictionary for efficient lookup
                network_address_objects_dict = {entry['name']: entry for entry in self._network_address_objects_info}
                self._network_address_objects_info = network_address_objects_dict

            # Fetch network group objects if not already fetched
            if not self._network_group_objects_info:
                self._network_group_objects_info = self._SecurityDeviceConnection.object.networkgroup.get()
                # Convert the fetched information into a dictionary for efficient lookup
                network_group_objects_dict = {entry['name']: entry for entry in self._network_group_objects_info}
                self._network_group_objects_info = network_group_objects_dict

            # Fetch geolocation objects if not already fetched
            if not self._geolocation_objects_info:
                self._geolocation_objects_info = self._SecurityDeviceConnection.object.geolocation.get()
                # Convert the fetched information into a dictionary for efficient lookup
                geolocation_objects_dict = {entry['name']: entry for entry in self._geolocation_objects_info}
                self._geolocation_objects_info = geolocation_objects_dict

            # Fetch country objects if not already fetched
            if not self._countries_info:
                self._countries_info = self._SecurityDeviceConnection.object.country.get()
                # Convert the fetched information into a dictionary for efficient lookup
                countries_dict = {entry['id']: entry for entry in self._countries_info if 'id' in entry}
                self._countries_info = countries_dict

            # Fetch continent objects if not already fetched
            if not self._continents_info:
                self._continents_info = self._SecurityDeviceConnection.object.continent.get()
                # Convert the fetched information into a dictionary for efficient lookup
                continents_dict = {entry['name']: entry for entry in self._continents_info}
                self._continents_info = continents_dict
        
        if object_type == 'port_objects':
            if not self._port_objects_info:
                self._port_objects_info = self._SecurityDeviceConnection.object.port.get()
                ports_dict = {entry['name']: entry for entry in self._port_objects_info if 'name' in entry}
                self._port_objects_info = ports_dict
            
            if not self._port_group_objects_info:
                self._port_group_objects_info = self._SecurityDeviceConnection.object.portobjectgroup.get()
                port_groups_dict = {entry['name']: entry for entry in self._port_group_objects_info if 'name' in entry}
                self._port_group_objects_info = port_groups_dict
        
        if object_type == 'url_objects':
            if not self._url_objects_info:
                self._url_objects_info = self._SecurityDeviceConnection.object.url.get()
                url_objects_dict = {entry['name']: entry for entry in self._url_objects_info if 'name' in entry}
                self._url_objects_info = url_objects_dict
            
            if not self._url_object_groups_info:
                self._url_object_groups_info = self._SecurityDeviceConnection.object.urlgroup.get()
                url_group_objects_dict = {entry['name']: entry for entry in self._url_object_groups_info if 'name' in entry}
                self._url_object_groups_info = url_group_objects_dict

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