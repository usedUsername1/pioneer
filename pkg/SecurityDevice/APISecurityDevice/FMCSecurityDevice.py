from abc import abstractmethod
from pkg.Container import SecurityPolicyContainer, ObjectPolicyContainer
from pkg.SecurityDevice.APISecurityDevice.APISecurityDeviceConnection import APISecurityDeviceConnection
from pkg.DeviceObject.FMCDeviceObject import FMCObject, FMCNetworkGroupObject, FMCNetworkObject, FMCNetworkLiteralObject, \
FMCPortObject, FMCICMPObject, FMCLiteralICMPObject, FMCPortGroupObject, FMCPortLiteralObject, FMCGeolocationObject, \
FMCContinentObject, FMCCountryObject, FMCURLObject, FMCURLLiteral, FMCURLGroupObject
from pkg.Policy.FMCPolicy import FMCSecurityPolicy
from pkg.SecurityDevice import SecurityDevice

import utils.helper as helper
import fireREST
import utils.gvars as gvars

general_logger = helper.logging.getLogger('general')

class FMCDeviceConnection(APISecurityDeviceConnection):
    """
    Represents a connection to a Firepower Management Center (FMC) device.
    """

    def __init__(self, api_username, api_secret, api_hostname, api_port, domain):
        """
        Initialize an FMCDeviceConnection instance.

        Parameters:
            api_username (str): The API username for the connection.
            api_secret (str): The API secret for the connection.
            api_hostname (str): The hostname of the FMC device.
            api_port (int): The port number for the connection.
            domain (str): The domain of the FMC device.
        """
        super().__init__(api_username, api_secret, api_hostname, api_port)
        self._domain = domain
        self._device_connection = self.return_security_device_conn_object()  # Initialize _device_connection with FMC object
        general_logger.debug(f"Called FMCDeviceConnection __init__ with parameters: username {api_username}, hostname {api_hostname}, port {api_port}, domain {domain}.")

    def connect_to_security_device(self):
        """
        Connect to the Firepower Management Center (FMC) device.

        Returns:
            fireREST.FMC: An FMC connection object.
        """
        # Implement connection to FMC specific to FMCDeviceConnection
        fmc_conn = fireREST.FMC(hostname=self._api_hostname, username=self._api_username, password=self._api_secret, domain=self._domain, protocol=self._api_port, timeout=30)
        return fmc_conn

#TODO: maybe use setters for setting the values in here, and use the getters from the parent class to retrieve the info. just like you do for objects
class FMCPolicyContainer(SecurityPolicyContainer):
    """
    Represents a policy container specific to the Firepower Management Center (FMC).
    """

    def __init__(self, container_info) -> None:
        """
        Initialize an FMCPolicyContainer instance.

        Parameters:
            container_info (dict): Information about the policy container.
        """
        general_logger.debug("Called FMCPolicyContainer::__init__()")
        super().__init__(container_info)

    def get_parent_name(self):
        """
        Get the name of the parent policy.

        Returns:
            str: Name of the parent policy.
        """
        general_logger.debug("Called FMCPolicyContainer::get_parent_name()")
        try:
            return self._container_info['metadata']['parentPolicy']['name']
        except KeyError:
            return None

    def is_child_container(self):
        """
        Check if the container is a child container.

        Returns:
            bool: True if the container is a child container, False otherwise.
        """
        general_logger.debug("Called FMCPolicyContainer::is_child_container()")
        return self._container_info['metadata']['inherit']

    def get_name(self):
        """
        Get the name of the policy container.

        Returns:
            str: Name of the policy container.
        """
        general_logger.debug("Called FMCPolicyContainer::get_name()")
        return self._container_info['name']

#TODO: maybe use setters for setting the values in here, and use the getters from the parent class to retrieve the info. just like you do for objects
class FMCObjectContainer(ObjectPolicyContainer):
    """
    Represents an object container specific to the Firepower Management Center (FMC).
    """

    def __init__(self, container_info) -> None:
        """
        Initialize an FMCObjectContainer instance.

        Parameters:
            container_info (dict): Information about the object container.
        """
        general_logger.debug("Called FMCObjectContainer::__init__()")
        super().__init__(container_info)

    def is_child_container(self):
        """
        Check if the container is a child container.

        Returns:
            bool: Always returns False for FMC object containers.
        """
        general_logger.debug("Called FMCObjectContainer::is_child_container()")
        return False

    def get_parent_name(self):
        """
        Get the name of the parent container.

        Returns:
            None: Since FMC object containers do not have parent containers, it returns None.
        """
        general_logger.debug("Called FMCObjectContainer::get_parent_name()")
        return None
  
class FMCSecurityDevice(SecurityDevice):
    """
    Represents a Cisco Firepower Management Center (FMC) security device.

    Args:
        name (str): The name of the security device.
        sec_device_database: The database for the security device.
        security_device_username (str): The username for accessing the security device.
        security_device_secret (str): The secret for accessing the security device.
        security_device_hostname (str): The hostname or IP address of the security device.
        security_device_port (int): The port number for connecting to the security device.
        domain (str): The domain of the security device.

    Attributes:
        _sec_device_connection: The connection to the FMC device.
    """

    def __init__(self, name, sec_device_database, security_device_username, security_device_secret, security_device_hostname, security_device_port, domain):
        """
        Initializes an FMCSecurityDevice instance.

        Args:
            name (str): The name of the security device.
            sec_device_database: The database for the security device.
            security_device_username (str): The username for accessing the security device.
            security_device_secret (str): The secret for accessing the security device.
            security_device_hostname (str): The hostname or IP address of the security device.
            security_device_port (int): The port number for connecting to the security device.
            domain (str): The domain of the security device.
        """
        general_logger.debug("Called FMCSecurityDevice::__init__()")
        super().__init__(name, sec_device_database)
        # Establish connection to FMC device
        self._sec_device_connection = FMCDeviceConnection(security_device_username, security_device_secret, security_device_hostname, security_device_port, domain).connect_to_security_device()
        self._network_address_objects_info = None
        self._network_group_objects_info = None
        self._geolocation_objects_info = None
        self._countries_info = None
        self._continents_info = None
        self._port_objects_info = None
        self._port_group_objects_info = None
        self._url_objects_info = None
        self._url_object_groups_info = None

    def return_security_policy_container_object(self, container_name):
        general_logger.debug("Called FMCSecurityDevice::return_security_policy_container_object()")
        """
        Returns the security policy container object.

        Args:
            container_name (str): The name of the container.

        Returns:
            FMCPolicyContainer: The security policy container object.
        """
        # Retrieve ACP information from FMC device
        acp_info = self._sec_device_connection.policy.accesspolicy.get(name=container_name)
        # Initialize and return FMCPolicyContainer object
        return FMCPolicyContainer(acp_info)
    
    def return_security_policy_object(self, container_name):
        general_logger.debug("Called FMCSecurityDevice::return_security_policy_object()")
        """
        Returns a list of security policy objects.

        Args:
            container_name (str): The name of the container.

        Returns:
            list: A list of FMCSecurityPolicy objects.
        """
        # Initialize an empty list to store FMCSecurityPolicy objects
        security_policy_objects = []

        # Retrieve security policy information from FMC device using the provided container name
        fmc_policy_info = self._sec_device_connection.policy.accesspolicy.accessrule.get(container_name=container_name)

        # Iterate through each policy entry retrieved from the FMC device
        for fmc_policy_entry in fmc_policy_info:
            # Create an instance of FMCSecurityPolicy using the policy entry and append it to the list
            security_policy_objects.append(FMCSecurityPolicy(fmc_policy_entry))
        
        # Return the list of FMCSecurityPolicy objects
        return security_policy_objects

    # there are no object containers per se in FMC, therefore, only dummy info will be returned
    def return_object_container_object(self, container_name):
        general_logger.debug("Called FMCSecurityDevice::return_object_container_object(). There are no actual containers on this type of security device. Will return a virtual one.")
        """
        Returns the object container object.

        Args:
            container_name (str): The name of the container.

        Returns:
            FMCObjectContainer: The object container object.
        """
        container_info = 'DUMMY_CONTAINER'
        dummy_container = FMCObjectContainer(container_info)
        dummy_container.set_name("virtual_object_container")
        dummy_container.set_parent(None)
        return dummy_container

    #TODO: move this managed devices functions
    def process_managed_device(self, managed_device):
        """
        Process a managed device.

        Args:
            managed_device (dict): Information about the managed device.

        Returns:
            tuple: A tuple containing device name, assigned security policy container, device hostname, and device cluster.
        """
        device_name = managed_device['name']
        general_logger.info(f"Got the following managed device {device_name}.")
        assigned_security_policy_container = managed_device['accessPolicy']['name']
        device_hostname = managed_device['hostName']
        device_cluster = None

        # Check if the device is part of a cluster
        try:
            device_cluster = managed_device['metadata']['containerDetails']['name']
            general_logger.info(f"Managed device {managed_device} is part of a cluster {device_cluster}.")
        except KeyError:
            general_logger.info(f"Managed device {managed_device} is NOT part of a cluster {device_cluster}.")

        return device_name, assigned_security_policy_container, device_hostname, device_cluster

    def get_managed_devices_info(self):
        """
        Retrieve information about managed devices.

        Returns:
            list: List of dictionaries containing information about managed devices.
        """
        general_logger.debug("Called function get_managed_devices_info().")
        general_logger.info("################## GETTING MANAGED DEVICES INFO ##################")

        # Execute the request to retrieve information about the devices
        managed_devices = self._sec_device_connection.device.devicerecord.get()
        general_logger.debug(f"Executed API call to the FMC device, got the following info {managed_devices}.")
        return managed_devices

    def get_security_policies_info(self, policy_container_name):
        """
        Retrieve information about security policies within a specified container.

        Args:
            policy_container_name (str): Name of the container containing the security policies.

        Returns:
            list: List of dictionaries containing information about security policies.
        """
        general_logger.debug("Called function get_security_policies_info().")
        general_logger.info("################## GETTING SECURITY POLICIES INFO ##################")

        # Execute the request to retrieve information about the security policies
        security_policies_info = self._sec_device_connection.policy.accesspolicy.accessrule.get(container_name=policy_container_name)
        return security_policies_info
    
    def get_device_version(self):
        """
        Retrieve the version of the device's server.

        Returns:
            str: Version of the device's server.
        """
        general_logger.debug("Called FMCSecurityDevice::get_device_version()")
        # Retrieve device system information to get the server version
        device_system_info = self._sec_device_connection.system.info.serverversion.get()

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
        general_logger.debug("Called FMCSecurityDevice::fetch_objects_info()")
        # Fetch information for network objects
        if object_type == 'network_objects':
            # Fetch network address objects if not already fetched
            if not self._network_address_objects_info:
                self._network_address_objects_info = self._sec_device_connection.object.networkaddress.get()
                # Convert the fetched information into a dictionary for efficient lookup
                network_address_objects_dict = {entry['name']: entry for entry in self._network_address_objects_info}
                self._network_address_objects_info = network_address_objects_dict

            # Fetch network group objects if not already fetched
            if not self._network_group_objects_info:
                self._network_group_objects_info = self._sec_device_connection.object.networkgroup.get()
                # Convert the fetched information into a dictionary for efficient lookup
                network_group_objects_dict = {entry['name']: entry for entry in self._network_group_objects_info}
                self._network_group_objects_info = network_group_objects_dict

            # Fetch geolocation objects if not already fetched
            if not self._geolocation_objects_info:
                self._geolocation_objects_info = self._sec_device_connection.object.geolocation.get()
                # Convert the fetched information into a dictionary for efficient lookup
                geolocation_objects_dict = {entry['name']: entry for entry in self._geolocation_objects_info}
                self._geolocation_objects_info = geolocation_objects_dict

            # Fetch country objects if not already fetched
            if not self._countries_info:
                self._countries_info = self._sec_device_connection.object.country.get()
                # Convert the fetched information into a dictionary for efficient lookup
                countries_dict = {entry['id']: entry for entry in self._countries_info if 'id' in entry}
                self._countries_info = countries_dict

            # Fetch continent objects if not already fetched
            if not self._continents_info:
                self._continents_info = self._sec_device_connection.object.continent.get()
                # Convert the fetched information into a dictionary for efficient lookup
                continents_dict = {entry['name']: entry for entry in self._continents_info}
                self._continents_info = continents_dict
        
        if object_type == 'port_objects':
            if not self._port_objects_info:
                self._port_objects_info = self._sec_device_connection.object.port.get()
                ports_dict = {entry['name']: entry for entry in self._port_objects_info if 'name' in entry}
                self._port_objects_info = ports_dict
            
            if not self._port_group_objects_info:
                self._port_group_objects_info = self._sec_device_connection.object.portobjectgroup.get()
                port_groups_dict = {entry['name']: entry for entry in self._port_group_objects_info if 'name' in entry}
                self._port_group_objects_info = port_groups_dict
        
        if object_type == 'url_objects':
            if not self._url_objects_info:
                self._url_objects_info = self._sec_device_connection.object.url.get()
                url_objects_dict = {entry['name']: entry for entry in self._url_objects_info if 'name' in entry}
                self._url_objects_info = url_objects_dict
            
            if not self._url_object_groups_info:
                self._url_object_groups_info = self._sec_device_connection.object.urlgroup.get()
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
        general_logger.debug("Called FMCSecurityDevice::_return_group_object_members_helper()")

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
            group_member_literals_list += FMCObject.convert_network_literals_to_objects(literal_members)
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
        general_logger.debug("Called FMCSecurityDevice::return_network_objects()")
        
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
        # Log a debug message indicating the function call
        general_logger.debug("Called FMCSecurityDevice::return_port_objects()")
        
        # Log an informative message about processing network objects data info
        general_logger.info("Processing port objects data info. Retrieving all objects from the database, processing them, and returning their info.")

        port_objects_from_device_list = []
        for port_object_name in object_names:
            if port_object_name.startswith(gvars.port_literal_prefix):
                if 'ICMP' in port_object_name:
                    port_objects_from_device_list.append(FMCLiteralICMPObject(port_object_name))
                else:
                    port_objects_from_device_list.append(FMCPortLiteralObject(port_object_name))
            elif port_object_name in self._port_objects_info:
                # do a check here and see if the current object is an ICMP object or nay. if it is not, then create a PortObject
                if 'ICMP' in self._port_objects_info[port_object_name]['type']:
                    port_objects_from_device_list.append(FMCICMPObject(self._port_objects_info[port_object_name]))
                else:
                    port_objects_from_device_list.append(FMCPortObject(self._port_objects_info[port_object_name]))

            elif port_object_name in self._port_group_objects_info:
                port_group_object = FMCPortGroupObject(self._port_group_objects_info[port_object_name])
                self._return_group_object_members_helper(port_group_object, 'port_objects', port_objects_from_device_list)
                port_objects_from_device_list.append(port_group_object)
        
        return port_objects_from_device_list

    def return_url_objects(self, object_names):
        # Log a debug message indicating the function call
        general_logger.debug("Called FMCSecurityDevice::return_url_objects()")
        
        # Log an informative message about processing network objects data info
        general_logger.info("Processing url objects data info. Retrieving all objects from the database, processing them, and returning their info.")

        url_objects_from_device_list = []
        for url_object_name in object_names:
            if url_object_name.startswith(gvars.url_literal_prefix):
                url_objects_from_device_list.append(FMCURLLiteral(url_object_name))

            elif url_object_name in self._url_objects_info:
                url_objects_from_device_list.append(FMCURLObject(self._url_objects_info[url_object_name]))

            elif url_object_name in self._url_object_groups_info:
                url_group_object = FMCURLGroupObject(self._url_object_groups_info[url_object_name])
                self._return_group_object_members_helper(url_group_object, 'url_objects', url_objects_from_device_list)
                url_objects_from_device_list.append(url_group_object)
        
        return url_objects_from_device_list