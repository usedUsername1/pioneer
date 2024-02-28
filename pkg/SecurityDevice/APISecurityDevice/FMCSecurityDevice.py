from abc import abstractmethod
from pkg.Container import SecurityPolicyContainer, ObjectPolicyContainer
from pkg.DeviceObject import Object, NetworkObject, GroupObject, NetworkGroupObject, GeolocationObject
from pkg.SecurityDevice.APISecurityDevice.APISecurityDeviceConnection import APISecurityDeviceConnection
from pkg.SecurityDevice import SecurityDevice
from pkg.Policy import SecurityPolicy
import utils.helper as helper
import fireREST
import sys
import ipaddress
import utils.exceptions as PioneerExceptions
import utils.gvars as gvars

class FMCObject(Object):
    """
    A class representing a FMC object.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the FMCObject instance.

        Args:
            object_info (dict): Information about the FMC object.
        """
        helper.logging.debug("Called FMCObject::__init__()")
        super().__init__(object_info)
    
    def set_name(self):
        """
        Set the name of the FMC object.
        
        Returns:
            str: The name of the FMC object.
        """
        helper.logging.debug("Called FMCObject::set_name()")
        name = self._object_info['name']
        return super().set_name(name)

    def set_description(self):
        """
        Set the description of the FMC object.

        Returns:
            str: The description of the FMC object.
        """
        helper.logging.debug("Called FMCObject::set_description()")
        try:
            description = self._object_info['description']
        except KeyError:
            description = None
        return super().set_description(description)

    def set_object_container_name(self):
        """
        Set the name of the object container for the FMC object.

        Returns:
            str: The name of the object container.
        """
        helper.logging.debug("Called FMCObject::set_object_container_name()")
        container_name = 'virtual_object_container'
        return super().set_object_container_name(container_name)
    
    def set_override_bool(self):
        """
        Set the override status of the FMC object.

        Returns:
            bool: The override status of the FMC object.
        """
        helper.logging.debug("Called FMCObject::set_override_bool()")
        is_overridable = self._object_info['overridable']
        return super().set_override_bool(is_overridable)

class FMCNetworkGroupObject(FMCObject, NetworkGroupObject):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)
    
    def set_member_names(self, members):
        return super().set_member_names(members)
    
class FMCNetworkObject(FMCObject, NetworkObject):
    """
    A class representing a network object in Firepower Management Center (FMC).
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the FMCNetworkObject instance.

        Args:
            object_info (dict): Information about the network object.
        """
        helper.logging.debug("Called FMCNetworkObject::__init__()")
        super().__init__(object_info)
    
    def set_network_address_value(self):
        """
        Set the value of the network address for the network object.

        Returns:
            str: The value of the network address.
        """
        helper.logging.debug("Called FMCNetworkObject::set_network_address_value()")
        value = self._object_info['value']
        return super().set_network_address_value(value)

    def set_network_address_type(self):
        """
        Set the type of the network address for the network object.

        Returns:
            str: The type of the network address.
        """
        helper.logging.debug("Called FMCNetworkObject::set_network_address_type()")
        type = self._object_info['type']
        return super().set_network_address_type(type)

class FMCNetworkLiteralObject(NetworkObject):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)
    
    def set_name(self):
        name = self._object_info
        return super().set_name(name)

    def set_object_container_name(self):
        container_name = 'virtual_object_container'
        return super().set_object_container_name(container_name)

    def set_network_address_value(self):
        split_name = self._name.split('_')
        subnet_id = split_name[1]
        netmask = split_name[2]
        value = subnet_id + '/' + netmask
        return super().set_network_address_value(value)

    def set_description(self):
        description = gvars.literal_objects_description
        return super().set_description(description)

    def set_network_address_type(self):
        split_name = self._name.split('_')
        netmask = split_name[2]
        type = ''

        if netmask == '32':
            type = 'Host'
        else:
            type = 'Network'

        return super().set_network_address_type(type)
    
    def set_override_bool(self):
        is_overridable = False
        return super().set_override_bool(is_overridable)

# class FMCPortObject(FMCObject):
#     pass

# class FMCPortGroupObject(FMCGroupObject):
#     pass


class FMCGeolocationObject(GeolocationObject):
    """
    A class representing a FMC geolocation object
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the FMCGeolocationObject instance.

        Args:
            object_info (dict): Information about the geolocation object.
        """
        helper.logging.debug(f"Called FMCGeolocationObject::__init__()")
        super().__init__(object_info)

    def set_name(self):
        """
        Set the name of the geolocation object.
        
        Returns:
            str: The name of the geolocation object.
        """
        helper.logging.debug("Called FMCGeolocationObject::set_name()")
        name = self._object_info['name']
        return super().set_name(name)

    def set_description(self):
        """
        Set the description of the geolocation object.

        Returns:
            None
        """
        helper.logging.debug("Called FMCGeolocationObject::set_description()")
        value = None
        return super().set_description(value)

    def set_object_container_name(self):
        """
        Set the name of the object container for the geolocation object.

        Returns:
            str: The name of the object container.
        """
        helper.logging.debug("Called FMCGeolocationObject::set_object_container_name()")
        object_container_name = 'virtual_object_container'
        return super().set_object_container_name(object_container_name)

    def set_continents(self):
        """
        Set the continents associated with the geolocation object.

        This method sets the continents associated with the geolocation object by creating instances of
        FMCContinentObject for each continent retrieved from the object's information.
        If there are no continents associated with the geolocation object, it sets the continents list to None.

        Returns:
            list: A list of FMCContinentObject instances representing continents.
        """
        # Debugging message to indicate that the method is being called
        helper.logging.debug("Called FMCGeolocationObject::set_continents()")
        
        # Initialize an empty list to store continent objects
        continent_objects_list = []
        
        try:
            # Attempt to retrieve continent information from the object's information
            continents_info = self._object_info['continents']
            
            # Iterate over each continent information entry
            for continent_info in continents_info:
                # Create an FMCContinentObject instance for each continent and append it to the list
                continent_objects_list.append(FMCContinentObject(continent_info))
        
        except KeyError:
            # If there is no continent information, set the continents list to None
            continent_objects_list = None
        
        # Call the superclass method to set the continents list
        return super().set_continents(continent_objects_list)

    #TODO: maybe make this method static?
    def set_countries(self):
        """
        Set the countries associated with the geolocation object.

        This method sets the countries associated with the geolocation object by creating instances of
        FMCCountryObject for each country retrieved from the object's information.
        It also adds countries of the continents associated with the geolocation object.

        Returns:
            list: A list of FMCCountryObject instances representing countries.
        """
        # Debugging message to indicate that the method is being called
        helper.logging.debug("Called FMCGeolocationObject::set_countries()")
        
        # Initialize an empty list to store country objects
        countries_objects_list = []
        
        # Attempt to retrieve country information from the object's information
        country_info = self._object_info.get('countries', [])
        
        # Iterate over each country information entry
        for country_entry in country_info:
            # Create an FMCCountryObject instance for each country and append it to the list
            countries_objects_list.append(FMCCountryObject(country_entry))
        
        # Add countries of the continents associated with the geolocation object
        for continent in self._continents:
            for country_info in continent.get_continent_info().get('countries', []):
                countries_objects_list.append(FMCCountryObject(country_info))
        
        # Call the superclass method to set the countries list
        return super().set_countries(countries_objects_list)

    # Don't delete this. They need to be here, otherwise GeolocationObject::process_policy_info() will throw an error since the method
    # called in there doesn't have parameters, however, the method definition of the class includes parameters.
    @abstractmethod
    def set_member_alpha2_codes(self):
        """
        Abstract method to set the member alpha-2 codes.
        """
        pass

    @abstractmethod
    def set_member_alpha3_codes(self):
        """
        Abstract method to set the member alpha-3 codes.
        """
        pass

    @abstractmethod
    def set_member_numeric_codes(self):
        """
        Abstract method to set the member numeric codes.
        """
        pass

class FMCContinentObject(GeolocationObject):
    """
    A class representing an FMC continent object.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the FMCContinentObject instance.

        Args:
            object_info (dict): Information about the continent object.
        """
        helper.logging.debug("Called FMCContinentObject::__init__()")
        super().__init__(object_info)
        
    def set_name(self):
        """
        Set the name of the continent object.
        
        Returns:
            str: The name of the continent object.
        """
        helper.logging.debug("Called FMCContinentObject::set_name()")
        name = self._object_info['name']
        return super().set_name(name)

    def set_object_container_name(self):
        """
        Set the name of the object container for the continent object.

        Returns:
            str: The name of the object container.
        """
        helper.logging.debug("Called FMCContinentObject::set_object_container_name()")
        object_container_name = 'virtual_object_container'
        return super().set_object_container_name(object_container_name)
    
    def set_continents(self):
        """
        Set the continents associated with the continent object.

        Returns:
            None
        """
        helper.logging.debug("Called FMCContinentObject::set_continents()")
        self._continents = None
    
    def get_member_continent_names(self):
        """
        Get the name of the continent.

        Returns:
            str: The name of the continent.
        """
        helper.logging.debug("Called FMCContinentObject::get_member_continent_names()")
        return self._object_info['name']
    
    @abstractmethod
    def set_continents(self):
        """
        Abstract method to set the continents associated with the continent object.
        """
        pass

    def set_countries(self):
        """
        Set the countries associated with the continent object.

        This method retrieves information about the countries associated with the continent from the object's information.
        It constructs a list of FMCCountryObject instances based on the retrieved country information.
        If there are no countries associated with the continent, the method sets the countries list to None.

        Returns:
            None
        """
        # Debugging message to indicate that the method is being called
        helper.logging.debug("Called FMCContinentObject::set_countries()")
        
        # Initialize an empty list to store country objects
        countries_objects_list = []
        
        try:
            # Attempt to retrieve country information from the object's information
            country_info = self._object_info['countries']
            
            # Iterate over each country information entry
            for country_info_entry in country_info:
                # Create an FMCCountryObject instance for each country and append it to the list
                countries_objects_list.append(FMCCountryObject(country_info_entry))
        
        except KeyError:
            # If there is no country information, set the countries list to None
            countries_objects_list = None
            
        # Call the superclass method to set the countries list
        return super().set_countries(countries_objects_list)

    def set_member_alpha2_codes(self):
        """
        Set the member alpha-2 codes of the continent object.

        Returns:
            None
        """
        helper.logging.debug("Called FMCContinentObject::set_member_alpha2_codes()")
        pass

    def set_member_alpha3_codes(self):
        """
        Set the member alpha-3 codes of the continent object.

        Returns:
            None
        """
        helper.logging.debug("Called FMCContinentObject::set_member_alpha3_codes()")
        pass

    def set_member_numeric_codes(self):
        """
        Set the member numeric codes of the continent object.

        Returns:
            None
        """
        helper.logging.debug("Called FMCContinentObject::set_member_numeric_codes()")
        pass

    #TODO: move this
    def get_continent_info(self):
        """
        Get information about the continent.

        Returns:
            dict: Information about the continent.
        """
        helper.logging.debug("Called FMCContinentObject::get_continent_info()")
        return self._object_info

class FMCCountryObject(GeolocationObject):
    """
    A class representing a FMC country object.
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the FMCCountryObject instance.

        Args:
            object_info (dict): Information about the country object.
        """
        super().__init__(object_info)
    
    def set_name(self):
        """
        Set the name of the country object.

        Returns:
            str: The name of the country object.
        """
        try:
            name = self._object_info['name']
        except KeyError:
            name = None
        return super().set_name(name)

    def set_object_container_name(self):
        """
        Set the name of the object container for the country object.

        Returns:
            str: The name of the object container.
        """
        object_container_name = 'virtual_object_container'
        return super().set_object_container_name(object_container_name)
    
    def set_continents(self):
        """
        Set the continents associated with the country object.

        Returns:
            None
        """
        return super().set_continents(None)
    
    def set_countries(self):
        """
        Set the countries associated with the country object.

        Returns:
            None
        """
        pass

    def set_member_alpha2_codes(self):
        """
        Set the member alpha-2 code of the country object.

        Returns:
            str: The alpha-2 code of the country.
        """
        alpha2_code = self._object_info['iso2']
        return super().set_member_alpha2_codes(alpha2_code)
    
    def set_member_alpha3_codes(self):
        """
        Set the member alpha-3 code of the country object.

        Returns:
            str: The alpha-3 code of the country.
        """
        alpha3_code = self._object_info['iso3']
        return super().set_member_alpha3_codes(alpha3_code)
    
    def set_member_numeric_codes(self):
        """
        Set the member numeric code of the country object.

        Returns:
            int: The numeric code of the country.
        """
        numeric_code = self._object_info['id']
        return super().set_member_numeric_codes(numeric_code)
    
    def get_member_country_names(self):
        """
        Get the name of the country.

        Returns:
            str: The name of the country.
        """
        return self._name

    def get_member_alpha2_codes(self):
        """
        Get the alpha-2 code of the country.

        Returns:
            str: The alpha-2 code of the country.
        """
        return self._country_alpha2_codes
    
    def get_member_alpha3_codes(self):
        """
        Get the alpha-3 code of the country.

        Returns:
            str: The alpha-3 code of the country.
        """
        return self._country_alpha3_codes
    
    def get_member_numeric_codes(self):
        """
        Get the numeric code of the country.

        Returns:
            int: The numeric code of the country.
        """
        return self._country_numeric_codes

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
        helper.logging.debug(f"Called FMCDeviceConnection __init__ with parameters: username {api_username}, hostname {api_hostname}, port {api_port}, domain {domain}.")

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
        helper.logging.debug("Called FMCPolicyContainer::__init__()")
        super().__init__(container_info)

    def get_parent_name(self):
        """
        Get the name of the parent policy.

        Returns:
            str: Name of the parent policy.
        """
        helper.logging.debug("Called FMCPolicyContainer::get_parent_name()")
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
        helper.logging.debug("Called FMCPolicyContainer::is_child_container()")
        return self._container_info['metadata']['inherit']

    def get_name(self):
        """
        Get the name of the policy container.

        Returns:
            str: Name of the policy container.
        """
        helper.logging.debug("Called FMCPolicyContainer::get_name()")
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
        helper.logging.debug("Called FMCObjectContainer::__init__()")
        super().__init__(container_info)

    def is_child_container(self):
        """
        Check if the container is a child container.

        Returns:
            bool: Always returns False for FMC object containers.
        """
        helper.logging.debug("Called FMCObjectContainer::is_child_container()")
        return False

    def get_parent_name(self):
        """
        Get the name of the parent container.

        Returns:
            None: Since FMC object containers do not have parent containers, it returns None.
        """
        helper.logging.debug("Called FMCObjectContainer::get_parent_name()")
        return None
  
class FMCSecurityPolicy(SecurityPolicy):
    """
    Represents a security policy specific to the Firepower Management Center (FMC).
    """

    def __init__(self, policy_info_fmc) -> None:
        """
        Initialize an FMCSecurityPolicy instance.

        Parameters:
            policy_info_fmc (dict): Information about the security policy.
        """
        helper.logging.debug("FMCSecurityPolicy::__init__()")
        super().__init__(policy_info_fmc)

    # Methods for setting various attributes of the security policy
    def set_name(self):
        """
        Set the name of the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_name()")
        name = self._policy_info['name']
        return super().set_name(name)

    def set_container_name(self):
        """
        Set the name of the policy container.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_container_name()")
        container_name = self._policy_info['metadata']['accessPolicy']['name']
        return super().set_container_name(container_name)

    def set_container_index(self):
        """
        Set the index of the policy container.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_container_index()")
        index = self._policy_info['metadata']['ruleIndex']
        return super().set_container_index(index)

    def set_status(self):
        """
        Set the status of the security policy (enabled or disabled).
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_status()")
        status = 'enabled' if self._policy_info.get('enabled', False) else 'disabled'
        return super().set_status(status)

    def set_category(self):
        """
        Set the category of the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_category()")
        category = self._policy_info['metadata']['category']
        return super().set_category(category)

    def set_source_zones(self):
        """
        Set the source zones for the security policy.

        Returns:
            list: List of source zones.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_source_zones()")
        try:
            source_zones = [self._policy_info['sourceZones']]
        except KeyError:
            source_zones = ['any']
        return super().set_source_zones(source_zones)


    def set_destination_zones(self):
        """
        Set the destination zones for the security policy.

        Returns:
            list: List of destination zones.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_destination_zones()")
        try:
            destination_zones = [self._policy_info['destinationZones']]
        except KeyError:
            destination_zones = ['any']
        return super().set_destination_zones(destination_zones)

    def set_source_networks(self):
        """
        Set the source networks for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_source_networks()")
        try:
            source_networks = [self._policy_info['sourceNetworks']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit source networks defined on this policy.")
            source_networks = ['any']
        return super().set_source_networks(source_networks)

    def set_destination_networks(self):
        """
        Set the destination networks for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_destination_networks()")
        try:
            destination_networks = [self._policy_info['destinationNetworks']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit destination networks defined on this policy.")
            destination_networks = ['any']
        return super().set_destination_networks(destination_networks)

    def set_source_ports(self):
        """
        Set the source ports for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_source_ports()")
        try:
            source_ports = [self._policy_info['sourcePorts']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit source ports defined on this policy.")
            source_ports = ['any']
        return super().set_source_ports(source_ports)

    def set_destination_ports(self):
        """
        Set the destination ports for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_destination_ports()")
        try:
            destination_ports = [self._policy_info['destinationPorts']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit destination ports defined on this policy.")
            destination_ports = ['any']
        return super().set_destination_ports(destination_ports)

    def set_schedule_objects(self):
        """
        Set the schedule objects for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_schedule_objects()")
        try:
            schedule_objects = [self._policy_info['timeRangeObjects']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit schedule objects defined on this policy.")
            schedule_objects = ['any']
        return super().set_schedule_objects(schedule_objects)

    def set_users(self):
        """
        Set the users for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_users()")
        try:
            users = [self._policy_info['users']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit users defined on this policy.")
            users = ['any']
        return super().set_users(users)

    def set_urls(self):
        """
        Set the URLs for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_urls()")
        try:
            urls = [self._policy_info['urls']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit URLs defined on this policy.")
            urls = ['any']
        return super().set_urls(urls)

    def set_policy_apps(self):
        """
        Set the applications for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_policy_apps()")
        try:
            policy_apps = [self._policy_info['applications']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit applications defined on this policy.")
            policy_apps = ['any']
        return super().set_policy_apps(policy_apps)

    def set_description(self):
        """
        Set the description for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_description()")
        try:
            description = self._policy_info['description']
        except KeyError:
            helper.logging.info("It looks like there is no description defined on this policy.")
            description = None
        return super().set_description(description)

    def set_comments(self):
        """
        Set the comments for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_comments()")
        try:
            comments = [self._policy_info['commentHistoryList']]
        except KeyError:
            helper.logging.info("It looks like there are no comments defined on this policy.")
            comments = None
        return super().set_comments(comments)

    def set_log_setting(self):
        """
        Set the log settings for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_log_setting()")
        try:
            log_settings = ['FMC'] if self._policy_info['sendEventsToFMC'] else []
            log_settings += ['Syslog'] if self._policy_info['enableSyslog'] else []
        except KeyError:
            helper.logging.info("It looks like there are no log settings defined on this policy.")
            log_settings = None
        return super().set_log_setting(log_settings)

    def set_log_start(self):
        """
        Set the start logging for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_log_start()")
        log_start = self._policy_info['logBegin']
        return super().set_log_start(log_start)

    def set_log_end(self):
        """
        Set the end logging for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_log_end()")
        log_end = self._policy_info['logEnd']
        return super().set_log_end(log_end)

    def set_section(self):
        """
        Set the section for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_section()")
        section = self._policy_info['metadata']['section']
        return super().set_section(section)

    def set_action(self):
        """
        Set the action for the security policy.
        """
        helper.logging.debug("Called FMCSecurityPolicy::set_action()")
        action = self._policy_info['action']
        return super().set_action(action)

#TODO: see if debugging is really necessary on these functions
    def extract_policy_object_info(self, raw_object, object_type):
        """
        Extract information about policy objects based on object type.

        Parameters:
            raw_object (dict): Information about the policy object.
            object_type (str): Type of the policy object.

        Returns:
            dict: Extracted information about the policy object.
        """
        helper.logging.debug(f"Called FMCSecurityPolicy::extract_policy_object_info().")
        match object_type:
            case 'security_zone':
                return self.extract_security_zone_object_info(raw_object)
            case 'network_address_object':
                return self.extract_network_address_object_info(raw_object)
            case 'port_object':
                return self.extract_port_object_info(raw_object)
            case 'user_object':
                return self.extract_user_object_info(raw_object)
            case 'schedule_object':
                return self.extract_schedule_object_info(raw_object)
            case 'url_object':
                return self.extract_url_object_info(raw_object)
            case 'l7_app_object':
                return self.extract_l7_app_object_info(raw_object)
            case 'comment':
                return self.extract_comments(raw_object)
                    
    def extract_security_zone_object_info(self, security_zone_object_info):
        """
        Extract security zone information from the provided data structure.

        This method extracts the names of security zones from the given data structure.

        Parameters:
            security_zone_object_info (dict): A dictionary containing information about security zone objects.

        Returns:
            list: A list of security zone names extracted from the provided data structure.
        """
        # Log a debug message indicating the function call
        helper.logging.debug("Called FMCSecurityPolicy::extract_security_zone_object_info()")
        
        # Initialize an empty list to store the extracted security zone names
        extracted_security_zones = []

        # Iterate through each security zone entry in the provided data structure
        for security_zone_entry in security_zone_object_info['objects']:
            # Extract the name of the security zone and append it to the list
            extracted_security_zones.append(security_zone_entry['name'])
        
        # Return the list of extracted security zone names
        return extracted_security_zones
        
    def extract_network_address_object_info(self, network_object_info):
        """
        Extract network address object information from the provided data structure.

        This method extracts the names of network address objects from the given data structure.

        Parameters:
            network_object_info (dict): Information about network address objects.

        Returns:
            list: A list of network address object names extracted from the provided data structure.
        """
        # Log a debug message indicating the function call
        helper.logging.debug("Called FMCSecurityPolicy::extract_network_address_object_info()")

        # Initialize an empty list to store the extracted network address object names
        extracted_member_network_objects = []

        # Extract information from proper network objects
        try:
            helper.logging.info(f"Found network objects on this policy.")
            # Retrieve the list of network objects from the provided data structure
            network_object_info_objects = network_object_info['objects']
            
            # Iterate through each network object entry
            for network_object_entry in network_object_info_objects:
                # Extract the name and type of the network object
                network_object_name = network_object_entry['name']
                network_object_type = network_object_entry['type']
                
                # Append the network object name to the list
                if network_object_type == 'Country':
                    # If the network object is of type 'Country', prepend its ID before the name
                    network_object_name = network_object_entry['id'] + gvars.separator_character + network_object_name
                extracted_member_network_objects.append(network_object_name)
        except KeyError:
            # If there are no network objects, log an informational message
            helper.logging.info(f"It looks like there are no network objects on this policy.")

        # Extract information from network literals
        try:
            helper.logging.info(f"Found network literals on this policy.")
            # Retrieve the list of network literals from the provided data structure
            network_literals = network_object_info['literals']
            # Log an informational message indicating the search for literals
            helper.logging.info(f"I am looking for literals.")
            # Log debug information about the found literals
            helper.logging.debug(f"Literals found {network_literals}.")
            # Convert network literals to network objects and add them to the extracted list
            extracted_member_network_objects += FMCSecurityDevice.convert_network_literals_to_objects(network_literals)
        except KeyError:
            # If there are no network literals, log an informational message
            helper.logging.info(f"It looks like there are no network literals on this policy.")

        # Return the list of extracted network address object names
        return extracted_member_network_objects
    
    def extract_port_object_info(self, port_object_info):
        """
        Extract port object information from the provided data structure.

        This method extracts the names of port objects from the given data structure.

        Parameters:
            port_object_info (dict): Information about port objects.

        Returns:
            list: A list of port object names extracted from the provided data structure.
        """
        # Log a debug message indicating the function call
        helper.logging.debug("Called FMCSecurityPolicy::extract_port_object_info()")

        # Initialize an empty list to store the extracted port object names
        port_objects_list = []

        # Extract information from proper port objects
        try:
            helper.logging.info(f"Found port objects on this policy.")
            # Retrieve the list of port objects from the provided data structure
            port_object_info_objects = port_object_info['objects']
            
            # Iterate through each port object entry
            for port_object_entry in port_object_info_objects:
                # Extract the name of the port object and append it to the list
                port_object_name = port_object_entry['name']
                port_objects_list.append(port_object_name)
        except KeyError:
            # If there are no port objects, log an informational message
            helper.logging.info(f"It looks like there are no port objects on this policy.")
        
        # Extract information from port literals
        try:
            helper.logging.info(f"Found port literals on this policy.")
            # Log an informational message indicating the search for port literals
            helper.logging.info(f"I am looking for port literals...")
            # Retrieve the list of port literals from the provided data structure
            port_literals = port_object_info['literals']
            # Log an informational message indicating the found port literals
            helper.logging.info(f"I have found literals.")
            # Log debug information about the found port literals
            helper.logging.info(f"Port literals found: {port_literals}.")
            # Process each port literal using the convert_port_literals_to_objects function
            port_objects_list += FMCSecurityDevice.convert_port_literals_to_objects(port_literals)
        except KeyError:
            # If there are no port literals, log an informational message
            helper.logging.info(f"It looks like there are no port literals on this policy.")
        
        # Return the list of extracted port object names
        return port_objects_list

    def extract_user_object_info(self, user_object_info):
        """
        Extract user object information from the provided data structure.

        This method extracts the names of user objects from the given data structure.

        Parameters:
            user_object_info (dict): Information about user objects.

        Returns:
            list: A list of processed user object entries containing user type and name.
        """
        # Log a debug message indicating the function call
        helper.logging.debug("Called FMCSecurityPolicy::extract_user_object_info()")
        helper.logging.info(f"Found users on this policy.")
        # Initialize an empty list to store the processed user object entries
        extracted_user_objects = []

        # Iterate through each user object entry in the provided data structure
        for user_object_entry in user_object_info['objects']:
            # Extract the name of the user object
            user_object_name = user_object_entry['name']
            # Construct the processed user object entry containing user type and name
            user_object_processed_entry = user_object_entry['type'] + gvars.separator_character + user_object_name
            # Append the processed user object entry to the list
            extracted_user_objects.append(user_object_processed_entry)
        
        # Return the list of processed user object entries
        return extracted_user_objects

    def extract_schedule_object_info(self, schedule_object_info):
        """
        Extract schedule object information from the provided data structure.

        This method extracts the names of schedule objects from the given data structure.

        Parameters:
            schedule_object_info (list): Information about schedule objects.

        Returns:
            list: A list of schedule object names extracted from the provided data structure.
        """
        # Log a debug message indicating the function call
        helper.logging.debug("Called FMCSecurityPolicy::extract_schedule_object_info()")
        
        helper.logging.info(f"Found schedule objects on this policy.")
        # Initialize an empty list to store the extracted schedule object names
        extracted_schedule_objects = []
        
        # Iterate through each schedule object entry in the provided data structure
        for schedule_object_entry in schedule_object_info:
            # Extract the name of the schedule object and append it to the list
            schedule_object_name = schedule_object_entry['name']
            extracted_schedule_objects.append(schedule_object_name)
        
        # Return the list of extracted schedule object names
        return extracted_schedule_objects

    # there are three cases which need to be processed here. the url can be an object, a literal, or a category with reputation
    def extract_url_object_info(self, url_object_info):
        """
        Extract URL object information from the provided data structure.

        This method extracts information about URL objects, literals, and categories from the given data structure.

        Parameters:
            url_object_info (dict): Information about URL objects.

        Returns:
            list: A list of URL objects, including objects, literals, and categories, extracted from the provided data structure.
        """
        # Log a debug message indicating the function call
        helper.logging.debug("Called FMCSecurityPolicy::extract_url_object_info()")
        
        # Initialize an empty list to store the extracted URL objects
        policy_url_objects_list = []

        # Extract URL objects
        try:
            helper.logging.info(f"Found URL objects on this policy.")
            # Retrieve the list of URL objects from the provided data structure
            policy_url_objects = url_object_info['objects']
            # Iterate through each URL object entry
            for policy_url_object in policy_url_objects:
                # Extract the name of the URL object and append it to the list
                policy_url_object_name = policy_url_object['name']
                policy_url_objects_list.append(policy_url_object_name)
        except KeyError:
            # If there are no URL objects, log an informational message
            helper.logging.info("It looks like there are no URL objects on this policy.")

        # Extract URL literals
        try:
            helper.logging.info(f"Found URL literals on this policy.")
            # Retrieve the list of URL literals from the provided data structure
            policy_url_literals = url_object_info['literals']
            # Iterate through each URL literal entry
            for policy_url_literal in policy_url_literals:
                # Extract the URL literal value and append it to the list
                policy_url_literal_value = policy_url_literal['url']
                policy_url_objects_list.append(policy_url_literal_value)
        except KeyError:
            # If there are no URL literals, log an informational message
            helper.logging.info("It looks like there are no URL literals on this policy.")

        # Extract URL categories with reputation
        try:
            helper.logging.info(f"Found URL categories with reputation on this policy.")
            # Retrieve the list of URL categories with reputation from the provided data structure
            policy_url_categories = url_object_info['urlCategoriesWithReputation']
            # Iterate through each URL category entry
            for policy_url_category in policy_url_categories:
                # Extract the category name and reputation, then construct a formatted name and append it to the list
                category_name = policy_url_category['category']['name']
                category_reputation = policy_url_category['reputation']
                category_name = f"URL_CATEGORY{gvars.separator_character}{category_name}{gvars.separator_character}{category_reputation}"
                policy_url_objects_list.append(category_name)
        except KeyError:
            # If there are no URL categories with reputation, log an informational message
            helper.logging.info("It looks like there are no URL categories on this policy.")

        # Return the list of extracted URL objects
        return policy_url_objects_list
    
    def extract_l7_app_object_info(self, l7_app_object_info):
        """
        Extract Layer 7 application object information from the provided data structure.

        This method extracts information about Layer 7 applications and their associated filters from the given data structure.

        Parameters:
            l7_app_object_info (dict): Information about Layer 7 application objects.

        Returns:
            list: A list of Layer 7 application names and their associated filters extracted from the provided data structure.
        """
        # Initialize an empty list to store the extracted Layer 7 application information
        policy_l7_apps_list = []

        # Log a debug message indicating the function call
        helper.logging.debug("Called FMCSecurityPolicy::extract_l7_app_object_info()")
        
        # Extract regular Layer 7 applications
        try:
            helper.logging.info(f"Found L7 applications on this policy.")
            # Retrieve the list of Layer 7 applications from the provided data structure
            policy_l7_apps = l7_app_object_info['applications']
            # Iterate through each Layer 7 application entry
            for policy_l7_app in policy_l7_apps:
                # Construct the name of the Layer 7 application and append it to the list
                policy_l7_name = 'APP' + gvars.separator_character + policy_l7_app['name']
                policy_l7_apps_list.append(policy_l7_name)
        except KeyError:
            # If there are no Layer 7 applications, log an informational message
            helper.logging.info("It looks like there are no Layer 7 apps on this policy.")

        # Extract Layer 7 application filters
        try:
            helper.logging.info(f"Found L7 application filters on this policy.")
            # Retrieve the list of Layer 7 application filters from the provided data structure
            policy_l7_app_filters = l7_app_object_info['applicationFilters']
            # Iterate through each Layer 7 application filter entry
            for policy_l7_app_filter in policy_l7_app_filters:
                # Construct the name of the Layer 7 application filter and append it to the list
                policy_l7_app_filter_name = 'APP_FILTER' + gvars.separator_character + policy_l7_app_filter['name']
                policy_l7_apps_list.append(policy_l7_app_filter_name)
        except KeyError:
            # If there are no Layer 7 application filters, log an informational message
            helper.logging.info("It looks like there are no Layer 7 application filters on this policy.")

        # Extract inline Layer 7 application filters
        try:
            helper.logging.info(f"Found L7 inline application filters on this policy.")
            # Retrieve the list of inline Layer 7 application filters from the provided data structure
            policy_inline_l7_app_filters = l7_app_object_info['inlineApplicationFilters']
            # Iterate through each entry in the list of inline Layer 7 application filters
            for filter_dict in policy_inline_l7_app_filters:
                for key, elements in filter_dict.items():
                    if isinstance(elements, list):
                        # Iterate through each element in the inline Layer 7 application filter entry
                        for element in elements:
                            # Construct the name of the inline Layer 7 application filter and append it to the list
                            filter_name = f"inlineApplicationFilters{gvars.separator_character}{key}{gvars.separator_character}{element['name']}"
                            policy_l7_apps_list.append(filter_name)
        except KeyError:
            # If there are no inline Layer 7 application filters, log an informational message
            helper.logging.info("It looks like there are no Inline Layer 7 application filters on this policy.")

        # Return the list of extracted Layer 7 application information
        return policy_l7_apps_list

    def extract_comments(self, comment_info):
        """
        Extract comments from the provided data structure.

        This method extracts comments from the given data structure and returns a list of dictionaries containing user and comment content.

        Parameters:
            comment_info (list): Information about comments.

        Returns:
            list: A list of dictionaries containing user and comment content extracted from the provided data structure.
        """
        # Log a debug message indicating the function call
        helper.logging.debug("Called FMCSecurityPolicu::extract_comments()")
        helper.logging.info(f"Found comments on this policy.")
        # Initialize an empty list to store the processed comments
        processed_comment_list = []

        # Iterate over each comment entry
        for comment_entry in comment_info:
            # Extract the user's name and comment content
            comment_user = comment_entry['user']['name']
            comment_content = comment_entry['comment']
            # Store the user and comment content in a dictionary and append it to the list
            processed_comment_list.append({'user': comment_user, 'content': comment_content})

        # Log a debug message indicating the completion of comment processing
        helper.logging.debug(f"Finished processing comments. This is the list: {processed_comment_list}.")
        
        # Return the list of processed comments
        return processed_comment_list

class FMCSecurityDevice(SecurityDevice):
    """
    Represents a security device connected to Cisco Firepower Management Center (FMC).

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
        helper.logging.debug("Called FMCSecurityDevice::__init__()")
        super().__init__(name, sec_device_database)
        # Establish connection to FMC device
        self._sec_device_connection = FMCDeviceConnection(security_device_username, security_device_secret, security_device_hostname, security_device_port, domain).connect_to_security_device()
        self._network_address_objects_info = None
        self._network_group_objects_info = None
        self._geolocation_objects_info = None
        self._countries_info = None
        self._continents_info = None

    def return_security_policy_container_object(self, container_name):
        helper.logging.debug("Called FMCSecurityDevice::return_security_policy_container_object()")
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
        helper.logging.debug("Called FMCSecurityDevice::return_security_policy_object()")
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
        helper.logging.debug("Called FMCSecurityDevice::return_object_container_object(). There are no actual containers on this type of security device. Will return a virtual one.")
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
        helper.logging.info(f"Got the following managed device {device_name}.")
        assigned_security_policy_container = managed_device['accessPolicy']['name']
        device_hostname = managed_device['hostName']
        device_cluster = None

        # Check if the device is part of a cluster
        try:
            device_cluster = managed_device['metadata']['containerDetails']['name']
            helper.logging.info(f"Managed device {managed_device} is part of a cluster {device_cluster}.")
        except KeyError:
            helper.logging.info(f"Managed device {managed_device} is NOT part of a cluster {device_cluster}.")

        return device_name, assigned_security_policy_container, device_hostname, device_cluster

    def get_managed_devices_info(self):
        """
        Retrieve information about managed devices.

        Returns:
            list: List of dictionaries containing information about managed devices.
        """
        helper.logging.debug("Called function get_managed_devices_info().")
        helper.logging.info("################## GETTING MANAGED DEVICES INFO ##################")

        # Execute the request to retrieve information about the devices
        managed_devices = self._sec_device_connection.device.devicerecord.get()
        helper.logging.debug(f"Executed API call to the FMC device, got the following info {managed_devices}.")
        return managed_devices

    def get_security_policies_info(self, policy_container_name):
        """
        Retrieve information about security policies within a specified container.

        Args:
            policy_container_name (str): Name of the container containing the security policies.

        Returns:
            list: List of dictionaries containing information about security policies.
        """
        helper.logging.debug("Called function get_security_policies_info().")
        helper.logging.info("################## GETTING SECURITY POLICIES INFO ##################")

        # Execute the request to retrieve information about the security policies
        security_policies_info = self._sec_device_connection.policy.accesspolicy.accessrule.get(container_name=policy_container_name)
        return security_policies_info
    
    def get_device_version(self):
        """
        Retrieve the version of the device's server.

        Returns:
            str: Version of the device's server.
        """
        helper.logging.debug("Called FMCSecurityDevice::get_device_version()")
        # Retrieve device system information to get the server version
        device_system_info = self._sec_device_connection.system.info.serverversion.get()

        # Extract the exact info needed from the response got from the device
        device_version = device_system_info[0]['serverVersion']
        return device_version
    
    # This function returns Python network objects back to the caller.
    # for the objects stored in the database, it checks where they are exactly located on the Security Device
    # if "example" is a network address, it will stop processing and then it will return a network address object
    def fetch_objects_info(self, object_type):
        match object_type:
            case 'network_objects':
                if not self._network_address_objects_info:
                    self._network_address_objects_info = self._sec_device_connection.object.networkaddress.get()
                    network_address_objects_dict = {entry['name']: entry for entry in self._network_address_objects_info}
                    self._network_address_objects_info = network_address_objects_dict

                if not self._network_group_objects_info:
                    self._network_group_objects_info = self._sec_device_connection.object.networkgroup.get()
                    network_group_objects_dict = {entry['name']: entry for entry in self._network_group_objects_info}
                    self._network_group_objects_info = network_group_objects_dict

                if not self._geolocation_objects_info:
                    self._geolocation_objects_info = self._sec_device_connection.object.geolocation.get()
                    geolocation_objects_dict = {entry['name']: entry for entry in self._geolocation_objects_info}
                    self._geolocation_objects_info = geolocation_objects_dict

                if not self._countries_info:
                    self._countries_info = self._sec_device_connection.object.country.get()
                    countries_dict = {entry['id']: entry for entry in self._countries_info if 'id' in entry}
                    self._countries_info = countries_dict

                if not self._continents_info:
                    self._continents_info = self._sec_device_connection.object.continent.get()
                    continents_dict = {entry['name']: entry for entry in self._continents_info}
                    self._continents_info = continents_dict

    # this function is responsible for retrieving all the member objects
    # it also sets the members of a group objects to be the objects retrieved
    # what if i set the members of the object here?
    # TODO: this could probabily be rewritten in a better way
    def _return_group_object_members_helper(self, group_object, object_type, group_member_objects):
        group_member_object_names = []
        # look for literals and objects in the info of the object
        group_object_info = group_object.get_info()

        try:
            object_members = group_object_info['objects']
            for object_member in object_members:
                group_member_object_names.append(object_member['name'])
        except KeyError:
            print('No member objects')
        
        try:
            literal_members = group_object_info['literals']
            group_member_object_names += FMCSecurityDevice.convert_network_literals_to_objects(literal_members)

        except KeyError:
            print("No literal members")

        # set the member names of the group
        group_object.set_member_names(group_member_object_names)

        match object_type:
            case 'network_objects':
                group_member_objects.append(self.return_network_objects(group_member_object_names))

    # TODO: rewrite this function
    # init all the info of the objects (in the init of FMCSecurityDevice)
    # convert it to dictionaries (new function required)
    # loop through the members of an object and recursively look it up (new function required)
    def return_network_objects(self, object_names):
        """
        Retrieve Python objects with the information about network objects from the device.

        This method retrieves network objects' information from the device, processes it, and returns Python representations of network objects.

        Returns:
            list: A list of Python representations of network objects.
        """
        # Log a debug message indicating the function call
        helper.logging.debug("Called FMCSecurityDevice::return_network_objects()")
        
        # Log an informative message about processing network objects data info
        helper.logging.info("Processing network objects data info. Retrieving all objects from the database, processing them, and returning their info.")

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
                    network_objects_from_device_list.append(FMCNetworkObject(self._network_address_objects_info[network_object_name]))
                
                    #######
                elif network_object_name in self._network_group_objects_info:
                    network_group_object = FMCNetworkGroupObject(self._network_group_objects_info[network_object_name])
                    
                    self._return_group_object_members_helper(network_group_object, 'network_objects', network_objects_from_device_list)
                    # loop through objects, if member is network group, create group object with it and loop through it again
                    # now process this object and get the member info, and based on the member info, append the created object to the network_objects_from_device_list
                    network_objects_from_device_list.append(FMCNetworkGroupObject(self._network_group_objects_info[network_object_name]))
                    #########

                elif network_object_name in self._geolocation_objects_info:
                    network_objects_from_device_list.append(FMCGeolocationObject(self._geolocation_objects_info[network_object_name]))
                
                elif network_object_name in self._continents_info:
                    network_objects_from_device_list.append(FMCContinentObject(self._continents_info[network_object_name]))
                else:
                    # Log an error message for invalid network objects
                    helper.logging.error(f"{network_object_name} is an invalid object!")
        
        # Return the list of network objects retrieved from the device
        return network_objects_from_device_list

    @staticmethod
    def convert_port_literals_to_objects(port_literals):
        helper.logging.debug("Called FMCSecurityDevice::convert_port_literals_to_objects().")
        """
        Convert port literals to objects.

        Args:
            port_literals (list): List of port literals.

        Returns:
            list: List of port object names.
        """
        port_objects_list = []

        # Process each port literal
        for port_literal in port_literals:
            literal_protocol = port_literal['protocol']

            # Handle ICMP literals separately
            if literal_protocol in ["1", "58"]:
                helper.logging.info(f"I have encountered an ICMP literal: {port_literal['type']}.")
                literal_port_nr = port_literal['icmpType']
            else:
                literal_port_nr = port_literal['port']

            # Convert protocol number to a known IANA keyword
            try:
                literal_protocol_keyword = helper.protocol_number_to_keyword(literal_protocol)
            except PioneerExceptions.UnknownProtocolNumber:
                helper.logging.error(f"Protocol number: {literal_protocol} cannot be converted to a known IANA keyword.")
                continue

            # Create the name of the port object
            port_object_name = f"{gvars.port_literal_prefix}_{literal_protocol_keyword}_{literal_port_nr}"
            port_objects_list.append(port_object_name)

        helper.logging.debug(f"Finished converting all literals to objects. This is the list with converted literals {port_objects_list}.")
        return port_objects_list

    @staticmethod
    def convert_network_literals_to_objects(network_literals):
        helper.logging.debug("Called FMSecurityPolicy::convert_network_literals_to_objects().")
        """
        Convert network literals to objects.

        Args:
            network_literals (list): List of network literals.

        Returns:
            list: List of network object names.
        """
        network_objects_list = []

        # Loop through the network literals.
        for network_literal in network_literals:
            helper.logging.debug(f"Converting literal {network_literal} to object.")
            # Extract the value of the network literal
            literal_value = network_literal['value']

            # Extract the type of the network literal. Can be either "Host" or "Network"
            # The name of the converted object will depend on the network literal type
            literal_type = network_literal['type']

            # The literal type can be either a host or a network
            if literal_type == 'Network':
                helper.logging.debug(f"{network_literal} is of type Network.")
                # Define the CIDR notation IP address
                ip_cidr = literal_value

                # Create an IPv4 network object
                network = ipaddress.ip_network(ip_cidr, strict=False)

                # Extract the network address and netmask
                network_address = network.network_address
                netmask = str(network.prefixlen)  # Extract the prefix length instead of the full netmask

            elif literal_type == 'Host':
                helper.logging.debug(f"{network_literal} is of type Host.")
                netmask = '32'
                network_address = literal_value  # Assuming literal_value is the host address

            else:
                helper.logging.debug(f"Cannot determine type of {network_literal}. Presented type is {literal_type}.")
                continue

            # Create the name of the object (NL_networkaddress_netmask)
            network_object_name = gvars.network_literal_prefix + str(network_address) + "_" + str(netmask)
            helper.logging.debug(f"Converted network literal {network_literal} to object {network_object_name}.")
            network_objects_list.append(network_object_name)
        
        helper.logging.debug(f"Finished converting all literals to objects. This is the list with converted literals {network_objects_list}.")
        return network_objects_list