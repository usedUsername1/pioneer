from abc import abstractmethod
from pkg.Container import SecurityPolicyContainer, ObjectPolicyContainer
from pkg.DeviceObject import Object, GroupObject, GeolocationObject
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
    pass

class FMCGroupObject(GroupObject):
    pass

class FMCNetworkObject(FMCObject):
    pass

class FMCNetworkGroupObject(FMCGroupObject):
    pass

class FMCPortObject(FMCObject):
    pass

class FMCPortGroupObject(FMCGroupObject):
    pass

class FMCNetworkLiteral(FMCNetworkObject):
    pass

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
        super().__init__(object_info)

    def set_name(self):
        """
        Set the name of the geolocation object.
        
        Returns:
            str: The name of the geolocation object.
        """
        name = self._object_info['name']
        return super().set_name(name)

    def set_description(self):
        """
        Set the description of the geolocation object.

        Returns:
            None
        """
        value = None
        return super().set_description(value)

    def set_object_container_name(self):
        """
        Set the name of the object container for the geolocation object.

        Returns:
            str: The name of the object container.
        """
        object_container_name = 'virtual_object_container'
        return super().set_object_container_name(object_container_name)

    def set_continents(self):
        """
        Set the continents associated with the geolocation object.

        Returns:
            list: A list of FMCContinentObject instances representing continents.
        """
        continent_objects_list = []
        try:
            continents_info = self._object_info['continents']
            for continent_info in continents_info:
                continent_objects_list.append(FMCContinentObject(continent_info))
        except KeyError:
            continent_objects_list = None
        return super().set_continents(continent_objects_list)

    def set_countries(self):
        """
        Set the countries associated with the geolocation object.

        Returns:
            list: A list of FMCCountryObject instances representing countries.
        """
        countries_objects_list = []
        try:
            country_info = self._object_info['countries']
            for country_entry in country_info:
                countries_objects_list.append(FMCCountryObject(country_entry))
        except KeyError:
            countries_objects_list = None

        # Add countries of the continents
        for continent in self._continents:
            for country_info in continent.get_continent_info()['countries']:
                countries_objects_list.append(FMCCountryObject(country_info))

        return super().set_countries(countries_objects_list)

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
    A class representing a FMC continent object
    """

    def __init__(self, object_info) -> None:
        """
        Initialize the FMCContinentObject instance.

        Args:
            object_info (dict): Information about the continent object.
        """
        super().__init__(object_info)
        
    def set_name(self):
        """
        Set the name of the continent object.
        
        Returns:
            str: The name of the continent object.
        """
        name = self._object_info['name']
        return super().set_name(name)

    def set_object_container_name(self):
        """
        Set the name of the object container for the continent object.

        Returns:
            str: The name of the object container.
        """
        object_container_name = 'virtual_object_container'
        return super().set_object_container_name(object_container_name)
    
    def set_continents(self):
        """
        Set the continents associated with the continent object.

        Returns:
            None
        """
        self._continents = None
    
    def get_member_continent_names(self):
        """
        Get the name of the continent.

        Returns:
            str: The name of the continent.
        """
        return self._object_info['name']
    
    @abstractmethod
    def set_continents(self):
        """
        Abstract method to set the continents associated with the continent object.
        """
        pass

    def set_countries(self):
        countries_objects_list = []
        try:
            country_info = self._object_info['countries']
            for country_info in country_info:
                countries_objects_list.append(FMCCountryObject(country_info))
        except KeyError:
            countries_objects_list = None    
        return super().set_countries(countries_objects_list)

    def set_member_alpha2_codes(self):
        pass

    def set_member_alpha3_codes(self):
        pass

    def set_member_numeric_codes(self):
        pass

    #TODO: move this
    def get_continent_info(self):
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

#TODO: maybe use setters for setting the values in here, and use the getters from the parent class to retrieve the info
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

#TODO: maybe use setters for setting the values in here, and use the getters from the parent class to retrieve the info
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
        super().__init__(policy_info_fmc)

    # Methods for setting various attributes of the security policy
    def set_name(self):
        """Set the name of the security policy."""
        name = self._policy_info['name']
        return super().set_name(name)

    def set_container_name(self):
        """Set the name of the policy container."""
        container_name = self._policy_info['metadata']['accessPolicy']['name']
        return super().set_container_name(container_name)

    def set_container_index(self):
        """Set the index of the policy container."""
        index = self._policy_info['metadata']['ruleIndex']
        return super().set_container_index(index)
    
    def set_status(self):
        """
        Set the status of the security policy (enabled or disabled).
        """
        status = 'enabled' if self._policy_info.get('enabled', False) else 'disabled'
        return super().set_status(status)

    def set_category(self):
        """
        Set the category of the security policy.
        """
        category = self._policy_info['metadata']['category']
        return super().set_category(category)

    def set_source_zones(self):
        """
        Set the source zones for the security policy.
        """
        source_zones = self._policy_info.get('sourceZones', ['any'])
        return super().set_source_zones(source_zones)

    def set_destination_zones(self):
        """
        Set the destination zones for the security policy.
        """
        destination_zones = self._policy_info.get('destinationZones', ['any'])
        return super().set_destination_zones(destination_zones)

    def set_source_networks(self):
        """
        Set the source networks for the security policy.
        """
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
        log_start = self._policy_info['logBegin']
        return super().set_log_start(log_start)

    def set_log_end(self):
        """
        Set the end logging for the security policy.
        """
        log_end = self._policy_info['logEnd']
        return super().set_log_end(log_end)

    def set_section(self):
        """
        Set the section for the security policy.
        """
        section = self._policy_info['metadata']['section']
        return super().set_section(section)

    def set_action(self):
        """
        Set the action for the security policy.
        """
        action = self._policy_info['action']
        return super().set_action(action)

    def extract_policy_object_info(self, raw_object, object_type):
        """
        Extract information about policy objects based on object type.

        Parameters:
            raw_object (dict): Information about the policy object.
            object_type (str): Type of the policy object.

        Returns:
            dict: Extracted information about the policy object.
        """
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

        Parameters:
            security_zone_object_info (dict): Information about security zone objects.

        Returns:
            list: List of security zone names.
        """
        helper.logging.debug("Called extract_security_zone_object_info()")
        extracted_security_zones = []
        for security_zone_entry in security_zone_object_info['objects']:
            extracted_security_zones.append(security_zone_entry['name'])
        
        return extracted_security_zones
        
    def extract_network_address_object_info(self, network_object_info):
        """
        Extract network address object information from the provided data structure.

        Parameters:
            network_object_info (dict): Information about network address objects.

        Returns:
            list: List of network address object names.
        """
        helper.logging.debug("Called extract_network_address_object_info()")
        extracted_member_network_objects = []

        # Extract information from proper network objects
        try:
            network_object_info_objects = network_object_info['objects']
            for network_object_entry in network_object_info_objects:
                network_object_name = network_object_entry['name']
                network_object_type = network_object_entry['type']
                if network_object_type == 'Country':
                    network_object_name = network_object_entry['id'] + gvars.separator_character + network_object_name
                extracted_member_network_objects.append(network_object_name)
        except KeyError:
            helper.logging.info(f"It looks like there are no network objects on this policy.")

        # Extract information from network literals
        try:
            helper.logging.info(f"I am looking for literals.")
            network_literals = network_object_info['literals']
            helper.logging.debug(f"Literals found {network_literals}.")
            extracted_member_network_objects += self.convert_network_literals_to_objects(network_literals)
        except KeyError:
            helper.logging.info(f"It looks like there are no network literals on this policy.")
        
        return extracted_member_network_objects
    
    def extract_port_object_info(self, port_object_info):
        """
        Extract port object information from the provided data structure.

        Parameters:
            port_object_info (dict): Information about port objects.

        Returns:
            list: List of port object names.
        """
        port_objects_list = []

        # Extract information from proper port objects
        try:
            port_object_info_objects = port_object_info['objects']
            for port_object_entry in port_object_info_objects:
                port_object_name = port_object_entry['name']
                port_objects_list.append(port_object_name)
        except KeyError:
            helper.logging.info(f"It looks like there are no port objects on this policy.")
        
        # Extract information from port literals
        try:
            helper.logging.info(f"I am looking for port literals...")
            port_literals = port_object_info['literals']
            helper.logging.info(f"I have found literals.")
            helper.logging.info(f"Port literals found: {port_literals}.")
            # Process each port literal using the convert_port_literals_to_objects function
            port_objects_list += self.convert_port_literals_to_objects(port_literals)
        except KeyError:
            helper.logging.info(f"It looks like there are no port literals on this policy.")
        
        return port_objects_list

    def extract_user_object_info(self, user_object_info):
        """
        Extract user object information from the provided data structure.

        Parameters:
            user_object_info (dict): Information about user objects.

        Returns:
            list: List of processed user object entries.
        """
        helper.logging.debug("Called extract_user_object_info()")
        extracted_user_objects = []

        for user_object_entry in user_object_info['objects']:
            user_object_name = user_object_entry['name']
            user_object_processed_entry = user_object_entry['type'] + gvars.separator_character + user_object_name
            extracted_user_objects.append(user_object_processed_entry)
        
        return extracted_user_objects

    def extract_schedule_object_info(self, schedule_object_info):
        """
        Extract schedule object information from the provided data structure.

        Parameters:
            schedule_object_info (list): Information about schedule objects.

        Returns:
            list: List of schedule object names.
        """
        helper.logging.debug("Called extract_schedule_object_info()")
        extracted_schedule_objects = []
        for schedule_object_entry in schedule_object_info:
            schedule_object_name = schedule_object_entry['name']
            extracted_schedule_objects.append(schedule_object_name)
        
        return extracted_schedule_objects

    # there are three cases which need to be processed here. the url can be an object, a literal, or a category with reputation
    def extract_url_object_info(self, url_object_info):
        """
        Extract URL object information from the provided data structure.

        Parameters:
            url_object_info (dict): Information about URL objects.

        Returns:
            list: List of URL objects, including objects, literals, and categories.
        """
        policy_url_objects_list = []

        # Extract URL objects
        try:
            policy_url_objects = url_object_info['objects']
            for policy_url_object in policy_url_objects:
                policy_url_object_name = policy_url_object['name']
                policy_url_objects_list.append(policy_url_object_name)
        except KeyError:
            helper.logging.info("It looks like there are no URL objects on this policy.")

        # Extract URL literals
        try:
            policy_url_literals = url_object_info['literals']
            for policy_url_literal in policy_url_literals:
                policy_url_literal_value = policy_url_literal['url']
                policy_url_objects_list.append(policy_url_literal_value)
        except KeyError:
            helper.logging.info("It looks like there are no URL literals on this policy.")

        # Extract URL categories with reputation
        try:
            policy_url_categories = url_object_info['urlCategoriesWithReputation']
            for policy_url_category in policy_url_categories:
                category_name = policy_url_category['category']['name']
                category_reputation = policy_url_category['reputation']
                category_name = f"URL_CATEGORY{gvars.separator_character}{category_name}{gvars.separator_character}{category_reputation}"
                policy_url_objects_list.append(category_name)
        except KeyError:
            helper.logging.info("It looks like there are no URL categories on this policy.")

        return policy_url_objects_list
    
    def extract_l7_app_object_info(self, l7_app_object_info):
        """
        Extract Layer 7 application object information from the provided data structure.

        Parameters:
            l7_app_object_info (dict): Information about Layer 7 application objects.

        Returns:
            list: List of Layer 7 application names and their associated filters.
        """
        policy_l7_apps_list = []

        # Extract regular L7 applications
        try:
            policy_l7_apps = l7_app_object_info['applications']
            for policy_l7_app in policy_l7_apps:
                policy_l7_name = 'APP' + gvars.separator_character + policy_l7_app['name']
                policy_l7_apps_list.append(policy_l7_name)
        except KeyError:
            helper.logging.info("It looks like there are no Layer 7 apps on this policy.")

        # Extract L7 application filters
        try:
            policy_l7_app_filters = l7_app_object_info['applicationFilters']
            for policy_l7_app_filter in policy_l7_app_filters:
                policy_l7_app_filter_name = 'APP_FILTER' + gvars.separator_character + policy_l7_app_filter['name']
                policy_l7_apps_list.append(policy_l7_app_filter_name)
        except KeyError:
            helper.logging.info("It looks like there are no Layer 7 application filters on this policy.")

        # Extract inline L7 application filters
        try:
            policy_inline_l7_app_filters = l7_app_object_info['inlineApplicationFilters']
            for filter_dict in policy_inline_l7_app_filters:
                for key, elements in filter_dict.items():
                    if isinstance(elements, list):
                        for element in elements:
                            filter_name = f"inlineApplicationFilters{gvars.separator_character}{key}{gvars.separator_character}{element['name']}"
                            policy_l7_apps_list.append(filter_name)
        except KeyError:
            helper.logging.info("It looks like there are no Inline Layer 7 application filters on this policy.")

        return policy_l7_apps_list

    def extract_comments(self, comment_info):
        """
        Extract comments from the provided data structure.

        Parameters:
            comment_info (list): Information about comments.

        Returns:
            list: List of dictionaries containing user and comment content.
        """
        helper.logging.debug("Called extract_comments()")
        processed_comment_list = []

        # Iterate over each comment entry
        for comment_entry in comment_info:
            # Extract user's name and comment content
            comment_user = comment_entry['user']['name']
            comment_content = comment_entry['comment']
            # Store user and comment content in a dictionary and append it to the list
            processed_comment_list.append({'user': comment_user, 'content': comment_content})

        helper.logging.debug(f"Finished processing comments. This is the list: {processed_comment_list}.")
        return processed_comment_list
    
    #TODO: might need this in other places as well, maybe move it to another class
    # Convert it to static method and put them in the FMCSecurityDevice class
    def convert_network_literals_to_objects(self, network_literals):
        helper.logging.debug("Called convert_network_literals_to_objects().")
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

    # this too
    def convert_port_literals_to_objects(self, port_literals):
        helper.logging.debug("Called convert_port_literals_to_objects().")
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
        container_info = ''
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

# everything enclosed here must disappear
########################################
    def process_network_literals(self, network_address_literals):
        """
        Process network address literals.

        Args:
            network_address_literals (list): List of network address literals.

        Returns:
            list: List of dictionaries containing processed network literals information.
        """
        helper.logging.debug(f"Called process_network_literals(). Input data: {network_address_literals}.")
        helper.logging.info("I am now processing the imported network literals. I am processing and formatting all the data retrieved from the policies.")

        if not network_address_literals:
            helper.logging.info("There are no literals to process.")
            return []

        processed_network_literals_info = []
        object_container_name = "virtual_object_container"
        literal_object_description = "Originally a literal value. Converted to object by Pioneer."

        for current_network_literal in network_address_literals:
            # Split the string by the "_" to extract subnet and netmask.
            # Example output: ['NL', '10.10.10.10', '32']
            helper.logging.info(f"I am processing literal {current_network_literal}.")
            split_network_literal = current_network_literal.split('_')
            network_literal_subnet, network_literal_netmask = split_network_literal[1], split_network_literal[2]

            # Determine the network address type (Host or Network)
            network_address_type = 'Host' if network_literal_netmask == '32' else 'Network'

            # Create the object value string
            network_object_value = f"{network_literal_subnet}/{network_literal_netmask}"

            # Build the processed network literal entry
            processed_network_literal_entry = {
                "network_address_name": current_network_literal,
                "object_container_name": object_container_name,
                "network_address_value": network_object_value,
                "network_address_description": literal_object_description,
                "network_address_type": network_address_type,
                "overridable_object": False  # Literals cannot be overridden
            }

            helper.logging.info(f"Finished processing literal {current_network_literal}.")
            helper.logging.debug(f"Processed entry for this literal is: {processed_network_literal_entry}.")
            processed_network_literals_info.append(processed_network_literal_entry)

        helper.logging.debug(f"Finished processing all the netowrk literals. This is the formatted data: {processed_network_literals_info}.")
        return processed_network_literals_info
            
    def process_network_address_objects(self, network_address_objects_list, network_address_objects_info_dict):
        """
        Process network address objects.

        Args:
            network_address_objects_list (list): List of network address object names.
            network_address_objects_info_dict (dict): Dictionary containing information about network address objects.

        Returns:
            list: List of dictionaries containing processed network objects information.
        """
        helper.logging.debug(f"Called process_network_address_objects().")
        helper.logging.info("I am now processing the imported network objects. I am processing and formatting all the data retrieved from the policies.")
        
        if not network_address_objects_list:
            helper.logging.info("There are no network address objects to process.")
            return []

        processed_network_object_info = []
        object_container_name = "virtual_object_container"

        for network_address_object_name in network_address_objects_list:
            helper.logging.info(f"I am processing network object {network_address_object_name}.")
            # Look up the object in the dictionary containing the network address object information
            matching_address_object_entry = network_address_objects_info_dict.get(network_address_object_name, {})
            helper.logging.debug(f"Found matching entry for object {network_address_object_name}. Entry data: {matching_address_object_entry}.")

            # Extract all the required data from the entry
            network_address_value = matching_address_object_entry.get('value', '')
            network_address_object_description = matching_address_object_entry.get('description', None)
            network_address_object_type = matching_address_object_entry.get('type', '')
            is_overridable_object = matching_address_object_entry.get('overridable', False)

            # Build the processed network object entry
            processed_network_object_entry = {
                "network_address_name": network_address_object_name,
                "object_container_name": object_container_name,
                "network_address_value": network_address_value,
                "network_address_description": network_address_object_description,
                "network_address_type": network_address_object_type,
                "overridable_object": is_overridable_object
            }

            helper.logging.info(f"Finished processing object {network_address_object_name}.")
            helper.logging.debug(f"Processed entry for this object is: {processed_network_object_entry}.")
            processed_network_object_info.append(processed_network_object_entry)

        helper.logging.debug(f"Finished processing all the network objects. This is the formatted data: {processed_network_object_info}.")
        return processed_network_object_info

    # be aware, you need to process:
        # objects that are part of a group. those objects could not be on the policy, therefore they are not in the DB yet
        # groups that are part of object groups. some recursive shit needs to be done here
    def process_network_address_group_objects(self, network_address_group_objects_list, network_address_group_objects_info_dict):
        """
        Process network address group objects.

        Args:
            network_address_group_objects_list (list): List of network address group object names.
            network_address_group_objects_info_dict (dict): Dictionary containing information about network address group objects.

        Returns:
            tuple: A tuple containing processed network group objects information, object members list,
                   and literal group members list.
        """
        helper.logging.debug(f"Called process_network_address_group_objects().")
        helper.logging.info("I am now processing the imported network group objects. I am processing and formatting all the data retrieved from the policies.")
        if not network_address_group_objects_list:
            helper.logging.info("There are no network address group objects to process.")
            return [], [], []

        processed_network_address_group_object_info = []
        object_container_name = "virtual_object_container"

        # Lists to store names of all object members, group members, and literal members
        object_member_list, group_object_member_list, literal_group_member_list = [], [], []

        for network_address_group_object_name in network_address_group_objects_list:
            helper.logging.info(f"I am now processing the following group object: {network_address_group_object_name}.")
            matching_address_group_object = network_address_group_objects_info_dict.get(network_address_group_object_name, {})
            helper.logging.debug(f"Found matching entry for object group: {network_address_group_object_name}. Entry data: {matching_address_group_object}.")
            network_address_group_member_names = []
            network_address_group_members = matching_address_group_object.get('objects', [])
            helper.logging.info(f"I am now processing group object members.")
            helper.logging.debug(f"Found the following members: {network_address_group_members}.")
            network_address_group_description = matching_address_group_object.get('description', None)
            is_overridable_object = matching_address_group_object.get('overridable', False)

            for object_member in network_address_group_members:
                helper.logging.debug(f"I am now processing group object member: {object_member}.")
                if object_member['type'] == 'NetworkGroup':
                    # Add the group object to the list tracking NetworkGroup members
                    group_object_member_list.append(object_member['name'])
                    helper.logging.debug(f"{object_member['name']} is a network address group object member.")
                    
                    # Add the group object to the list tracking all the members
                    network_address_group_member_names.append(object_member['name'])
                else:
                    helper.logging.debug(f"{object_member['name']} is a network address object member.")
                    object_member_list.append(object_member['name'])
                    network_address_group_member_names.append(object_member['name'])

            literals = matching_address_group_object.get('literals', [])
            literal_objects_list = self.convert_network_literals_to_objects(literals)
            
            # extract the converted literals from the list and add them to the object
            for literal in literal_objects_list:
                helper.logging.debug(f"I am now processing group object literal member: {literal}.")
                if isinstance(literal, str) and literal is not None:
                    network_address_group_member_names.append(literal)
                else:
                    # Handle the case where the literal is not a valid string
                    helper.logging.error(f"I have found an invalid literal: {literal}. Check it manually.")

            literal_group_member_list.extend(literal_objects_list)


            processed_network_address_group_object_entry = {
                "network_address_group_name": network_address_group_object_name,
                "object_container_name": object_container_name,
                "network_address_group_members": network_address_group_member_names,
                "network_address_group_description": network_address_group_description,
                "overridable_object": is_overridable_object
            }

            helper.logging.info(f"Finished processing network address group object {network_address_group_object_name}.")
            helper.logging.debug(f"Processed entry for this object is: {processed_network_address_group_object_entry}.")

            processed_network_address_group_object_info.append(processed_network_address_group_object_entry)

        nested_group_objects, nested_objects, nested_literals = self.process_network_address_group_objects(group_object_member_list, network_address_group_objects_info_dict)

        object_member_list.extend(nested_objects)
        literal_group_member_list.extend(nested_literals)
        processed_network_address_group_object_info.extend(nested_group_objects)
        
        helper.logging.debug(f"Finished processing network address group object members. This is the formatted data of all the group objects {processed_network_address_group_object_info}. Additionally, I have found the following lists - object members {object_member_list} and - literal members {literal_group_member_list}.")
        return processed_network_address_group_object_info, object_member_list, literal_group_member_list
    
    def process_port_literals(self):
        pass
    # TODO: should ICMP objects be processed here or somewhere else?
    def process_port_objects(self):
        pass

    def process_port_group_objects(self):
        pass

    def get_port_objects_info(self):
        helper.logging.debug("Called get_port_objects_info()")
        helper.logging.info("I am now processing the port objects data info. I am retrieving all objects from the database, processing them, and returning all the info about them.")
        # Retrieve all port object info from the database
        port_objects_db = self.get_db_objects('port_objects')
        return port_objects_db
        # Get the information of all port objects from FMC
        port_objects_info = self._api_connection.object.port.get()
        
        # Get the information of all port group objects from FMC
        port_group_objects_info = self._api_connection.object.portobjectgroup.get()

        # Retrieve the names of all port objects
        fmc_port_objects_list = [fmc_port_object['name'] for fmc_port_object in port_address_objects_info]

        # Retrieve the names of all port group objects
        fmc_port_group_objects_list = [fmc_port_group_object['name'] for fmc_port_group_object in port_address_group_objects_info]

        # Convert these to dictionaries for more efficient lookups
        port_address_group_objects_info = {entry['name']: entry for entry in port_address_group_objects_info}
        port_address_objects_info = {entry['name']: entry for entry in port_address_objects_info}

        return port_objects_db
########################################
    
    # This function returns Python network objects back to the caller.
    # for the objects stored in the database, it checks where they are exactly located on the Security Device
    # if "example" is a network address, it will stop processing and then it will return a network address object
    def return_network_objects(self):
        """
        Retrieve information about network objects.

        Returns:
            list: List of network objects.
        """
        helper.logging.debug("Called return_network_objects()")
        helper.logging.info("Processing network objects data info. Retrieving all objects from the database, processing them, and returning their info.")

        # Retrieve all network object info from the database
        network_objects_from_db = self.get_db_objects('network_objects')
        
        # Get the information of all network address objects, network group objects, geolocation objects, countries, and continents from FMC
        network_address_objects_info = self._sec_device_connection.object.networkaddress.get()
        network_group_objects_info = self._sec_device_connection.object.networkgroup.get()
        geolocation_objects_info = self._sec_device_connection.object.geolocation.get()
        countries_info = self._sec_device_connection.object.country.get()
        continents_info = self._sec_device_connection.object.continent.get()

        # Convert obtained data into dictionaries for efficient lookups
        network_address_objects_dict = {entry['name']: entry for entry in network_address_objects_info}
        network_group_objects_dict = {entry['name']: entry for entry in network_group_objects_info}
        geolocation_objects_dict = {entry['name']: entry for entry in geolocation_objects_info}
        countries_dict = {entry['id']: entry for entry in countries_info if 'id' in entry}
        continents_dict = {entry['name']: entry for entry in continents_info}

        network_objects_from_device_list = []

        for network_object_name in network_objects_from_db:
            if network_object_name.startswith(gvars.network_literal_prefix):
                network_objects_from_device_list.append(FMCNetworkLiteral(network_object_name))

            elif gvars.separator_character in network_object_name:
                country_id, country_name = network_object_name.split(gvars.separator_character)
                country_object_info = countries_dict.get(country_id)
                if country_object_info:
                    network_objects_from_device_list.append(FMCCountryObject(country_object_info))
            else:
                if network_object_name in network_address_objects_dict:
                    network_objects_from_device_list.append(FMCNetworkObject(network_address_objects_dict[network_object_name]))
                elif network_object_name in network_group_objects_dict:
                    network_objects_from_device_list.append(FMCNetworkGroupObject(network_group_objects_dict[network_object_name]))
                elif network_object_name in geolocation_objects_dict:
                    network_objects_from_device_list.append(FMCGeolocationObject(geolocation_objects_dict[network_object_name]))
                elif network_object_name in continents_dict:
                    network_objects_from_device_list.append(FMCContinentObject(continents_dict[network_object_name]))
                else:
                    helper.logging.error(f"{network_object_name} is an invalid object!")
                    
        return network_objects_from_device_list