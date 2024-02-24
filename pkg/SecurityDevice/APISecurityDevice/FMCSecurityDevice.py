# interbang: ‽
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

#TODO: define all the necessary setters here and set the values accordingly
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

# since a geolocation object is made out both of continents and countries, wouldn't creatin objects with the data be easier?
class FMCGeolocationObject(GeolocationObject):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)
    
    def set_name(self, value):
        name = self._object_info['name']
        return super().set_name(name)
    
    # Geolocation objects don't have a description
    def set_description(self, value):
        value = None
        return super().set_description(value)
    
    def set_continents(self, continents):
        try:
            continents = self._object_info['continents']
        except KeyError:
            continents = None        
        return super().set_continents(continents)
    
    def set_countries(self, countries):
        try:
            countries = self._object_info['countries']
        except KeyError:
            countries = None    
        return super().set_countries(countries)
    
    # thhis function will work as long as continents different from None
    def extract_continents_info(self):
        continent_names = []
        continent_countries_names = []
        continent_countries_alpha2_codes = []
        continent_countries_alpha3_codes = []
        continent_countries_numeric_codes = []

        continent_countries = []
        if self._continents is None:
            return None
        
        # loop through the continents, extract the continent info and create continent objects with it
        for continent_info in self._continents:
            continent_object = FMCContinentObject(continent_info)
            
            # set the attributes of the continent object
            continent_object.set_name()
            continent_object.set_description()
            continent_object.set_continents()
            continent_object.set_countries()
            
            continent_country_objects = continent_object.get_countries()
            for country_object in continent_country_objects:
                # for every country object, extract the whatever codes names from it and append it to the list
                pass

            # append the countries of the
            continent_countries.append(continent_object)


# since a continent is made out of multiple countries, wouldn't it be easier to set country objects to it, and then use the setters and getters for countries?
class FMCContinentObject(FMCGeolocationObject):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)

    def set_name(self, name):
        name = self._object_info['name']
        return super().set_name(name)
    
    def set_continents(self, continent_name):
        continent_name = self._object_info['name']
        return super().set_continents(continent_name)
    
    def set_countries(self, countries):
        countries = self._object_info['countries']
        return super().set_countries(countries)

    def extract_countries_info(self):
        pass

# be aware, objects_info is a dict with the key being the ID of the country
class FMCCountryObject(FMCGeolocationObject):
    def __init__(self, object_info) -> None:
        super().__init__(object_info)

    # TODO: is setting the name like this really going to work?
    def set_name(self, name):
        name = self._object_info['name']
        return super().set_name(name)
    
    # A country object can't have continent members
    def set_continents(self, value):
        value = None
        return super().set_continents(value)
    
    def set_countries(self, name):
        name = self._object_info['name']
        return super().set_countries(name)
    
    def set_country_alpha2_codes(self, alpha2_code):
        alpha2_code = self._object_info['iso2']
        return super().set_country_alpha2_codes(alpha2_code)
    
    def set_country_alpha3_codes(self, alpha3_code):
        alpha3_code = self._object_info['iso3']
        return super().set_country_alpha3_codes(alpha3_code)
    
    def set_country_numeric_codes(self, numeric_code):
        numeric_code = self._object_info['id']
        return super().set_country_numeric_codes(numeric_code)


class FMCDeviceConnection(APISecurityDeviceConnection):
    def __init__(self, api_username, api_secret, api_hostname, api_port, domain):
        super().__init__(api_username, api_secret, api_hostname, api_port)
        self._domain = domain
        self._device_connection = self.return_security_device_conn_object()  # Initialize _device_connection with FMC object
        helper.logging.debug(f"Called FMCDeviceConnection __init__ with parameters: username {api_username}, hostname {api_hostname}, port {api_port}, domain {domain}.")

    def connect_to_security_device(self):
        # Implement connection to FMC specific to FMCDeviceConnection
        fmc_conn = fireREST.FMC(hostname=self._api_hostname, username=self._api_username, password=self._api_secret, domain=self._domain, protocol=self._api_port, timeout=30)
        return fmc_conn
        
class FMCPolicyContainer(SecurityPolicyContainer):
    def __init__(self, container_info) -> None:
        super().__init__(container_info)
    
    def get_parent_name(self):
        try:
            return self._container_info['metadata']['parentPolicy']['name']
        except KeyError:
            return None
        
    def is_child_container(self):
        if self._container_info['metadata']['inherit'] == True:
            return True
        else:
            return False
        
    def get_name(self):
        return self._container_info['name']

class FMCObjectContainer(ObjectPolicyContainer):
    def __init__(self, container_info) -> None:
        super().__init__(container_info)
    
    def is_child_container(self):
        return False

    def get_parent_name(self):
        None

# TODO; wouldn't it be simpler to process the data in the setter functions?
# actually no, because the problem is that you DON'T use objects for all the Policy elements
# like you use for Device objects. you don't 
# like, set the processed data as attribute and have it returned?    
class FMCSecurityPolicy(SecurityPolicy):
    def __init__(self, policy_info_fmc) -> None:
        super().__init__(policy_info_fmc)

    def set_name(self):
        name = self._policy_info['name']
        return super().set_name(name)
    
    def set_container_name(self):
        container_name = self._policy_info['metadata']['accessPolicy']['name']
        return super().set_container_name(container_name)

    def set_container_index(self):
        index = self._policy_info['metadata']['ruleIndex']
        return super().set_container_index(index)
    
    def set_status(self):
        status = 'enabled' if self._policy_info['enabled'] else 'disabled'
        return super().set_status(status)

    def set_category(self):
        category = self._policy_info['metadata']['category']
        return super().set_category(category)

    def set_source_zones(self):
        try:
            source_zones = [self._policy_info['sourceZones']]
        except KeyError:
            source_zones = ['any']
        return super().set_source_zones(source_zones)

    def set_destination_zones(self):
        try:
            destination_zones = [self._policy_info['destinationZones']]
        except KeyError:
            destination_zones = ['any']
        return super().set_destination_zones(destination_zones)

    def set_source_networks(self):
        try:
            source_networks = [self._policy_info['sourceNetworks']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit source networks defined on this policy.")
            source_networks = ['any']
        return super().set_source_networks(source_networks)

    def set_destination_networks(self):
        try:
            destination_networks = [self._policy_info['destinationNetworks']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit destination networks defined on this policy.")
            destination_networks = ['any']
        return super().set_destination_networks(destination_networks)

    def set_source_ports(self):
        try:
            source_ports = [self._policy_info['sourcePorts']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit source ports defined on this policy.")
            source_ports = ['any']
        return super().set_source_ports(source_ports)

    def set_destination_ports(self):
        try:
            destination_ports = [self._policy_info['destinationPorts']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit destination ports defined on this policy.")
            destination_ports = ['any']
        return super().set_destination_ports(destination_ports)

    def set_schedule_objects(self):
        try:
            schedule_objects = [self._policy_info['timeRangeObjects']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit schedule objects defined on this policy.")
            schedule_objects = ['any']
        return super().set_schedule_objects(schedule_objects)

    def set_users(self):
        try:
            users = [self._policy_info['users']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit users defined on this policy.")
            users = ['any']
        return super().set_users(users)

    def set_urls(self):
        try:
            urls = [self._policy_info['urls']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit URLs defined on this policy.")
            urls = ['any']
        return super().set_urls(urls)

    def set_policy_apps(self):
        try:
            policy_apps = [self._policy_info['applications']]
        except KeyError:
            helper.logging.info("It looks like there are no explicit applications defined on this policy.")
            policy_apps = ['any']
        return super().set_policy_apps(policy_apps)

    def set_description(self):
        try:
            description = self._policy_info['description']
        except KeyError:
            helper.logging.info("It looks like there is no description defined on this policy.")
            description = None
        return super().set_description(description)

    def set_comments(self):
        try:
            comments = [self._policy_info['commentHistoryList']]
        except KeyError:
            helper.logging.info("It looks like there are no comments defined on this policy.")
            comments = None
        return super().set_comments(comments)

    def set_log_setting(self):
        try:
            log_settings = ['FMC'] if self._policy_info['sendEventsToFMC'] else []
            log_settings += ['Syslog'] if self._policy_info['enableSyslog'] else []
        except KeyError:
            helper.logging.info("It looks like there are no log settings defined on this policy.")
            log_settings = None
        return super().set_log_setting(log_settings)

    def set_log_start(self):
        log_start = self._policy_info['logBegin']
        return super().set_log_start(log_start)

    def set_log_end(self):
        log_end = self._policy_info['logEnd']
        return super().set_log_end(log_end)

    def set_section(self):
        section = self._policy_info['metadata']['section']
        return super().set_section(section)

    def set_action(self):
        action = self._policy_info['action']
        return super().set_action(action)

    def extract_policy_object_info(self, raw_object, object_type):
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
        helper.logging.debug("Called extract_security_zone_object_info()")
        extracted_security_zones = []
        for security_zone_entry in security_zone_object_info['objects']:
            extracted_security_zones.append(security_zone_entry['name'])
        
        return extracted_security_zones
        
    def extract_network_address_object_info(self, network_object_info):
        helper.logging.debug("Called extract_network_address_object_info()")
        # network_object object could be a proper object or a network literal
        extracted_member_network_objects = []
        try:
            # log that you found objects
            network_object_info_objects = network_object_info['objects']

            # loop through all the found member objects, extract the info and add it to the list that will be returned to the caller
            for network_object_entry in network_object_info_objects:
                network_object_name = network_object_entry['name']
                network_object_type = network_object_entry['type']
                if network_object_type == 'Country':
                    network_object_name = network_object_entry['id'] + gvars.separator_character + network_object_name
                extracted_member_network_objects.append(network_object_name)
        except KeyError:
            helper.logging.info(f"It looks like there are no network objects on this policy.")

        try:
            helper.logging.info(f"I am looking for literals.")
            # log info that you found literals
            network_literals = network_object_info['literals']
            helper.logging.debug(f"Literals found {network_literals}.")
            extracted_member_network_objects += self.convert_network_literals_to_objects(network_literals)
        except KeyError:
            helper.logging.info(f"It looks like there are no network literals on this policy.")
        
        return extracted_member_network_objects
    
    def extract_port_object_info(self, port_object_info):
        port_objects_list = []
        try:
            port_object_info_objects = port_object_info['objects']
            # Process each port object
            for port_object_entry in port_object_info_objects:
                port_object_name = port_object_entry['name']
                port_objects_list.append(port_object_name)
        except KeyError:
            helper.logging.info(f"It looks like there are no port objects on this policy.")
        
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
        helper.logging.debug("Called extract_user_object_info()")
        extracted_user_objects = []

        for user_object_entry in user_object_info['objects']:
            user_object_name = user_object_entry['name']
            user_object_processed_entry = user_object_entry['type'] + gvars.separator_character + user_object_name
            extracted_user_objects.append(user_object_processed_entry)
        
        return extracted_user_objects
    
    def extract_schedule_object_info(self, schedule_object_info):
        helper.logging.debug("Called extract_schedule_object_info()")
        extracted_schedule_objects = []
        for schedule_object_entry in schedule_object_info:
            schedule_object_name = schedule_object_entry['name']
            extracted_schedule_objects.append(schedule_object_name)
        
        return extracted_schedule_objects

    # there are three cases which need to be processed here. the url can be an object, a literal, or a category with reputation
    def extract_url_object_info(self, url_object_info):
        policy_url_objects_list = []
        try:
            policy_url_objects = url_object_info['objects']
            for policy_url_object in policy_url_objects:
                policy_url_object_name = policy_url_object['name']
                policy_url_objects_list.append(policy_url_object_name)

        except KeyError:
            helper.logging.info("It looks like there are no URL objects on this policy.")

        try:
            policy_url_literals = url_object_info['literals']
            for policy_url_literal in policy_url_literals:
                helper.logging.debug(f"Processing policy URL literal: {policy_url_literal}.")
                policy_url_literal_value = policy_url_literal['url']
                helper.logging.info(f"Processed policy URL literal: {policy_url_literal_value}.")
                policy_url_objects_list.append(policy_url_literal_value)

        except KeyError:
            helper.logging.info("It looks like there are no URL literals on this policy.")

        try:
            policy_url_categories = url_object_info['urlCategoriesWithReputation']
            for policy_url_category in policy_url_categories:
                helper.logging.debug(f"Processing policy URL category: {policy_url_category}.")
                category_name = policy_url_category['category']['name']

                category_reputation = policy_url_category['reputation']
                helper.logging.info(f"Processed policy URL category: {category_name}. It has a reputation of {category_reputation}")

                category_name = f"URL_CATEGORY{gvars.separator_character}{category_name}{gvars.separator_character}{category_reputation}"

                policy_url_objects_list.append(category_name)

        except KeyError:
            helper.logging.info("It looks like there are no URL categories on this policy.")

        return policy_url_objects_list
    
    def extract_l7_app_object_info(self, l7_app_object_info):
        policy_l7_apps_list = []

        try:
            policy_l7_apps = l7_app_object_info['applications']
            for policy_l7_app in policy_l7_apps:
                policy_l7_name = 'APP' + gvars.separator_character + policy_l7_app['name']
                policy_l7_apps_list.append(policy_l7_name)

        except KeyError:
            helper.logging.info("It looks like there are no L7 apps on this policy.")

        try:
            helper.logging.info("I am looking for L7 applications filters on this policy.")
            policy_l7_app_filters = l7_app_object_info['applicationFilters']
            helper.logging.debug(f"Found L7 app filters: {policy_l7_app_filters}")

            for policy_l7_app_filter in policy_l7_app_filters:
                helper.logging.debug(f"Processing policy L7 app filter: {policy_l7_app_filter}.")
                policy_l7_app_filter_name = 'APP_FILTER' + gvars.separator_character + policy_l7_app_filter['name']
                helper.logging.info(f"Processed policy L7 app filter: {policy_l7_app_filter_name}.")
                policy_l7_apps_list.append(policy_l7_app_filter_name)

        except KeyError:
            helper.logging.info("It looks like there are no L7 application filters on this policy.")

        try:
            # Access the Inline L7 application filters from the 'sec_policy' dictionary
            policy_inline_l7_app_filters = l7_app_object_info['inlineApplicationFilters']

            helper.logging.info(f"I have found L7 inline app filters on this policy.)")
            helper.logging.debug(f"Found L7 inline app filters on this policy: {policy_inline_l7_app_filters}")

            # Iterate over each dictionary in 'policy_inline_l7_app_filters' list.
            # I have no idea what the fuck me and chatGPT did here, but it works very fine!
            for index in range(len(policy_inline_l7_app_filters)):
                # Iterate over each key/category in the current Inline L7 application filter dictionary.
                for policy_inline_l7_app_filter_key, policy_inline_l7_app_filter_elements in policy_inline_l7_app_filters[index].items():
                    # Skip any non-list elements
                    if not isinstance(policy_inline_l7_app_filter_elements, list):
                        continue

                    # Create a list to store the names of filter elements in the current category
                    # TODO: modify this so that " " are not present
                    filter_element_names = [f"inlineApplicationFilters{gvars.separator_character}{policy_inline_l7_app_filter_key}{gvars.separator_character}{policy_inline_l7_app_filter_element['name']}" for policy_inline_l7_app_filter_element in policy_inline_l7_app_filter_elements]

                    # Append the list of filter element names to the 'policy_l7_apps_list'
                    policy_l7_apps_list.extend(filter_element_names)

        except KeyError:
            helper.logging.info("It looks like there are no Inline L7 application filters on this policy.")

        return policy_l7_apps_list

    def extract_comments(self, comment_info):
        helper.logging.debug("Called extract_comments()")
        processed_comment_list = []

        for comment_entry in comment_info:
            comment_user = comment_entry['user']['name']
            comment_content = comment_entry['comment']
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
    def __init__(self, name, sec_device_database, security_device_username, security_device_secret, security_device_hostname, security_device_port, domain):
        super().__init__(name, sec_device_database)
        helper.logging.debug(f"Called FMCSecurityDevice __init__()")
        self._sec_device_connection = FMCDeviceConnection(security_device_username, security_device_secret, security_device_hostname, security_device_port, domain).connect_to_security_device()

    def return_security_policy_container_object(self, container_name):
        acp_info = self._sec_device_connection.policy.accesspolicy.get(name=container_name)
        return FMCPolicyContainer(acp_info)
    
    # return a list with policy objects for the whole container
    def return_security_policy_object(self, container_name):
        security_policy_objects = []
        fmc_policy_info = self._sec_device_connection.policy.accesspolicy.accessrule.get(container_name=container_name)
        for fmc_policy_entry in fmc_policy_info:
            security_policy_objects.append(FMCSecurityPolicy(fmc_policy_entry))
        
        return security_policy_objects

    # there are no object containers per se in FMC, therefore, only dummy info will be returned
    def return_object_container_object(self, container_name):
        helper.logging.info("Called return_security_policy_container_object().")
        helper.logging.info(f"################## Importing configuration of the object policy containers. This is a FMC device, nothing to import, will return: virtual_object_container ##################")
        container_info = ''
        dummy_container = FMCObjectContainer(container_info)
        dummy_container.set_name("virtual_object_container")
        dummy_container.set_parent(None)
        return dummy_container

    def process_managed_device(self, managed_device):
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
        helper.logging.debug("Called function get_managed_devices_info().")
        """
        Retrieve information about managed devices.

        Returns:
            list: List of dictionaries containing information about managed devices.
        """
        helper.logging.info("################## GETTING MANAGED DEVICES INFO ##################")

        # Execute the request to retrieve information about the devices
        managed_devices = self._sec_device_connection.device.devicerecord.get()
        helper.logging.debug(f"Executed API call to the FMC device, got the following info {managed_devices}.")
        return managed_devices

    def get_security_policies_info(self, policy_container_name):
        helper.logging.debug("Called function get_security_policies_info().")
        """
        Retrieve information about managed devices.

        Returns:
            list: List of dictionaries containing information about managed devices.
        """
        helper.logging.info("################## GETTING SECURITY POLICIES INFO ##################")

        # Execute the request to retrieve information about the devices
        security_policies_info = self._sec_device_connection.policy.accesspolicy.accessrule.get(container_name=policy_container_name)
        # helper.logging.debug(f"Executed API call to the FMC device, got the following info {security_policies_info}.")
        return security_policies_info
    
    def get_device_version(self):
        helper.logging.debug("Called function det_device_version()")
        """
        Retrieve the version of the device's server.

        Returns:
            str: Version of the device's server.
        """
        # Retrieve device system information to get the server version
        device_system_info = self._sec_device_connection.system.info.serverversion.get()
        helper.logging.debug(f"Executed API call to the FMC device, got the following info {device_system_info}.")
        device_version = device_system_info[0]['serverVersion']
        return device_version
    
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

    def process_geolocation_objects(self, geolocation_objects_list, geolocation_objects_info, continents_info, countries_info):
        helper.logging.debug(f"Called process_geolocation_objects().")
        helper.logging.info("I am now processing the imported geolocation objects. I am processing and formatting all the data retrieved from the policies.")
        
        if not geolocation_objects_list:
            helper.logging.info("There are no geolocation objects to process.")
            return []
        
        processed_geolocation_object_info = []
        object_container_name = "virtual_object_container"
        
        # loop through the geo-location objects and check:
        for geolocation_object_name in geolocation_objects_list:
            continent_member_names = []

            country_member_names = []
            country_member_numeric_codes = []
            country_member_alpha2_codes = []
            country_member_alpha3_codes = []

            helper.logging.info(f"I am processing geolocation object {geolocation_object_name}.")
            matching_geolocation_continent = continents_info.get(geolocation_object_name, {})
            matching_geolocation_object = geolocation_objects_info.get(geolocation_object_name, {})
            # look in the name of the object. if it contains the interbang character, then split it. use the ID to lookup in the dictionary with the list
            if gvars.separator_character in geolocation_object_name:
                helper.logging.info(f"Location object: {geolocation_object_name} is a country defined directly on the policy.")
                country_id, country_name = geolocation_object_name.split(gvars.separator_character)
                
                # get the info of the country by its ID
                matching_country = countries_info.get(country_id, {})
                helper.logging.debug(f"Found matching entry for object {geolocation_object_name}. Entry data: {matching_country}")

                # create the lists with the info about the country members
                country_member_names.append(country_name)
                country_member_numeric_codes.append(country_id)
                country_member_alpha2_codes.append(matching_country['iso2'])
                country_member_alpha3_codes.append(matching_country['iso3'])
                
            # look up in the dictionary containing the info about the continet objects and see if there is an entry found for the current geolocation object
            elif matching_geolocation_continent is not None and matching_geolocation_continent != {}:
                helper.logging.info(f"Location object: {geolocation_object_name} is a continent defined directly on the policy.")
                helper.logging.debug(f"Found matching entry for object {geolocation_object_name}. Entry data: {matching_geolocation_continent}.")
                # now loop through the countries of the continent and add them to the members list
                continent_member_names.append(geolocation_object_name)
                for continent_country in matching_geolocation_continent['countries']:
                    try:
                        country_member_names.append(continent_country['name'])
                    except KeyError:
                        helper.logging.error(f"There is a problem with the following continent country object: {continent_country}")
                        continue
                    country_member_numeric_codes.append(continent_country['id'])
                    country_member_alpha2_codes.append(continent_country['iso2'])
                    country_member_alpha3_codes.append(continent_country['iso3'])   
            
            # look up in the dictionary containing the info about the geolocation objects and see if there is an entry found for the current geolocation object
            elif matching_geolocation_object is not None and matching_geolocation_object != {}:
                helper.logging.info(f"Location object: {geolocation_object_name} is an actual object.")
                helper.logging.debug(f"Found matching entry for object {geolocation_object_name}. Entry data: {matching_geolocation_object}.")
                # go through the continents of the geolocation object
                if 'continents' in matching_geolocation_object:
                    for continent in matching_geolocation_object['continents']:
                        continent_member_names.append(continent['name'])
                        # and go through the countries of the continent, extract the data and add it to the lists tracking it
                        for country in continent['countries']:
                            country_member_names.append(country['name'])
                            country_member_numeric_codes.append(country['id'])
                            country_member_alpha2_codes.append(country['iso2'])
                            country_member_alpha3_codes.append(country['iso3'])     
                
                # check if there are countries on the
                if 'countries' in matching_geolocation_object:
                    for country in matching_geolocation_object['countries']:
                        country_member_names.append(country['name'])
                        country_member_numeric_codes.append(country['id'])
                        country_member_alpha2_codes.append(country['iso2'])
                        country_member_alpha3_codes.append(country['iso3'])
 
            else:
                helper.logging.error(f"Object: {geolocation_object_name} is of type unknown. I cannot import/process it.")
            # look up in the dictionary containing the info about the continet objects and see if there is an entry found for the current geolocation object

            # Build the processed network object entry
            processed_geolocation_object_entry = {
                "geolocation_object_name": geolocation_object_name,
                "object_container_name": object_container_name,
                "continent_member_names": continent_member_names,
                "country_member_names": country_member_names,
                "country_member_alpha2_codes": country_member_alpha2_codes,
                "country_member_alpha3_codes": country_member_alpha3_codes,
                "country_member_numeric_codes": country_member_numeric_codes,
            }
            helper.logging.info(f"Finished processing object {geolocation_object_name}.")
            helper.logging.debug(f"Processed entry for this object is: {processed_geolocation_object_entry}.")
            processed_geolocation_object_info.append(processed_geolocation_object_entry)
        
        return processed_geolocation_object_info
    
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

    # This function returns Python network objects back to the caller.
    # for the objects stored in the database, it checks where they are exactly located on the Security Device
    # if "example" is a network address, it will stop processing and then it will return a network address object
    def return_network_objects(self):
        helper.logging.debug("Called return_network_objects()")
        helper.logging.info("Processing network objects data info. Retrieving all objects from the database, processing them, and returning their info.")

        # Step 1: Retrieve all network object info from the database
        network_objects_from_db = self.get_db_objects('network_objects')
        
        # Step 2: Get the information of all network address objects, network group objects, geolocation objects, countries, and continents from FMC
        network_address_objects_info = self._api_connection.object.networkaddress.get()
        network_group_objects_info = self._api_connection.object.networkgroup.get()
        geolocation_objects_info = self._api_connection.object.geolocation.get()
        countries_info = self._api_connection.object.country.get()
        continents_info = self._api_connection.object.continent.get()

        # Step 3: Convert obtained data into dictionaries for efficient lookups
        # TODO: try and excepts here, in case conversion might fail
        network_address_objects_dict = {entry['name']: entry for entry in network_address_objects_info}
        network_group_objects_dict = {entry['name']: entry for entry in network_group_objects_info}
        geolocation_objects_dict = {entry['name']: entry for entry in geolocation_objects_info}
        countries_dict = {entry['id']: entry for entry in countries_info if 'id' in entry}
        continents_dict = {entry['name']: entry for entry in continents_info}

        network_objects_from_device_list = []

        for network_object_name in network_objects_from_db:
            if network_object_name.startswith(gvars.network_literal_prefix):
                network_objects_from_device_list.append(FMCNetworkLiteral(network_object_name))
            #TODO: modify country lookup
            elif gvars.separator_character in network_object_name:
                country_name, _ = network_object_name.split(gvars.separator_character)
                country_object_info = countries_dict.get(country_name)
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
                    helper.logging.error(f"{network_object_name} in an invalid object!")

                    
        return network_objects_from_device_list