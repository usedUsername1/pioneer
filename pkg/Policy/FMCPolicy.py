from pkg.Policy import SecurityPolicy
import utils.helper as helper
import utils.gvars as gvars
from pkg.DeviceObject.FMCDeviceObject import FMCObject

special_policies_logger = helper.logging.getLogger('special_policies')
special_policies_logger.info("INITIALIZED IN FMCPOLICY")
general_logger = helper.logging.getLogger('general')

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
        general_logger.debug("FMCSecurityPolicy::__init__()")
        super().__init__(policy_info_fmc)

    # Methods for setting various attributes of the security policy
    def set_name(self):
        """
        Set the name of the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_name()")
        name = self._policy_info['name']
        return super().set_name(name)

    def set_container_name(self):
        """
        Set the name of the policy container.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_container_name()")
        container_name = self._policy_info['metadata']['accessPolicy']['name']
        return super().set_container_name(container_name)

    def set_container_index(self):
        """
        Set the index of the policy container.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_container_index()")
        index = self._policy_info['metadata']['ruleIndex']
        return super().set_container_index(index)

    def set_status(self):
        """
        Set the status of the security policy (enabled or disabled).
        """
        general_logger.debug("Called FMCSecurityPolicy::set_status()")
        status = 'enabled' if self._policy_info.get('enabled', False) else 'disabled'
        return super().set_status(status)

    def set_category(self):
        """
        Set the category of the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_category()")
        category = self._policy_info['metadata']['category']
        return super().set_category(category)

    def set_source_zones(self):
        """
        Set the source zones for the security policy.

        Returns:
            list: List of source zones.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_source_zones()")
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
        general_logger.debug("Called FMCSecurityPolicy::set_destination_zones()")
        try:
            destination_zones = [self._policy_info['destinationZones']]
        except KeyError:
            destination_zones = ['any']
        return super().set_destination_zones(destination_zones)

    def set_source_networks(self):
        """
        Set the source networks for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_source_networks()")
        try:
            source_networks = [self._policy_info['sourceNetworks']]
        except KeyError:
            general_logger.info("It looks like there are no explicit source networks defined on this policy.")
            source_networks = ['any']
        return super().set_source_networks(source_networks)

    def set_destination_networks(self):
        """
        Set the destination networks for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_destination_networks()")
        try:
            destination_networks = [self._policy_info['destinationNetworks']]
        except KeyError:
            general_logger.info("It looks like there are no explicit destination networks defined on this policy.")
            destination_networks = ['any']
        return super().set_destination_networks(destination_networks)

    def set_source_ports(self):
        """
        Set the source ports for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_source_ports()")
        try:
            source_ports = [self._policy_info['sourcePorts']]
        except KeyError:
            general_logger.info("It looks like there are no explicit source ports defined on this policy.")
            source_ports = ['any']
        return super().set_source_ports(source_ports)

    def set_destination_ports(self):
        """
        Set the destination ports for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_destination_ports()")
        try:
            destination_ports = [self._policy_info['destinationPorts']]
        except KeyError:
            general_logger.info("It looks like there are no explicit destination ports defined on this policy.")
            destination_ports = ['any']
        return super().set_destination_ports(destination_ports)

    def set_schedule_objects(self):
        """
        Set the schedule objects for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_schedule_objects()")
        try:
            schedule_objects = [self._policy_info['timeRangeObjects']]
        except KeyError:
            general_logger.info("It looks like there are no explicit schedule objects defined on this policy.")
            schedule_objects = ['any']
        return super().set_schedule_objects(schedule_objects)

    def set_users(self):
        """
        Set the users for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_users()")
        try:
            users = [self._policy_info['users']]
        except KeyError:
            general_logger.info("It looks like there are no explicit users defined on this policy.")
            users = ['any']
        return super().set_users(users)

    def set_urls(self):
        """
        Set the URLs for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_urls()")
        try:
            urls = [self._policy_info['urls']]
        except KeyError:
            general_logger.info("It looks like there are no explicit URLs defined on this policy.")
            urls = ['any']
        return super().set_urls(urls)

    def set_policy_apps(self):
        """
        Set the applications for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_policy_apps()")
        try:
            policy_apps = [self._policy_info['applications']]
        except KeyError:
            general_logger.info("It looks like there are no explicit applications defined on this policy.")
            policy_apps = ['any']
        return super().set_policy_apps(policy_apps)

    def set_description(self):
        """
        Set the description for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_description()")
        try:
            description = self._policy_info['description']
        except KeyError:
            general_logger.info("It looks like there is no description defined on this policy.")
            description = None
        return super().set_description(description)

    def set_comments(self):
        """
        Set the comments for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_comments()")
        try:
            comments = [self._policy_info['commentHistoryList']]
        except KeyError:
            general_logger.info("It looks like there are no comments defined on this policy.")
            comments = None
        return super().set_comments(comments)

    def set_log_setting(self):
        """
        Set the log settings for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_log_setting()")
        try:
            log_settings = ['FMC'] if self._policy_info['sendEventsToFMC'] else []
            log_settings += ['Syslog'] if self._policy_info['enableSyslog'] else []
        except KeyError:
            general_logger.info("It looks like there are no log settings defined on this policy.")
            log_settings = None
        return super().set_log_setting(log_settings)

    def set_log_start(self):
        """
        Set the start logging for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_log_start()")
        log_start = self._policy_info['logBegin']
        return super().set_log_start(log_start)

    def set_log_end(self):
        """
        Set the end logging for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_log_end()")
        log_end = self._policy_info['logEnd']
        return super().set_log_end(log_end)

    def set_section(self):
        """
        Set the section for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_section()")
        section = self._policy_info['metadata']['section']
        return super().set_section(section)

    def set_action(self):
        """
        Set the action for the security policy.
        """
        general_logger.debug("Called FMCSecurityPolicy::set_action()")
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
        general_logger.debug(f"Called FMCSecurityPolicy::extract_policy_object_info().")
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
        general_logger.debug("Called FMCSecurityPolicy::extract_security_zone_object_info()")
        
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
        general_logger.debug("Called FMCSecurityPolicy::extract_network_address_object_info()")

        # Initialize an empty list to store the extracted network address object names
        extracted_member_network_objects = []

        # Extract information from proper network objects
        try:
            general_logger.info(f"Found network objects on this policy.")
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
            general_logger.info(f"It looks like there are no network objects on this policy.")

        # Extract information from network literals
        try:
            general_logger.info(f"Found network literals on this policy.")
            # Retrieve the list of network literals from the provided data structure
            network_literals = network_object_info['literals']
            # Log an informational message indicating the search for literals
            general_logger.info(f"I am looking for literals.")
            # Log debug information about the found literals
            general_logger.debug(f"Literals found {network_literals}.")
            # Convert network literals to network objects and add them to the extracted list
            extracted_member_network_objects += FMCObject.convert_network_literals_to_objects(network_literals)
        except KeyError:
            # If there are no network literals, log an informational message
            general_logger.info(f"It looks like there are no network literals on this policy.")

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
        general_logger.debug("Called FMCSecurityPolicy::extract_port_object_info()")

        # Initialize an empty list to store the extracted port object names
        port_objects_list = []

        # Extract information from proper port objects
        try:
            general_logger.info(f"Found port objects on this policy.")
            # Retrieve the list of port objects from the provided data structure
            port_object_info_objects = port_object_info['objects']
            
            # Iterate through each port object entry
            for port_object_entry in port_object_info_objects:
                # Extract the name of the port object and append it to the list
                port_object_name = port_object_entry['name']
                port_objects_list.append(port_object_name)
        except KeyError:
            # If there are no port objects, log an informational message
            general_logger.info(f"It looks like there are no port objects on this policy.")
        
        # Extract information from port literals
        try:
            general_logger.info(f"Found port literals on this policy.")
            # Log an informational message indicating the search for port literals
            general_logger.info(f"I am looking for port literals...")
            # Retrieve the list of port literals from the provided data structure
            port_literals = port_object_info['literals']
            # Log an informational message indicating the found port literals
            general_logger.info(f"I have found literals.")
            # Log debug information about the found port literals
            general_logger.info(f"Port literals found: {port_literals}.")
            # Process each port literal using the convert_port_literals_to_objects function
            port_objects_list += FMCObject.convert_port_literals_to_objects(port_literals)
        except KeyError:
            # If there are no port literals, log an informational message
            general_logger.info(f"It looks like there are no port literals on this policy.")
        
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
        general_logger.debug("Called FMCSecurityPolicy::extract_user_object_info()")
        general_logger.info(f"Found users on this policy.")
        # Initialize an empty list to store the processed user object entries
        extracted_user_objects = []

        # Iterate through each user object entry in the provided data structure
        for user_object_entry in user_object_info['objects']:
            # Extract the name of the user object
            user_object_name = user_object_entry['name']
            special_policies_logger.info(f"User object name: <{user_object_name}>, user object type: <{user_object_entry['type']}>")
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
        general_logger.debug("Called FMCSecurityPolicy::extract_schedule_object_info()")
        
        general_logger.info(f"Found schedule objects on this policy.")
        # Initialize an empty list to store the extracted schedule object names
        extracted_schedule_objects = []
        
        # Iterate through each schedule object entry in the provided data structure
        for schedule_object_entry in schedule_object_info:
            # Extract the name of the schedule object and append it to the list
            schedule_object_name = schedule_object_entry['name']
            special_policies_logger.info(f"Schedule object name: <{schedule_object_name}>.")
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
        general_logger.debug("Called FMCSecurityPolicy::extract_url_object_info()")
        
        # Initialize an empty list to store the extracted URL objects
        policy_url_objects_list = []

        # Extract URL objects
        try:
            general_logger.info(f"Found URL objects on this policy.")
            # Retrieve the list of URL objects from the provided data structure
            policy_url_objects = url_object_info['objects']
            # Iterate through each URL object entry
            for policy_url_object in policy_url_objects:
                # Extract the name of the URL object and append it to the list
                policy_url_object_name = policy_url_object['name']
                special_policies_logger.info(f"URL object name: <{policy_url_object_name}>.")
                policy_url_objects_list.append(policy_url_object_name)
        except KeyError:
            # If there are no URL objects, log an informational message
            general_logger.info("It looks like there are no URL objects on this policy.")

        # Extract URL literals
        try:
            general_logger.info(f"Found URL literals on this policy.")
            # Retrieve the list of URL literals from the provided data structure
            policy_url_literals = url_object_info['literals']
            # Iterate through each URL literal entry
            for policy_url_literal in policy_url_literals:
                # Extract the URL literal value and append it to the list
                policy_url_literal_value = policy_url_literal['url']
                special_policies_logger.info(f"URL literal: <{policy_url_literal_value}>.")
                policy_url_objects_list.append(policy_url_literal_value)
        except KeyError:
            # If there are no URL literals, log an informational message
            general_logger.info("It looks like there are no URL literals on this policy.")

        # Extract URL categories with reputation
        try:
            general_logger.info(f"Found URL categories with reputation on this policy.")
            # Retrieve the list of URL categories with reputation from the provided data structure
            policy_url_categories = url_object_info['urlCategoriesWithReputation']
            # Iterate through each URL category entry
            for policy_url_category in policy_url_categories:
                # Extract the category name and reputation, then construct a formatted name and append it to the list
                category_name = policy_url_category['category']['name']
                category_reputation = policy_url_category['reputation']
                special_policies_logger.info(f"URL category name: <{category_name}>, with reputation <{category_reputation}>.")
                category_name = f"URL_CATEGORY{gvars.separator_character}{category_name}{gvars.separator_character}{category_reputation}"
                policy_url_objects_list.append(category_name)
        except KeyError:
            # If there are no URL categories with reputation, log an informational message
            general_logger.info("It looks like there are no URL categories on this policy.")

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
        general_logger.debug("Called FMCSecurityPolicy::extract_l7_app_object_info()")
        
        # Extract regular Layer 7 applications
        try:
            general_logger.info(f"Found L7 applications on this policy.")
            # Retrieve the list of Layer 7 applications from the provided data structure
            policy_l7_apps = l7_app_object_info['applications']
            # Iterate through each Layer 7 application entry
            for policy_l7_app in policy_l7_apps:
                special_policies_logger.info(f"L7 application name: <{policy_l7_app['name']}>.")
                # Construct the name of the Layer 7 application and append it to the list
                policy_l7_name = 'APP' + gvars.separator_character + policy_l7_app['name']
                policy_l7_apps_list.append(policy_l7_name)
        except KeyError:
            # If there are no Layer 7 applications, log an informational message
            general_logger.info("It looks like there are no Layer 7 apps on this policy.")

        # Extract Layer 7 application filters
        try:
            general_logger.info(f"Found L7 application filters on this policy.")
            # Retrieve the list of Layer 7 application filters from the provided data structure
            policy_l7_app_filters = l7_app_object_info['applicationFilters']
            # Iterate through each Layer 7 application filter entry
            for policy_l7_app_filter in policy_l7_app_filters:
                special_policies_logger.info(f"L7 application filter name: <{policy_l7_app_filter['name']}>.")
                # Construct the name of the Layer 7 application filter and append it to the list
                policy_l7_app_filter_name = 'APP_FILTER' + gvars.separator_character + policy_l7_app_filter['name']
                policy_l7_apps_list.append(policy_l7_app_filter_name)
        except KeyError:
            # If there are no Layer 7 application filters, log an informational message
            general_logger.info("It looks like there are no Layer 7 application filters on this policy.")

        # Extract inline Layer 7 application filters
        try:
            general_logger.info(f"Found L7 inline application filters on this policy.")
            # Retrieve the list of inline Layer 7 application filters from the provided data structure
            policy_inline_l7_app_filters = l7_app_object_info['inlineApplicationFilters']
            # Iterate through each entry in the list of inline Layer 7 application filters
            for filter_dict in policy_inline_l7_app_filters:
                for key, elements in filter_dict.items():
                    if isinstance(elements, list):
                        # Iterate through each element in the inline Layer 7 application filter entry
                        for element in elements:
                            # Construct the name of the inline Layer 7 application filter and append it to the list
                            special_policies_logger.info(f"L7 inline application filter: <{key}>, name: <{element['name']}>.")
                            filter_name = f"inlineApplicationFilters{gvars.separator_character}{key}{gvars.separator_character}{element['name']}"
                            policy_l7_apps_list.append(filter_name)
        except KeyError:
            # If there are no inline Layer 7 application filters, log an informational message
            general_logger.info("It looks like there are no Inline Layer 7 application filters on this policy.")

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
        general_logger.debug("Called FMCSecurityPolicu::extract_comments()")
        general_logger.info(f"Found comments on this policy.")
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
        general_logger.debug(f"Finished processing comments. This is the list: {processed_comment_list}.")
        
        # Return the list of processed comments
        return processed_comment_list
