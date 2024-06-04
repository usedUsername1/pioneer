from pkg.Policy import SecurityPolicy
import utils.helper as helper
import utils.gvars as gvars
from pkg.DeviceObject.FMCDeviceObject import FMCObject, FMCObjectWithLiterals
from pkg.Container import Container

special_policies_logger = helper.logging.getLogger('special_policies')
general_logger = helper.logging.getLogger('general')

class FMCSecurityPolicy(SecurityPolicy, FMCObjectWithLiterals):
    """
    Represents a security policy specific to the Firepower Management Center (FMC).
    """
    # duct tape solution :(
    # Class variables
    _VirtualObjectContainer = None
    _Database = None
    _initialized = False  # Initialization flag

    @classmethod
    def initialize_class_variables(cls, PolicyContainer):
        """
        Initialize class variables if they are not already initialized.
        """
        if not cls._initialized:
            security_device = PolicyContainer.get_security_device()
            cls._Database = security_device.get_database()
            cls._VirtualObjectContainer = Container(security_device, "", "virtual_object_container", None)
            cls._VirtualObjectContainer.set_uid(
                cls._Database.get_object_containers_table().get('uid', 'name', 'virtual_container')[0][0]
            )
            cls._initialized = True

    def __init__(self, PolicyContainer, policy_info) -> None:
        """
        Initialize an FMCSecurityPolicy instance.

        Parameters:
            policy_info_fmc (dict): Information about the security policy.
        """
        self._PolicyContainer = PolicyContainer

        # Initialize class variables if not already done
        FMCSecurityPolicy.initialize_class_variables(PolicyContainer)

        self._name = policy_info['name']
        self._container_index = policy_info['metadata']['ruleIndex']
        self._status = 'enabled' if policy_info.get('enabled', False) else 'disabled'
        self._category = policy_info['metadata']['category']
        self._source_zones = self.extract_security_zone_object_info(policy_info.get('sourceZones'))
        self._destination_zones = self.extract_security_zone_object_info(policy_info.get('destinationZones'))

        self._source_networks = self.extract_network_address_object_info(policy_info.get('sourceNetworks'), self._VirtualObjectContainer, self._Database)
        self._destination_networks = self.extract_network_address_object_info(policy_info.get('destinationNetworks'), self._VirtualObjectContainer, self._Database)

        self._source_ports = None # self.extract_port_object_info(policy_info.get('sourcePorts'))
        self._destination_ports = None # self.extract_port_object_info(policy_info.get('destinationPorts'))
        self._schedule_objects = None # self.extract_schedule_object_info(policy_info.get('timeRangeObjects'))
        self._users = None # self.extract_user_object_info(policy_info.get('users'))
        self._urls = None # self.extract_url_object_info(policy_info['urls'])
        self._policy_apps = None # self.extract_l7_app_object_info(policy_info['applications'])
        self._description = policy_info.get('description')
        self._comments = self.extract_comments(policy_info.get('commentHistoryList'))
        self._log_to_manager = policy_info.get('sendEventsToFMC', False)
        self._log_to_syslog = policy_info.get('enableSyslog', False)
        self._log_start = policy_info['logBegin']
        self._log_end = policy_info['logEnd']
        self._section = policy_info['metadata']['section']
        self._action = policy_info['action']

        super().__init__(
            self._PolicyContainer,
            policy_info,
            self._name,
            self._container_index,
            self._status,
            self._category,
            self._source_zones,
            self._destination_zones,
            self._source_networks,
            self._destination_networks,
            self._source_ports,
            self._destination_ports,
            self._schedule_objects,
            self._users,
            self._urls,
            self._policy_apps,
            self._description,
            self._comments,
            self._log_to_manager,
            self._log_to_syslog,
            self._log_start,
            self._log_end,
            self._section,
            self._action
        )
  
    def extract_security_zone_object_info(self, security_zone_object_info):
        """
        Extract security zone information from the provided data structure.

        This method extracts the names of security zones from the given data structure.

        Parameters:
            security_zone_object_info (dict): A dictionary containing information about security zone objects.

        Returns:
            list: A list of security zone names extracted from the provided data structure.
        """
        # Initialize an empty list to store the extracted security zone names
        extracted_security_zones = []

        # Iterate through each security zone entry in the provided data structure
        if security_zone_object_info is not None:
            for security_zone_entry in security_zone_object_info['objects']:
                # Extract the name of the security zone and append it to the list
                extracted_security_zones.append(security_zone_entry['name'])
        else:
            extracted_security_zones = None
        
        # Return the list of extracted security zone names
        return extracted_security_zones
    
    #TODO: prettify this
    def extract_network_address_object_info(self, network_object_info, VirtualObjectContainer, Database):
        extracted_network_objects = []

        if network_object_info is not None:
            network_objects = network_object_info.get('objects')
            if network_objects is not None:
                for network_object_entry in network_objects:
                    # Extract the name and type of the network object
                    network_object_name = network_object_entry['name']
                    network_object_type = network_object_entry['type']
                    # Append the network object name to the list
                    if network_object_type == 'Country' or network_object_type == 'Geolocation':
                        # If the network object is of type 'Country', prepend its ID before the name
                        PolicyRegion = FMCObjectWithLiterals.convert_policy_region_to_object(VirtualObjectContainer, network_object_entry)
                        PolicyRegion.save(Database)
                        extracted_network_objects.append(PolicyRegion.get_name())
                    extracted_network_objects.append(network_object_name)
            
            network_literals = network_object_info.get('literals')
            if network_literals is not None:
                for network_literal_entry in network_literals:
                    ConvertedLiteral = FMCObjectWithLiterals.convert_network_literal_to_object(VirtualObjectContainer, network_literal_entry)
                    ConvertedLiteral.save(Database)
                    extracted_network_objects.append(ConvertedLiteral.get_name())
        else:
            extracted_network_objects = None
        
        return extracted_network_objects
    
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
                special_policies_logger.info(f"URL object name: <{policy_url_object_name}>. URL type <{policy_url_object['type']}>")
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
                literal_url_name = gvars.url_literal_prefix + policy_url_literal_value
                special_policies_logger.info(f"URL literal: <{policy_url_literal_value}>.")
                policy_url_objects_list.append(literal_url_name)
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
                try:
                    category_reputation = policy_url_category['reputation']
                except KeyError:
                    general_logger.debug("No category reputation present for this URL category")
                    category_reputation = 'None'
                    
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

        This method extracts comments from the given data structure and returns a string containing user and comment content.

        Parameters:
            comment_info (list): Information about comments.

        Returns:
            str: A string containing user and comment content extracted from the provided data structure, separated by newlines.
        """
        # Check if comment_info is None
        if comment_info is None:
            processed_comments = None
        else:
            # Create a string with all comments, each separated by a newline
            processed_comments = "\n".join(
                f"User: <{comment_entry['user']['name']}> commented: <{comment_entry['comment']}>"
                for comment_entry in comment_info
            )

        # Return the combined string of processed comments
        return processed_comments
