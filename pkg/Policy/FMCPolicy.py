from pkg.Policy import SecurityPolicy
import utils.helper as helper
import utils.gvars as gvars
from pkg.DeviceObject.FMCDeviceObject import FMCObjectWithLiterals, FMCPolicyUserObject, FMCURLCategoryObject, FMCL7AppObject, FMCL7AppFilterObject, FMCL7AppGroupObject
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
        self._policy_info = policy_info
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

        self._source_ports = self.extract_port_object_info(policy_info.get('sourcePorts'), self._VirtualObjectContainer, self._Database)
        self._destination_ports = self.extract_port_object_info(policy_info.get('destinationPorts'), self._VirtualObjectContainer, self._Database)

        self._schedule_objects = self.extract_schedule_object_info(policy_info.get('timeRangeObjects'))
        self._users = self.extract_user_object_info(policy_info.get('users'), self._VirtualObjectContainer, self._Database)

        self._urls = self.extract_url_object_info(policy_info.get('urls'), self._VirtualObjectContainer, self._Database)
        self._policy_apps = self.extract_l7_app_object_info(policy_info.get('applications'), self._VirtualObjectContainer, self._Database)
        
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
    
    def extract_network_address_object_info(self, network_object_info, VirtualObjectContainer, Database):
        # Initialize an empty list to store extracted network objects
        extracted_network_objects = []

        # If no network object information is provided, return None
        if network_object_info is None:
            return None

        # Process network objects
        network_objects = network_object_info.get('objects', [])
        for network_object_entry in network_objects:
            # Extract the name and type of the network object
            network_object_name = network_object_entry['name']
            network_object_type = network_object_entry['type']
            
            # If the network object is of type 'Country' or 'Geolocation'
            if network_object_type in {'Country', 'Geolocation'}:
                # Convert the policy region to an object and save it
                PolicyRegion = FMCObjectWithLiterals.convert_policy_region_to_object(VirtualObjectContainer, network_object_entry)
                PolicyRegion.save(Database)
                # Append the name of the PolicyRegion to the list
                extracted_network_objects.append(PolicyRegion.get_name())
            
            # Append the name of the network object to the list
            extracted_network_objects.append(network_object_name)

        # Process network literals
        network_literals = network_object_info.get('literals', [])
        for network_literal_entry in network_literals:
            # Convert the network literal to an object and save it
            ConvertedLiteral = FMCObjectWithLiterals.convert_network_literal_to_object(VirtualObjectContainer, network_literal_entry)
            ConvertedLiteral.save(Database)
            # Append the name of the ConvertedLiteral to the list
            extracted_network_objects.append(ConvertedLiteral.get_name())

        # Return the list of extracted network objects
        return extracted_network_objects
    
    def extract_port_object_info(self, port_object_info, VirtualObjectContainer, Database):
        """
        Extract port object information from the provided data structure.

        This method extracts the names of port objects from the given data structure.

        Parameters:
            port_object_info (dict): Information about port objects.

        Returns:
            list: A list of port object names extracted from the provided data structure.
        """
        # Initialize an empty list to store the extracted port object names
        extracted_port_objects = []

        # If no port object information is provided, return None
        if port_object_info is None:
            return None

        # Process port objects
        port_objects = port_object_info.get('objects', [])
        for port_object_entry in port_objects:
            # Extract the name of the port object and append it to the list
            port_object_name = port_object_entry['name']
            extracted_port_objects.append(port_object_name)

        # Process port literals
        port_literals = port_object_info.get('literals', [])
        for port_literal_entry in port_literals:
            # Convert the port literal to an object
            ConvertedLiteral = FMCObjectWithLiterals.convert_port_literals_to_objects(VirtualObjectContainer, port_literal_entry, self._policy_info)

            # Save the literal object
            ConvertedLiteral.save(Database)
            # Append the name of the literal to the list
            extracted_port_objects.append(ConvertedLiteral.get_name())

        # Return the list of extracted port objects
        return extracted_port_objects

    def extract_user_object_info(self, user_object_info, VirtualObjectContainer, Database):
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
        if user_object_info is not None:
            for user_object_entry in user_object_info['objects']:
                # Extract the name of the user object and ensure all required keys exist
                if 'name' in user_object_entry and 'realm' in user_object_entry and 'name' in user_object_entry['realm']:
                    user_object_name = user_object_entry['name']
                    special_policies_logger.info(f"User object name: <{user_object_name}>, user object type: <{user_object_entry['type']}>")
                    # Construct the processed user object entry containing user type and name
                    user_object_processed_entry = user_object_entry['realm']['name'] + '\\' + user_object_name
                    object_info = {'name': user_object_processed_entry}
                    # Create the object
                    UserObject = FMCPolicyUserObject(VirtualObjectContainer, object_info)
                    UserObject.save(Database)
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
        if schedule_object_info is not None:
            for schedule_object_entry in schedule_object_info:
                # Extract the name of the schedule object and append it to the list
                schedule_object_name = schedule_object_entry['name']
                special_policies_logger.info(f"Schedule object name: <{schedule_object_name}>.")
                extracted_schedule_objects.append(schedule_object_name)
        
        # Return the list of extracted schedule object names
        return extracted_schedule_objects

    # there are three cases which need to be processed here. the url can be an object, a literal, or a category with reputation
    def extract_url_object_info(self, url_object_info, VirtualObjectContainer, Database):
        """
        Extract URL object information from the provided data structure.

        This method extracts information about URL objects, literals, and categories from the given data structure.

        Parameters:
            url_object_info (dict): Information about URL objects.

        Returns:
            list: A list of URL objects, including objects, literals, and categories, extracted from the provided data structure.
        """
        # Initialize an empty list to store the extracted URL objects
        extracted_url_objects = []

        # If no URL object information is provided, return None
        if url_object_info is None:
            return None

        # Extract URL objects
        url_objects = url_object_info.get('objects', [])
        for url_object_entry in url_objects:
            url_object_name = url_object_entry['name']
            special_policies_logger.info(f"URL object name: <{url_object_name}>. URL type <{url_object_entry['type']}>")
            extracted_url_objects.append(url_object_name)
            
        # Extract URL literals and create objects with it
        url_literals = url_object_info.get('literals', [])
        for url_literal_entry in url_literals:
            # Convert the URL literal to an object and save it
            ConvertedLiteral = FMCObjectWithLiterals.convert_url_literal_to_object(VirtualObjectContainer, url_literal_entry)
            ConvertedLiteral.save(Database)
            # Append the name of the ConvertedLiteral to the list
            extracted_url_objects.append(ConvertedLiteral.get_name())

        url_categories = url_object_info.get('urlCategoriesWithReputation', [])
        for url_category_entry in url_categories:
            category_name = url_category_entry['category']['name']
            category_reputation = url_category_entry.get('reputation', None)
            special_policies_logger.info(f"URL category name: <{category_name}>, with reputation <{category_reputation}>.")
            object_info = {'name':category_name, 'reputation': category_reputation}
            ConvertedURLCategory = FMCURLCategoryObject(VirtualObjectContainer, object_info)
            ConvertedURLCategory.save(Database)
            extracted_url_objects.append(category_name)

        # Return the list of extracted URL objects
        return extracted_url_objects
    
    def extract_l7_app_object_info(self, l7_app_object_info, VirtualObjectContainer, Database):
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

        # If no Layer 7 application object information is provided, return None
        if l7_app_object_info is None:
            return None

        # Extract regular Layer 7 applications
        general_logger.info(f"Found L7 applications on this policy.")
        policy_l7_apps = l7_app_object_info.get('applications', [])
        for policy_l7_app in policy_l7_apps:
            special_policies_logger.info(f"L7 application name: <{policy_l7_app['name']}>.")
            # Convert this to an FMCL7AppObject
            object_info = {'name':policy_l7_app['name']}
            ConvertedApp = FMCL7AppObject(VirtualObjectContainer, object_info)
            ConvertedApp.save(Database)
            policy_l7_apps_list.append(ConvertedApp.get_name())

        # Extract Layer 7 application filters
        general_logger.info(f"Found L7 application filters on this policy.")
        policy_l7_app_filters = l7_app_object_info.get('applicationFilters', [])
        for policy_l7_app_filter in policy_l7_app_filters:
            special_policies_logger.info(f"L7 application filter name: <{policy_l7_app_filter['name']}>.")
            # Convert this to FMCL7AppGroupObject
            object_info = {'name':policy_l7_app_filter['name']}
            ConvertedAppFilter = FMCL7AppGroupObject(VirtualObjectContainer, object_info)
            ConvertedAppFilter.save(Database)
            policy_l7_apps_list.append(ConvertedAppFilter.get_name())

        # Extract inline Layer 7 application filters
        general_logger.info(f"Found L7 inline application filters on this policy.")
        policy_inline_l7_app_filters = l7_app_object_info.get('inlineApplicationFilters', [])
        for filter_dict in policy_inline_l7_app_filters:
            for key, elements in filter_dict.items():
                if isinstance(elements, list):
                    for element in elements:
                        special_policies_logger.info(f"L7 inline application filter: <{key}>, name: <{element['name']}>.")
                        filter_name = f"inlineApplicationFilters{gvars.separator_character}{key}{gvars.separator_character}{element['name']}"
                        policy_l7_apps_list.append(filter_name)
                        # Convert this to FMCL7AppFilterObject
                        object_info = {'name':element['name'], 'type':key}
                        ConvertedInlineFilter = FMCL7AppFilterObject(VirtualObjectContainer, object_info)
                        ConvertedInlineFilter.save(Database)
                        policy_l7_apps_list.append(ConvertedInlineFilter.get_name())

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
