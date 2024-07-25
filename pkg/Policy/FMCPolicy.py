from pkg.Policy import SecurityPolicy
import utils.helper as helper
import utils.gvars as gvars
from pkg.DeviceObject.FMCDeviceObject import FMCObjectWithLiterals, FMCPolicyUserObject, FMCURLCategoryObject, FMCL7AppObject, FMCL7AppFilterObject, FMCL7AppGroupObject
from pkg.Container import Container

special_policies_logger = helper.logging.getLogger(gvars.special_policies_logger)
general_logger = helper.logging.getLogger(gvars.general_logger)

class FMCSecurityPolicy(SecurityPolicy, FMCObjectWithLiterals):
    """
    Represents a security policy specific to the Firepower Management Center (FMC).
    """

    _virtual_object_container = None
    _db = None
    _initialized = False  # Initialization flag

    @classmethod
    def initialize_class_variables(cls, policy_container):
        """
        Initialize class variables if they are not already initialized.

        Args:
            policy_container (PolicyContainer): The policy container to initialize from.
        """
        if not cls._initialized:
            security_device = policy_container.security_device
            cls._db = security_device.db
            cls._virtual_object_container = Container(security_device, gvars.virtual_container_name, None)
            cls._virtual_object_container.uid = cls._db.object_containers_table.get('uid', 'name', gvars.virtual_container_name)[0][0]
            cls._initialized = True

    def __init__(self, policy_container, policy_info) -> None:
        """
        Initialize an FMCSecurityPolicy instance.

        Args:
            policy_container (PolicyContainer): The policy container holding the policy.
            policy_info (dict): Information about the security policy.
        """
        self._PolicyContainer = policy_container
        self._policy_info = policy_info

        # The object container is needed in order to store literal objects and other special parameters
        FMCSecurityPolicy.initialize_class_variables(policy_container)

        self._name = policy_info['name']
        self._container_index = policy_info['metadata']['ruleIndex']
        self._status = 'enabled' if policy_info.get('enabled', False) else 'disabled'
        self._category = policy_info['metadata']['category']
        self._source_zones = self.extract_security_zone_object_info(policy_info.get('sourceZones'))
        self._destination_zones = self.extract_security_zone_object_info(policy_info.get('destinationZones'))
        self._source_networks = self.extract_network_address_object_info(policy_info.get('sourceNetworks'), self._virtual_object_container, self._db)
        self._destination_networks = self.extract_network_address_object_info(policy_info.get('destinationNetworks'), self._virtual_object_container, self._db)
        self._source_ports = self.extract_port_object_info(policy_info.get('sourcePorts'), self._virtual_object_container, self._db)
        self._destination_ports = self.extract_port_object_info(policy_info.get('destinationPorts'), self._virtual_object_container, self._db)
        self._schedule_objects = self.extract_schedule_object_info(policy_info.get('timeRangeObjects'))
        self._users = self.extract_user_object_info(policy_info.get('users'), self._virtual_object_container, self._db)
        self._urls = self.extract_url_object_info(policy_info.get('urls'), self._virtual_object_container, self._db)
        self._policy_apps = self.extract_l7_app_object_info(policy_info.get('applications'), self._virtual_object_container, self._db)
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
            list: A list of security zone names extracted from the provided data structure, or None if no information is provided.
        """
        # Initialize an empty list to store the extracted security zone names
        extracted_security_zones = []

        # Check if security_zone_object_info is not None before processing
        if security_zone_object_info:
            # Iterate through each security zone entry in the provided data structure
            for security_zone_entry in security_zone_object_info['objects']:
                # Extract the name of the security zone and append it to the list
                extracted_security_zones.append(security_zone_entry['name'])
        else:
            extracted_security_zones = None

        # Return the list of extracted security zone names
        return extracted_security_zones
    
    def extract_network_address_object_info(self, network_object_info, virtual_object_container, db):
        """
        Extract network address information from the provided data structure.

        This method processes both network objects and literals, converts them to internal objects, and saves them to the db.

        Parameters:
            network_object_info (dict): A dictionary containing information about network objects and literals.
            virtual_object_container (Container): A container for virtual objects.
            db (db): The db instance where the objects will be saved.

        Returns:
            list: A list of extracted network object names.
        """
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
            if network_object_type == 'Geolocation':
                # Convert the policy region to an object and save it
                policy_region = FMCObjectWithLiterals.convert_policy_region_to_object(virtual_object_container, network_object_entry)
            elif network_object_type == 'Country':
                policy_region = FMCObjectWithLiterals.convert_policy_country_to_object(virtual_object_container, network_object_entry)
            else:
                policy_region = None

            if policy_region:
                policy_region.save(db)
                # Append the name of the policy region to the list
                extracted_network_objects.append(policy_region.name)
            
            # Append the name of the network object to the list
            extracted_network_objects.append(network_object_name)

        # Process network literals
        network_literals = network_object_info.get('literals', [])
        for network_literal_entry in network_literals:
            # Convert the network literal to an object and save it
            converted_literal = FMCObjectWithLiterals.convert_network_literal_to_object(virtual_object_container, network_literal_entry)
            converted_literal.save(db)
            # Append the name of the converted literal to the list
            extracted_network_objects.append(converted_literal.name)

        # Return the list of extracted network objects
        return extracted_network_objects
    
    def extract_port_object_info(self, port_object_info, virtual_object_container, db):
        """
        Extract port object information from the provided data structure.

        This method processes both port objects and literals, converts them to internal objects, and saves them to the db.

        Parameters:
            port_object_info (dict): A dictionary containing information about port objects and literals.
            virtual_object_container (Container): A container for virtual objects.
            db (db): The db instance where the objects will be saved.

        Returns:
            list: A list of extracted port object names.
        """
        # Initialize an empty list to store extracted port objects
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
            converted_literal = FMCObjectWithLiterals.convert_port_literals_to_objects(virtual_object_container, port_literal_entry, self._policy_info)

            # Save the literal object
            converted_literal.save(db)
            # Append the name of the literal to the list
            extracted_port_objects.append(converted_literal.name)

        # Return the list of extracted port objects
        return extracted_port_objects

    def extract_user_object_info(self, user_object_info, virtual_object_container, db):
        """
        Extract user object information from the provided data structure.

        This method processes user objects, converts them to internal objects, saves them to the db, and returns their names.

        Parameters:
            user_object_info (dict): A dictionary containing information about user objects.
            virtual_object_container (Container): A container for virtual objects.
            db (db): The db instance where the objects will be saved.

        Returns:
            list: A list of processed user object entries containing the user type and name.
        """
        # Log a debug message indicating the function call
        general_logger.info("Processing user objects from policy.")
        
        # Initialize an empty list to store processed user object entries
        processed_user_objects = []

        # If no user object information is provided, return an empty list
        if user_object_info is not None:
            for user_object_entry in user_object_info.get('objects', []):
                # Ensure all required keys exist
                if 'name' in user_object_entry and 'realm' in user_object_entry and 'name' in user_object_entry['realm']:
                    user_object_name = user_object_entry['name']
                    user_realm_name = user_object_entry['realm']['name']
                    
                    # Log information about the user object
                    special_policies_logger.info(f"User object name: <{user_object_name}>, user object type: <{user_object_entry['type']}>")
                    
                    # Construct the processed user object entry
                    processed_user_entry = f"{user_realm_name}\\{user_object_name}"
                    
                    # Create the user object
                    user_object_info = {'name': processed_user_entry}
                    user_object = FMCPolicyUserObject(virtual_object_container, user_object_info)
                    user_object.save(db)
                    
                    # Append the processed user object entry to the list
                    processed_user_objects.append(processed_user_entry)

        # Return the list of processed user object entries
        return processed_user_objects

    def extract_schedule_object_info(self, schedule_object_info):
        """
        Extract schedule object information from the provided data structure.

        This method processes the provided list of schedule objects, logs details about each schedule, 
        and returns a list of their names.

        Parameters:
            schedule_object_info (list): A list of dictionaries, each containing information about a schedule object.

        Returns:
            list: A list of schedule object names extracted from the provided data structure.
        """
        # Log a message indicating the presence of schedule objects
        general_logger.info("Processing schedule objects from this policy.")
        
        # Initialize an empty list to store the names of the schedule objects
        schedule_object_names = []
        
        # If no schedule object information is provided, return an empty list
        if schedule_object_info is not None:
            for schedule_entry in schedule_object_info:
                # Extract the name of the schedule object and log its details
                schedule_name = schedule_entry.get('name')
                if schedule_name:
                    special_policies_logger.info(f"Schedule object name: <{schedule_name}>.")
                    schedule_object_names.append(schedule_name)
        
        # Return the list of schedule object names
        return schedule_object_names

    # there are three cases which need to be processed here. the url can be an object, a literal, or a category with reputation
    def extract_url_object_info(self, url_object_info, virtual_object_container, db):
        """
        Extract URL object information from the provided data structure.

        This method processes the provided data structure to extract URL objects, literals, and categories,
        and then returns a list of their names. It also creates and saves URL literal and category objects.

        Parameters:
            url_object_info (dict): A dictionary containing information about URL objects, literals, and categories.

        Returns:
            list: A list of names of URL objects, literals, and categories extracted from the provided data structure.
        """
        # Log a message indicating the start of URL object extraction
        general_logger.info("Processing URL objects from this policy.")
        
        # Initialize a list to store the names of extracted URL objects
        url_object_names = []

        # If no URL object information is provided, return an empty list
        if url_object_info is None:
            return url_object_names

        # Process URL objects
        url_objects = url_object_info.get('objects', [])
        for url_object in url_objects:
            url_object_name = url_object.get('name')
            url_object_type = url_object.get('type')
            if url_object_name:
                special_policies_logger.info(f"URL object name: <{url_object_name}>, URL type: <{url_object_type}>")
                url_object_names.append(url_object_name)

        # Process URL literals
        url_literals = url_object_info.get('literals', [])
        for url_literal in url_literals:
            literal_object = FMCObjectWithLiterals.convert_url_literal_to_object(virtual_object_container, url_literal)
            literal_object.save(db)
            url_object_names.append(literal_object.name)

        # Process URL categories
        url_categories = url_object_info.get('urlCategoriesWithReputation', [])
        for url_category in url_categories:
            category_name = url_category.get('category', {}).get('name')
            category_reputation = url_category.get('reputation', None)
            if category_name:
                special_policies_logger.info(f"URL category name: <{category_name}>, Reputation: <{category_reputation}>")
                category_info = {'name': category_name, 'reputation': category_reputation}
                category_object = FMCURLCategoryObject(virtual_object_container, category_info)
                category_object.save(db)
                url_object_names.append(category_name)

        # Return the list of URL object names
        return url_object_names
        
    def extract_l7_app_object_info(self, l7_app_object_info, virtual_object_container, db):
        """
        Extract Layer 7 application object information from the provided data structure.

        This method processes the provided data structure to extract information about Layer 7 applications,
        application filters, and inline application filters. It creates and saves objects for these components
        and returns a list of their names.

        Parameters:
            l7_app_object_info (dict): A dictionary containing information about Layer 7 applications,
                                    application filters, and inline application filters.

        Returns:
            list: A list of names of Layer 7 applications, application filters, and inline application filters
                extracted from the provided data structure.
        """
        # Log the start of Layer 7 application extraction
        general_logger.info("Processing Layer 7 application objects from this policy.")
        
        # Initialize a list to store the names of Layer 7 applications and filters
        l7_app_names = []

        # Return an empty list if no Layer 7 application information is provided
        if l7_app_object_info is None:
            return l7_app_names

        # Extract and process regular Layer 7 applications
        applications = l7_app_object_info.get('applications', [])
        for app in applications:
            app_name = app.get('name')
            if app_name:
                special_policies_logger.info(f"Layer 7 application name: <{app_name}>.")
                app_object = FMCL7AppObject(virtual_object_container, {'name': app_name})
                app_object.save(db)
                l7_app_names.append(app_object.name)

        # Extract and process Layer 7 application filters
        app_filters = l7_app_object_info.get('applicationFilters', [])
        for app_filter in app_filters:
            filter_name = app_filter.get('name')
            if filter_name:
                special_policies_logger.info(f"Layer 7 application filter name: <{filter_name}>.")
                filter_object = FMCL7AppGroupObject(virtual_object_container, {'name': filter_name})
                filter_object.save(db)
                l7_app_names.append(filter_object.name)

        # Extract and process inline Layer 7 application filters
        inline_app_filters = l7_app_object_info.get('inlineApplicationFilters', [])
        for filter_entry in inline_app_filters:
            for filter_type, filters in filter_entry.items():
                if isinstance(filters, list):
                    for filter_item in filters:
                        filter_name = filter_item.get('name')
                        if filter_name:
                            special_policies_logger.info(f"Layer 7 inline application filter type: <{filter_type}>, name: <{filter_name}>.")
                            # full_filter_name = f"inlineApplicationFilters{gvars.separator_character}{filter_type}{gvars.separator_character}{filter_name}"
                            # l7_app_names.append(full_filter_name)
                            inline_filter_object = FMCL7AppFilterObject(virtual_object_container, {'name': filter_name, 'type': filter_type})
                            inline_filter_object.save(db)
                            l7_app_names.append(inline_filter_object.name)

        # Return the list of extracted Layer 7 application names and filter names
        return l7_app_names

    def extract_comments(self, comment_info):
        """
        Extract comments from the provided data structure.

        This method processes a list of comments, each associated with a user, and returns a string
        that combines all comments into a single string with each comment separated by a newline.

        Parameters:
            comment_info (list): A list of dictionaries, each containing information about a comment,
                                including user details and comment content.

        Returns:
            str: A string where each line contains the user and their associated comment.
        """
        # Initialize the processed_comments as an empty string
        if comment_info is None:
            processed_comments = ""
        else:
            # Join each comment entry into a single string, separating entries with newlines
            processed_comments = "\n".join(
                f"User: <{comment_entry['user']['name']}> commented: <{comment_entry['comment']}>"
                for comment_entry in comment_info
            )

        # Return the combined string of processed comments
        return processed_comments
