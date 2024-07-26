from abc import abstractmethod
import utils.helper as helper
import utils.gvars as gvars
from pkg import SecurityPolicyContainersMapTable, MigrationProjectGeneralDataTable, MigrationProjectDevicesTable, SecurityDeviceInterfaceMap, \
LogSettingsTable, SpecialSecurityPolicyParametersTable, NetworkObjectTypesMapTable, SecurityPolicyActionMapTable, SecurityPolicySectionMap
from pkg.SecurityDevice import SecurityDeviceDatabase

special_policies_log = helper.logging.getLogger(gvars.special_policies_logger)

class MigrationProjectDatabase(SecurityDeviceDatabase):
    def __init__(self, cursor):
        """
        Initialize the MigrationProjectDatabase instance.

        Args:
            cursor (Cursor): The cursor object used to interact with the db.
        """
        super().__init__(cursor)

        # Initialize tables
        self._security_policy_containers_map_table = SecurityPolicyContainersMapTable(self)
        self._migration_project_general_data_table = MigrationProjectGeneralDataTable(self)
        self._migration_project_devices_table = MigrationProjectDevicesTable(self)
        self._security_device_interface_map_table = SecurityDeviceInterfaceMap(self)

        self._log_settings_table = LogSettingsTable(self)
        self._special_security_policy_parameters_table = SpecialSecurityPolicyParametersTable(self)
        self._network_object_types_map_table = NetworkObjectTypesMapTable(self)
        self._security_policy_action_map_table = SecurityPolicyActionMapTable(self)
        self._security_policy_section_map_table = SecurityPolicySectionMap(self)

    def create_migration_project_tables(self):
        """
        Create the necessary tables for storing data from imported security devices.
        """
        # Create base security device tables
        self.create_security_device_tables()
        
        # Create specific migration project tables
        self._security_policy_containers_map_table.create()
        self._migration_project_general_data_table.create()
        self._migration_project_devices_table.create()
        self._security_device_interface_map_table.create()

        self._log_settings_table.create()
        self._special_security_policy_parameters_table.create()
        self._network_object_types_map_table.create()
        self._network_object_types_map_table.pre_insert_data()
        
        self._security_policy_action_map_table.create()
        self._security_policy_action_map_table.pre_insert_data()
        
        self._security_policy_section_map_table.create()
        self._security_policy_section_map_table.pre_insert_data()

    @property
    def migration_project_general_data_table(self):
        """
        Get the migration project general data table.

        Returns:
            MigrationProjectGeneralDataTable: The general data table for the migration project.
        """
        return self._migration_project_general_data_table
    
    @property
    def migration_project_devices_table(self):
        """
        Get the migration project devices table.

        Returns:
            MigrationProjectDevicesTable: The devices table for the migration project.
        """
        return self._migration_project_devices_table
    
    @property
    def security_policy_containers_map_table(self):
        """
        Get the security policy containers map table.

        Returns:
            SecurityPolicyContainersMapTable: The map table for security policy containers.
        """
        return self._security_policy_containers_map_table
    
    @property
    def security_device_interface_map_table(self):
        """
        Get the security device interface map table.

        Returns:
            SecurityDeviceInterfaceMap: The map table for security device interfaces.
        """
        return self._security_device_interface_map_table

    @property
    def log_settings_table(self):
        """
        Get the log settings table.

        Returns:
            LogSettingsTable: The table for log settings.
        """
        return self._log_settings_table

    @property
    def special_security_policy_parameters_table(self):
        """
        Get the special security policy parameters table.

        Returns:
            SpecialSecurityPolicyParametersTable: The table for special security policy parameters.
        """
        return self._special_security_policy_parameters_table

    @property
    def network_object_types_map_table(self):
        """
        Get the network object types map table.

        Returns:
            NetworkObjectTypesMapTable: The map table for network object types.
        """
        return self._network_object_types_map_table

    @property
    def security_policy_action_map_table(self):
        """
        Get the security policy action map table.

        Returns:
            SecurityPolicyActionMapTable: The map table for security policy actions.
        """
        return self._security_policy_action_map_table
    
    @property
    def security_policy_section_map_table(self):
        """
        Get the security policy section map table.

        Returns:
            SecurityPolicySectionMap: The map table for security policy sections.
        """
        return self._security_policy_section_map_table

class MigrationProject:
    def __init__(self, name, db):
        """
        Initialize the MigrationProject instance.

        Args:
            name (str): The name of the migration project.
            db (MigrationProjectDatabase): The db instance associated with the migration project.
        """
        self._name = name
        self._db = db

    @property
    def db(self):
        """
        Get the db instance associated with the migration project.

        Returns:
            MigrationProjectDatabase: The db instance.
        """
        return self._db
    
    @property
    def name(self):
        """
        Get the name of the migration project.

        Returns:
            str: The name of the migration project.
        """
        return self._name

    def save_general_info(self, description, creation_timestamp):
        """
        Save the general information of the migration project to the db.

        Args:
            description (str): A description of the migration project.
            creation_timestamp (str): The timestamp when the migration project was created.
        """
        self.db.migration_project_general_data_table.insert(self._name, description, creation_timestamp)

    def import_data(self, source_security_device, target_security_device):
        """
        Import data from the source security device to the target security device.

        Args:
            source_security_device (SecurityDevice): The security device providing the source data.
            target_security_device (SecurityDevice): The security device receiving the data.
        """
        # Retrieve the migration project devices table
        migration_project_devices_table = self.db.migration_project_devices_table
        
        # Insert the UIDs of the source and target devices into the migration project devices table
        migration_project_devices_table.insert(
            source_security_device.uid, 
            target_security_device.uid
        )

        # List of tables to copy
        tables = [
            # General Data Table
            '_general_data_table',

            # Policy Containers
            '_security_policy_containers_table',
            '_nat_policy_containers_table',
            '_object_containers_table',
            '_security_zone_containers_table',
            '_managed_device_containers_table',

            # Managed Devices
            '_managed_devices_table',

            # Security Policies
            '_security_policies_table',

            # Zones
            '_security_zones_table',

            # Objects
            '_url_objects_table',
            '_network_address_objects_table',
            '_port_objects_table',
            '_icmp_objects_table',
            '_geolocation_objects_table',
            '_country_objects_table',
            '_schedule_objects_table',

            # Groups
            '_network_group_objects_table',
            '_port_group_objects_table',
            '_url_group_objects_table',

            # Group Members
            '_network_group_objects_members_table',
            '_port_group_objects_members_table',
            '_url_group_objects_members_table',

            # Policy Users
            '_policy_users_table',

            # Layer 7 Applications
            '_l7_apps_table',
            '_l7_app_filters_table',
            '_l7_app_groups_table',
            '_l7_app_group_members_table',

            # URL Categories
            '_url_categories_table',

            # Security Policy Details
            '_security_policy_zones_table',
            '_security_policy_networks_table',
            '_security_policy_ports_table',
            '_security_policy_users_table',
            '_security_policy_urls_table',
            '_security_policy_l7_apps_table',
            '_security_policy_schedule_table'
        ]

        # Copy data for each table
        for table_name in tables:
            # Get source and target tables for the current table
            source_device_db_table = getattr(source_security_device.db, table_name)
            target_device_db_table = getattr(target_security_device.db, table_name)
            target_project_db_table = getattr(self.db, table_name)

            # Fetch all data from the source and target tables
            source_data = source_device_db_table.get('*')
            target_data = target_device_db_table.get('*')

            # Insert data from source and target into the target project table
            for row in source_data:
                target_project_db_table.insert(*row)
            for row in target_data:
                target_project_db_table.insert(*row)
    
    def map_containers(self, source_container_name, target_container_name):
        # Get source security device uid based on source container name
        source_container_data = self.db.security_policy_containers_table.get(['uid', 'security_device_uid'], 'name', source_container_name)
        if not source_container_data:
            raise ValueError(f"Source container with name '{source_container_name}' not found.")

        source_container_uid, source_device_uid = source_container_data[0]

        # Get target device uid based on source device uid from migration project devices
        target_device_data = self.db.migration_project_devices_table.get('target_device_uid', 'source_device_uid', source_device_uid)
        if not target_device_data:
            raise ValueError(f"Target device for source device uid '{source_device_uid}' not found.")

        target_device_uid = target_device_data[0]

        # Get target container uid based on target container name and target device uid
        target_container_data = self.db.security_policy_containers_table.get(['uid'], ['name', 'security_device_uid'], [target_container_name, target_device_uid], multiple_where=True)
        if not target_container_data:
            raise ValueError(f"Target container with name '{target_container_name}' for device uid '{target_device_uid}' not found.")

        target_container_uid = target_container_data[0][0]

        # Insert the data into the containers map table
        self.db.security_policy_containers_map_table.insert(source_container_uid, target_container_uid)
    
    def map_zones(self, source_zone_name, target_zone_name):
        """
        Maps a source security zone to a target security zone.

        Args:
            source_zone_name (str): The name of the source security zone.
            target_zone_name (str): The name of the target security zone.

        Raises:
            ValueError: If the source or target zone is not found.
        """

        # Fetch source zone UID based on the source zone name
        source_zone_data = self.db.security_zones_table.get(['uid'], 'name', source_zone_name)
        if not source_zone_data:
            raise ValueError(f"Source zone with name '{source_zone_name}' not found.")

        source_zone_uid = source_zone_data[0][0]

        # Fetch target zone UID based on the target zone name
        target_zone_data = self.db.security_zones_table.get(['uid'], 'name', target_zone_name)
        if not target_zone_data:
            raise ValueError(f"Target zone with name '{target_zone_name}' not found.")

        target_zone_uid = target_zone_data[0][0]

        # Insert the mapping between source and target zone UIDs into the security device interface map table
        self.db.security_device_interface_map_table.insert(source_zone_uid, target_zone_uid)

    def set_log_manager(self, log_manager_name):
        """
        Sets the log manager by inserting its name into the log settings table.

        Args:
            log_manager_name (str): The name of the log manager to be set.

        """
        # Insert the log manager name into the log settings table
        self.db.log_settings_table.insert(log_manager_name)

    def set_security_profile(self, security_profile):
        """
        Sets the security profile by inserting it into the special security policy parameters table.

        Args:
            security_profile (str): The security profile to be set.

        """
        # Insert the security profile into the special security policy parameters table
        self.db.special_security_policy_parameters_table.insert(security_profile)

    def load_containers_map(self):
        """
        Loads the mapping of source security policy containers to target security policy containers.

        Retrieves the source and target security policy container UIDs from the containers map table,
        and then fetches the names of the target containers to create a mapping dictionary.

        Returns:
            dict: A dictionary where keys are source container UIDs and values are target container names.
        
        Raises:
            ValueError: If a target container with a given UID is not found in the security policy containers table.
        """
        # Fetch the mapping of source to target container UIDs from the database
        containers_map = self.db.security_policy_containers_map_table.get(
            ['source_security_policy_container_uid', 'target_security_policy_container_uid']
        )

        # Initialize the dictionary to store the container mappings
        containers_map_dict = {}

        # Process each pair of source and target container UIDs
        for source_container_uid, target_container_uid in containers_map:
            # Fetch the name of the target security policy container
            target_container_data = self.db.security_policy_containers_table.get(
                ['name'], 'uid', target_container_uid
            )
            
            # If the target container is not found, raise an exception
            if not target_container_data:
                raise ValueError(f"Target container with UID '{target_container_uid}' not found.")
            
            # Extract the target container name from the fetched data
            target_container_name = target_container_data[0][0]

            # Map the source container UID to the target container name
            containers_map_dict[source_container_uid] = target_container_name

        return containers_map_dict

    def load_security_zones_map(self):
        """
        Loads the mapping of source security zones to target security zones.

        Retrieves the source and target security zone UIDs from the security device interface map table,
        and then fetches the names of the target zones to create a mapping dictionary.

        Returns:
            dict: A dictionary where keys are source zone UIDs and values are target zone names.
        
        Raises:
            ValueError: If a target security zone with a given UID is not found in the security zones table.
        """
        # Retrieve the mapping of source to target security zone UIDs from the database
        zones_map = self.db.security_device_interface_map_table.get(
            ['source_security_zone', 'target_security_zone']
        )

        # Initialize the dictionary to store the zone mappings
        zones_map_dict = {}

        # Process each pair of source and target zone UIDs
        for source_zone_uid, target_zone_uid in zones_map:
            # Fetch the name of the target security zone
            target_zone_data = self.db.security_zones_table.get(
                ['name'], 'uid', target_zone_uid
            )
            
            # If the target zone is not found, raise an exception
            if not target_zone_data:
                raise ValueError(f"Target security zone with UID '{target_zone_uid}' not found.")
            
            # Extract the target zone name from the fetched data
            target_zone_name = target_zone_data[0][0]

            # Map the source zone UID to the target zone name
            zones_map_dict[source_zone_uid] = target_zone_name

        return zones_map_dict

    def load_network_object_types_map(self):
        """
        Loads and returns a dictionary mapping network object types from the source security device 
        to the corresponding types in the target security device.

        This method retrieves the network object type for both the source and target security devices, 
        then fetches the mappings from the network object types map table in the database. It returns
        a dictionary where the keys are source network object types and the values are their corresponding
        target network object types.

        Returns:
            dict: A dictionary mapping source network object types to target network object types.
        """
        # Retrieve the network object type for the source security device
        source_device_type = self._source_security_device.db.general_data_table.get(
            'type', 'name', self._source_security_device.name
        )[0][0]

        # Retrieve the network object type for the target security device
        target_device_type = self._target_security_device.db.general_data_table.get(
            'type', 'name', self._target_security_device.name
        )[0][0]

        # Retrieve the network object type mappings from the database
        network_object_types_map = self.db.network_object_types_map_table.get(
            columns=[source_device_type, target_device_type]
        )

        # Initialize a dictionary to store the mappings from source to target network object types
        network_object_types_map_dict = {}

        # Process each mapping and populate the dictionary
        for source_action, destination_action in network_object_types_map:
            network_object_types_map_dict[source_action] = destination_action

        return network_object_types_map_dict

    def load_security_policies_actions_map(self):
        """
        Loads and returns a dictionary mapping security policy actions from the source security device 
        to the corresponding actions in the target security device.

        This method retrieves the security policy action type for both the source and target security devices, 
        then fetches the mappings from the security policy action map table in the database. It returns
        a dictionary where the keys are source security policy actions and the values are their corresponding
        target security policy actions.

        Returns:
            dict: A dictionary mapping source security policy actions to target security policy actions.
        """
        # Retrieve the security policy action type for the source security device
        source_device_type = self._source_security_device.db.general_data_table.get(
            'type', 'name', self._source_security_device.name
        )[0][0]

        # Retrieve the security policy action type for the target security device
        target_device_type = self._target_security_device.db.general_data_table.get(
            'type', 'name', self._target_security_device.name
        )[0][0]

        # Retrieve the security policy action mappings from the database
        security_policy_actions_map = self.db.security_policy_action_map_table.get(
            columns=[source_device_type, target_device_type]
        )

        # Initialize a dictionary to store the mappings from source to target security policy actions
        security_policy_actions_map_dict = {}

        # Process each mapping and populate the dictionary
        for source_action, target_action in security_policy_actions_map:
            # Optional: Validate or use source_device_type and target_device_type if needed
            # For example, if the mapping is specific to device types
            # if source_device_type == 'some_type' and target_device_type == 'another_type':
            #     # Process mapping based on device types

            security_policy_actions_map_dict[source_action] = target_action

        return security_policy_actions_map_dict

    def load_log_settings(self):
        """
        Retrieves the log manager settings from the log settings table in the database.

        This method queries the log settings table to obtain the log manager configuration,
        which is then returned.

        Returns:
            str: The log manager configuration setting.
        """
        # Query the table to get the log manager setting
        log_manager_setting = self.db.log_settings_table.get('log_manager')[0][0]
        
        return log_manager_setting
        
    def load_special_security_policy_parameters(self):
        """
        Retrieves the special security policy parameters from the special security policy parameters table in the database.

        This method queries the special security policy parameters table to obtain the security profile setting,
        which is then returned.

        Returns:
            str: The security profile setting from the special security policy parameters table.
        """        
        # Query the table to get the security profile setting
        security_profile_setting = self.db.special_security_policy_parameters_table.get('security_profile')[0][0]
        
        return security_profile_setting

    def load_section_map(self):
        """
        Retrieves the mapping of security policy sections from the section map table in the database.

        This method queries the section map table to obtain mappings between source and target security policy sections
        based on the device types of the source and target security devices. It returns a dictionary where the keys are
        source sections and the values are their corresponding target sections.

        Returns:
            dict: A dictionary mapping source security policy sections to their corresponding target sections.
        """
        # Retrieve the type of the source and target security devices
        source_device_type = self._source_security_device.db.general_data_table.get(
            'type', 'name', self._source_security_device.name
        )[0][0]
        target_device_type = self._target_security_device.db.general_data_table.get(
            'type', 'name', self._target_security_device.name
        )[0][0]

        # Retrieve the section map table from the database
        section_map_table = self.db.security_policy_section_map_table.get([source_device_type, target_device_type])
        
        # Initialize a dictionary to store the section mappings
        section_map = {}

        # Process each mapping from the section map table
        for row in section_map_table:
            source_section = row[0]
            destination_section = row[1]
            section_map[source_section] = destination_section
        
        return section_map
