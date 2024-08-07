from abc import abstractmethod
from pkg import PioneerDatabase, GeneralDataTable, SecurityPolicyContainersTable, NATPolicyContainersTable, ObjectContainersTable, SecurityPoliciesTable, \
SecurityZonesTable, URLObjectsTable, NetworkAddressObjectsTable, \
GeolocationObjectsTable, CountryObjectsTable, PortObjectsTable, ICMPObjectsTable, ScheduleObjectsTable, ManagedDevicesTable, ManagedDeviceContainersTable, SecurityZoneContainersTable, \
NetworkGroupObjectsTable, PortGroupObjectsTable, URLGroupObjectsTable, NetworkGroupObjectsMembersTable, PortGroupObjectsMembersTable, URLGroupObjectsMembersTable, \
PolicyUsersTable, L7AppsTable, L7AppFiltersTable, L7AppGroupsTable, L7AppGroupMembersTable, URLCategoriesTable, SecurityPolicyZonesTable, SecurityPolicyNetworksTable, \
SecurityPolicyPortsTable, SecurityPolicyUsersTable, SecurityPolicyURLsTable, SecurityPolicyL7AppsTable, SecurityPolicyScheduleTable, NATPoliciesTable
import utils.helper as helper
import sys
import utils.gvars as gvars

general_logger = helper.logging.getLogger('general')
class SecurityDeviceDatabase(PioneerDatabase):
    """
    A class representing a db for security devices.
    """

    def __init__(self, cursor):
        """
        Initialize the SecurityDeviceDatabase instance.

        Args:
            cursor: The cursor object for db operations.
        """
        super().__init__(cursor)

        # Initialize table instances
        self._general_data_table = GeneralDataTable(self)
        self._security_policy_containers_table = SecurityPolicyContainersTable(self)
        self._nat_policy_containers_table = NATPolicyContainersTable(self)
        self._object_containers_table = ObjectContainersTable(self)
        self._security_zone_containers_table = SecurityZoneContainersTable(self)
        self._managed_device_containers_table = ManagedDeviceContainersTable(self)
        self._managed_devices_table = ManagedDevicesTable(self)
        self._security_policies_table = SecurityPoliciesTable(self)
        self._nat_policies_table = NATPoliciesTable(self)
        self._security_zones_table = SecurityZonesTable(self)
        self._url_objects_table = URLObjectsTable(self)
        self._network_address_objects_table = NetworkAddressObjectsTable(self)
        self._port_objects_table = PortObjectsTable(self)
        self._icmp_objects_table = ICMPObjectsTable(self)
        self._geolocation_objects_table = GeolocationObjectsTable(self)
        self._country_objects_table = CountryObjectsTable(self)
        self._schedule_objects_table = ScheduleObjectsTable(self)
        self._network_group_objects_table = NetworkGroupObjectsTable(self)
        self._port_group_objects_table = PortGroupObjectsTable(self)
        self._url_group_objects_table = URLGroupObjectsTable(self)
        self._network_group_objects_members_table = NetworkGroupObjectsMembersTable(self)
        self._port_group_objects_members_table = PortGroupObjectsMembersTable(self)
        self._url_group_objects_members_table = URLGroupObjectsMembersTable(self)
        self._policy_users_table = PolicyUsersTable(self)
        self._l7_apps_table = L7AppsTable(self)
        self._l7_app_filters_table = L7AppFiltersTable(self)
        self._l7_app_groups_table = L7AppGroupsTable(self)
        self._l7_app_group_members_table = L7AppGroupMembersTable(self)
        self._url_categories_table = URLCategoriesTable(self)
        self._security_policy_zones_table = SecurityPolicyZonesTable(self)
        self._security_policy_networks_table = SecurityPolicyNetworksTable(self)
        self._security_policy_ports_table = SecurityPolicyPortsTable(self)
        self._security_policy_users_table = SecurityPolicyUsersTable(self)
        self._security_policy_urls_table = SecurityPolicyURLsTable(self)
        self._security_policy_l7_apps_table = SecurityPolicyL7AppsTable(self)
        self._security_policy_schedule_table = SecurityPolicyScheduleTable(self)

    def create_security_device_tables(self):
        """
        Create all security device tables in the db.
        """
        general_logger.info("Creating the PostgreSQL tables in device db.")
        
        # Create tables
        self._general_data_table.create()
        self._security_policy_containers_table.create()
        self._nat_policy_containers_table.create()
        self._object_containers_table.create()
        self._security_zone_containers_table.create()
        self._managed_device_containers_table.create()
        self._managed_devices_table.create()
        self._security_policies_table.create()
        self._nat_policies_table.create()
        self._security_zones_table.create()
        self._url_objects_table.create()
        self._network_address_objects_table.create()
        self._port_objects_table.create()
        self._icmp_objects_table.create()
        self._geolocation_objects_table.create()
        self._country_objects_table.create()
        self._schedule_objects_table.create()
        self._network_group_objects_table.create()
        self._port_group_objects_table.create()
        self._url_group_objects_table.create()
        self._network_group_objects_members_table.create()
        self._port_group_objects_members_table.create()
        self._url_group_objects_members_table.create()
        self._policy_users_table.create()
        self._l7_apps_table.create()
        self._l7_app_filters_table.create()
        self._l7_app_groups_table.create()
        self._l7_app_group_members_table.create()
        self._url_categories_table.create()
        self._security_policy_zones_table.create()
        self._security_policy_networks_table.create()
        self._security_policy_ports_table.create()
        self._security_policy_users_table.create()
        self._security_policy_urls_table.create()
        self._security_policy_l7_apps_table.create()
        self._security_policy_schedule_table.create()

    @property
    def security_policy_zones_table(self):
        """
        Get the SecurityPolicyZonesTable instance.
        
        Returns:
            SecurityPolicyZonesTable: The security policy zones table instance.
        """
        return self._security_policy_zones_table

    @property
    def security_policy_networks_table(self):
        """
        Get the SecurityPolicyNetworksTable instance.
        
        Returns:
            SecurityPolicyNetworksTable: The security policy networks table instance.
        """
        return self._security_policy_networks_table

    @property
    def security_policy_ports_table(self):
        """
        Get the SecurityPolicyPortsTable instance.
        
        Returns:
            SecurityPolicyPortsTable: The security policy ports table instance.
        """
        return self._security_policy_ports_table

    @property
    def security_policy_users_table(self):
        """
        Get the SecurityPolicyUsersTable instance.
        
        Returns:
            SecurityPolicyUsersTable: The security policy users table instance.
        """
        return self._security_policy_users_table

    @property
    def security_policy_urls_table(self):
        """
        Get the SecurityPolicyURLsTable instance.
        
        Returns:
            SecurityPolicyURLsTable: The security policy URLs table instance.
        """
        return self._security_policy_urls_table

    @property
    def security_policy_l7_apps_table(self):
        """
        Get the SecurityPolicyL7AppsTable instance.
        
        Returns:
            SecurityPolicyL7AppsTable: The security policy Layer 7 applications table instance.
        """
        return self._security_policy_l7_apps_table

    @property
    def security_policy_schedule_table(self):
        """
        Get the SecurityPolicyScheduleTable instance.
        
        Returns:
            SecurityPolicyScheduleTable: The security policy schedule table instance.
        """
        return self._security_policy_schedule_table

    @property
    def country_objects_table(self):
        """
        Get the CountryObjectsTable instance.
        
        Returns:
            CountryObjectsTable: The country objects table instance.
        """
        return self._country_objects_table

    @property
    def policy_users_table(self):
        """
        Get the PolicyUsersTable instance.
        
        Returns:
            PolicyUsersTable: The policy users table instance.
        """
        return self._policy_users_table

    @property
    def url_categories_table(self):
        """
        Get the URLCategoriesTable instance.
        
        Returns:
            URLCategoriesTable: The URL categories table instance.
        """
        return self._url_categories_table

    @property
    def l7_apps_table(self):
        """
        Get the L7AppsTable instance.
        
        Returns:
            L7AppsTable: The Layer 7 applications table instance.
        """
        return self._l7_apps_table

    @property
    def l7_app_filters_table(self):
        """
        Get the L7AppFiltersTable instance.
        
        Returns:
            L7AppFiltersTable: The Layer 7 application filters table instance.
        """
        return self._l7_app_filters_table

    @property
    def l7_app_groups_table(self):
        """
        Get the L7AppGroupsTable instance.
        
        Returns:
            L7AppGroupsTable: The Layer 7 application groups table instance.
        """
        return self._l7_app_groups_table

    @property
    def l7_app_group_members_table(self):
        """
        Get the L7AppGroupMembersTable instance.
        
        Returns:
            L7AppGroupMembersTable: The Layer 7 application group members table instance.
        """
        return self._l7_app_group_members_table

    @property
    def general_data_table(self):
        """
        Get the GeneralDataTable instance.
        
        Returns:
            GeneralDataTable: The general data table instance.
        """
        return self._general_data_table

    @property
    def security_policy_containers_table(self):
        """
        Get the SecurityPolicyContainersTable instance.
        
        Returns:
            SecurityPolicyContainersTable: The security policy containers table instance.
        """
        return self._security_policy_containers_table

    @property
    def nat_policy_containers_table(self):
        """
        Get the NATPolicyContainersTable instance.
        
        Returns:
            NATPolicyContainersTable: The NAT policy containers table instance.
        """
        return self._nat_policy_containers_table

    @property
    def object_containers_table(self):
        """
        Get the ObjectContainersTable instance.
        
        Returns:
            ObjectContainersTable: The object containers table instance.
        """
        return self._object_containers_table

    @property
    def zone_containers_table(self):
        """
        Get the SecurityZoneContainersTable instance.
        
        Returns:
            SecurityZoneContainersTable: The security zone containers table instance.
        """
        return self._security_zone_containers_table

    @property
    def managed_device_containers_table(self):
        """
        Get the ManagedDeviceContainersTable instance.
        
        Returns:
            ManagedDeviceContainersTable: The managed device containers table instance.
        """
        return self._managed_device_containers_table

    @property
    def security_policies_table(self):
        """
        Get the SecurityPoliciesTable instance.
        
        Returns:
            SecurityPoliciesTable: The security policies table instance.
        """
        return self._security_policies_table

    @property
    def nat_policies_table(self):
        """
        Get the NATPoliciesTable instance.
        
        Returns:
            NATPoliciesTable: The NAT policies table instance.
        """
        return self._nat_policies_table

    @property
    def url_objects_table(self):
        """
        Get the URLObjectsTable instance.
        
        Returns:
            URLObjectsTable: The URL objects table instance.
        """
        return self._url_objects_table

    @property
    def network_address_objects_table(self):
        """
        Get the NetworkAddressObjectsTable instance.
        
        Returns:
            NetworkAddressObjectsTable: The network address objects table instance.
        """
        return self._network_address_objects_table

    @property
    def geolocation_objects_table(self):
        """
        Get the GeolocationObjectsTable instance.
        
        Returns:
            GeolocationObjectsTable: The geolocation objects table instance.
        """
        return self._geolocation_objects_table

    @property
    def port_objects_table(self):
        """
        Get the PortObjectsTable instance.
        
        Returns:
            PortObjectsTable: The port objects table instance.
        """
        return self._port_objects_table

    @property
    def icmp_objects_table(self):
        """
        Get the ICMPObjectsTable instance.
        
        Returns:
            ICMPObjectsTable: The ICMP objects table instance.
        """
        return self._icmp_objects_table

    @property
    def managed_devices_table(self):
        """
        Get the ManagedDevicesTable instance.
        
        Returns:
            ManagedDevicesTable: The managed devices table instance.
        """
        return self._managed_devices_table

    @property
    def security_zones_table(self):
        """
        Get the SecurityZonesTable instance.
        
        Returns:
            SecurityZonesTable: The security zones table instance.
        """
        return self._security_zones_table

    @property
    def network_group_objects_table(self):
        """
        Get the NetworkGroupObjectsTable instance.
        
        Returns:
            NetworkGroupObjectsTable: The network group objects table instance.
        """
        return self._network_group_objects_table

    @property
    def port_group_objects_table(self):
        """
        Get the PortGroupObjectsTable instance.
        
        Returns:
            PortGroupObjectsTable: The port group objects table instance.
        """
        return self._port_group_objects_table

    @property
    def url_group_objects_table(self):
        """
        Get the URLGroupObjectsTable instance.
        
        Returns:
            URLGroupObjectsTable: The URL group objects table instance.
        """
        return self._url_group_objects_table

    @property
    def network_group_objects_members_table(self):
        """
        Get the NetworkGroupObjectsMembersTable instance.
        
        Returns:
            NetworkGroupObjectsMembersTable: The network group objects members table instance.
        """
        return self._network_group_objects_members_table

    @property
    def port_group_objects_members_table(self):
        """
        Get the PortGroupObjectsMembersTable instance.
        
        Returns:
            PortGroupObjectsMembersTable: The port group objects members table instance.
        """
        return self._port_group_objects_members_table

    @property
    def url_group_objects_members_table(self):
        """
        Get the URLGroupObjectsMembersTable instance.
        
        Returns:
            URLGroupObjectsMembersTable: The URL group objects members table instance.
        """
        return self._url_group_objects_members_table

    @property
    def schedule_objects_table(self):
        """
        Get the ScheduleObjectsTable instance.
        
        Returns:
            ScheduleObjectsTable: The schedule objects table instance.
        """
        return self._schedule_objects_table

class SecurityDevice:
    def __init__(self, uid, name, db, device_connection):
        """
        Initialize a SecurityDevice instance.

        Parameters:
            uid (str): Unique identifier for the security device.
            name (str): The name of the security device.
            db (SecurityDeviceDatabase): An instance of the db for the security device.
            device_connection (DeviceConnection): An instance representing the device connection.
        """
        self._uid = uid
        self._name = name
        self._db = db
        self._device_connection = device_connection

    @property
    def uid(self):
        """
        Get the UID of the security device.
        
        Returns:
            str: The UID of the security device.
        """
        return self._uid

    @uid.setter
    def uid(self, value):
        """
        Set the UID of the security device.
        
        Parameters:
            value (str): The new UID of the security device.
        """
        self._uid = value

    @property
    def name(self):
        """
        Get the name of the security device.
        
        Returns:
            str: The name of the security device.
        """
        return self._name

    @property
    def db(self):
        """
        Get the db instance associated with the security device.
        
        Returns:
            SecurityDeviceDatabase: The db instance.
        """
        return self._db

    @db.setter
    def db(self, value):
        """
        Set the db instance associated with the security device.
        
        Parameters:
            value (SecurityDeviceDatabase): The new db instance.
        """
        self._db = value

    @property
    def device_connection(self):
        """
        Get the device connection instance.
        
        Returns:
            DeviceConnection: The device connection instance.
        """
        return self._device_connection

    @device_connection.setter
    def device_connection(self, value):
        """
        Set the device connection instance.
        
        Parameters:
            value (DeviceConnection): The new device connection instance.
        """
        self._device_connection = value

    def save_general_info(self, security_device_uid, security_device_name, security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain):
        """
        Save general information about the security device to the db.

        Parameters:
            security_device_uid (str): The UID of the security device.
            security_device_name (str): The name of the security device.
            security_device_username (str): The username for the security device.
            security_device_secret (str): The secret for the security device.
            security_device_hostname (str): The hostname of the security device.
            security_device_type (str): The type of the security device.
            security_device_port (int): The port used by the security device.
            security_device_version (str): The version of the security device.
            domain (str): The domain of the security device.
        """
        # Insert general information into the general data table
        self._db.general_data_table.insert(
            security_device_uid,
            security_device_name,
            security_device_username,
            security_device_secret,
            security_device_hostname,
            security_device_type,
            security_device_port,
            security_device_version,
            domain
        )

    def get_device_version_from_device_conn(self):
        """
        Retrieve the version of the device's server using the established device connection.

        This method uses the device connection to obtain the version information of the device. 
        It logs the device version if successfully retrieved, or logs a critical error and exits 
        the program if an exception occurs.

        Returns:
            str: The version of the device's server.

        Raises:
            SystemExit: Exits the program with status code 1 if there is an error during retrieval.
        """
        # Log a debug message to indicate that the function is being executed
        general_logger.debug("Attempting to retrieve the device version from the device connection.")

        try:
            device_version = self.get_device_version()
            # Log an informational message with the retrieved device version
            general_logger.info(f"Got device version: {device_version}")
            
            # Return the retrieved device version
            return device_version
        
        except Exception as err:
            # Log a critical error message if an exception occurs during version retrieval
            general_logger.critical(f"Could not retrieve platform version. Reason: {err}")
            
            # Exit the program with status code 1 to indicate a critical failure
            sys.exit(1)
        
    def create_py_object(self, object_type, object_entry, object_container):
        """
        Create a Python object based on the specified object type and entry, for the provided object container.

        This method matches the provided object type with predefined constants and calls the appropriate method to 
        create and return the corresponding object. 

        Parameters:
            object_type (str): The type of the object to create.
            object_entry (dict): The entry data used to initialize the object.
            object_container (ObjectContainer): The container used to manage objects.

        Returns:
            object: The created Python object based on the object type.

        Raises:
            ValueError: If the object type does not match any of the predefined types.
        """
        # Match the object_type with predefined constants and return the corresponding object
        match object_type:
            case gvars.security_zone_container:
                # Return a security zone container object
                return self.return_zone_container_object(object_entry)
            
            case gvars.managed_device_container:
                # Return a managed device container object
                return self.return_managed_device_container_object(object_entry)
            
            case gvars.object_containers:
                # Return a generic object container object
                return self.return_object_container_object(object_entry)
            
            case gvars.security_policy_container:
                # Return a security policy container object
                return self.return_security_policy_container_object(object_entry)
            
            case gvars.nat_policy_container:
                # Return a NAT policy container object
                return self.return_nat_policy_container_object(object_entry)
            
            case gvars.security_zone:
                # Return a security zone object
                return self.return_security_zone_object(object_container, object_entry)
            
            case gvars.managed_device:
                # Return a managed device object
                return self.return_managed_device(object_container, object_entry)
            
            case gvars.network_object:
                # Return a network object
                return self.return_network_object(object_container, object_entry)
            
            case gvars.network_group_object:
                # Return a network group object
                return self.return_network_group_object(object_container, object_entry)
            
            case gvars.port_object:
                # Return a port object
                return self.return_port_object(object_container, object_entry)
            
            case gvars.port_group_object:
                # Return a port group object
                return self.return_port_group_object(object_container, object_entry)
            
            case gvars.url_object:
                # Return a URL object
                return self.return_url_object(object_container, object_entry)
            
            case gvars.url_group_object:
                # Return a URL group object
                return self.return_url_group_object(object_container, object_entry)
            
            case gvars.schedule_object:
                # Return a schedule object
                return self.return_schedule_object(object_container, object_entry)
            
            case gvars.security_policy:
                # Return a security policy object
                return self.return_security_policy_object(object_container, object_entry)
            
            case _:
                # Raise an error if the object type does not match any known type
                raise ValueError(f"Unknown object type: {object_type}")

    def get_container_info_from_device_conn(self, container_type):
        """
        Retrieve information about containers from the security device and process it.

        This function retrieves information about containers of the specified type from the security device. It processes the retrieved
        information, creates Python objects for each container, and saves them to the database. The function handles different container types,
        including nested containers, and provides logging and error handling.

        Parameters:
            container_type (str): The type of containers to retrieve information for. Examples include 'object_containers', 'security_policy_container', etc.

        Returns:
            set: A set of container objects that were created and processed.

        Raises:
            ValueError: If the provided container_type is unknown.
        """
        # Log the start of the process, including the type of container being imported
        general_logger.info(f"Importing configuration of the device containers. Container type: <{container_type}>")
        
        try:
            # Match the container_type with predefined constants and retrieve the relevant container information
            match container_type:
                case gvars.security_policy_container:
                    containers_info = self.return_security_policy_container_info()
                case gvars.security_zone_container:
                    containers_info = self.return_zone_container_info()
                case gvars.managed_device_container:
                    containers_info = self.return_managed_device_container_info()
                case gvars.object_containers:
                    containers_info = self.return_object_container_info()
                case gvars.nat_policy_container:
                    containers_info = self.return_nat_container_object()
                case _:
                    raise ValueError(f"Unknown container type: {container_type}")
        
        except Exception as err:
            # Log a critical error if an exception occurs during retrieval
            general_logger.critical(f"Could not retrieve container info. Reason: <{err}>")
            sys.exit(1)

        # Initialize a set to store container objects
        container_objects = set()

        if containers_info is not None:
            for container_entry in containers_info:
                # Create a Python object for each container entry
                current_container = self.create_py_object(container_type, container_entry, object_container=None)
                
                # Log the name of the current container being processed
                general_logger.info(f"Processing <{container_type}> container. Name: <{current_container.parent_name}>")
                
                # Log the parent container information
                parent_container_name = current_container.parent_name
                general_logger.info(f"<{current_container.parent_name}> is a child container. Its parent is: <{parent_container_name}>.")
                
                # Add the container object to the set
                container_objects.add(current_container)

            # Log the completion of container processing and start inserting them into the database
            general_logger.info(f"Finished processing all containers of type <{container_type}>. I will now start inserting them in the db.")
            
            # Create a mapping from parent container names to their corresponding objects
            parent_name_to_object = {container.name: container for container in container_objects}

            for container in container_objects:
                # Set the parent container if applicable
                parent_name = container.parent_name
                if parent_name:
                    parent_container = parent_name_to_object.get(parent_name)
                    if parent_container:
                        container.parent = parent_container
                
                # Save the container object to the database
                container.save(self._db)
        
        return container_objects

    def get_object_info_from_device_conn(self, object_type, object_container):
        """
        Retrieve and process information about objects from the security device.

        This function retrieves information about objects of the specified type from the security device. Depending on the type of object, 
        it processes and saves the information into the database. For group objects, additional relationships are created.

        Parameters:
            object_type (str): The type of objects to retrieve information for. Examples include 'security_zone', 'managed_device', etc.
            object_container: The container object used for processing specific types of objects. Its usage depends on the object_type.

        Returns:
            None
        """
        # Retrieve the object information based on the provided object_type
        match object_type:
            case gvars.security_zone:
                objects_info = self.return_security_zone_info()
            case gvars.managed_device:
                objects_info = self.return_managed_device_info()
            case gvars.network_object:
                objects_info = self.return_network_object_info()
            case gvars.network_group_object:
                objects_info = self.return_network_group_object_info()
            case gvars.port_object:
                objects_info = self.return_port_object_info()
            case gvars.port_group_object:
                objects_info = self.return_port_group_object_info()
            case gvars.url_object:
                objects_info = self.return_url_object_info()
            case gvars.url_group_object:
                objects_info = self.return_url_group_object_info()
            case gvars.schedule_object:
                objects_info = self.return_schedule_object_info()
            case gvars.security_policy:
                objects_info = self.return_security_policy_info(object_container)
            case _:
                raise ValueError(f"Unknown object type: {object_type}")

        if objects_info is not None:
            if 'group' not in object_type:
                # Process and save individual objects to the database
                for object_entry in objects_info:
                    security_device_object = self.create_py_object(object_type, object_entry, object_container)
                    security_device_object.save(self.db)
            else:
                # Process and save group objects to the database
                group_objects = []
                for object_entry in objects_info:
                    security_device_object = self.create_py_object(object_type, object_entry, object_container)
                    security_device_object.save(self.db)
                    group_objects.append(security_device_object)

                # Preload data for group objects
                preloaded_object_data = PioneerDatabase.preload_object_data(object_type, self.db)

                # Create relationships for group objects in the database
                for group_object in group_objects:
                    group_object.create_relationships_in_db(self.db, preloaded_object_data)

    # these functions are overridden in the subclasses whenever needed/relevant
    def return_object_container_info(self):
        return ["container"]

    def return_managed_device_container_info(self):
        return ["container"]
    
    def return_zone_container_info(self):
        return ["container"]
    
    def return_security_policy_container_info(self):
        return ["container"]

    def return_nat_container_object(self):
        return ["container"]

    def get_general_data(self, column, name_col=None, val=None, order_param=None):
        """
        Retrieve a specific piece of data from the general data table.

        This method fetches data from the general data table based on the specified column and optional parameters.
        It retrieves the first value of the specified column from the query result.

        Parameters:
            column (str): The name of the column from which to retrieve data.
            name_col (str, optional): The name of the column used for filtering results. Default is None.
            val (str, optional): The value used to filter the results. Default is None.
            order_param (str, optional): The column name used to order the results. Default is None.

        Returns:
            The first value of the specified column from the query result.
        """
        # Query the general data table to get the data
        result = self.db.general_data_table.get(column, name_col, val, order_param)
        
        # Return the first value of the first row from the result
        return result[0][0] if result else None

class APISecurityDevice(SecurityDevice):
    def __init__(self, user, db, password, host, port):
        """
        Initialize an API Security Device.

        Args:
            user (str): The username for the security device.
            db (str): The db name for the security device.
            password (str): The password for the security device.
            host (str): The hostname of the security device.
            port (int): The port number for connecting to the security device.
        """
        super().__init__(user, db, password, host, port)
