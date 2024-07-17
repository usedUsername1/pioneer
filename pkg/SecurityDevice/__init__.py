from abc import abstractmethod
from pkg import PioneerDatabase, GeneralDataTable, SecurityPolicyContainersTable, NATPolicyContainersTable, ObjectContainersTable, SecurityPoliciesTable, \
SecurityZonesTable, URLObjectsTable, NetworkAddressObjectsTable, \
GeolocationObjectsTable, CountryObjectsTable, PortObjectsTable, ICMPObjectsTable, ScheduleObjectsTable, ManagedDevicesTable, ManagedDeviceContainersTable, SecurityZoneContainersTable, \
NetworkGroupObjectsTable, PortGroupObjectsTable, URLGroupObjectsTable, NetworkGroupObjectsMembersTable, PortGroupObjectsMembersTable, URLGroupObjectsMembersTable, \
PolicyUsersTable, L7AppsTable, L7AppFiltersTable, L7AppGroupsTable, L7AppGroupMembersTable, URLCategoriesTable, SecurityPolicyZonesTable, SecurityPolicyNetworksTable, \
SecurityPolicyPortsTable, SecurityPolicyUsersTable, SecurityPolicyURLsTable, SecurityPolicyL7AppsTable, SecurityPolicyScheduleTable
import utils.helper as helper
import sys
import utils.gvars as gvars

general_logger = helper.logging.getLogger('general')
class SecurityDeviceDatabase(PioneerDatabase):
    """
    A class representing a database for security devices.
    """

    def __init__(self, cursor):
        """
        Initialize the SecurityDeviceDatabase instance.

        Args:
            cursor: The cursor object for database operations.
        """
        super().__init__(cursor)
        # General Data Table
        self._GeneralDataTable = GeneralDataTable(self)
        
        # Containers
        self._SecurityPolicyContainersTable = SecurityPolicyContainersTable(self)
        self._NATPolicyContainersTable = NATPolicyContainersTable(self)
        self._ObjectContainersTable = ObjectContainersTable(self)
        self._SecurityZoneContainersTable = SecurityZoneContainersTable(self)
        self._ManagedDeviceContainersTable = ManagedDeviceContainersTable(self)
        
        # Managed Devices
        self._ManagedDevicesTable = ManagedDevicesTable(self)
        
        # Security Policies
        self._SecurityPoliciesTable = SecurityPoliciesTable(self)
        
        # Zones
        self._SecurityZonesTable = SecurityZonesTable(self)
        
        # Objects
        self._URLObjectsTable = URLObjectsTable(self)
        self._NetworkAddressObjectsTable = NetworkAddressObjectsTable(self)
        self._PortObjectsTable = PortObjectsTable(self)
        self._ICMPObjectsTable = ICMPObjectsTable(self)
        self._GeolocationObjectsTable = GeolocationObjectsTable(self)
        self._CountryObjectsTable = CountryObjectsTable(self)
        self._ScheduleObjectsTable = ScheduleObjectsTable(self)
        
        # Groups
        self._NetworkGroupObjectsTable = NetworkGroupObjectsTable(self)
        self._PortGroupObjectsTable = PortGroupObjectsTable(self)
        self._URLGroupObjectsTable = URLGroupObjectsTable(self)
        
        # Group Members
        self._NetworkGroupObjectsMembersTable = NetworkGroupObjectsMembersTable(self)
        self._PortGroupObjectsMembersTable = PortGroupObjectsMembersTable(self)
        self._URLGroupObjectsMembersTable = URLGroupObjectsMembersTable(self)
        
        # Policy Users
        self._PolicyUsersTable = PolicyUsersTable(self)
        
        # Layer 7 Applications
        self._L7AppsTable = L7AppsTable(self)
        self._L7AppFiltersTable = L7AppFiltersTable(self)
        self._L7AppGroupsTable = L7AppGroupsTable(self)
        self._L7AppGroupMembersTable = L7AppGroupMembersTable(self)
        
        # URL Categories
        self._URLCategoriesTable = URLCategoriesTable(self)
        
        # Security Policy Details
        self._SecurityPolicyZonesTable = SecurityPolicyZonesTable(self)
        self._SecurityPolicyNetworksTable = SecurityPolicyNetworksTable(self)
        self._SecurityPolicyPortsTable = SecurityPolicyPortsTable(self)
        self._SecurityPolicyUsersTable = SecurityPolicyUsersTable(self)
        self._SecurityPolicyURLsTable = SecurityPolicyURLsTable(self)
        self._SecurityPolicyL7AppsTable = SecurityPolicyL7AppsTable(self)
        self._SecurityPolicyScheduleTable = SecurityPolicyScheduleTable(self)

    def create_security_device_tables(self):
        general_logger.info("Creating the PostgreSQL tables in device database.")
        self._GeneralDataTable.create()
        self._SecurityPolicyContainersTable.create()
        self._NATPolicyContainersTable.create()
        self._ObjectContainersTable.create()
        self._SecurityZoneContainersTable.create()
        self._ManagedDeviceContainersTable.create()
        self._ManagedDevicesTable.create()
        self._SecurityPoliciesTable.create()
        # self._PoliciesHitcountTable.create()
        self._SecurityZonesTable.create()
        self._URLObjectsTable.create()
        self._NetworkAddressObjectsTable.create()
        self._NetworkGroupObjectsTable.create()
        self._PortGroupObjectsTable.create()
        self._URLGroupObjectsTable.create()
        self._NetworkGroupObjectsMembersTable.create()
        self._PortGroupObjectsMembersTable.create()
        self._URLGroupObjectsMembersTable.create()
        self._GeolocationObjectsTable.create()
        self._CountryObjectsTable.create()
        self._PortObjectsTable.create()
        self._ICMPObjectsTable.create()
        self._ScheduleObjectsTable.create()
        self._PolicyUsersTable.create()
        self._L7AppsTable.create()
        self._L7AppFiltersTable.create()
        self._L7AppGroupsTable.create()
        self._L7AppGroupMembersTable.create()
        self._URLCategoriesTable.create()
        self._SecurityPolicyZonesTable.create()
        self._SecurityPolicyNetworksTable.create()
        self._SecurityPolicyPortsTable.create()
        self._SecurityPolicyUsersTable.create()
        self._SecurityPolicyURLsTable.create()
        self._SecurityPolicyL7AppsTable.create()
        self._SecurityPolicyScheduleTable.create()
    
    # Getter methods for each attribute
    def get_security_policy_zones_table(self):
        return self._SecurityPolicyZonesTable

    def get_security_policy_networks_table(self):
        return self._SecurityPolicyNetworksTable

    def get_security_policy_ports_table(self):
        return self._SecurityPolicyPortsTable

    def get_security_policy_users_table(self):
        return self._SecurityPolicyUsersTable

    def get_security_policy_urls_table(self):
        return self._SecurityPolicyURLsTable

    def get_security_policy_l7_apps_table(self):
        return self._SecurityPolicyL7AppsTable

    def get_security_policy_schedule_table(self):
        return self._SecurityPolicyScheduleTable

    def get_country_objects_table(self):
        return self._CountryObjectsTable
    
    def get_policy_user_objects_table(self):
        return self._PolicyUsersTable
    
    def get_url_category_objects_table(self):
        return self._URLCategoriesTable
    
    def get_l7_app_objects_table(self):
        return self._L7AppsTable
    
    def get_l7_app_filter_objects_table(self):
        return self._L7AppFiltersTable
    
    def get_l7_app_group_objects_table(self):
        return self._L7AppGroupsTable
    
    def get_l7_app_group_members_table(self):
        return self._L7AppGroupMembersTable

    def get_general_data_table(self):
        return self._GeneralDataTable

    def get_security_policy_containers_table(self):
        return self._SecurityPolicyContainersTable

    def get_object_containers_table(self):
        return self._ObjectContainersTable

    def get_zone_containers_table(self):
        return self._SecurityZoneContainersTable
    
    def get_managed_device_containers_table(self):
        return self._ManagedDeviceContainersTable

    def get_security_policies_table(self):
        return self._SecurityPoliciesTable

    def get_url_objects_table(self):
        return self._URLObjectsTable

    def get_network_address_objects_table(self):
        return self._NetworkAddressObjectsTable

    def get_geolocation_objects_table(self):
        return self._GeolocationObjectsTable

    def get_port_objects_table(self):
        return self._PortObjectsTable

    def get_icmp_objects_table(self):
        return self._ICMPObjectsTable

    def get_managed_devices_table(self):
        return self._ManagedDevicesTable
    
    def get_security_zones_table(self):
        return self._SecurityZonesTable

    def get_network_group_objects_table(self):
        return self._NetworkGroupObjectsTable

    def get_port_group_objects_table(self):
        return self._PortGroupObjectsTable

    def get_url_group_objects_table(self):
        return self._URLGroupObjectsTable

    def get_network_group_objects_members_table(self):
        return self._NetworkGroupObjectsMembersTable

    def get_port_group_objects_members_table(self):
        return self._PortGroupObjectsMembersTable

    def get_url_group_objects_members_table(self):
        return self._URLGroupObjectsMembersTable
    
    def get_schedule_objects_table(self):
        return self._ScheduleObjectsTable

class SecurityDevice:
    def __init__(self, uid, name, DeviceDatabase, DeviceConnection):
        """
        Initialize a SecurityDevice instance.

        Parameters:
        - name (str): The name of the security device.
        - DeviceDatabase (Database): An instance of the database for the security device.
        """
        self._uid = uid
        self._name = name
        self._Database = DeviceDatabase
        self._DeviceConnection = DeviceConnection
    
    def get_database(self):
        return self._Database
    
    def set_DeviceConnection(self, Connection):
        self._DeviceConnection = Connection
    
    def save_general_info(self, security_device_uid, security_device_name, security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain):
        GeneralDataTable = self._Database.get_general_data_table()
        GeneralDataTable.insert(security_device_uid, security_device_name, security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain)

    def set_database(self, Database):
        self._Database = Database

    def get_database(self):
        return self._Database

    def set_uid(self, uid):
        self._uid = uid

    def get_uid(self):
        return self._uid
    
    def get_name(self):
        return self._name
    
    def get_device_connection(self):
        return self._DeviceConnection 

    def get_device_version_from_device_conn(self):
        """
        Retrieve the version of the device's server using the established device connection.

        Returns:
            str: Version of the device's server.
        """
        # Log a debug message to indicate that the function is called

        try:
            # Attempt to retrieve the device version using the method get_device_version()
            device_version = self.get_device_version()
            
            # Log an informational message indicating that the device version is retrieved successfully
            general_logger.info(f"Got device version: <{device_version}>")
            
            # Return the retrieved device version
            return device_version
        except Exception as err:
            # Log a critical error message if there is an exception during the retrieval process
            general_logger.critical(f'Could not retrieve platform version. Reason: <{err}?')
            
            # Exit the program with status code 1 indicating a critical error
            sys.exit(1)
        
    def create_py_object(self, object_type, object_entry, ObjectContainer):
        match object_type:
            case 'security_zone_container':
                return self.return_zone_container(object_entry)
            case 'managed_device_container':
                return self.return_managed_device_container(object_entry)
            case 'object_container':
                return self.return_object_container(object_entry)
            case 'security_policy_container':
                return self.return_security_policy_container(object_entry)
            case 'security_zone':
                return self.return_security_zone(ObjectContainer, object_entry)
            case 'managed_device':
                return self.return_managed_device(ObjectContainer, object_entry)
            case 'network_object':
                return self.return_network_object(ObjectContainer, object_entry)
            case 'network_group_object':
                return self.return_network_group_object(ObjectContainer, object_entry)
            case 'geolocation_object':
                return self.return_geolocation_object(ObjectContainer, object_entry)
            case 'port_object':
                return self.return_port_object(ObjectContainer, object_entry)
            case 'port_group_object':
                return self.return_port_group_object(ObjectContainer, object_entry)
            case 'url_object':
                return self.return_url_object(ObjectContainer, object_entry)
            case 'url_group_object':
                return self.return_url_group_object(ObjectContainer, object_entry)
            case 'schedule_object':
                return self.return_schedule_object(ObjectContainer, object_entry)
            case 'security_policy_group':
                return self.return_security_policy_object(ObjectContainer, object_entry)

    def get_container_info_from_device_conn(self, container_type):
        """
        Retrieve information about containers from the security device.

        This function retrieves information about containers from a security device, processes it, and returns the processed information in a structured format.
        It handles different types of containers, including nested containers with parent-child relationships. Logging and error handling are included
        to ensure smooth execution and provide informative messages in case of errors.

        Parameters:
        - container_type (str): Type of containers to retrieve information for. E.g., object, security policy containers.

        """
        general_logger.info(f"Importing configuration of the device containers. Container type: <{container_type}>")
        
        try:
            match container_type:
                case 'security_policy_container':
                    containers_info = self.return_security_policy_container_info()
                case 'security_zone_container':
                    containers_info = self.return_zone_container_info()
                case 'managed_device_container':
                    containers_info = self.return_managed_device_container_info()
                case 'object_container':
                    containers_info = self.return_object_container_info()
                case _:
                    raise ValueError(f"Unknown container type: {container_type}")
        except Exception as err:
            general_logger.critical(f"Could not retrieve container info. Reason: <{err}>")
            sys.exit(1)

        container_objects = set()

        if containers_info is not None:
            for container_entry in containers_info:
                current_container = self.create_py_object(container_type, container_entry, ObjectContainer=None)

                current_container_name = current_container.get_parent_name()

                general_logger.info(f"Processing <{container_type}> container. Name: <{current_container_name}>")

                parent_container_name = current_container.get_parent_name()
                general_logger.info(f"<{current_container_name}> is a child container. Its parent is: <{parent_container_name}>.")

                container_objects.add(current_container)

            general_logger.info(f"Finished processing all containers of type <{container_type}>. I will now start inserting them in the database.")
            parent_name_to_object = {container.get_name(): container for container in container_objects}

            for Container in container_objects:
                parent_name = Container.get_parent_name()
                if parent_name:
                    ParentContainer = parent_name_to_object.get(parent_name)
                    if ParentContainer:
                        Container.set_parent(ParentContainer)

                Container.save(self._Database)
            
            return container_objects

    def get_object_info_from_device_conn(self, object_type, ObjectContainer):
        """
        Retrieve information about objects.

        Returns:
            list: List of dictionaries containing information about objects.
        """
        match object_type:
            case 'security_zone':
                objects_info = self.return_security_zone_info()
            case 'managed_device':
                objects_info = self.return_managed_device_info()
            case 'network_object':
                objects_info = self.return_network_object_info()
            case 'network_group_object':
                objects_info = self.return_network_group_object_info()
            case 'geolocation_object':
                objects_info = self.return_geolocation_object_info()
            case 'port_object':
                objects_info = self.return_port_object_info()
            case 'port_group_object':
                objects_info = self.return_port_group_object_info()
            case 'url_object':
                objects_info = self.return_url_object_info()
            case 'url_group_object':
                objects_info = self.return_url_group_object_info()
            case 'schedule_object':
                objects_info = self.return_schedule_object_info()
            # group is used here as a "flag" value. it marks the fact
            # that the security policies will be processed as object groups
            # also, only the security policies for a particular object container
            # specified by the user will be returned
            case 'security_policy_group':
                objects_info = self.return_security_policy_info(ObjectContainer)
        
        # cpu_usage, ram_usage = helper.get_usage()
        # print(f"CPU usage during retrieving objects <{object_type}>: {cpu_usage}%")
        # print(f"RAM usage during retrieving objects <{object_type}>: {ram_usage}%")
        # Iterate over each managed device entry in the retrieved objects info
        if objects_info is not None:
            if 'group' not in object_type:
                for object_entry in objects_info:
                    # return an object here for each of the entries
                    SecurityDeviceObject = self.create_py_object(object_type, object_entry, ObjectContainer)
                    # save it in the database
                    SecurityDeviceObject.save(self._Database)
            else:
                group_objects = []
                for object_entry in objects_info:
                    # return an object here for each of the entries
                    SecurityDeviceObject = self.create_py_object(object_type, object_entry, ObjectContainer)
                    # save it in the database)
                    SecurityDeviceObject.save(self._Database)
                    group_objects.append(SecurityDeviceObject)
                
                # the object type and the dictionary with name uid mapping being the value of the key
                Database = self.get_database()
                # preload the data
                preloaded_object_data = PioneerDatabase.preload_object_data(object_type, Database)

                for GroupObject in group_objects:
                    GroupObject.create_relationships_in_db(Database, preloaded_object_data)

    # these functions are overridden in the subclasses whenever needed/relevant
    def return_object_container_info(self):
        return ["container"]

    def return_managed_device_container_info(self):
        return ["container"]
    
    def return_zone_container_info(self):
        return ["container"]
    
    def return_security_policy_container_info(self):
        return ["container"]

    def get_general_data(self, column, name_col=None, val=None, order_param=None):
        return self._Database.get_general_data_table().get(column, name_col, val, order_param)[0][0]

class APISecurityDevice(SecurityDevice):
    def __init__(self, user, database, password, host, port):
        """
        Initialize an API Security Device.

        Args:
            user (str): The username for the security device.
            database (str): The database name for the security device.
            password (str): The password for the security device.
            host (str): The hostname of the security device.
            port (int): The port number for connecting to the security device.
        """
        general_logger.debug(f"Called APISecurityDevice::__init__().")
        super().__init__(user, database, password, host, port)
