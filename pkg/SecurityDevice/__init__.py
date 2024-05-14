from abc import abstractmethod
from pkg import PioneerDatabase, GeneralDataTable, SecurityPolicyContainersTable, NATPolicyContainersTable, ObjectContainersTable, SecurityPoliciesTable, \
PoliciesHitcountTable, SecurityZonesTable, URLObjectsTable, URLObjectGroupsTable, NetworkAddressObjectsTable, NetworkAddressObjectGroupsTable, \
GeolocationObjectsTable, PortObjectsTable, ICMPObjectsTable, PortObjectGroupsTable, ScheduleObjectsTable, ManagedDevicesTable, ManagedDeviceContainersTable, ZoneContainersTable
import utils.helper as helper
import json
import sys
import utils.gvars as gvars
from pkg.DeviceObject import NetworkObject, NetworkGroupObject, GeolocationObject, PortObject, PortGroupObject, ICMPObject, URLObject, URLGroupObject

general_logger = helper.logging.getLogger('general')
# TODO: instantiate the database table objects and create the tables in the database
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
        self._GeneralDataTable = GeneralDataTable(self)
        self._SecurityPolicyContainersTable = SecurityPolicyContainersTable(self)
        self._ObjectContainersTable = ObjectContainersTable(self)
        self._ZoneContainersTable = ZoneContainersTable(self)
        self._ManagedDeviceContainersTable = ManagedDeviceContainersTable(self)
        self._SecurityPoliciesTable = SecurityPoliciesTable(self)
        self._UrlObjectsTable = URLObjectsTable(self)
        self._UrlObjectGroupsTable = URLObjectGroupsTable(self)
        self._NetworkAddressObjectsTable = NetworkAddressObjectsTable(self)
        self._NetworkAddressObjectGroupsTable = NetworkAddressObjectGroupsTable(self)
        self._GeolocationObjectsTable = GeolocationObjectsTable(self)
        self._PortObjectsTable = PortObjectsTable(self)
        self._ICMPObjectsTable = ICMPObjectsTable(self)
        self._PortObjectGroupsTable = PortObjectGroupsTable(self)
        self._ManagedDevicesTable = ManagedDevicesTable(self)

    def create_security_device_tables(self):
        general_logger.info(f"Creating the PostgreSQL tables in device database.")
        self._GeneralDataTable.create()
        self._SecurityPolicyContainersTable.create()
        self._ObjectContainersTable.create()
        self._ZoneContainersTable.create()
        self._ManagedDeviceContainersTable.create()
        self._SecurityPoliciesTable.create()
        self._UrlObjectsTable.create()
        self._UrlObjectGroupsTable.create()
        self._NetworkAddressObjectsTable.create()
        self._NetworkAddressObjectGroupsTable.create()
        self._GeolocationObjectsTable.create()
        self._PortObjectsTable.create()
        self._ICMPObjectsTable.create()
        self._PortObjectGroupsTable.create()
        self._ManagedDevicesTable.create()

    def get_general_data_table(self):
        return self._GeneralDataTable

    def get_security_policy_containers_table(self):
        return self._SecurityPolicyContainersTable

    def get_object_containers_table(self):
        return self._ObjectContainersTable

    def get_zone_containers_table(self):
        return self._ZoneContainersTable
    
    def get_managed_device_containers_table(self):
        return self._ManagedDeviceContainersTable

    def get_security_policies_table(self):
        return self._SecurityPoliciesTable

    def get_url_objects_table(self):
        return self._UrlObjectsTable

    def get_url_object_groups_table(self):
        return self._UrlObjectGroupsTable

    def get_network_address_objects_table(self):
        return self._NetworkAddressObjectsTable

    def get_network_address_object_groups_table(self):
        return self._NetworkAddressObjectGroupsTable

    def get_geolocation_objects_table(self):
        return self._GeolocationObjectsTable

    def get_port_objects_table(self):
        return self._PortObjectsTable

    def get_icmp_objects_table(self):
        return self._ICMPObjectsTable

    def get_port_object_groups_table(self):
        return self._PortObjectGroupsTable

    def get_managed_devices_table(self):
        return self._ManagedDevicesTable

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
    
    def set_DeviceConnection(self, Connection):
        self._DeviceConnection = Connection
    
    def save_general_info(self, security_device_uid, security_device_name, security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain):
        GeneralDataTable = self._Database.get_general_data_table()
        GeneralDataTable.insert(security_device_uid, security_device_name, security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain)

    def set_database(self, Database):
        self._Database = Database

    def set_uid(self, uid):
        self._uid = uid

    def get_uid(self):
        return self._uid

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
        
    def create_py_object(self, object_type, object_entry):
        match object_type:
            case 'zone_container':
                return self.return_zone_container(object_entry)
            case 'managed_device_container':
                return self.return_managed_device_container(object_entry)
            case 'object_container':
                return self.return_object_container(object_entry)
            case 'security_policy_container':
                return self.return_security_policy_container(object_entry)
            case 'security_zone':
                return self.return_security_zone(object_entry)
            case 'managed_device':
                return self.return_managed_device(object_entry)

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
                case 'zone_container':
                    containers_info = self.return_zone_container_info()
                case 'managed_device_container':
                    containers_info = self.return_managed_device_container_info()
                case 'object_container':
                    containers_info = self.return_object_container_info()
        except Exception as err:
            # Log a critical error message if managed devices retrieval fails and exit the program
            general_logger.critical(f"Could not retrieve container info. Reason: <{err}>")
            sys.exit(1)

        # Set to store processed container names
        processed_containers = set()

        for container_entry in containers_info:
            CurrentContainer = self.create_py_object(container_type, container_entry)

            # Set name and parent for the current container
            CurrentContainer.set_name()
            CurrentContainer.set_parent()

            current_container_name = CurrentContainer.get_name()

            # Skip processing if the container is already processed
            if current_container_name in processed_containers:
                continue

            general_logger.info(f"Processing <{container_type}> container. Name: <{current_container_name}>")

            # Retrieve the parent container name
            parent_container_name = CurrentContainer.get_parent()
            general_logger.info(f"<{current_container_name}> is a child container. Its parent is: <{parent_container_name}>.")

            # Save the current container in the database
            CurrentContainer.save(self._Database)

            # Add the current container to the set of processed containers
            processed_containers.add(current_container_name)

        # Log completion message for all containers
        general_logger.info(f"Finished processing all containers of type <{container_type}>.")

    # TODO: merge the get_policy_info function here as well, add the container_list parameter. this container_list will, by default, be
    # should container_list be kept? should just a container name be used?
    # the problem is that there are cases where objects belong to a container and cases where objects belong to a device?
    def get_object_info_from_device_conn(self, object_type):
        """
        Retrieve information about managed devices.

        Returns:
            list: List of dictionaries containing information about managed devices.
        """
        match object_type:
            case 'security_zone':
                objects_info = self.return_security_zone_info()
            case 'managed_device':
                objects_info = self.return_managed_device_info()
        
        # Iterate over each managed device entry in the retrieved managed devices info
        for object_entry in objects_info:
            # return an object here for each of the entries
            SecurityDeviceObject = self.create_py_object(object_type, object_entry)
            # set all the attributes of the object
            SecurityDeviceObject.set_attributes()
            # save it in the database
            SecurityDeviceObject.save(self._Database)

    # these functions are overridden in the subclasses whenever needed/relevant
    def return_object_container_info(self):
        return "container"

    def return_managed_device_container_info(self):
        return "container"
    
    def return_zone_container_info(self):
        return "container"
    
    def return_security_policy_container_info(self):
        return "container"

    def get_policy_info_from_device_conn(self, policy_containers_list, policy_type):
        """
        Retrieve information about policies from the specified policy containers.

        Args:
            policy_containers_list (list): List of policy container names.

        Returns:
            list: List of dictionaries containing information about policies.
        """
        general_logger.info(f"################## Importing <{policy_type}>. ##################")
        # Iterate over each policy container name in the provided list
        for policy_container in policy_containers_list:
            policy_info = self.get_policy_info(policy_container, policy_type)
            # now loop through the policy info
            for policy_entry in policy_info:
                # and create the policy object
                Policy = self.create_policy(policy_type, policy_entry)
                
                # set the attributes of the policy
                Policy.set_attributes()

                # save the policy data in the database
                Policy.save(self._Database)
    
    # call the implementations of create_network_objects, create_port_objects, create_url_objects
    #TODO: uncomment all when done testing
    def migrate_config(self, SourceDevice):
        print("called migrate config")
        # # create the network objects
        network_object_names = SourceDevice.get_db_objects_from_table('network_address_name', 'network_address_objects_table')
        self.migrate_network_objects(network_object_names, SourceDevice)

        # # create the network group objects
        network_group_object_names = SourceDevice.get_db_objects_from_table('network_address_group_name', 'network_address_object_groups_table')
        self.migrate_network_group_objects(network_group_object_names, SourceDevice)

        # create the port objects
        port_object_names = SourceDevice.get_db_objects_from_table('port_name', 'port_objects_table')
        self.migrate_port_objects(port_object_names, SourceDevice)

        # # create the port group objects
        port_group_object_names = SourceDevice.get_db_objects_from_table('port_group_name', 'port_object_groups_table')
        self.migrate_port_group_objects(port_group_object_names, SourceDevice)

        # create the url objects
        url_object_names = SourceDevice.get_db_objects_from_table('url_object_name', 'url_objects_table')
        self.migrate_url_objects(url_object_names, SourceDevice, 'url_object')

        # # # create the url group objects
        url_group_object_names = SourceDevice.get_db_objects_from_table('url_object_group_name', 'url_object_groups_table')
        self.migrate_url_objects(url_group_object_names, SourceDevice, 'url_group')

        # # create the PA tags corresponding to the policy category
        categories = set(SourceDevice.get_db_objects_from_table('security_policy_category', 'security_policies_table'))
        self.migrate_tags(categories)
        
        # # create the policies
        # # retrieve the policies and order them by their security_policy_index
        security_policy_names = SourceDevice.get_db_objects_from_table_order_by('security_policy_name', 'security_policies_table', 'security_policy_index')
        self.migrate_security_policies(security_policy_names, SourceDevice)

    def get_general_data(self, column, name_col=None, val=None, order_param=None):
        return self._Database.get_general_data_table().get(column, name_col, val, order_param)[0][0]

    # the following functions process the data from the database. all the objects are processed, the unique values
    # are gathered and returned in a list that will be further processed by the program
    def get_db_objects(self, object_type):
        """
        Retrieve and return unique database objects based on the specified type.

        Args:
            object_type (str): The type of objects to retrieve. It should correspond to a column in the database.

        Returns:
            list: A list of unique objects of the specified type.
        Raises:
            ValueError: If the provided object type is not valid.
        """
        # Map object types to their respective columns in the database
        object_column_mapping = {
            'security_zone_objects': ['security_policy_source_zones', 'security_policy_destination_zones'],
            'network_objects': ['security_policy_source_networks', 'security_policy_destination_networks'],
            'port_objects': ['security_policy_source_ports', 'security_policy_destination_ports'],
            'schedule_objects': ['security_policy_schedules'],
            'policy_users': ['security_policy_users'],
            'url_objects': ['security_policy_urls'],
            'app_objects': ['security_policy_l7_apps'],
            'categories': ['security_policy_category']
        }

        # Validate the provided object type
        if object_type not in object_column_mapping:
            raise ValueError(f"Invalid object type: {object_type}")

        # Construct the SQL query
        columns = ", ".join(object_column_mapping[object_type])
        select_command = f"SELECT {columns} FROM security_policies_table;"

        # Execute the SQL query and fetch the results
        query_result = self._Database.get_table_value('security_policies_table', select_command)

        # Flatten the results so that the unique values can be returned
        unique_objects_list = self._Database.flatten_query_result(query_result)

        # Remove the 'any' element of the list, if it exists. It is not an object that can be imported
        element_to_remove = 'any'
        if element_to_remove in unique_objects_list:
            unique_objects_list.remove(element_to_remove)

        return unique_objects_list

    def get_db_objects_from_table(self, column, table):
        select_command = f"SELECT {column} FROM {table};"
        
        # Execute the SQL query and fetch the results
        query_result = self._Database.get_table_value(table, select_command)

        # Extract elements from tuples and flatten the list
        flattened_list = [item[0] for item in query_result]

        # Remove the 'any' element of the list, if it exists. It is not an object that can be imported
        if 'any' in flattened_list:
            flattened_list.remove('any')

        return flattened_list

    # def update_db_value(self, table, column, old_value, new_value)
    def update_db_value(self, table, column, old_value, new_value):
        
        update_query = f"""
            UPDATE {table}
            SET {column} = '{new_value}'
            WHERE {column} = '{old_value}';
        """

        self._Database.update_table_value(table, update_query)

    def set_policy_param(self, table, security_policy_name, column_name, new_value):
        update_query = f"""
            UPDATE {table}
            SET {column_name} = '{new_value}'
            WHERE security_policy_name = '{security_policy_name}';
        """

        self._Database.update_table_value(table, update_query)

    def set_port_members(self, table, port_group_name, column_name, new_value):
        update_query = f"""
            UPDATE {table}
            SET {column_name} = '{new_value}'
            WHERE port_group_name = '{port_group_name}';
        """

        self._Database.update_table_value(table, update_query)

    def set_url_group_members(self, url_members, url_group_name):
        update_query = f"""
            UPDATE url_object_groups_table
            SET url_object_members = '{url_members}'
            WHERE url_object_group_name = '{url_group_name}';
        """
        self._Database.update_table_value('url_object_groups_table', update_query)

    def update_array_value(self, table, column_name, old_value, new_value):

        update_query = f"""
            UPDATE {table}
            SET {column_name} = array_replace({column_name}, '{old_value}', '{new_value}')
            WHERE '{old_value}' = ANY({column_name})
        """
        self._Database.update_table_value(table, update_query)

    def get_policy_param(self, policy_name, param_column):
        select_query = f"select {param_column} from security_policies_table where security_policy_name = '{policy_name}'"
        # Execute the SQL query and fetch the results
        query_result = self._Database.get_table_value('security_policies_table', select_query)

        # Extract elements from tuples and flatten the list
        flattened_list = [item[0] for item in query_result]

        # Remove the 'any' element of the list, if it exists. It is not an object that can be imported
        if 'any' in flattened_list:
            flattened_list.remove('any')

        return flattened_list

    def remove_array_value(self, table, column_name, value_to_remove):
        update_query = f"""
            UPDATE {table}
            SET {column_name} = array_remove({column_name}, '{value_to_remove}')
            WHERE '{value_to_remove}' = ANY({column_name})
        """
        self._Database.update_table_value(table, update_query)

    def delete_referenced_objects(self, port_group_name):
        # Check if the specified port group exists in the array
        select_query = f"""
            SELECT security_policy_destination_ports 
            FROM security_policies_table 
            WHERE '{port_group_name}' = ANY(security_policy_destination_ports);
        """
        row = self._Database.get_table_value('security_policies_table', select_query)

        if row is None:
            print(f"No references found for {port_group_name}.")
            return
        
        destination_ports = row[0]
        
        if len(destination_ports) > 1:
            # Construct the SQL query to remove the specified element from the array
            delete_query = f"""
                UPDATE security_policies_table 
                SET security_policy_destination_ports = array_remove(security_policy_destination_ports, %s)
                WHERE '{port_group_name}' = ANY(security_policy_destination_ports);
            """
            # Execute the query with parameters
            self._Database.update_table_value('security_policies_table', delete_query)
            
        elif len(destination_ports) == 1:
            # If there's only one element, replace it with {any}
            uopdate_value = '{any}'
            update_query = f"""
                UPDATE security_policies_table 
                SET security_policy_destination_ports = '{uopdate_value}'
                WHERE '{port_group_name}' = ANY(security_policy_destination_ports);
            """
            # Execute the query with parameters
            self._Database.update_table_value('security_policies_table', update_query)
        
        # print(f"Reference to {port_group_name} deleted successfully.")

    def remove_port_group(self, port_group_name):

        delete_query = f""" delete from  port_object_groups_table where port_group_name = '{port_group_name}';"""

        self._Database.update_table_value('port_object_groups_table', delete_query)
    
    def get_port_group_members(self, table, name):
        select_command = f"SELECT port_group_members FROM port_object_groups_table WHERE port_group_name = '{name}';"

        # Execute the SQL query and fetch the results
        query_result = self._Database.get_table_value(table, select_command)

        # Extract elements from tuples and flatten the list
        flattened_list = [item[0] for item in query_result]

        # Remove the 'any' element of the list, if it exists. It is not an object that can be imported
        if 'any' in flattened_list:
            flattened_list.remove('any')

        return flattened_list

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
