from abc import abstractmethod
from pkg import PioneerDatabase, GeneralDataTable, SecurityPolicyContainersTable, NATPolicyContainersTable, ObjectContainersTable, SecurityPoliciesTable, \
PoliciesHitcountTable, SecurityZonesTable, URLObjectsTable, URLObjectGroupsTable, NetworkAddressObjectsTable, NetworkAddressObjectGroupsTable, \
GeolocationObjectsTable, PortObjectsTable, ICMPObjectsTable, PortObjectGroupsTable, ScheduleObjectsTable, ManagedDevicesTable, ManagedDevice
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
    def __init__(self, name, DeviceDatabase, DeviceConnection):
        """
        Initialize a SecurityDevice instance.

        Parameters:
        - name (str): The name of the security device.
        - DeviceDatabase (Database): An instance of the database for the security device.
        """
        self._name = name
        self._Database = DeviceDatabase
        self._DeviceConnection = DeviceConnection
    
    def set_DeviceConnection(self, Connection):
        self._DeviceConnection = Connection
    
    def save_general_info(self, security_device_name, security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain):
        GeneralDataTable = self._Database.get_general_data_table()
        GeneralDataTable.insert(security_device_name, security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain)

    def set_database(self, Database):
        self._Database = Database

    def create_container(self, container_name, container_type):
        match container_type:
            case "security_policies_container":
                container = self.return_security_policy_container(container_name)
            case "objects_container":
                container = self.return_objects_container()
        
        return container
    
    def create_device_object(object_type):
        pass

    def get_policy_info(self, container_name, policy_type):
        policy_info = None
        match policy_type:
            case 'security_policy':
                policy_info = self.return_security_policies_info(container_name)
            # case 'nat_policy':
            #     policy_info = self.return_nat_policy_info()
        
        return policy_info

    def create_policy(self, policy_type, policy_entry):
        match policy_type:
            case 'security_policy':
                policy = self.create_security_policy(policy_entry)
        
        return policy

    def get_container_info_from_device_conn(self, containers_list, container_type):
        """
        Retrieve information about containers from the security device.
        The purpose of this function is to provide a flexible and robust mechanism for retrieving information about containers from a security device,
        processing it, and returning the processed information in a structured format.
        It handles different types of containers, and can handle nested containers with parent-child relationships.
        Additionally, it includes logging and error handling to ensure smooth execution and provide informative messages in case of errors.

        Parameters:
        - containers_list (list): List of container names passed by the user to retrieve information for.
        - container_type (str): Type of containers to retrieve information for. E.g: object, security policy containers

        Returns:
        - list: List of processed container information.
        """
        general_logger.info(f"################## Importing configuration of the device containers. Container type: <{container_type}> ##################")

        for container_name in containers_list:
            try:
                CurrentContainer = self.create_container(container_name, container_type)
                CurrentContainer.set_name()
                CurrentContainer.set_parent()
                CurrentContainer.set_security_device_name(self._name)

                general_logger.info(f"I am now processing the <{container_type}> container, name: <{container_name}>")
                # Check if the current container has parent containers
                while CurrentContainer.is_child_container():
                    CurrentContainer.set_name()
                    CurrentContainer.set_parent()
                    CurrentContainer.set_security_device_name(self._name)

                    # Retrieve the parent container name
                    parent_container_name = CurrentContainer.get_parent()
                    general_logger.info(f"<{CurrentContainer.get_name()}> is a CHILD container. Its parent is: <{parent_container_name}>.")
                    try:
                        # Retrieve the parent container object using the same retrieval function
                        ParentContainer = self.create_container(parent_container_name, container_type)

                        # save the current container in the database
                        CurrentContainer.save(self._Database)

                        # Set the parent container as the current container for the next iteration
                        CurrentContainer = ParentContainer
                    except Exception as e:
                        general_logger.error(f"Error retrieving parent container: <{parent_container_name}>. Reason: <{e}>")
                        break  # Break out of the loop if there's an error retrieving the parent container

                # If we break out of the loop, then it means we reached the highest parent in the hierarchy
                # We also need to get the data for it
                else:
                    CurrentContainer.set_name()
                    CurrentContainer.set_parent()
                    CurrentContainer.set_security_device_name(self._name)
                    general_logger.info(f"Finished processing all children. <{CurrentContainer.get_name()}> is the highest container in the parent-child hierarchy.")
                    CurrentContainer.save(self._Database)

            except Exception as err:
                general_logger.error(f"Could not retrieve info regarding the container <{container_name}>. Reason: <{err}>")
                sys.exit(1)

        general_logger.info(f"I have finished completely processing <{container_type}> container, name: <{container_name}>.")

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

    def get_policy_info_from_device_conn(self, policy_type, policy_containers_list):
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

    def get_managed_devices_info_from_device_conn(self):
        """
        Retrieve information about managed devices.

        Returns:
            list: List of dictionaries containing information about managed devices.
        """
        # Log a debug message indicating that the function is called
        # Log an informational message indicating that managed devices info retrieval is initiated        
        try:
            # Attempt to retrieve managed devices info from the security device connection
            # return a ManagedDevices object here
            managed_devices_info = self.get_managed_devices_info()
            general_logger.debug(f"Raw managed devices info: <{managed_devices_info}>.")
        except Exception as err:
            # Log a critical error message if managed devices retrieval fails and exit the program
            general_logger.critical(f"Could not retrieve managed devices. Reason: <{err}>")
            sys.exit(1)
        
        # Iterate over each managed device entry in the retrieved managed devices info
        for managed_device_entry in managed_devices_info:
            # return an object here for each of the entries
            ManagedDeviceObj = self.create_managed_device(managed_device_entry)
            # set all the attributes of the object
            ManagedDeviceObj.set_attributes()
            # save it in the database
            ManagedDeviceObj.save(self._Database)
    
    def get_object_info_from_device_conn(self, object_type):
        """
        Retrieve information about objects of a specified type from the security device. It defines a dictionary mapping object types to functions retrieving objects
        It then retrieves objects of the specified type using the dictionary, processes each retrieved object, appends the processed objects to a list,
        and finally returns the list of processed objects.

        Args:
            object_type (str): Type of objects to retrieve information for.

        Returns:
            list: List of processed objects.
        """
        # Log a debug message indicating that the function is called
        # Define a dictionary mapping object types to functions retrieving objects
        match object_type:
            case 'network_objects':
                self.fetch_objects_info('network_objects')
                object_names = self.get_db_objects('network_objects')
                processed_objects_dict = {
                    "network_objects": [],
                    "network_group_objects": [],
                    "geolocation_objects": []
                }
                
            case 'port_objects':
                self.fetch_objects_info('port_objects')
                object_names = self.get_db_objects('port_objects')
                processed_objects_dict = {
                    "port_objects": [],
                    "icmp_port_objects": [],
                    "port_group_objects": []
                }
            
            case 'url_objects':
                self.fetch_objects_info('url_objects')
                object_names = self.get_db_objects('url_objects')
                processed_objects_dict = {
                    "url_objects": [],
                    "url_group_objects": []
                }                
        #TODO: proper support for schedule objects, users and l7 apps
        object_type_mapping = {
            'network_objects': self.return_network_objects,
            'port_objects': self.return_port_objects,
            # 'schedule_objects': self.return_schedule_objects(),
            # 'policy_users': self.return_policy_users(),
            'url_objects': self.return_url_objects,
            # 'app_objects': self.return_app_objects()
        }

        # Retrieve the function corresponding to the specified object type
        retrieve_function = object_type_mapping.get(object_type)

        if retrieve_function is None:
            return []  # Or raise an error if necessary

        # Call the function to retrieve objects of the specified type
        retrieved_objects_list = retrieve_function(object_names)

        general_logger.info(f"################## Importing object configuration. Object type is: <{object_type}>. ##################")        
        # Process retrieved objects
        for RetrievedObject in retrieved_objects_list:
            general_logger.info(f"Processing object: <{RetrievedObject.get_name()}. Object type is: <{object_type}>")
            general_logger.debug(f"Raw object info: <{RetrievedObject.get_info()}>")
            # Process the retrieved object
            processed_object_info = RetrievedObject.process_object()
            # Append the processed object to the corresponding list based on its type
            if isinstance(RetrievedObject, NetworkObject):
                processed_objects_dict["network_objects"].append(processed_object_info)
            elif isinstance(RetrievedObject, NetworkGroupObject):
                processed_objects_dict["network_group_objects"].append(processed_object_info)
            elif isinstance(RetrievedObject, GeolocationObject):
                processed_objects_dict["geolocation_objects"].append(processed_object_info)
            elif isinstance(RetrievedObject, PortObject):
                processed_objects_dict["port_objects"].append(processed_object_info)
            elif isinstance(RetrievedObject, ICMPObject):
                processed_objects_dict["icmp_port_objects"].append(processed_object_info)
            elif isinstance(RetrievedObject, PortGroupObject):
                processed_objects_dict["port_group_objects"].append(processed_object_info)
            elif isinstance(RetrievedObject, URLObject):
                processed_objects_dict["url_objects"].append(processed_object_info)
            elif isinstance(RetrievedObject, URLGroupObject):
                processed_objects_dict["url_group_objects"].append(processed_object_info)

            general_logger.info(f"Processed object: <{RetrievedObject.get_name()}. Object type is: <{object_type}>")
            general_logger.debug(f"Processed object info: <{processed_object_info}>")
        
        # Return the dictionary of processed objects
        return [processed_objects_dict]

    @abstractmethod
    def create_managed_device(self, managed_device_entry):
        pass

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

    def insert_into_network_address_objects_table(self, network_objects_data):
        """
        Insert network address objects data into the 'network_address_objects_table'.

        Parameters:
        - network_objects_data (list): List of dictionaries containing network address objects information.

        Returns:
        None
        """
        for current_object_entry in network_objects_data:
            # Extract data from the current network address object entry
            network_address_name = current_object_entry['network_address_name']

            # Check for duplicates before insertion
            if self.verify_duplicate('network_address_objects_table', 'network_address_name', network_address_name):
                general_logger.warn(f"Duplicate entry for network address object: <{network_address_name}>. Skipping insertion.")
                continue

            object_container_name = current_object_entry['object_container_name']
            network_address_value = current_object_entry['network_address_value']
            network_address_description = current_object_entry['network_address_description']
            network_address_type = current_object_entry['network_address_type']
            is_overridable_object = current_object_entry['overridable_object']

            # SQL command to insert data into the 'network_address_objects_table'
            insert_command = """
                INSERT INTO network_address_objects_table (
                    network_address_name, 
                    security_device_name, 
                    object_container_name,
                    network_address_value, 
                    network_address_description, 
                    network_address_type, 
                    overridable_object
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s
                )
            """

            # Values to be inserted into the table
            values = (
                network_address_name,
                self._name,
                object_container_name,
                network_address_value,
                network_address_description,
                network_address_type,
                is_overridable_object
            )

            # Execute the insert command with the specified values
            self._Database.insert_table_value('network_address_objects_table', insert_command, values)

    def insert_into_network_address_object_groups_table(self, network_group_objects_data):
        """
        Insert network address object groups data into the 'network_address_objects_table'.

        Parameters:
        - network_group_objects_data (list): List of dictionaries containing network address object groups information.

        Returns:
        None
        """
        for current_group_object_entry in network_group_objects_data:
            # Extract data from the current network address object group entry
            network_address_group_name = current_group_object_entry['network_address_group_name']
            # Check for duplicates before insertion
            if self.verify_duplicate('network_address_object_groups_table', 'network_address_group_name', network_address_group_name):
                general_logger.warn(f"Duplicate entry for network address object group: <{network_address_group_name}>. Skipping insertion.")
                continue
            
            object_container_name = current_group_object_entry['object_container_name']
            network_address_group_members = current_group_object_entry['network_address_group_members']
            network_address_group_members = "{" + ",".join(network_address_group_members) + "}"
            network_address_description = current_group_object_entry['network_address_group_description']
            is_overridable_object = current_group_object_entry['overridable_object']

            # SQL command to insert data into the 'network_address_objects_table'
            insert_command = """
                INSERT INTO network_address_object_groups_table (
                    network_address_group_name, 
                    security_device_name,
                    object_container_name, 
                    network_address_group_members,
                    network_address_group_description, 
                    overridable_object
                ) VALUES (
                    %s, %s, %s, %s, %s, %s
                )
            """

            # Values to be inserted into the table
            values = (
                network_address_group_name,
                self._name,
                object_container_name,
                network_address_group_members,
                network_address_description,
                is_overridable_object
            )

            # Execute the insert command with the specified values
            self._Database.insert_table_value('network_address_object_groups_table', insert_command, values)

    def insert_into_security_policy_containers_table(self, containers_data):
        """
        Insert values into the 'security_policy_containers_table' table.

        Parameters:
        - containers_data (list): List of dictionaries containing security policy container information.

        Returns:
        None
        """
        for container_entry in containers_data:
            # Extract data from the current security policy container entry
            container_name = container_entry['security_policy_container_name']
            container_parent = container_entry['security_policy_parent']

            # Check for duplicates before insertion
            if self.verify_duplicate('security_policy_containers_table', 'security_policy_container_name', container_name):
                general_logger.warn(f"Duplicate entry for container: <{container_name}>. Skipping insertion.")
                continue

            # SQL command to insert data into the 'security_policy_containers_table'
            insert_command = """
                INSERT INTO security_policy_containers_table (
                    security_device_name, 
                    security_policy_container_name, 
                    security_policy_container_parent
                ) VALUES (
                    %s, %s, %s
                )
            """

            # Values to be inserted into the table
            values = (
                self._name,
                container_name,
                container_parent
            )

            # Execute the insert command with the specified values
            self._Database.insert_table_value('security_policy_containers_table', insert_command, values)

    def insert_into_geolocation_table(self, geolocation_object_data):
        """
        Insert values into the 'geolocation_objects_table' table.

        Parameters:
        - geolocation_object_data (list): List of dictionaries containing geolocation object information.

        Returns:
        None
        """
        for geo_entry in geolocation_object_data:
            # Extract data from the current geolocation object entry
            geo_name = geo_entry.get('geolocation_object_name', None)
            container_name = geo_entry.get('object_container_name', None)
            continent_names = [geo_entry.get('continent_member_names', [])]
            country_names = [geo_entry.get('country_member_names', [])]
            country_alpha2 = [geo_entry.get('country_member_alpha2_codes', [])]
            country_alpha3 = [geo_entry.get('country_member_alpha3_codes', [])]
            country_numeric = [geo_entry.get('country_member_numeric_codes', [])]

            # Check for duplicates before insertion
            if self.verify_duplicate('geolocation_objects_table', 'geolocation_object_name', geo_name):
                general_logger.warn(f"Duplicate entry for geolocation object: <{geo_name}>. Skipping insertion.")
                continue

            # SQL command to insert data into the 'geolocation_objects_table'
            insert_command = """
                INSERT INTO geolocation_objects_table (
                    geolocation_object_name,
                    security_device_name,
                    object_container_name,
                    continent_member_names,
                    country_member_names,
                    country_member_alpha2_codes,
                    country_member_alpha3_codes,
                    country_member_numeric_codes
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s
                )
            """

            # Values to be inserted into the table
            values = (
                geo_name,
                self._name,
                container_name,
                continent_names,
                country_names,
                country_alpha2,
                country_alpha3,
                country_numeric
            )

            # Execute the insert command with the specified values
            self._Database.insert_table_value('geolocation_objects_table', insert_command, values)

    def verify_duplicate(self, table, column, value):
        general_logger.info(f"Verifying duplicate in table {table}, column {column}, for value {value}.")
        """
        Verify if a duplicate entry exists in the specified table and column.

        Args:
            table (str): Name of the table to check for duplicates.
            column (str): Name of the column to check for duplicates.
            value (str): Value to check for duplicate entries in the specified column.

        Returns:
            bool: True if a duplicate entry exists, False otherwise.
        """
        # Use parameterized query to prevent SQL injection
        select_command = "SELECT EXISTS(SELECT 1 FROM {} WHERE {} = %s);".format(table, column)

        # Execute the parameterized query and get the result
        is_duplicate = self._Database.get_table_value(table, select_command, (value,))
        general_logger.info(f"Verified duplicate in table {table}, column {column}, for value {value}. Result is {is_duplicate}")

        # Return the result as a boolean
        return is_duplicate[0][0]
    
    def insert_into_port_objects_table(self, port_object_data):
        """
        Insert values into the 'port_objects_table' table.

        Parameters:
        - port_object_data (list): List of dictionaries containing port object information.

        Returns:
        None
        """
        for port_entry in port_object_data:
            # Extract data from the current port object entry
            port_name = port_entry['port_name']
            object_container_name = port_entry['object_container_name']
            port_protocol = port_entry.get('port_protocol')
            port_number = port_entry.get('port_number')
            port_description = port_entry.get('port_description')
            overridable_object = port_entry.get('overridable_object')

            # Check for duplicates before insertion
            if self.verify_duplicate('port_objects_table', 'port_name', port_name):
                general_logger.warn(f"Duplicate entry for port object: <{port_name}>. Skipping insertion.")
                continue

            # SQL command to insert data into the 'port_objects_table'
            insert_command = """
                INSERT INTO port_objects_table (
                    port_name, 
                    security_device_name, 
                    object_container_name, 
                    port_protocol, 
                    port_number, 
                    port_description, 
                    overridable_object
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s
                )
            """

            # Values to be inserted into the table
            values = (
                port_name,
                self._name,
                object_container_name,
                port_protocol,
                port_number,
                port_description,
                overridable_object
            )

            # Execute the insert command with the specified values
            self._Database.insert_table_value('port_objects_table', insert_command, values)

    def insert_into_icmp_objects_table(self, icmp_object_data):
        """
        Insert values into the 'icmp_objects_table' table.

        Parameters:
        - icmp_object_data (list): List of dictionaries containing ICMP object information.

        Returns:
        None
        """
        for icmp_entry in icmp_object_data:
            # Extract data from the current ICMP object entry
            icmp_name = icmp_entry['icmp_name']
            object_container_name = icmp_entry['object_container_name']
            icmp_type = icmp_entry.get('icmp_type')
            icmp_code = icmp_entry.get('icmp_code')
            icmp_description = icmp_entry.get('icmp_description')
            overridable_object = icmp_entry.get('overridable_object')

            # Check for duplicates before insertion
            if self.verify_duplicate('icmp_objects_table', 'icmp_name', icmp_name):
                general_logger.warn(f"Duplicate entry for ICMP object: <{icmp_name}>. Skipping insertion.")
                continue

            # SQL command to insert data into the 'icmp_objects_table'
            insert_command = """
                INSERT INTO icmp_objects_table (
                    icmp_name, 
                    security_device_name, 
                    object_container_name, 
                    icmp_type, 
                    icmp_code, 
                    icmp_description, 
                    overridable_object
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s
                )
            """

            # Values to be inserted into the table
            values = (
                icmp_name,
                self._name,
                object_container_name,
                icmp_type,
                icmp_code,
                icmp_description,
                overridable_object
            )

            # Execute the insert command with the specified values
            self._Database.insert_table_value('icmp_objects_table', insert_command, values)

    def insert_into_port_object_groups_table(self, port_object_group_data):
        """
        Insert values into the 'port_object_groups_table' table.

        Parameters:
        - port_object_group_data (list): List of dictionaries containing port object group information.

        Returns:
        None
        """
        for group_entry in port_object_group_data:
            # Extract data from the current port object group entry
            port_group_name = group_entry['port_group_name']
            object_container_name = group_entry['object_container_name']
            port_group_members = group_entry.get('port_group_members')
            port_group_description = group_entry.get('port_group_description')
            overridable_object = group_entry.get('overridable_object')

            # Check for duplicates before insertion
            if self.verify_duplicate('port_object_groups_table', 'port_group_name', port_group_name):
                general_logger.warn(f"Duplicate entry for port object group: <{port_group_name}>. Skipping insertion.")
                continue

            # SQL command to insert data into the 'port_object_groups_table'
            insert_command = """
                INSERT INTO port_object_groups_table (
                    port_group_name, 
                    security_device_name, 
                    object_container_name, 
                    port_group_members, 
                    port_group_description, 
                    overridable_object
                ) VALUES (
                    %s, %s, %s, %s, %s, %s
                )
            """

            # Values to be inserted into the table
            values = (
                port_group_name,
                self._name,
                object_container_name,
                port_group_members,
                port_group_description,
                overridable_object
            )

            # Execute the insert command with the specified values
            self._Database.insert_table_value('port_object_groups_table', insert_command, values)

    def insert_into_url_objects_table(self, url_objects_data):
        """
        Insert values into the 'url_object_groups_table' table.

        Parameters:
        - url_object_group_data (list): List of dictionaries containing URL object group information.

        Returns:
        None
        """
        for group_entry in url_objects_data:
            # Extract data from the current URL object group entry
            url_object_name = group_entry['url_object_name']
            object_container_name = group_entry['object_container_name']
            url_object_value = group_entry.get('url_value')  # Assuming it's a single value, not a list
            url_group_description = group_entry['url_object_description']

            # Check for duplicates before insertion
            if self.verify_duplicate('url_objects_table', 'url_object_name', url_object_name):
                general_logger.warn(f"Duplicate entry for URL object: <{url_object_name}>. Skipping insertion.")
                continue

            # SQL command to insert data into the 'url_objects_table'
            insert_command = """
                INSERT INTO url_objects_table (
                    url_object_name, 
                    security_device_name, 
                    object_container_name, 
                    url_value, 
                    url_object_description
                ) VALUES (
                    %s, %s, %s, %s, %s
                )
            """

            # Values to be inserted into the table
            values = (
                url_object_name,
                self._name,
                object_container_name,
                url_object_value,
                url_group_description
            )

            # Execute the insert command with the specified values
            self._Database.insert_table_value('url_objects_table', insert_command, values)

    def insert_into_url_object_groups_table(self, url_object_group_data):
        """
        Insert values into the 'url_object_groups_table' table.

        Parameters:
        - url_object_group_data (list): List of dictionaries containing URL object group information.

        Returns:
        None
        """
        for group_entry in url_object_group_data:
            # Extract data from the current URL object group entry
            url_object_group_name = group_entry['url_object_group_name']
            object_container_name = group_entry['object_container_name']
            url_object_members = group_entry['url_object_members']
            url_object_description = group_entry['url_group_object_description']

            # Check for duplicates before insertion
            if self.verify_duplicate('url_object_groups_table', 'url_object_group_name', url_object_group_name):
                general_logger.warn(f"Duplicate entry for URL object group: <{url_object_group_name}>. Skipping insertion.")
                continue

            # SQL command to insert data into the 'url_object_groups_table'
            insert_command = """
                INSERT INTO url_object_groups_table (
                    url_object_group_name, 
                    security_device_name, 
                    object_container_name, 
                    url_object_members, 
                    url_group_object_description
                ) VALUES (
                    %s, %s, %s, %s, %s
                )
            """

            # Values to be inserted into the table
            values = (
                url_object_group_name,
                self._name,
                object_container_name,
                url_object_members,
                url_object_description
            )

            # Execute the insert command with the specified values
            self._Database.insert_table_value('url_object_groups_table', insert_command, values)

        def delete_security_device(self):
            pass

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
