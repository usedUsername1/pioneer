from abc import ABC, abstractmethod
from pkg import PioneerDatabase, DBConnection
from pkg.Container import Container
import utils.helper as helper
import utils.gvars as gvars
import json
import sys
from pkg.DeviceObject import Object, NetworkObject, GroupObject, NetworkGroupObject, GeolocationObject
# TODO: create all the tables for all the objects
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
        helper.logging.debug(f"Called SecurityDeviceDatabase::__init__().")
    
    def create_security_device_tables(self):
        """
        Create tables for security device data in the database.
        """
        helper.logging.debug("Called SecurityDeviceDatabase::create_security_device_tables().")
        helper.logging.info("Creating table: <general_data_table>.")
        self.table_factory("general_data_table")
        helper.logging.info("Created table: <general_data_table>.")
        helper.logging.info("Creating table: <security_policy_containers_table>.")
        self.table_factory("security_policy_containers_table")
        helper.logging.info("Created table: <security_policy_containers_table>.")

        helper.logging.info("Creating table: <nat_policy_containers_table>.")
        self.table_factory("nat_policy_containers_table")
        helper.logging.info("Created table: <nat_policy_containers_table>.")

        helper.logging.info("Creating table: <object_containers_table>.")
        self.table_factory("object_containers_table")
        helper.logging.info("Created table: <object_containers_table>.")

        helper.logging.info("Creating table: <security_policies_table>.")
        self.table_factory("security_policies_table")
        helper.logging.info("Created table: <security_policies_table>.")

        helper.logging.info("Creating table: <policies_hitcount_table>.")
        self.table_factory("policies_hitcount_table")
        helper.logging.info("Created table: <policies_hitcount_table>.")

        # Uncomment if needed
        # helper.logging.info("Creating table: <nat_policies_table>.")
        # self.table_factory("nat_policies_table")
        # helper.logging.info("Created table: <nat_policies_table>.")

        # helper.logging.info("Creating table: <user_source_table>.")
        # self.table_factory("user_source_table")
        # helper.logging.info("Created table: <user_source_table>.")

        # helper.logging.info("Creating table: <policy_users_table>.")
        # self.table_factory("policy_users_table")
        # helper.logging.info("Created table: <policy_users_table>.")

        helper.logging.info("Creating table: <security_zones_table>.")
        self.table_factory("security_zones_table")
        helper.logging.info("Created table: <security_zones_table>.")

        helper.logging.info("Creating table: <urls_table>.")
        self.table_factory("urls_table")
        helper.logging.info("Created table: <urls_table>.")

        # Uncomment if needed
        # helper.logging.info("Creating table: <urls_categories_table>.")
        # self.table_factory("urls_categories_table")
        # helper.logging.info("Created table: <urls_categories_table>.")

        # Uncomment if needed
        # helper.logging.info("Creating table: <l7_apps_table>.")
        # self.table_factory("l7_apps_table")
        # helper.logging.info("Created table: <l7_apps_table>.")

        helper.logging.info("Creating table: <network_address_objects_table>.")
        self.table_factory("network_address_objects_table")
        helper.logging.info("Created table: <network_address_objects_table>.")

        helper.logging.info("Creating table: <network_address_object_groups_table>.")
        self.table_factory("network_address_object_groups_table")
        helper.logging.info("Created table: <network_address_object_groups_table>.")

        helper.logging.info("Creating table: <port_objects_table>.")
        self.table_factory("port_objects_table")
        helper.logging.info("Created table: <port_objects_table>.")

        helper.logging.info("Creating table: <port_object_groups_table>.")
        self.table_factory("port_object_groups_table")
        helper.logging.info("Created table: <port_object_groups_table>.")

        helper.logging.info("Creating table: <schedule_objects_table>.")
        self.table_factory("schedule_objects_table")
        helper.logging.info("Created table: <schedule_objects_table>.")

        helper.logging.info("Creating table: <managed_devices_table>.")
        self.table_factory("managed_devices_table")
        helper.logging.info("Created table: <managed_devices_table>.")

        helper.logging.info("Creating table: <geolocation_objects_table>.")
        self.table_factory("geolocation_objects_table")
        helper.logging.info("Created table: <geolocation_objects_table>.")

        # Uncomment if needed
        # helper.logging.info("Creating table: <override_objects_table>.")
        # self.table_factory("override_objects_table")
        # helper.logging.info("Created table: <override_objects_table>.")

    #TODO: tables for l7 and ping apps
    #TODO: table for time range objects
    def table_factory(self, table_name):
        """
        Create a table in the database if it does not already exist.

        Args:
            table_name (str): The name of the table to create.
        """
        helper.logging.debug(f"Called SecurityDeviceDatabase::table_factory().")
        match table_name:
            case 'general_data_table':
                # Define the command for creating the general_data_table
                command = """CREATE TABLE IF NOT EXISTS general_data_table (
                security_device_name TEXT PRIMARY KEY,
                security_device_username TEXT NOT NULL,
                security_device_secret TEXT NOT NULL,
                security_device_hostname TEXT NOT NULL,
                security_device_type TEXT NOT NULL,
                security_device_port TEXT NOT NULL,
                security_device_version TEXT NOT NULL,
                security_device_domain TEXT NOT NULL
                );"""

            case 'security_policy_containers_table':
                command = """CREATE TABLE IF NOT EXISTS security_policy_containers_table (
                security_device_name TEXT NOT NULL,
                security_policy_container_name TEXT PRIMARY KEY,
                security_policy_container_parent TEXT,
                FOREIGN KEY(security_device_name) REFERENCES general_data_table(security_device_name)
                );"""
            
            case 'nat_policy_containers_table':
                command = """CREATE TABLE IF NOT EXISTS nat_policy_containers_table (
                security_device_name TEXT NOT NULL,
                nat_policy_container_name TEXT PRIMARY KEY,
                nat_policy_container_parent TEXT,
                FOREIGN KEY(security_device_name) REFERENCES general_data_table(security_device_name)
                );"""
            
            case 'object_containers_table':
                command = """CREATE TABLE IF NOT EXISTS object_containers_table (
                security_device_name TEXT NOT NULL,
                object_container_name TEXT PRIMARY KEY,
                object_container_parent TEXT,
                FOREIGN KEY(security_device_name) REFERENCES general_data_table(security_device_name)
                );"""

            # TODO: do i need two tables here? one for pre-processing and one for post-processing?
            case 'security_policies_table':
                command = """CREATE TABLE IF NOT EXISTS security_policies_table (
                security_device_name TEXT NOT NULL,
                security_policy_name TEXT NOT NULL,
                security_policy_container_name TEXT NOT NULL,
                security_policy_index INT,
                security_policy_category TEXT,
                security_policy_status TEXT NOT NULL,
                security_policy_source_zones TEXT[] NOT NULL,
                security_policy_destination_zones TEXT[] NOT NULL,
                security_policy_source_networks TEXT[] NOT NULL,
                security_policy_destination_networks TEXT[] NOT NULL,
                security_policy_source_ports TEXT[] NOT NULL,
                security_policy_destination_ports TEXT[] NOT NULL,
                security_policy_schedules TEXT[] NOT NULL,
                security_policy_users TEXT[] NOT NULL,
                security_policy_urls TEXT[] NOT NULL,
                security_policy_l7_apps TEXT[] NOT NULL,
                security_policy_description TEXT,
                security_policy_comments TEXT[],
                security_policy_log_setting TEXT[],
                security_policy_log_start BOOLEAN NOT NULL,
                security_policy_log_end BOOLEAN NOT NULL,
                security_policy_section TEXT,
                security_policy_action TEXT,
                FOREIGN KEY(security_policy_container_name) REFERENCES security_policy_containers_table(security_policy_container_name)
                );"""
            
            # this table stores info about the hitcounts of the security policies and of the nat policies
            # TODO: how to get the hitcount info per policy and per device?

            case 'policies_hitcount_table':
                command = """CREATE TABLE IF NOT EXISTS policies_hitcount_table (
                security_device_name TEXT NOT NULL,
                security_policy_name TEXT NOT NULL,
                security_policy_container_name TEXT NOT NULL,
                security_policy_hitcount INTEGER,
                security_policy_last_hit TIMESTAMP,
                nat_policy_name TEXT NOT NULL,
                nat_policy_container_name TEXT NOT NULL,
                nat_policy_hitcount INTEGER,
                nat_policy_last_hit TIMESTAMP,
                assigned_device_name TEXT NOT NULL,
                FOREIGN KEY(security_policy_container_name) REFERENCES security_policy_containers_table(security_policy_container_name),
                FOREIGN KEY(nat_policy_container_name) REFERENCES security_policy_containers_table(security_policy_container_name)
                );"""

            #TODO: add support for NAT rules
            case 'nat_policies_table':
                pass
            
            #TODO: properly define this table. stores the info about the user sources (AD, RADIUS, TACACS..)
            case 'user_source_table':
                pass
            
            #TODO: add proper support for firewall users
            case 'policy_users_table':
                command = """CREATE TABLE IF NOT EXISTS policy_users_table (
                    policy_users TEXT PRIMARY KEY,
                    security_device_name TEXT NOT NULL,
                    FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)
                );"""

            # stores information about the security zones names and mapped interfaces on a managed device of the security device
            case 'security_zones_table':
                command = """CREATE TABLE IF NOT EXISTS security_zones_table (
                security_zone_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                security_zone_assigned_device TEXT,
                security_zone_mapped_interfaces TEXT[],
                security_zone_description TEXT,
                FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)
                );"""

            case 'urls_table':
                command = """CREATE TABLE IF NOT EXISTS url_objects_table (
                url_object_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                url_object_members TEXT[],
                url_object_description TEXT,
                FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)
                );"""

            #TODO: add proper support for url categories
            case 'urls_categories_table':
                command = """CREATE TABLE IF NOT EXISTS urls_categories_table (
                    url_category_name TEXT PRIMARY KEY,
                    security_device_name TEXT NOT NULL,
                    object_container_name TEXT NOT NULL,
                    FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)
                );"""
            
            #TODO: add proper support for l7 apps
            case 'l7_apps_table':
                command = """CREATE TABLE IF NOT EXISTS l7_apps_table (
                l7_app_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)
                );"""

            case 'network_address_objects_table':
                command = """CREATE TABLE IF NOT EXISTS network_address_objects_table (
                network_address_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                network_address_value TEXT,
                network_address_description TEXT,
                network_address_type TEXT,
                overridable_object BOOLEAN NOT NULL,
                FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)
                );"""

            case 'network_address_object_groups_table':
                command = """CREATE TABLE IF NOT EXISTS network_address_object_groups_table (
                network_address_group_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                network_address_group_members TEXT[],
                network_address_group_description TEXT,
                overridable_object BOOLEAN NOT NULL,
                FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)
                );"""

            case 'port_objects_table':
                command = """CREATE TABLE IF NOT EXISTS port_objects_table (
                port_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                port_protocol TEXT,
                port_number TEXT,
                port_description TEXT,
                overridable_object BOOLEAN NOT NULL,
                FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)
                );"""

            case 'port_object_groups_table':
                command = """CREATE TABLE IF NOT EXISTS port_object_groups_table (
                port_group_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                port_group_members TEXT[],
                port_group_description TEXT,
                overridable_object BOOLEAN NOT NULL,
                FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)
                );"""
            
            case 'schedule_objects_table':
                command = """CREATE TABLE IF NOT EXISTS schedule_objects_table(
                schedule_object_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                recurring BOOLEAN NOT NULL,
                start_date TEXT,
                start_time TEXT,
                end_date TEXT,
                end_time TEXT,
                reccurence_type TEXT,
                daily_start TEXT,
                daily_end TEXT,
                week_day TEXT,
                week_day_start TEXT,
                week_day_end TEXT,
                FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)
                )"""

            case 'managed_devices_table':
                command = """CREATE TABLE IF NOT EXISTS managed_devices_table (
                security_device_name TEXT NOT NULL,
                managed_device_name TEXT PRIMARY KEY,
                assigned_security_policy_container TEXT,
                hostname TEXT,
                cluster TEXT,
                FOREIGN KEY(security_device_name) REFERENCES general_data_table(security_device_name)
                );"""
            
            case 'geolocation_objects_table':
                command = """CREATE TABLE IF NOT EXISTS geolocation_objects_table (
                geolocation_object_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                continent_member_names TEXT[],
                country_member_names TEXT[],
                country_member_alpha2_codes TEXT[],
                country_member_alpha3_codes TEXT[],
                country_member_numeric_codes TEXT[],
                FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)
                )"""
            
            # this table stores info about the objects who are overriden. the stored info is the object name, its value, the device where the override is set
            # TODO: add support for overridden objects
            # case 'override_objects_table':
            #     pass

        # create the table in the database
        self.create_table(table_name, command)

class SecurityDeviceConnection:
    """
    A class representing a connection to a security device.
    """

    def __init__(self) -> None:
        """
        Initialize the SecurityDeviceConnection instance.
        """
        pass

class SecurityDevice:
    def __init__(self, name, sec_device_database):
        """
        Initialize a SecurityDevice instance.

        Parameters:
        - name (str): The name of the security device.
        - sec_device_database (Database): An instance of the database for the security device.
        """
        helper.logging.debug("Called SecurityDevice::__init__.")
        self._name = name
        self._database = sec_device_database

    def get_containers_info_from_device_conn(self, containers_list, container_type):
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
        helper.logging.debug(f"Called SecurityDevice::get_containers_info_from_device_conn()")
        helper.logging.info(f"################## Importing configuration of the device containers. Container type: <{container_type}> ##################")
        processed_container_list = []
        
        # Define a dictionary to map container types to their corresponding retrieval functions
        container_type_mapping = {
            'security_policies_container': self.return_security_policy_container_object,
            'object_container': self.return_object_container_object
        }

        for container_name in containers_list:
            try:
                CurrentContainer = ''
                # Use the container_type_mapping dictionary to retrieve the appropriate retrieval function
                retrieve_container_function = container_type_mapping.get(container_type)
                if retrieve_container_function is not None:
                    CurrentContainer = retrieve_container_function(container_name)
                else:
                    helper.logging.error(f"Invalid container type: <{container_type}>")
                    continue  # Skip to the next container if the container type is invalid
                    
                helper.logging.info(f"I am now processing the <{container_type}> container, name: <{CurrentContainer.get_name()}>")
                helper.logging.debug(f"Raw container info:  <{CurrentContainer.get_info()}>")
                # Check if the current container has parent containers
                while CurrentContainer.is_child_container():
                    # Retrieve the parent container name
                    parent_container_name = CurrentContainer.get_parent_name()
                    helper.logging.info(f"<{CurrentContainer.get_name()}> is a CHILD container. Its parent is: <{parent_container_name}>.")
                    try:
                        # Retrieve the parent container object using the same retrieval function
                        ParentContainer = retrieve_container_function(parent_container_name)

                        # set the current's container parent
                        CurrentContainer.set_parent(ParentContainer)
                        # Process the current container
                        processed_current_container = CurrentContainer.process_container_info()
                        helper.logging.info(f"Processed container: <{CurrentContainer.get_name()}>")
                        helper.logging.debug(f"Processed container info is: <{processed_current_container}>.")
                        processed_container_list.append(processed_current_container)

                        # Set the parent container as the current container for the next iteration
                        CurrentContainer = ParentContainer
                    except Exception as e:
                        helper.logging.error(f"Error retrieving parent container '{parent_container_name}': {e}")
                        break  # Break out of the loop if there's an error retrieving the parent container
                
                # If we break out of the loop, then it means we reached the highest parent in the hierarchy
                # We also need to get the data for it
                else:
                    helper.logging.info(f"Finished processing all children. <{CurrentContainer.get_name()}> is the highest container in the parent-child hierarchy. Sending it for processing.")
                    processed_current_container = CurrentContainer.process_container_info()
                    helper.logging.info(f"Finished processing container: <{CurrentContainer.get_name()}>.")
                    helper.logging.debug(f"Processed container info is: <{processed_current_container}>.")
                    processed_container_list.append(processed_current_container)
            except Exception as err:
                helper.logging.error(f"Could not retrieve info regarding the container {container_name}. Reason: {err}.")
                print(f"Could not retrieve info regarding the container {container_name}. Reason: {err}.")
                sys.exit(1)
        
        helper.logging.info(f"I have finished completely processing <{container_type}> container, name: <{CurrentContainer.get_name()}> ")
        return processed_container_list
    
    @abstractmethod
    def return_security_policy_container_object(self):
        """
        Abstract method to return a security policy container object. This method is overridden by the implementation of a child SecurityDevice class.
        """
        pass

    @abstractmethod
    def get_device_version(self):
        """
        Abstract method to retrieve the version of the device's server. This method is overridden by the implementation of a child SecurityDevice class.
        
        Returns:
            String: A string containing info about the platform on which the security device is running
        """
        pass

    @abstractmethod
    def return_security_policy_object(self):
        """
        Abstract method to return a security policy object. This method is overridden by the implementation of a child SecurityDevice class.
        
        Returns:
            Object: A device-specifc security policy object.
        """
        pass

    @abstractmethod
    def return_object_container_object(self, container_name):
        """
        Abstract method to return an object container object. This method is overridden by the implementation of a child SecurityDevice class.

        Args:
            container_name (str): Name of the object container.

        Returns:
            Object: Object container object.
        """
        pass

    @abstractmethod
    def get_managed_devices_info(self):
        """
        Abstract method to retrieve information about managed devices. This method is overridden by the implementation of a child SecurityDevice class.

        Returns:
            list: List of dictionaries containing information about managed devices.
        """
        pass

    @abstractmethod
    def process_managed_device(self):
        """
        Abstract method to process information about a managed device. This method is overridden by the implementation of a child SecurityDevice class.

        Returns:
            tuple: Tuple containing information about the managed device.
        """
        pass

    def get_device_version_from_device_conn(self):
        """
        Retrieve the version of the device's server using the established device connection.

        Returns:
            str: Version of the device's server.
        """
        # Log a debug message to indicate that the function is called
        helper.logging.debug("Called SecurityDevice::get_device_version_from_device_conn()")

        try:
            # Attempt to retrieve the device version using the method get_device_version()
            device_version = self.get_device_version()
            
            # Log an informational message indicating that the device version is retrieved successfully
            helper.logging.info(f"Got device version: <{device_version}>")
            
            # Return the retrieved device version
            return device_version
        except Exception as err:
            # Log a critical error message if there is an exception during the retrieval process
            helper.logging.critical(f'Could not retrieve platform version. Reason: <{err}?')
            
            # Exit the program with status code 1 indicating a critical error
            sys.exit(1)

    def get_policy_info_from_device_conn(self, policy_type, sec_policy_containers_list):
        """
        Retrieve information about policies from the specified policy containers.

        Args:
            sec_policy_containers_list (list): List of policy container names.

        Returns:
            list: List of dictionaries containing information about policies.
        """
        # Log a debug message indicating that the function is called
        helper.logging.debug("Called get_policy_info_from_device_conn().")
        # Log an informational message indicating that policy info configuration is being imported


        # Define a dictionary to map container types to their corresponding retrieval functions
        policy_type_mapping = {
            'security_policy': self.return_security_policy_object,
            # 'nat_policy': self.return_object_container_object
        }
        helper.logging.info(f"################## Importing policy info configuration. Policy type is <{policy_type}>. ##################")
        # Initialize an empty list to store processed policy information
        processed_policy_info = []
        
        policy_retriever_function = policy_type_mapping.get(policy_type)
        # Iterate over each policy container name in the provided list
        for sec_policy_container_name in sec_policy_containers_list:
            # Log an informational message indicating the processing of policies for the current container
            helper.logging.info(f"Processing policies, type <{policy_type}> of the following container: <{sec_policy_container_name}>.")
            
            # Retrieve raw policy objects from the specified container
            raw_policy_objects_list = policy_retriever_function(sec_policy_container_name)

            # Iterate over each raw policy object
            for RawPolicyObject in raw_policy_objects_list:
                # Process the raw policy object to extract relevant information
                processed_sec_policy_entry = RawPolicyObject.process_policy_info()
                # Append the processed policy entry to the list
                processed_policy_info.append(processed_sec_policy_entry)

        # Return the list of processed policy information
        return processed_policy_info

    #TODO: this needs to be modified when ManagedDevice class will be implemented
    def get_managed_devices_info_from_device_conn(self):
        """
        Retrieve information about managed devices.

        Returns:
            list: List of dictionaries containing information about managed devices.
        """
        # Log a debug message indicating that the function is called
        helper.logging.debug("Called function get_managed_devices_info().")
        # Log an informational message indicating that managed devices info retrieval is initiated
        helper.logging.info("################## GETTING MANAGED DEVICES INFO ##################")
        
        try:
            # Attempt to retrieve managed devices info from the security device connection
            managed_devices_info = self.get_managed_devices_info()
        except Exception as err:
            # Log a critical error message if managed devices retrieval fails and exit the program
            helper.logging.critical(f'Could not retrieve managed devices. Reason: {err}')
            sys.exit(1)

        # Initialize an empty list to store processed managed devices
        processed_managed_devices = []
        
        # Iterate over each managed device entry in the retrieved managed devices info
        for managed_device_entry in managed_devices_info:
            # Process the managed device entry to extract relevant information
            device_name, assigned_security_policy_container, device_hostname, device_cluster = self.process_managed_device(managed_device_entry)
            # Create a dictionary containing processed information about the managed device
            processed_managed_device = {
                "managed_device_name": device_name,
                "assigned_security_policy_container": assigned_security_policy_container,
                "hostname": device_hostname,
                "cluster": device_cluster
            }
            # Append the processed managed device entry to the list
            processed_managed_devices.append(processed_managed_device)

        # Return the list of processed managed devices
        return processed_managed_devices
    
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
        helper.logging.debug("Called SecurityDevice::get_object_info_from_device_conn()")
        # Define a dictionary mapping object types to functions retrieving objects
        match object_type:
            case 'network_objects':
                self.fetch_objects_info('network_objects')
                object_names = self.get_db_objects('network_objects')
                
            case 'port_objects':
                self.fetch_objects_info('port_objects')
                object_names = self.get_db_objects('port_objects')

        object_type_mapping = {
            'network_objects': self.return_network_objects,
            'port_objects': self.return_port_objects,
            # 'schedule_objects': self.return_schedule_objects(),
            # 'policy_users': self.return_policy_users(),
            # 'url_objects': self.return_url_objects(),
            # 'app_objects': self.return_app_objects()
        }

        # Retrieve the function corresponding to the specified object type
        retrieve_function = object_type_mapping.get(object_type)

        if retrieve_function is None:
            return []  # Or raise an error if necessary

        # Call the function to retrieve objects of the specified type
        retrieved_objects_list = retrieve_function(object_names)

        helper.logging.info(f"################## Importing object configuration. Object type is: <{object_type}>. ##################")
        # Initialize an empty dictionary to store processed objects organized by type
        processed_objects_dict = {
            "network_objects": [],
            "network_group_objects": [],
            "geolocation_objects": []
        }
        
        # Process retrieved objects
        for RetrievedObject in retrieved_objects_list:
            helper.logging.info(f"Processing object: <{RetrievedObject.get_name()}. Object type is: <{object_type}>")
            helper.logging.debug(f"Raw object info: <{RetrievedObject.get_info()}>")
            # Process the retrieved object
            processed_object_info = RetrievedObject.process_object()
            print(processed_object_info)
            # Append the processed object to the corresponding list based on its type
            if isinstance(RetrievedObject, NetworkObject):
                processed_objects_dict["network_objects"].append(processed_object_info)
            elif isinstance(RetrievedObject, NetworkGroupObject):
                processed_objects_dict["network_group_objects"].append(processed_object_info)
            elif isinstance(RetrievedObject, GeolocationObject):
                processed_objects_dict["geolocation_objects"].append(processed_object_info)
            helper.logging.info(f"Processed object: <{RetrievedObject.get_name()}. Object type is: <{object_type}>")
            helper.logging.debug(f"Processed object info: <{processed_object_info}>")
            # Print the processed object (for debugging purposes)
        
        # Return the dictionary of processed objects
        return [processed_objects_dict]

    
    @abstractmethod
    def fetch_objects_info(self, object_type):
        pass

    @abstractmethod
    def return_network_objects(self):
        """
        Abstract method to return network objects. This method is overridden by the implementation of a child SecurityDevice class.

        Returns:
            list: List of processed network objects.
        """
        pass

    @abstractmethod
    def return_port_objects(self):
        """
        Abstract method to return port objects. This method is overridden by the implementation of a child SecurityDevice class.

        Returns:
            list: List of processed port objects.
        """
        pass
    
    @abstractmethod
    def return_schedule_objects(self):
        """
        Abstract method to return schedule objects. This method is overridden by the implementation of a child SecurityDevice class.

        Returns:
            list: List of processed schedule objects.
        """
        pass

    @abstractmethod
    def return_policy_users(self):
        """
        Abstract method to return policy users. This method is overridden by the implementation of a child SecurityDevice class.

        Returns:
            list: List of processed policy users.
        """
        pass

    @abstractmethod
    def return_url_objects(self):
        """
        Abstract method to return URL objects. This method is overridden by the implementation of a child SecurityDevice class.

        Returns:
            list: List of processed URL objects.
        """
        pass

    @abstractmethod
    def return_app_objects(self):
        """
        Abstract method to return application objects. This method is overridden by the implementation of a child SecurityDevice class.

        Returns:
            list: List of processed application objects.
        """
        pass

    def get_security_device_type_from_db(self):
        helper.logging.debug(f"Called SecurityDevice::get_security_device_type().")
        helper.logging.info(f"Fetching the device type of device: <{self._name}>.")
        """
        Retrieve the security device type.

        Returns:
        - str: The security device type.
        """
        helper.logging.info(f"Got device type: <{self._get_security_device_attribute('security_device_type')}>.")
        return self._get_security_device_attribute('security_device_type')

    def get_security_device_hostname_from_db(self):
        helper.logging.debug(f"Called SecurityDevice::get_security_device_hostname_from_db().")
        helper.logging.info(f"Fetching the hostname of {self._name}.")
        """
        Retrieve the security device hostname.

        Returns:
        - str: The security device hostname.
        """
        helper.logging.info(f"Got device hostname: <{self._get_security_device_attribute('security_device_hostname')}>.")
        return self._get_security_device_attribute('security_device_hostname')

    def get_security_device_username_from_db(self):
        helper.logging.debug(f"Called SecurityDevice::get_security_device_username_from_db().")
        helper.logging.info(f"Fetching the username of device <{self._name}>.")
        """
        Retrieve the security device username.

        Returns:
        - str: The security device username.
        """
        helper.logging.info(f"Got device username: <{self._get_security_device_attribute('security_device_username')}>.")
        return self._get_security_device_attribute('security_device_username')

    def get_security_device_secret_from_db(self):
        helper.logging.debug(f"Called get_security_device_secret_from_db().")
        helper.logging.info(f"Fetching the secret of <{self._name}>.")
        """
        Retrieve the security device secret.

        Returns:
        - str: The security device secret.
        """
        helper.logging.info(f"Got device secret: ... .")
        return self._get_security_device_attribute('security_device_secret')

    def get_security_device_domain_from_db(self):
        helper.logging.debug(f"Called SecurityDevice::get_security_device_domain_from_db().")
        helper.logging.info(f"Fetching the domain of <{self._name}>.")
        """
        Retrieve the security device domain.

        Returns:
        - str: The security device domain.
        """
        helper.logging.info(f"Got device domain: <{self._get_security_device_attribute('security_device_domain')}>.")
        return self._get_security_device_attribute('security_device_domain')

    def get_security_device_port_from_db(self):
        helper.logging.debug(f"Called SecurityDevice::get_security_device_port_from_db().")
        helper.logging.info(f"Fetching the port of <{self._name}>.")
        """
        Retrieve the security device port.

        Returns:
        - str: The security device port.
        """
        helper.logging.info(f"Got device port: <{self._get_security_device_attribute('security_device_port')}>.")
        return self._get_security_device_attribute('security_device_port')

    def get_security_device_version_from_db(self):
        helper.logging.debug(f"Called SecurityDevice::get_security_device_version_from_db().")
        helper.logging.info(f"Fetching the version of <{self._name}>.")
        """
        Retrieve the security device version.

        Returns:
        - str: The security device version.
        """
        helper.logging.info(f"Got device version: <{self._get_security_device_attribute('security_device_version')}>.")
        return self._get_security_device_attribute('security_device_version')

    def _get_security_device_attribute(self, attribute):
        helper.logging.debug(f"Called SecurityDevice::_get_security_device_attribute().")
        """
        Retrieve a specific attribute of the security device.

        Parameters:
        - attribute (str): The attribute to retrieve.

        Returns:
        - str: The value of the specified attribute for the security device.
        """
        select_command = f"SELECT {attribute} FROM general_data_table WHERE security_device_name = %s"
        result = self._database.get_table_value('general_data_table', select_command, (self._name,))
        return result[0][0] if result else None

    # the following functions process the data from the database. all the objects are processed, the unique values
    # are gathered and returned in a list that will be further processed by the program
    def get_db_objects(self, object_type):
        helper.logging.debug(f"Called SecurityDevice::get_db_objects().")
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
        }

        # Validate the provided object type
        if object_type not in object_column_mapping:
            raise ValueError(f"Invalid object type: {object_type}")

        # Construct the SQL query
        columns = ", ".join(object_column_mapping[object_type])
        select_command = f"SELECT {columns} FROM security_policies_table;"

        # Execute the SQL query and fetch the results
        query_result = self._database.get_table_value('security_policies_table', select_command)

        # Flatten the results so that the unique values can be returned
        unique_objects_list = self._database.flatten_query_result(query_result)

        # Remove the 'any' element of the list, if it exists. It is not an object that can be imported
        element_to_remove = 'any'
        if element_to_remove in unique_objects_list:
            unique_objects_list.remove(element_to_remove)

        return unique_objects_list
    
    def insert_into_managed_devices_table(self, managed_device_info):
        helper.logging.debug(f"Called SecurityDevice::insert_into_managed_devices_table().")
        """
        Insert managed devices information into the 'managed_devices_table'.

        Parameters:
        - managed_device_info (list): List of dictionaries containing managed device information.

        Returns:
        None
        """
        for managed_device_entry in managed_device_info:
            # Extract data from the current managed device entry
            managed_device_name = managed_device_entry["managed_device_name"]
            assigned_security_policy_container = managed_device_entry["assigned_security_policy_container"]
            hostname = managed_device_entry["hostname"]
            cluster = managed_device_entry['cluster']

            # Check for duplicates before insertion
            if self.verify_duplicate('managed_devices_table', 'managed_device_name', managed_device_name):
                helper.logging.warn(f"Duplicate entry for managed device: <{managed_device_name}>. Skipping insertion.")
                continue

            # SQL command to insert data into the 'managed_devices_table'
            insert_command = """
            INSERT INTO managed_devices_table (
                security_device_name,
                managed_device_name,
                assigned_security_policy_container,
                hostname,
                cluster
            ) VALUES (
                %s, %s, %s, %s, %s
            )"""

            # Values to be inserted into the table
            values = (self._name, managed_device_name, assigned_security_policy_container, hostname, cluster)

            # Execute the insert command with the specified values
            self._database.insert_table_value('managed_devices_table', insert_command, values)

    def insert_into_general_table(self, security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain):
        helper.logging.debug("Called SecurityDevice::insert_into_general_table().")
        """
        Insert general information into the 'general_data_table'.

        Parameters:
        - security_device_username (str): Security device username.
        - security_device_secret (str): Security device secret.
        - security_device_hostname (str): Security device hostname.
        - security_device_type (str): Security device type.
        - security_device_port (str): Security device port.
        - security_device_version (str): Security device version.
        - domain (str): Security device domain.

        Returns:
        None
        """
        # Check for duplicates before insertion
        if self.verify_duplicate('general_data_table', 'security_device_name', self._name):
            helper.logging.warn(f"Duplicate entry for device name: <{self._name}>. Skipping insertion.")
            return

        insert_command = """
            INSERT INTO general_data_table (
                security_device_name, 
                security_device_username, 
                security_device_secret,
                security_device_hostname, 
                security_device_type, 
                security_device_port, 
                security_device_version, 
                security_device_domain
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s
            )
        """

        values = (
            self._name, 
            security_device_username, 
            security_device_secret, 
            security_device_hostname, 
            security_device_type, 
            security_device_port, 
            security_device_version, 
            domain
        )

        self._database.insert_table_value('general_data_table', insert_command, values)

    def insert_into_security_policy_containers_table(self, containers_data):
        helper.logging.debug("Called SecurityDevice::insert_into_security_policy_containers_table().")
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
                helper.logging.warn(f"Duplicate entry for container: <{container_name}>. Skipping insertion.")
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
            self._database.insert_table_value('security_policy_containers_table', insert_command, values)

    def insert_into_security_policies_table(self, sec_policy_data):
        helper.logging.debug("Called SecurityDevice::insert_into_security_policies_table().")
        """
        Insert security policy data into the 'security_policies_table'.

        Parameters:
        - sec_policy_data (list): List of dictionaries containing security policy information.

        Returns:
        None
        """
        # Loop through the security policy data, extract it, and then insert it into the table
        for current_policy_data in sec_policy_data:
            current_policy_name = current_policy_data["sec_policy_name"]
            
            # Check for duplicates before insertion
            if self.verify_duplicate('security_policies_table', 'security_policy_name', current_policy_name):
                helper.logging.warn(f"Duplicate entry for security policy: <{current_policy_name}>. Skipping insertion.")
                continue

            formatted_security_policy_source_zones = "{" + ",".join(current_policy_data["sec_policy_source_zones"]) + "}"
            formatted_security_policy_destination_zones = "{" + ",".join(current_policy_data["sec_policy_destination_zones"]) + "}"
            formatted_security_policy_source_networks = "{" + ",".join(current_policy_data["sec_policy_source_networks"]) + "}"
            formatted_security_policy_destination_networks = "{" + ",".join(current_policy_data["sec_policy_destination_networks"]) + "}"
            formatted_security_policy_source_ports = "{" + ",".join(current_policy_data["sec_policy_source_ports"]) + "}"
            formatted_security_policy_destination_ports = "{" + ",".join(current_policy_data["sec_policy_destination_ports"]) + "}"
            formatted_security_policy_schedules = "{" + ",".join(current_policy_data["sec_policy_schedules"]) + "}"
            formatted_security_policy_users = "{" + ",".join(current_policy_data["sec_policy_users"]) + "}"
            formatted_security_policy_urls = "{" + ",".join(current_policy_data["sec_policy_urls"]) + "}"
            formatted_security_policy_l7_apps = "{" + ",".join(current_policy_data["sec_policy_apps"]) + "}"
            comments = current_policy_data["sec_policy_comments"]

            # # TODO: not sure this is the most optimal solution, maybe retrieve all the comments in a list, without dictionaries
            if comments is not None:
                # Convert each dictionary to a JSON string and escape double quotes for SQL
                comments_as_json_strings = ['"' + json.dumps(comment).replace('"', '\\"') + '"' for comment in comments]
                # Join the strings into a PostgreSQL array format
                formatted_security_policy_comments = "{" + ",".join(comments_as_json_strings) + "}"
            else:
                # Set formatted_security_policy_comments to None when comments is None
                formatted_security_policy_comments = None

            formatted_security_policy_log_setting = "{" + ",".join(current_policy_data["sec_policy_log_settings"]) + "}"

            insert_command = """
                INSERT INTO security_policies_table (
                    security_device_name, 
                    security_policy_name, 
                    security_policy_container_name,
                    security_policy_index, 
                    security_policy_category, 
                    security_policy_status, 
                    security_policy_source_zones, 
                    security_policy_destination_zones, 
                    security_policy_source_networks, 
                    security_policy_destination_networks, 
                    security_policy_source_ports, 
                    security_policy_destination_ports, 
                    security_policy_schedules, 
                    security_policy_users, 
                    security_policy_urls, 
                    security_policy_l7_apps, 
                    security_policy_description, 
                    security_policy_comments, 
                    security_policy_log_setting, 
                    security_policy_log_start, 
                    security_policy_log_end, 
                    security_policy_section, 
                    security_policy_action
                ) VALUES (
                    %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s
                )
            """
            # Use a tuple to pass parameters to the execute method
            parameters = (
                self._name,
                current_policy_name,
                current_policy_data["sec_policy_container_name"],
                current_policy_data["security_policy_index"],
                current_policy_data["sec_policy_category"],
                current_policy_data["sec_policy_status"],
                formatted_security_policy_source_zones,
                formatted_security_policy_destination_zones,
                formatted_security_policy_source_networks,
                formatted_security_policy_destination_networks,
                formatted_security_policy_source_ports,
                formatted_security_policy_destination_ports,
                formatted_security_policy_schedules,
                formatted_security_policy_users,
                formatted_security_policy_urls,
                formatted_security_policy_l7_apps,
                current_policy_data["sec_policy_description"],
                formatted_security_policy_comments,
                formatted_security_policy_log_setting,
                current_policy_data["sec_policy_log_start"],
                current_policy_data["sec_policy_log_end"],
                current_policy_data["sec_policy_section"],
                current_policy_data["sec_policy_action"]
            )

            self._database.insert_table_value('security_policies_table', insert_command, parameters)

    def insert_into_object_containers_table(self, containers_data):
        helper.logging.debug("Called SecurityDevice::insert_into_object_containers_table().")
        """
        Insert values into the 'object_containers_table' table.

        Parameters:
        - containers_data (list): List of dictionaries containing object container information.

        Returns:
        None
        """
        for container_entry in containers_data:
            # Extract data from the current object container entry
            container_name = container_entry['object_container_name']
            container_parent = container_entry['object_container_parent']

            # Check for duplicates before insertion
            if self.verify_duplicate('object_containers_table', 'object_container_name', container_name):
                helper.logging.warn(f"Duplicate entry for object container: <{container_name}>. Skipping insertion.")
                continue

            # SQL command to insert data into the 'object_containers_table'
            insert_command = """
                INSERT INTO object_containers_table (
                    security_device_name, 
                    object_container_name, 
                    object_container_parent
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
            self._database.insert_table_value('object_containers_table', insert_command, values)

    def insert_into_network_address_objects_table(self, network_objects_data):
        helper.logging.debug("Called SecurityDevice::insert_into_network_address_objects_table().")
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
                helper.logging.warn(f"Duplicate entry for network address object: <{network_address_name}>. Skipping insertion.")
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
            self._database.insert_table_value('network_address_objects_table', insert_command, values)

    def insert_into_network_address_object_groups_table(self, network_group_objects_data):
        helper.logging.debug("Called SecurityDevice::insert_into_network_address_object_groups_table().")
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
                helper.logging.warn(f"Duplicate entry for network address object group: <{network_address_group_name}>. Skipping insertion.")
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
            self._database.insert_table_value('network_address_object_groups_table', insert_command, values)

    def insert_into_security_policy_containers_table(self, containers_data):
        helper.logging.debug("Called SecurityDevice::insert_into_security_policy_containers_table().")
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
                helper.logging.warn(f"Duplicate entry for container: <{container_name}>. Skipping insertion.")
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
            self._database.insert_table_value('security_policy_containers_table', insert_command, values)

    def insert_into_geolocation_table(self, geolocation_object_data):
        helper.logging.debug("Called SecurityDevice::insert_into_geolocation_table().")
        """
        Insert values into the 'geolocation_objects_table' table.

        Parameters:
        - geolocation_object_data (list): List of dictionaries containing geolocation object information.

        Returns:
        None
        """
        for geo_entry in geolocation_object_data:
            # Extract data from the current geolocation object entry
            geo_name = geo_entry['geolocation_object_name']
            container_name = geo_entry['object_container_name']
            continent_names = geo_entry['continent_member_names']
            country_names = geo_entry['country_member_names']
            country_alpha2 = geo_entry['country_member_alpha2_codes']
            country_alpha3 = geo_entry['country_member_alpha3_codes']
            country_numeric = geo_entry['country_member_numeric_codes']

            # Check for duplicates before insertion
            if self.verify_duplicate('geolocation_objects_table', 'geolocation_object_name', geo_name):
                helper.logging.warn(f"Duplicate entry for geolocation object: <{geo_name}>. Skipping insertion.")
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
            self._database.insert_table_value('geolocation_objects_table', insert_command, values)

    def verify_duplicate(self, table, column, value):
        helper.logging.debug("Called verify_duplicate().")
        helper.logging.info(f"Verifying duplicate in table {table}, column {column}, for value {value}.")
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
        is_duplicate = self._database.get_table_value(table, select_command, (value,))
        helper.logging.info(f"Verified duplicate in table {table}, column {column}, for value {value}. Result is {is_duplicate}")

        # Return the result as a boolean
        return is_duplicate[0][0]

    def delete_security_device(self):
        pass