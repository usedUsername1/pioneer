from abc import ABC, abstractmethod
from pkg import PioneerDatabase, DBConnection, Container
import utils.helper as helper
import utils.gvars as gvars
import json
import sys

# TODO: create all the tables for all the objects
class SecurityDeviceDatabase(PioneerDatabase):
    def __init__(self, cursor):
        super().__init__(cursor)
        helper.logging.debug(f"Called SecurityDeviceDatabase __init__ with the following cursor {self._cursor}.")
    
    def create_security_device_tables(self):
        helper.logging.debug(f"Called create_security_device_tables().")
        self.table_factory("general_data_table")
        self.table_factory("security_policy_containers_table")
        self.table_factory("nat_policy_containers_table")
        self.table_factory("object_containers_table")
        self.table_factory("security_policies_table")
        self.table_factory("policies_hitcount_table")
        # self.table_factory("nat_policies_table")
        # self.table_factory("user_source_table")
        # self.table_factory("policy_users_table")
        self.table_factory("security_zones_table")
        self.table_factory("urls_table")
        # self.table_factory("urls_categories_table")
        # self.table_factory("l7_apps_table")
        self.table_factory("network_address_objects_table")
        self.table_factory("network_address_object_groups_table")
        self.table_factory("port_objects_table")
        self.table_factory("port_object_groups_table")
        self.table_factory("schedule_objects_table")
        self.table_factory("managed_devices_table")
        self.table_factory("geolocation_objects_table")
        # self.table_factory("override_objects_table")

    
    #TODO: tables for l7 and ping apps
    #TODO: table for time range objects
    def table_factory(self, table_name):
        helper.logging.debug(f"Called table_factory() with the following parameters: table name: {table_name}.")
        match table_name:
            case 'general_data_table':
                # define the command for creating the table
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
                port_value TEXT,
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


class SecurityDeviceConnection():
    def __init__(self) -> None:
        pass

    def get_security_policy_container_data_by_name(self):
        pass

    def get_version(self):
        pass

class SecurityDevicePolicyContainer(Container):
    def __init__(self, name, parent, security_device_name, security_policy_info) -> None:
        super().__init__(name, parent, security_device_name)
        self._security_policy_info = security_policy_info

    def is_child_container(self):
        pass

# this will be a generic security device only with a database, acessing it will be possible
# in main, without acessing the protected attributes. better option for "--device"
class SecurityDevice:
    def __init__(self, name, sec_device_database, sec_device_connection = None, object_container = None, security_policy_containers = None):
        """
        Initialize a SecurityDevice instance.

        Parameters:
        - name (str): The name of the security device.
        - sec_device_database (Database): An instance of the database for the security device.
        """
        self._name = name
        self._database = sec_device_database
        self._sec_device_connection = sec_device_connection
        self._object_container = object_container
        self._security_policy_containers = security_policy_containers
        helper.logging.debug("Called SecurityDevice __init__.")

    # TODO: finish debugging this
    def get_security_policy_container_info_from_device_conn(self):
        helper.logging.debug(f"Called get_security_policy_containers_info with the following container list: {self._security_policy_containers}")
        helper.logging.info(f"################## Importing configuration of the security policy containers. ##################")
        """
        Retrieves information about security policy containers.

        Args:
            policy_container_names_list (list): A list of names of security policy containers.

        Returns:
            list: A list of dictionaries containing information about each security policy container.
                Each dictionary has the following keys:
                - 'security_policy_container_name': Name of the security policy container.
                - 'security_policy_parent': Name of the parent security policy container, or None if it has no parent.
        """

        security_policy_containers_info = []

        for policy_container_name in self._security_policy_containers:
            helper.logging.info(f"I am now processing the security policy container: {policy_container_name}")
            try:
                # Retrieve the info for the current acp
                sec_policy_container = self._sec_device_connection.get_security_policy_container_data_by_name(name=policy_container_name)
                # If the policy does not have a parent policy at all, then return a mapping with the current policy name and None to the caller
                if sec_policy_container.is_child_container():
                    # Try to retrieve the parent of the policy. There is an "inherit" boolean attribute in the acp_info response. If it is equal to 'true', then the policy has a parent
                    while sec_policy_container.is_child_container():
                        # Get the name of the current ACP name
                        child_policy_container_name = sec_policy_container.get_name()

                        # Get the name of the acp parent
                        parent_policy_container_name = sec_policy_container.get_parent_name()

                        helper.logging.info(f"Security policy container: {child_policy_container_name}, is the child of {parent_policy_container_name}.")
                        security_policy_containers_info.append({
                            'security_policy_container_name': child_policy_container_name,
                            'security_policy_parent': parent_policy_container_name
                        })

                        # Retrieve the parent info to be processed in the next iteration of the loop
                        sec_policy_container = self._sec_device_connection.get_security_policy_container_data_by_name(name=parent_policy_container_name)


                    # If the parent policy does not have a parent, then map the ACP to None
                    else:
                        helper.logging.info(f"Security policy container: {parent_policy_container_name}, is not a child contaier.")
                        security_policy_containers_info.append({
                            'security_policy_container_name': parent_policy_container_name,
                            'security_policy_parent': None
                        })
                
                else:
                    security_policy_containers_info.append({
                        'security_policy_container_name': policy_container_name,
                        'security_policy_parent': None
                    })

            except Exception as err:
                helper.logging.error(f"Could not retrieve info regarding the container {policy_container_name}. Reason: {err}.")
                sys.exit(1)

        helper.logging.debug(f"I am done processing the info of security policy containers. Got the following data: {security_policy_containers_info}.")
        return security_policy_containers_info

    def get_device_version_from_device_conn(self):
        helper.logging.debug("Called function det_device_version()")
        """
        Retrieve the version of the device's server.

        Returns:
            str: Version of the device's server.
        """
        # Retrieve device system information to get the server version
        try:
            device_version = self.get_device_version()
            helper.logging.info(f"Got device version {device_version}")
            return device_version
        except Exception as err:
            helper.logging.critical(f'Could not retrieve platform version. Reason: {err}')
            sys.exit(1)

    @abstractmethod
    def get_device_version(self):
        pass

    def get_managed_devices_info_from_device_conn(self):
        helper.logging.debug("Called function get_managed_devices_info().")
        """
        Retrieve information about managed devices.

        Returns:
            list: List of dictionaries containing information about managed devices.
        """
        helper.logging.info("################## GETTING MANAGED DEVICES INFO ##################")
        try:
            managed_devices_info = self.get_managed_devices_info()
        except Exception as err:
            helper.logging.critical(f'Could not retrieve managed devices. Reason: {err}')
            sys.exit(1)

        processed_managed_devices = []
        for managed_device_entry in managed_devices_info:
            device_name, assigned_security_policy_container, device_hostname, device_cluster = self.process_managed_device(managed_device_entry)
            managed_device_entry = {
                "managed_device_name": device_name,
                "assigned_security_policy_container": assigned_security_policy_container,
                "hostname": device_hostname,
                "cluster": device_cluster
            }
            processed_managed_devices.append(managed_device_entry)

        return processed_managed_devices

    @abstractmethod
    def get_managed_devices_info(self):
        pass

    @abstractmethod
    def process_managed_device(self):
        pass

    def get_security_device_type_from_db(self):
        helper.logging.debug(f"Called get_security_device_type().")
        helper.logging.info(f"Fetching the device type of {self._name}.")
        """
        Retrieve the security device type.

        Returns:
        - str: The security device type.
        """
        helper.logging.info(f"Got device type: {self._get_security_device_attribute('security_device_type')}.")
        return self._get_security_device_attribute('security_device_type')

    def get_security_device_hostname_from_db(self):
        helper.logging.debug(f"Called get_security_device_hostname().")
        helper.logging.info(f"Fetching the hostname of {self._name}.")
        """
        Retrieve the security device hostname.

        Returns:
        - str: The security device hostname.
        """
        helper.logging.info(f"Got device hostname: {self._get_security_device_attribute('security_device_hostname')}.")
        return self._get_security_device_attribute('security_device_hostname')

    def get_security_device_username_from_db(self):
        helper.logging.debug(f"Called get_security_device_username().")
        helper.logging.info(f"Fetching the username of {self._name}.")
        """
        Retrieve the security device username.

        Returns:
        - str: The security device username.
        """
        helper.logging.info(f"Got device username: {self._get_security_device_attribute('security_device_username')}.")
        return self._get_security_device_attribute('security_device_username')

    def get_security_device_secret_from_db(self):
        helper.logging.debug(f"Called get_security_device_secret().")
        helper.logging.info(f"Fetching the secret of {self._name}.")
        """
        Retrieve the security device secret.

        Returns:
        - str: The security device secret.
        """
        helper.logging.info(f"Got device secret: SECRET.")
        return self._get_security_device_attribute('security_device_secret')

    def get_security_device_domain_from_db(self):
        helper.logging.debug(f"Called get_security_device_domain().")
        helper.logging.info(f"Fetching the domain of {self._name}.")
        """
        Retrieve the security device domain.

        Returns:
        - str: The security device domain.
        """
        helper.logging.info(f"Got device domain: {self._get_security_device_attribute('security_device_domain')}.")
        return self._get_security_device_attribute('security_device_domain')

    def get_security_device_port_from_db(self):
        helper.logging.debug(f"Called get_security_device_port().")
        helper.logging.info(f"Fetching the port of {self._name}.")
        """
        Retrieve the security device port.

        Returns:
        - str: The security device port.
        """
        helper.logging.info(f"Got device port: {self._get_security_device_attribute('security_device_port')}.")
        return self._get_security_device_attribute('security_device_port')

    def get_security_device_version_from_db(self):
        helper.logging.debug(f"Called get_security_device_version().")
        helper.logging.info(f"Fetching the version of {self._name}.")
        """
        Retrieve the security device version.

        Returns:
        - str: The security device version.
        """
        helper.logging.info(f"Got device version: {self._get_security_device_attribute('security_device_version')}.")
        return self._get_security_device_attribute('security_device_version')

    def _get_security_device_attribute(self, attribute):
        helper.logging.debug(f"Called _get_security_device_attribute().")
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


    def set_security_policy_connection(self, security_policy_connection):
        self._security_policy_connection = security_policy_connection

    # the following functions process the data from the database. all the objects are processed, the unique values
    # are gathered and returned in a list that will be further processed by the program
    def get_db_objects(self, object_type):
        helper.logging.debug(f"Called get_db_objects().")
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
        helper.logging.debug(f"Called insert_into_managed_devices_table().")
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
                helper.logging.warn(f"Duplicate entry for managed device: {managed_device_name}. Skipping insertion.")
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
        helper.logging.debug("Called insert_into_general_table().")
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
            helper.logging.warn(f"Duplicate entry for device name: {self._name}. Skipping insertion.")
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
        helper.logging.debug("Called insert_into_security_policy_containers_table().")
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
                helper.logging.warn(f"Duplicate entry for container: {container_name}. Skipping insertion.")
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
        helper.logging.debug("Called insert_into_security_policies_table().")
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
                helper.logging.warn(f"Duplicate entry for security policy: {current_policy_name}. Skipping insertion.")
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
        helper.logging.debug("Called insert_into_object_containers_table().")
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
                helper.logging.warn(f"Duplicate entry for object container: {container_name}. Skipping insertion.")
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
        helper.logging.debug("Called insert_into_network_address_objects_table().")
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
                helper.logging.warn(f"Duplicate entry for network address object: {network_address_name}. Skipping insertion.")
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
        helper.logging.debug("Called insert_into_network_address_object_groups_table().")
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
                helper.logging.warn(f"Duplicate entry for network address object group: {network_address_group_name}. Skipping insertion.")
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
        helper.logging.debug("Called insert_into_security_policy_containers_table().")
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
                helper.logging.warn(f"Duplicate entry for container: {container_name}. Skipping insertion.")
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

    # TODO: now insert the extracted data
    def insert_into_geolocation_table(self, geolocation_object_data):
        helper.logging.debug("Called insert_into_geolocation_table().")
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


    # the following methods must be overriden by the device's specific methods
    # TODO: add all the methods necessary here (e.g process methods)
    def set_object_container(self, object_container):
        self._object_container = object_container
    
    def set_security_policy_container(self, security_policy_container):
        self._security_policy_container = security_policy_container
    
    @abstractmethod
    def get_sec_policies_data(self):
        pass

    @abstractmethod
    def extract_security_zones(self):
        pass

    @abstractmethod
    def extract_network_objects(self):
        pass

    @abstractmethod
    def extract_port_objects(self):
        pass

    @abstractmethod
    def extract_schedule_objects(self):
        pass

    @abstractmethod
    def extract_policy_users(self):
        pass

    @abstractmethod
    def extract_policy_urls(self):
        pass

    @abstractmethod
    def extract_policy_apps(self):
        pass

    @abstractmethod
    def extract_policy_comments(self):
        pass

    @abstractmethod
    def get_nat_policy_containers(self):
        pass

    @abstractmethod
    def get_object_containers(self):
        pass

    @abstractmethod
    def get_objects(self):
        pass

    @abstractmethod
    def get_network_address_objects(self):
        pass

    @abstractmethod
    def get_network_group_objects(self):
        pass

    @abstractmethod
    def get_port_objects(self):
        pass

    @abstractmethod
    def get_port_group_objects(self):
        pass

    @abstractmethod
    def get_url_objects(self):
        pass
    
    @abstractmethod
    def connect_to_security_device(self):
        pass
