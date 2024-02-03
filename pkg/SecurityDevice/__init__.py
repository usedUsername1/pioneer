from abc import ABC, abstractmethod
from pkg import PioneerDatabase, DBConnection
from pkg.PolicyPackage import SecurityPolicyPackage
from pkg.PolicyPackage import NATPolicyPackage
from pkg.DeviceObject.NetworkObject import NetworkObject
from pkg.DeviceObject.SecurityZone import SecurityZone
from pkg.DeviceObject.GroupObject.NetworkGroupObject import NetworkGroupObject
from pkg.DeviceObject.PortObject import PortObject
from pkg.DeviceObject.GroupObject.PortGroupObject import PortGroupObject
from pkg.DeviceObject.UserSource import UserSource
from pkg.DeviceObject.URL import URL
from pkg.DeviceObject.L7Application import L7Application
import utils.helper as helper
import utils.gvars as gvars
import json

# TODO: create all the tables for all the objects
class SecurityDeviceDatabase(PioneerDatabase):
    def __init__(self, cursor):
        super().__init__(cursor)
    
    def create_security_device_tables(self):
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
        # self.table_factory("override_objects_table")

    
    #TODO: tables for l7 and ping apps
    #TODO: table for time range objects
    def table_factory(self, table_name):
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
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name)
                );"""
            
            case 'nat_policy_containers_table':
                command = """CREATE TABLE IF NOT EXISTS nat_policy_containers_table (
                security_device_name TEXT NOT NULL,
                nat_policy_container_name TEXT PRIMARY KEY,
                nat_policy_container_parent TEXT,
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name)
                );"""
            
            case 'object_containers_table':
                command = """CREATE TABLE IF NOT EXISTS object_containers_table (
                security_device_name TEXT NOT NULL,
                object_container_name TEXT PRIMARY KEY,
                object_container_parent TEXT,
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name)
                );"""

            # TODO: do i need two tables here? one for pre-processing and one for post-processing?
            case 'security_policies_table':
                command = """CREATE TABLE IF NOT EXISTS security_policies_table (
                security_device_name TEXT NOT NULL,
                security_policy_name TEXT PRIMARY KEY,
                security_policy_container_name TEXT NOT NULL,
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
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_sec_policy_container
                    FOREIGN KEY(security_policy_container_name)
                        REFERENCES security_policy_containers_table(security_policy_container_name)
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
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_sec_policy_container
                    FOREIGN KEY(security_policy_container_name)
                        REFERENCES security_policy_containers_table(security_policy_container_name),
                CONSTRAINT fk_nat_policy_container
                    FOREIGN KEY(nat_policy_container_name)
                        REFERENCES security_policy_containers_table(security_policy_container_name)
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
                    CONSTRAINT fk_sec_dev_name
                        FOREIGN KEY(security_device_name)
                            REFERENCES general_data_table(security_device_name)
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
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_obj_container
                    FOREIGN KEY(object_container_name)
                        REFERENCES object_containers_table(object_container_name)
                );"""

            case 'urls_table':
                command = """CREATE TABLE IF NOT EXISTS url_objects_table (
                url_object_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                url_object_members TEXT[],
                url_object_description TEXT,
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_obj_container
                    FOREIGN KEY(object_container_name)
                        REFERENCES object_containers_table(object_container_name)
                );"""

            #TODO: add proper support for url categories
            case 'urls_categories_table':
                command = """CREATE TABLE IF NOT EXISTS urls_categories_table (
                    url_category_name TEXT PRIMARY KEY,
                    security_device_name TEXT NOT NULL,
                    object_container_name TEXT NOT NULL,
                    CONSTRAINT fk_sec_dev_name
                        FOREIGN KEY(security_device_name)
                            REFERENCES general_data_table(security_device_name),
                    CONSTRAINT fk_object_container
                        FOREIGN KEY(object_container_name)
                            REFERENCES object_containers_table(object_container_name)
                );"""
            
            #TODO: add proper support for l7 apps
            case 'l7_apps_table':
                command = """CREATE TABLE IF NOT EXISTS l7_apps_table (
                    l7_app_name TEXT PRIMARY KEY,
                    security_device_name TEXT NOT NULL,
                    object_container_name TEXT NOT NULL,
                    CONSTRAINT fk_sec_dev_name
                        FOREIGN KEY(security_device_name)
                            REFERENCES general_data_table(security_device_name),
                    CONSTRAINT fk_object_container
                        FOREIGN KEY(object_container_name)
                            REFERENCES object_containers_table(object_container_name)
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
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_obj_container
                    FOREIGN KEY(object_container_name)
                        REFERENCES object_containers_table(object_container_name)
                );"""

            case 'network_address_object_groups_table':
                command = """CREATE TABLE IF NOT EXISTS network_address_object_groups_table (
                network_address_group_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                network_address_group_members TEXT[],
                network_address_group_description TEXT,
                overridable_object BOOLEAN NOT NULL,
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_obj_container
                    FOREIGN KEY(object_container_name)
                        REFERENCES object_containers_table(object_container_name)
                );"""

            case 'port_objects_table':
                command = """CREATE TABLE IF NOT EXISTS port_objects_table (
                port_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                port_value TEXT,
                port_description TEXT,
                overridable_object BOOLEAN NOT NULL,
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_obj_container
                    FOREIGN KEY(object_container_name)
                        REFERENCES object_containers_table(object_container_name)
                );"""

            case 'port_object_groups_table':
                command = """CREATE TABLE IF NOT EXISTS port_object_groups_table (
                port_group_name TEXT PRIMARY KEY,
                security_device_name TEXT NOT NULL,
                object_container_name TEXT NOT NULL,
                port_group_members TEXT[] NOT NULL,
                port_group_description TEXT NOT NULL,
                overridable_object BOOLEAN NOT NULL,
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_obj_container
                    FOREIGN KEY(object_container_name)
                        REFERENCES object_containers_table(object_container_name)
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
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_obj_container
                    FOREIGN KEY(object_container_name)
                        REFERENCES object_containers_table(object_container_name)
                )"""

            case 'managed_devices_table':
                command = """CREATE TABLE IF NOT EXISTS managed_devices_table (
                security_device_name TEXT NOT NULL,
                managed_device_name TEXT PRIMARY KEY,
                assigned_security_policy_container TEXT,
                hostname TEXT,
                cluster TEXT,
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name)
                );"""
            
            # this table stores info about the objects who are overriden. the stored info is the object name, its value, the device where the override is set
            # TODO: add support for overridden objects
            case 'override_objects_table':
                pass

        # create the table in the database
        self.create_table(table_name, command)


class SecurityDeviceConnection():
    def __init__(self) -> None:
        pass


# this will be a generic security device only with a database, acessing it will be possible
# in main, without acessing the protected attributes. better option for "--device"
class SecurityDevice():
    def __init__(self, name, sec_device_database):
        self._name = name
        self._database = sec_device_database

    # maybe we should have import functions here? the import functions will be used for importing the configuration
    # from the device. the get functions will be used to retrieve info from the object's database
    # the following methods can be universal?
    # TODO: all the below functions should process the output returned.
    def get_security_device_type(self):        
        select_command = "SELECT security_device_type FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_type = self._database.get_table_value('general_data_table', select_command)
        return security_device_type[0][0]

    def get_security_device_hostname(self):
        select_command = "SELECT security_device_hostname FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_hostname = self._database.get_table_value('general_data_table', select_command)
        return security_device_hostname[0][0]

    def get_security_device_username(self):
        select_command = "SELECT security_device_username FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_hostname = self._database.get_table_value('general_data_table', select_command)
        return security_device_hostname[0][0]

    def get_security_device_secret(self):
        select_command = "SELECT security_device_secret FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_secret = self._database.get_table_value('general_data_table', select_command)
        return security_device_secret[0][0]

    def get_security_device_domain(self):
        select_command = "SELECT security_device_domain FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_domain = self._database.get_table_value('general_data_table', select_command)
        return security_device_domain[0][0]

    def get_security_device_port(self):
        select_command = "SELECT security_device_port FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_port = self._database.get_table_value('general_data_table', select_command)
        return security_device_port[0][0]
    
    def get_security_device_version(self):
        select_command = "SELECT security_device_version FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_version = self._database.get_table_value('general_data_table', select_command)
        return security_device_version[0][0]
    
    # the following functions process the data from the database. all the objects are processed, the unique values
    # are gathered and returned in a list that will be further processed by the program
    def get_db_objects(self, object_type):
        """
        Retrieve and return unique database objects based on the specified type.

        :param object_type: The type of objects to retrieve. It should correspond to a column in the database.
        :return: A list of unique objects of the specified type.
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

        if object_type not in object_column_mapping:
            raise ValueError(f"Invalid object type: {object_type}")

        # Construct the SQL query
        columns = ", ".join(object_column_mapping[object_type])
        select_command = f"SELECT {columns} FROM security_policies_table;"

        # Execute the SQL query and fetch the results
        query_result = self._database.get_table_value('security_policies_table', select_command)

        # Flatten the results so that the unique values can be returned
        unique_objects_list = self._database.flatten_query_result(query_result)

        # remove the 'any' element of the list, if it exists. it is not an object that can be imported
        element_to_remove = 'any'
        if element_to_remove in unique_objects_list:
            unique_objects_list.remove(element_to_remove)

        return unique_objects_list

    def insert_into_managed_devices_table(self, managed_device_info):
        # loop through the managed devices info, extract the data and insert it into the table
        for managed_device_entry in managed_device_info:
            managed_device_name = managed_device_entry["managed_device_name"]
            assigned_security_policy_container = managed_device_entry["assigned_security_policy_container"]
            hostname = managed_device_entry["hostname"]
            cluster = managed_device_entry['cluster']

            insert_command = """
            INSERT INTO managed_devices_table (
            security_device_name,
            managed_device_name,
            assigned_security_policy_container,
            hostname,
            cluster
            ) VALUES (
            '{}', '{}', '{}', '{}', '{}'
            );""".format(self._name, managed_device_name, assigned_security_policy_container, hostname, cluster)

            self._database.insert_table_value('managed_devices_table', insert_command)


    def insert_into_general_table(self, security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain):
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
                '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}'
            );
        """.format(
            self._name, 
            security_device_username, 
            security_device_secret, 
            security_device_hostname, 
            security_device_type, 
            security_device_port, 
            security_device_version, 
            domain
        )

        self._database.insert_table_value('general_data_table', insert_command)


    def insert_into_security_policy_containers_table(self, container_name, container_parent):
        insert_command = """
            INSERT INTO security_policy_containers_table (
                security_device_name, 
                security_policy_container_name, 
                security_policy_container_parent
            ) VALUES (
                '{}', '{}', '{}'
            )
        """.format(self._name, container_name, container_parent)
        
        self._database.insert_table_value('security_policy_containers_table', insert_command)
        
    def insert_into_security_policies_table(self, sec_policy_data):
        # loop through the security policy data, extract it and then insert it to the table
        for current_policy_data in sec_policy_data:
            print(current_policy_data)
            # the list values need to be formatted to a postgresql array format before they will be inserted in the DB
            formatted_security_policy_source_zones = "{" + ",".join( current_policy_data["sec_policy_source_zones"]) + "}"
            formatted_security_policy_destination_zones = "{" + ",".join( current_policy_data["sec_policy_destination_zones"]) + "}"
            formatted_security_policy_source_networks = "{" + ",".join( current_policy_data["sec_policy_source_networks"]) + "}"
            formatted_security_policy_destination_networks = "{" + ",".join( current_policy_data["sec_policy_destination_networks"]) + "}"
            formatted_security_policy_source_ports = "{" + ",".join( current_policy_data["sec_policy_source_ports"]) + "}"
            formatted_security_policy_destination_ports = "{" + ",".join( current_policy_data["sec_policy_destination_ports"]) + "}"
            formatted_security_policy_schedules = "{" + ",".join( current_policy_data["sec_policy_schedules"]) + "}"
            formatted_security_policy_users = "{" + ",".join( current_policy_data["sec_policy_users"]) + "}"
            formatted_security_policy_urls = "{" + ",".join( current_policy_data["sec_policy_urls"]) + "}"
            formatted_security_policy_l7_apps = "{" + ",".join( current_policy_data["sec_policy_apps"]) + "}"
            comments = current_policy_data["sec_policy_comments"]
            
            # TODO: not sure this is the most optimal solution, maybe retrieve all the comments in a list, without dictionaries
            if comments is not None:
                # Convert each dictionary to a JSON string and escape double quotes for SQL
                comments_as_json_strings = ['"' + json.dumps(comment).replace('"', '\\"') + '"' for comment in comments]
                # Join the strings into a PostgreSQL array format
                formatted_security_policy_comments = "{" + ",".join(comments_as_json_strings) + "}"
            else:
                # This block executes if 'sec_policy_comments' is None.
                # Here, 'formatted_security_policy_comments' is set to an empty dictionary.
                # This represents a valid empty JSON object.
                # It's a safe placeholder for scenarios where there are no comments.
                formatted_security_policy_comments = {}
            formatted_security_policy_log_setting = "{" + ",".join( current_policy_data["sec_policy_log_settings"]) + "}"

            insert_command = """
                INSERT INTO security_policies_table (
                    security_device_name, 
                    security_policy_name, 
                    security_policy_container_name, 
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
                    '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}'
                )""".format(
                    self._name,
                    current_policy_data["sec_policy_name"],
                    current_policy_data["sec_policy_container_name"],
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
            
            self._database.insert_table_value('security_policies_table', insert_command)

    def verify_duplicate(self, table, column, value):
        select_command = """SELECT EXISTS(SELECT 1 FROM {} WHERE {} = '{}');""".format(table, column, value)
        is_duplicate = self._database.get_table_value(table, select_command)

        return is_duplicate[0][0]

    def delete_security_device(self):
        pass

    # the following methods must be overriden by the device's specific methods
    # TODO: add all the methods necessary here (e.g process methods)
    @abstractmethod
    def get_sec_policy_container_info(self):
        pass
    
    @abstractmethod
    def get_sec_policies_data(self):
        pass

    @abstractmethod
    def process_security_zones(self):
        pass

    @abstractmethod
    def process_network_objects(self):
        pass

    @abstractmethod
    def process_ports_objects(self):
        pass

    @abstractmethod
    def process_schedule_objects(self):
        pass

    @abstractmethod
    def process_policy_users(self):
        pass

    @abstractmethod
    def process_policy_urls(self):
        pass

    @abstractmethod
    def process_policy_apps(self):
        pass

    @abstractmethod
    def process_policy_comments(self):
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
    def get_device_version(self):
        pass
    
    @abstractmethod
    def connect_to_security_device(self):
        pass
