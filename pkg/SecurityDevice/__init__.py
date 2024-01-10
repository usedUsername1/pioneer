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

# TODO: create all the tables for all the objects
class SecurityDeviceDatabase(PioneerDatabase):
    def __init__(self, cursor):
        super().__init__(cursor)
        # do I actually need the table_factory in init?        
        # self.table_factory("general_data_table")
        # self.table_factory("security_device_table")
    
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
        # self.table_factory("override_objects_table")

    
    #TODO: there are fields that should be null, go all over the fields again and decide what is null and what isn ot null
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

            case 'security_policies_table':
                command = """CREATE TABLE IF NOT EXISTS security_policies_table (
                security_policy_name TEXT PRIMARY KEY,
                security_policy_category TEXT,
                security_device_name TEXT NOT NULL,
                security_policy_container_name TEXT NOT NULL,
                security_policy_status TEXT NOT NULL,
                security_policy_source_zones TEXT[] NOT NULL,
                security_policy_destination_zones TEXT[] NOT NULL,
                security_policy_source_networks TEXT[] NOT NULL,
                security_policy_destination_networks TEXT[] NOT NULL,
                security_policy_source_ports TEXT[] NOT NULL,
                security_policy_destination_ports TEXT[] NOT NULL,
                security_policy_time_range TEXT[] NOT NULL,
                security_policy_users TEXT[] NOT NULL,
                security_policy_urls TEXT[] NOT NULL,
                security_policy_url_categories TEXT[] NOT NULL,
                security_policy_l7_apps TEXT[] NOT NULL,
                security_policy_l7_app_filters TEXT[] NOT NULL,
                security_policy_description TEXT,
                security_policy_log_setting TEXT,
                security_policy_log_start BOOLEAN NOT NULL,
                security_policy_log_end BOOLEAN NOT NULL,
                security_policy_pre_or_post TEXT,
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_sec_policy_container
                    FOREIGN KEY(security_policy_container_name)
                        REFERENCES security_policy_containers_table(security_policy_container_name)
                );"""
            
            # this table stores info about the hitcounts of the security policies and of the nat policies
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
                CONSTRAINT fk_object_container
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
                CONSTRAINT fk_object_container
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
                overriden_object BOOLEAN NOT NULL,
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_object_container
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
                overriden_object BOOLEAN NOT NULL,
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_object_container
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
                overriden_object BOOLEAN NOT NULL,
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_object_container
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
                overriden_object BOOLEAN NOT NULL,
                CONSTRAINT fk_sec_dev_name
                    FOREIGN KEY(security_device_name)
                        REFERENCES general_data_table(security_device_name),
                CONSTRAINT fk_object_container
                    FOREIGN KEY(object_container_name)
                        REFERENCES object_containers_table(object_container_name)
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
    def get_security_device_type(self):        
        select_command = "SELECT security_device_type FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_type = self._database.get_table_value('general_data_table', select_command)
        return security_device_type

    def get_security_device_hostname(self):
        select_command = "SELECT security_device_hostname FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_hostname = self._database.get_table_value('general_data_table', select_command)
        return security_device_hostname

    def get_security_device_username(self):
        select_command = "SELECT security_device_username FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_hostname = self._database.get_table_value('general_data_table', select_command)
        return security_device_hostname

    def get_security_device_secret(self):
        select_command = "SELECT security_device_secret FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_secret = self._database.get_table_value('general_data_table', select_command)
        return security_device_secret

    def get_security_device_domain(self):
        select_command = "SELECT security_device_domain FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_domain = self._database.get_table_value('general_data_table', select_command)
        return security_device_domain

    def get_security_device_port(self):
        select_command = "SELECT security_device_port FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_type = self._database.get_table_value('general_data_table', select_command)
        return security_device_type
    
    def get_security_device_version(self):
        select_command = "SELECT security_device_version FROM general_data_table WHERE security_device_name = '{}'".format(self._name)
        security_device_type = self._database.get_table_value('general_data_table', select_command)
        return security_device_type
    
    def insert_into_general_table(self, security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain):
        insert_command = """INSERT INTO general_data_table (security_device_name, security_device_username, security_device_secret,
                                            security_device_hostname, security_device_type, security_device_port, security_device_version, security_device_domain)
                                    VALUES ('{}', '{}', '{}', '{}', '{}', '{}', '{}', '{}');""".format(self._name, security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain)

        self._database.insert_table_value('general_data_table', insert_command)

    def delete_security_device(self):
        pass

    # the following methods must be overriden by the device's specific methods 
    @abstractmethod
    def import_sec_policy_containers(self):
        pass

    @abstractmethod
    def import_nat_policy_containers(self):
        pass

    @abstractmethod
    def import_object_containers(self):
        pass

    @abstractmethod
    def import_device_version(self):
        pass
    
    @abstractmethod
    def connect_to_security_device(self):
        pass
