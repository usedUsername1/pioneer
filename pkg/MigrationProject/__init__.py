from abc import abstractmethod
import utils.helper as helper
import utils.gvars as gvars
from pkg import PioneerDatabase, DBConnection, SecurityPolicyContainersMapTable, MigrationProjectGeneralDataTable, MigrationProjectDevicesTable, SecurityDeviceInterfaceMap
from pkg.SecurityDevice import SecurityDeviceDatabase

special_policies_log = helper.logging.getLogger(gvars.special_policies_logger)

class MigrationProjectDatabase(SecurityDeviceDatabase):
    def __init__(self, cursor):
        super().__init__(cursor)
        self._SecurityPolicyContainersMapTable = SecurityPolicyContainersMapTable(self)
        self._MigrationProjectGeneralDataTable = MigrationProjectGeneralDataTable(self)
        self._MigrationProjectDevicesTable = MigrationProjectDevicesTable(self)
        self._SecurityDeviceInterfaceMapTable = SecurityDeviceInterfaceMap(self)

    def create_migration_project_tables(self):
        # create the security device tables needed to store the data from the imported security devices
        self.create_security_device_tables()
        self._SecurityPolicyContainersMapTable.create()
        self._MigrationProjectGeneralDataTable.create()
        self._MigrationProjectDevicesTable.create()
        self._SecurityDeviceInterfaceMapTable.create()
    
    def get_migration_project_general_data_table(self):
        return self._MigrationProjectGeneralDataTable
    
    def get_migration_project_devices_table(self):
        return self._MigrationProjectDevicesTable
    
    def get_security_policy_containers_map_table(self):
        return self._SecurityPolicyContainersMapTable
    
    def get_security_device_interface_map_table(self):
        return self._SecurityDeviceInterfaceMapTable

class MigrationProject():
    def __init__(self, name, Database):
        self._name = name
        self._Database = Database
    
    def save_general_info(self, description, creation_timestamp):
        MigrationProjectGeneralDataTable = self._Database.get_migration_project_general_data_table()
        MigrationProjectGeneralDataTable.insert(self._name, description, creation_timestamp)
    
    def get_database(self):
        return self._Database
    
    def get_name(self):
        return self._name

    def import_data(self, SourceSecurityDevice, TargetSecurityDevice):
        # Insert the UIDs of the source and target device
        MigrationProjectDevicesTable = self._Database.get_migration_project_devices_table()
        MigrationProjectDevicesTable.insert(SourceSecurityDevice.get_uid(), TargetSecurityDevice.get_uid())

        # List of tables to copy
        tables = [
            # General Data Table
            '_GeneralDataTable',

            # Containers
            '_SecurityPolicyContainersTable',
            '_NATPolicyContainersTable',
            '_ObjectContainersTable',
            '_SecurityZoneContainersTable',
            '_ManagedDeviceContainersTable',

            # Managed Devices
            '_ManagedDevicesTable',

            # Security Policies
            '_SecurityPoliciesTable',

            # Zones
            '_SecurityZonesTable',

            # Objects
            '_URLObjectsTable',
            '_NetworkAddressObjectsTable',
            '_PortObjectsTable',
            '_ICMPObjectsTable',
            '_GeolocationObjectsTable',
            '_CountryObjectsTable',
            '_ScheduleObjectsTable',

            # Groups
            '_NetworkGroupObjectsTable',
            '_PortGroupObjectsTable',
            '_URLGroupObjectsTable',

            # Group Members
            '_NetworkGroupObjectsMembersTable',
            '_PortGroupObjectsMembersTable',
            '_URLGroupObjectsMembersTable',

            # Policy Users
            '_PolicyUsersTable',

            # Layer 7 Applications
            '_L7AppsTable',
            '_L7AppFiltersTable',
            '_L7AppGroupsTable',
            '_L7AppGroupMembersTable',

            # URL Categories
            '_URLCategoriesTable',

            # Security Policy Details
            '_SecurityPolicyZonesTable',
            '_SecurityPolicyNetworksTable',
            '_SecurityPolicyPortsTable',
            '_SecurityPolicyUsersTable',
            '_SecurityPolicyURLsTable',
            '_SecurityPolicyL7AppsTable',
            '_SecurityPolicyScheduleTable'
        ]

        # Copy data for each table
        for table_name in tables:
            # Get source and target tables
            source_security_device_table = getattr(SourceSecurityDevice.get_database(), f'{table_name}')
            target_security_device_table = getattr(TargetSecurityDevice.get_database(), f'{table_name}')
            target_table = getattr(self._Database, f'{table_name}')

            # Fetch all data from source table
            source_data = source_security_device_table.get('*')
            target_data = target_security_device_table.get('*')

            # Insert data into target table
            for row in source_data:
                target_table.insert(*row)
            for row in target_data:
                target_table.insert(*row)
    
    def map_containers(self, source_container_name, target_container_name):
        GeneralDataTable = self._Database.get_security_policy_containers_table()
        # get source uid
        source_container_uid = GeneralDataTable.get('uid', 'name', source_container_name)[0]

        # get destination uid
        target_container_uid = GeneralDataTable.get('uid', 'name', target_container_name)[0]

        # insert the data in the table
        self._Database.get_security_policy_containers_map_table().insert(source_container_uid, target_container_uid)
    
    def map_zones(self, source_zone_name, target_zone_name):
        SecurityZonesTable = self._Database.get_security_zones_table()

        # get the source zone uid
        source_zone_uid = SecurityZonesTable.get('uid', 'name', source_zone_name)[0]

        # get the source zone uid
        target_zone_uid = SecurityZonesTable.get('uid', 'name', target_zone_name)[0]

        self._Database.get_security_device_interface_map_table().insert(source_zone_uid, target_zone_uid)
