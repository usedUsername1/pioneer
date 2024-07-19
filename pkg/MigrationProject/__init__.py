from abc import abstractmethod
import utils.helper as helper
import utils.gvars as gvars
from pkg import PioneerDatabase, DBConnection, SecurityPolicyContainersMapTable, MigrationProjectGeneralDataTable, MigrationProjectDevicesTable, SecurityDeviceInterfaceMap, \
LogSettingsTable, SpecialSecurityPolicyParametersTable, NetworkObjectTypesMapTable, SecurityPolicyActionMapTable, SecurityPolicySectionMap
from pkg.SecurityDevice import SecurityDeviceDatabase

special_policies_log = helper.logging.getLogger(gvars.special_policies_logger)

#TODO: should the table containing mappings of actions and object types be created here?
class MigrationProjectDatabase(SecurityDeviceDatabase):
    def __init__(self, cursor):
        super().__init__(cursor)
        #TODO: these parameters might not be needed here
        self._SourceSecurityDevice = None
        self._TargetSecurityDevice = None

        self._SecurityPolicyContainersMapTable = SecurityPolicyContainersMapTable(self)
        self._MigrationProjectGeneralDataTable = MigrationProjectGeneralDataTable(self)
        self._MigrationProjectDevicesTable = MigrationProjectDevicesTable(self)
        self._SecurityDeviceInterfaceMapTable = SecurityDeviceInterfaceMap(self)

        self._LogSettingsTable = LogSettingsTable(self)
        self._SpecialSecurityPolicyParametersTable = SpecialSecurityPolicyParametersTable(self)
        self._NetworkObjectTypesMapTable = NetworkObjectTypesMapTable(self)
        self._SecurityPolicyActionMapTable = SecurityPolicyActionMapTable(self)
        self._SecurityPolicySectionMapTable = SecurityPolicySectionMap(self)

    def create_migration_project_tables(self):
        # create the security device tables needed to store the data from the imported security devices
        self.create_security_device_tables()
        self._SecurityPolicyContainersMapTable.create()
        self._MigrationProjectGeneralDataTable.create()
        self._MigrationProjectDevicesTable.create()
        self._SecurityDeviceInterfaceMapTable.create()

        self._LogSettingsTable.create()
        self._SpecialSecurityPolicyParametersTable.create()
        self._NetworkObjectTypesMapTable.create()
        self._NetworkObjectTypesMapTable.pre_insert_data()
        self._SecurityPolicyActionMapTable.create()
        self._SecurityPolicyActionMapTable.pre_insert_data()
        self._SecurityPolicySectionMapTable.create()
        self._SecurityPolicySectionMapTable.pre_insert_data()
    
    def get_migration_project_general_data_table(self):
        return self._MigrationProjectGeneralDataTable
    
    def get_migration_project_devices_table(self):
        return self._MigrationProjectDevicesTable
    
    def get_security_policy_containers_map_table(self):
        return self._SecurityPolicyContainersMapTable
    
    def get_security_device_interface_map_table(self):
        return self._SecurityDeviceInterfaceMapTable

    def get_log_settings_table(self):
        return self._LogSettingsTable

    def get_special_security_policy_parameters_table(self):
        return self._SpecialSecurityPolicyParametersTable

    def get_network_object_types_map_table(self):
        return self._NetworkObjectTypesMapTable

    def get_security_policy_action_map_table(self):
        return self._SecurityPolicyActionMapTable
    
    def get_security_policy_section_map(self):
        return self._SecurityPolicySectionMapTable

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
        MigrationProjectDevicesTable = self._Database.get_migration_project_devices_table()

        # Get source security device uid based on source container name
        source_container_data = GeneralDataTable.get(['uid', 'security_device_uid'], 'name', source_container_name)
        if not source_container_data:
            raise ValueError(f"Source container with name '{source_container_name}' not found.")

        source_container_uid, source_device_uid = source_container_data[0]

        # Get target device uid based on source device uid from migration project devices
        target_device_data = MigrationProjectDevicesTable.get('target_device_uid', 'source_device_uid', source_device_uid)
        if not target_device_data:
            raise ValueError(f"Target device for source device uid '{source_device_uid}' not found.")

        target_device_uid = target_device_data[0]

        # Get target container uid based on target container name and target device uid
        target_container_data = GeneralDataTable.get(['uid'], ['name', 'security_device_uid'], [target_container_name, target_device_uid], multiple_where=True)
        if not target_container_data:
            raise ValueError(f"Target container with name '{target_container_name}' for device uid '{target_device_uid}' not found.")

        target_container_uid = target_container_data[0][0]

        # Insert the data into the containers map table
        self._Database.get_security_policy_containers_map_table().insert(source_container_uid, target_container_uid)
    
    #TODO: modify map_zones like the map_containers
    def map_zones(self, source_zone_name, target_zone_name):
        SecurityZonesTable = self._Database.get_security_zones_table()

        # get the source zone uid
        source_zone_uid = SecurityZonesTable.get('uid', 'name', source_zone_name)[0]

        # get the source zone uid
        target_zone_uid = SecurityZonesTable.get('uid', 'name', target_zone_name)[0]

        self._Database.get_security_device_interface_map_table().insert(source_zone_uid, target_zone_uid)

    def set_log_manager(self, log_manager_name):
        LogSettingsTable = self._Database.get_log_settings_table()
        LogSettingsTable.insert(log_manager_name)

    def set_security_profile(self, security_profile):
        SpecialSecurityPolicyParameters = self._Database.get_special_security_policy_parameters_table()
        SpecialSecurityPolicyParameters.insert(security_profile)