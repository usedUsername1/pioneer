import utils.helper as helper
from pkg import PioneerDatabase, DBConnection, SecurityPolicyContainersMapTable, MigrationProjectGeneralDataTable, MigrationProjectDevicesTable, SecurityDeviceInterfaceMap
from pkg.SecurityDevice import SecurityDeviceDatabase

#TODO: should the migration db inherit from security device db or should
# all the code from security device db be moved here?
# create the extra tables needed for migration stuff
class MigrationProjectDatabase(SecurityDeviceDatabase):
    def __init__(self, cursor):
        super().__init__(cursor)
        self._SecurityPoliciesMapTable = SecurityPolicyContainersMapTable(self)
        self._MigrationProjectGeneralDataTable = MigrationProjectGeneralDataTable(self)
        self._MigrationProjectDevicesTable = MigrationProjectDevicesTable(self)
        self._SecurityDeviceInterfaceMap = SecurityDeviceInterfaceMap(self)

    def create_migration_project_tables(self):
        # create the security device tables needed to store the data from the imported security devices
        self.create_security_device_tables()
        self._SecurityPoliciesMapTable.create()
        self._MigrationProjectGeneralDataTable.create()
        self._MigrationProjectDevicesTable.create()
        self._SecurityDeviceInterfaceMap.create()
    
    def get_migration_project_general_data_table(self):
        return self._MigrationProjectGeneralDataTable
    
    def get_migration_project_devices_table(self):
        return self._MigrationProjectDevicesTable

class MigrationProject():
    def __init__(self, name, Database):
        self._name = name
        self._Database = Database
    
    def save_general_info(self, description, creation_timestamp):
        MigrationProjectGeneralDataTable = self._Database.get_migration_project_general_data_table()
        MigrationProjectGeneralDataTable.insert(self._name, description, creation_timestamp)
    
    def get_database(self):
        return self._Database

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

    @staticmethod
    def create_migration_project(db_user, migration_project_name, db_password, db_host, db_port):
        # Define the logging settings for general logging
        general_log_folder = helper.os.path.join('log', f'device_{migration_project_name}')
        helper.setup_logging(general_log_folder, {'general': 'general.log'})
        general_logger = helper.logging.getLogger('general')
        general_logger.info("################## Migration Project ##################")

        migration_project_db_name = migration_project_name + "_db"
        # Connect to the database of the security device
        MigrationProjectDBcursor = PioneerDatabase.connect_to_db(db_user, migration_project_db_name, db_password, db_host, db_port)

        # instantiate and extract all the data from a generic security device
        # the data will be used further for creating the specific security device object
        MigrationProjectDB = MigrationProjectDatabase(MigrationProjectDBcursor)

        MigrationProjectObject = MigrationProject(migration_project_name, MigrationProjectDB)

        return MigrationProjectObject