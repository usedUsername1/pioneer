from pkg.MigrationProject.PANMCMigrationProject import PANMCMigrationProject
from pkg.MigrationProject import MigrationProject, MigrationProjectDatabase
from pkg.SecurityDevice.SecurityDeviceFactory import SecurityDeviceFactory

import utils.helper as helper
import utils.gvars as gvars
from pkg import PioneerDatabase

@staticmethod
def create_migration_project(db_user, migration_project_name, db_password, db_host, db_port):
    # Define the logging settings for general logging
    log_folder = helper.os.path.join('log', f'device_{migration_project_name}')
    helper.setup_logging(log_folder, {gvars.general_logger: gvars.general_log_file,
                                        gvars.special_policies_logger: gvars.special_policies_logger_file})
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
    
@staticmethod
def build_migration_project(name, Database):
    # Retrieve the target_device_uid
    source_device_name = get_device_name(Database, 'source')
    target_device_name = get_device_name(Database, 'target')
    SourceSecurityDevice = SecurityDeviceFactory.create_security_device(gvars.pioneer_db_user, source_device_name, gvars.pioneer_db_user_pass, gvars.db_host, gvars.db_port)
    TargetSecurityDevice = SecurityDeviceFactory.create_security_device(gvars.pioneer_db_user, target_device_name, gvars.pioneer_db_user_pass, gvars.db_host, gvars.db_port)
    target_device_type = get_target_device_type_by_uid(Database)
    match target_device_type:
        case 'panmc-api':
            return PANMCMigrationProject(name, Database, SourceSecurityDevice, TargetSecurityDevice)
        case _:
            # Default case, return None or raise an error
            raise ValueError(f"Unsupported target device type: <{target_device_type}>.")

@staticmethod
def get_target_device_type_by_uid(Database):
    target_device_uid = Database.get_migration_project_devices_table().get(columns='target_device_uid')[0]
    # Define the join condition
    join_condition = {
        'table': 'general_security_device_data',
        'condition': 'migration_project_devices.target_device_uid = general_security_device_data.uid'
    }

    # Get the target device type
    target_device_info = Database.get_migration_project_devices_table().get(
        columns=['general_security_device_data.type'],
        name_col='migration_project_devices.target_device_uid',
        val=target_device_uid,
        join=join_condition
    )

    target_device_type = target_device_info[0][0]
    return target_device_type

@staticmethod
def get_device_name(Database, device_type):
    if device_type not in ['source', 'target']:
        raise ValueError("device_type must be either 'source' or 'target'")

    device_column = f'{device_type}_device_uid'
    
    # Retrieve the device UID from the migration_project_devices table
    device_uid = Database.get_migration_project_devices_table().get(columns=device_column)[0][0]

    # Define the join condition
    join_condition = {
        'table': 'general_security_device_data',
        'condition': f'migration_project_devices.{device_column} = general_security_device_data.uid'
    }

    # Query the database to get the device name
    device_info = Database.get_migration_project_devices_table().get(
        columns=['general_security_device_data.name'],
        name_col=f'migration_project_devices.{device_column}',
        val=device_uid,
        join=join_condition
    )

    # Return the device name if available
    device_name = device_info[0][0] if device_info else None
    return device_name