from pkg.MigrationProject.PANMCMigrationProject import PANMCMigrationProject
from pkg.MigrationProject import MigrationProject, MigrationProjectDatabase
from pkg.SecurityDevice.SecurityDeviceFactory import SecurityDeviceFactory

import utils.helper as helper
import utils.gvars as gvars
from pkg import PioneerDatabase

@staticmethod
def create_migration_project(db_user, migration_project_name, db_password, db_host, db_port):
    """
    Creates a new migration project, sets up logging, connects to the migration project db, and
    initializes a `MigrationProject` object.

    Args:
        db_user (str): The username for the db connection.
        migration_project_name (str): The name of the migration project.
        db_password (str): The password for the db connection.
        db_host (str): The hostname or IP address of the db server.
        db_port (int): The port number on which the db server is listening.

    Returns:
        MigrationProject: An instance of the `MigrationProject` class.
    """
    # Define the folder for logging based on the migration project name
    log_folder = helper.os.path.join('log', f'device_{migration_project_name}')

    # Set up logging configuration for general and special policies logs
    helper.setup_logging(
        log_folder, 
        {
            gvars.general_logger: gvars.general_log_file,
            gvars.special_policies_logger: gvars.special_policies_logger_file
        }
    )
    
    # Retrieve the general logger instance
    general_logger = helper.logging.getLogger('general')
    general_logger.info("################## Migration Project ##################")

    # Create the db name for the migration project
    migration_project_db_name = f"{migration_project_name}_db"

    # Connect to the db of the migration project
    migration_project_db_cursor = PioneerDatabase.connect_to_db(
        db_user, 
        migration_project_db_name, 
        db_password, 
        db_host, 
        db_port
    )

    # Instantiate the MigrationProjectDatabase with the obtained cursor
    migration_project_db = MigrationProjectDatabase(migration_project_db_cursor)

    # Create a MigrationProject object
    migration_project = MigrationProject(migration_project_name, migration_project_db)

    return migration_project
    
@staticmethod
def build_migration_project(name, db):
    """
    Constructs a migration project based on the provided name and db. This method retrieves 
    source and target device information, creates corresponding security devices, and initializes
    the appropriate migration project based on the target device type.

    Args:
        name (str): The name of the migration project.
        db (Database): The db instance used to retrieve device information and target device type.

    Returns:
        MigrationProject: An instance of a specific `MigrationProject` subclass, such as `PANMCMigrationProject`,
                           depending on the target device type.

    Raises:
        ValueError: If the target device type is unsupported.
    """
    # Retrieve the source and target device names from the db
    source_device_name = get_device_name(db, 'source')
    target_device_name = get_device_name(db, 'target')

    # Create security device instances for source and target
    source_security_device = SecurityDeviceFactory.create_security_device(
        gvars.pioneer_db_user, 
        source_device_name, 
        gvars.pioneer_db_user_pass, 
        gvars.db_host, 
        gvars.db_port
    )
    target_security_device = SecurityDeviceFactory.create_security_device(
        gvars.pioneer_db_user, 
        target_device_name, 
        gvars.pioneer_db_user_pass, 
        gvars.db_host, 
        gvars.db_port
    )

    # Retrieve the target device type from the db
    target_device_type = get_target_device_type_by_uid(db)

    # Instantiate and return the appropriate migration project based on target device type
    match target_device_type:
        case 'panmc_api':
            return PANMCMigrationProject(name, db, source_security_device, target_security_device)
        case _:
            # Raise an error if the target device type is unsupported
            raise ValueError(f"Unsupported target device type: <{target_device_type}>.")

@staticmethod
def get_target_device_type_by_uid(db):
    """
    Retrieves the type of the target security device based on its UID.

    Args:
        db (Database): The db instance used to fetch the target device UID and its type.

    Returns:
        str: The type of the target security device.

    Raises:
        IndexError: If no target device UID or type information is found in the db.
    """
    # Retrieve the target device UID from the migration project devices table
    target_device_uid = db.migration_project_devices_table.get(columns='target_device_uid')[0]
    
    # Define the join condition to get the device type
    join_condition = {
        'table': 'general_security_device_data',
        'condition': 'migration_project_devices.target_device_uid = general_security_device_data.uid'
    }

    # Fetch the target device type using the UID
    target_device_info = db.migration_project_devices_table.get(
        columns=['general_security_device_data.type'],
        name_col='migration_project_devices.target_device_uid',
        val=target_device_uid,
        join=join_condition
    )

    # Extract the device type from the fetched data
    target_device_type = target_device_info[0][0]

    return target_device_type

@staticmethod
def get_device_name(db, device_type):
    """
    Retrieves the name of a security device based on its type ('source' or 'target').

    Args:
        db (Database): The db instance used to fetch device details.
        device_type (str): The type of the device to retrieve ('source' or 'target').

    Returns:
        str: The name of the security device, or None if no name is found.

    Raises:
        ValueError: If the device_type is not 'source' or 'target'.
        IndexError: If no device UID is found in the db.
    """
    # Validate the device type
    if device_type not in ['source', 'target']:
        raise ValueError("device_type must be either 'source' or 'target'")

    # Define the column name for the device UID based on the device type
    device_uid_column = f'{device_type}_device_uid'
    
    # Retrieve the device UID from the migration_project_devices table
    device_uid_query = db.migration_project_devices_table.get(columns=device_uid_column)
    if not device_uid_query:
        raise IndexError(f"No device UID found for {device_type} device.")
    device_uid = device_uid_query[0][0]

    # Define the join condition to get the device name
    join_condition = {
        'table': 'general_security_device_data',
        'condition': f'migration_project_devices.{device_uid_column} = general_security_device_data.uid'
    }

    # Query the db to get the device name
    device_info = db.migration_project_devices_table.get(
        columns=['general_security_device_data.name'],
        name_col=f'migration_project_devices.{device_uid_column}',
        val=device_uid,
        join=join_condition
    )

    # Return the device name if available, otherwise return None
    device_name = device_info[0][0] if device_info else None
    return device_name