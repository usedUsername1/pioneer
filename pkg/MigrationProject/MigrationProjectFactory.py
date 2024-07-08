from pkg.MigrationProject.PANMCMigrationProject import PANMCMigrationProject
from pkg.MigrationProject import MigrationProject, MigrationProjectDatabase

import utils.helper as helper
from pkg import PioneerDatabase

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

#TODO: maybe be more specific when creating migration project, make sure you account for both source and target device.
@staticmethod
def build_migration_project(name, Database):
    # Retrieve the target_device_uid
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

    match target_device_type:
        case 'panmc-api':
            return PANMCMigrationProject(name, Database)
        case _:
            # Default case, return None or raise an error
            raise ValueError(f"Unsupported target device type: {target_device_type}")