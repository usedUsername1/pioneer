# git ls-files | xargs wc -l
import utils.helper as helper
import utils.gvars as gvars
from pkg.MigrationProject import MigrationProject, MigrationProjectDatabase
from pkg import PioneerDatabase
from pkg.SecurityDevice import SecurityDevice, SecurityDeviceDatabase 
from pkg.SecurityDevice.SecurityDeviceFactory import SecurityDeviceFactory
from pkg.MigrationProject import MigrationProjectFactory
import sys
from datetime import datetime, timezone
import time
from pkg.Container.PioneerContainer import PioneerSecurityPolicyContainer

# Disable logging for the 'fireREST' logger
helper.logging.getLogger('fireREST').setLevel(helper.logging.CRITICAL)

def main():
    # Retrieve db credentials and connection details from global variables
    db_user = gvars.pioneer_db_user
    db_password = gvars.pioneer_db_user_pass
    landing_db = gvars.landing_db
    db_host = gvars.db_host
    db_port = gvars.db_port

    # Create the parser for the Pioneer utility
    pioneer_parser = helper.create_parser()

    # Store the arguments passed by the user
    pioneer_args = pioneer_parser.parse_args()

    # Convert the args to a dictionary for easier processing
    pioneer_args = vars(pioneer_args)

    # Check if the necessary arguments for creating a security device are provided
    if (pioneer_args["create_security_device [name]"] and 
        pioneer_args["device_type [type]"] and 
        pioneer_args["hostname [hostname]"] and 
        pioneer_args["username [username]"] and 
        pioneer_args["secret [secret]"]):

        # Extract information about the security device from pioneer_args
        device_name = pioneer_args["create_security_device [name]"]
        device_type = pioneer_args["device_type [type]"]
        device_hostname = pioneer_args["hostname [hostname]"]
        device_username = pioneer_args["username [username]"]
        device_secret = pioneer_args["secret [secret]"]
        device_port = pioneer_args["port [port]"]
        device_domain = pioneer_args["domain [fmc_domain]"]

        # Set up logging directory
        log_folder = helper.os.path.join('log', f'device_{device_name}')
        helper.setup_logging(log_folder, {gvars.general_logger: gvars.general_log_file,
                                          gvars.special_policies_logger: gvars.special_policies_logger_file})
        
        general_logger = helper.logging.getLogger(gvars.general_logger)

        # Log the creation of a new security device
        general_logger.info(f"################## CREATING A NEW DEVICE: <{device_name}> ##################")
        general_logger.info(f"Got the following info about device from user: device name: <{device_name}>, type: <{device_type}>, hostname: <{device_hostname}>, username: <{device_username}>, secret: <>, port: <{device_port}>, domain: <{device_domain}>.")

        # Connect to the landing device db
        landing_db_cursor = PioneerDatabase.connect_to_db(db_user, landing_db, db_password, db_host, db_port)
        
        # Create the security device db object using the landing db connection
        security_device_db = SecurityDeviceDatabase(landing_db_cursor)

        # Generate a unique identifier for the security device
        device_uuid = helper.generate_uid()

        # Log connection to the security device
        general_logger.info(f"Connecting to the security device: <{device_name}>.")
        
        # Attempt to create the security device object based on the device type
        if '_api' in device_type:
            general_logger.info(f"The device <{device_name}> is an API device. Its API will be used for interacting with it.")
            security_device_object = SecurityDeviceFactory.build_api_security_device(
                device_uuid, device_name, device_type, 
                security_device_db, device_hostname, device_username, 
                device_secret, device_port, device_domain
            )
        else:
            general_logger.critical(f"Provided device type <{device_type}> is invalid.")
            sys.exit(1)
        
        # Log retrieval of the security device version
        general_logger.info(f"################## Getting the device version for device: <{device_name}>. ##################")
        
        # Get the version of the security device
        device_version = security_device_object.get_device_version_from_device_conn()
        
        # If version retrieval is successful, proceed with db creation and data insertion
        if device_version:
            # Create the security device db name
            security_device_db_name = device_name + '_db'
            general_logger.info(f"Connecting to the Postgres using user: <{db_user}>, password: ..., host: <{db_host}>, port: <{db_port}>, landing db: <{landing_db}>.")
            
            # Create the db for the security device
            security_device_db.create_db(security_device_db_name)

            # Connect to the newly created security device db
            security_device_db_cursor = PioneerDatabase.connect_to_db(db_user, security_device_db_name, db_password, db_host, db_port)
            security_device_db = SecurityDeviceDatabase(security_device_db_cursor)

            # Create the necessary tables in the device db
            security_device_db.create_security_device_tables()

            # Set the db for the security device object
            security_device_object.db = security_device_db

            # Insert general device info into the db
            general_logger.info(f"Inserting general device info in the db.")
            security_device_object.save_general_info(
                security_device_object.uid, device_name, device_username, 
                device_secret, device_hostname, device_type, 
                device_port, device_version, device_domain
            )

            # Log the import of object container data
            print("Importing the object container data.")
            general_logger.info(f"################## Getting the object containers of device: <{device_name}>. ##################")
            
            # Import and insert the object container data
            object_containers_list = security_device_object.get_container_info_from_device_conn(gvars.object_containers)
            
            # Log the import of security zones container data
            print("Importing security zones container data.")
            zone_containers_list = security_device_object.get_container_info_from_device_conn(gvars.security_zone_container)
            
            # Log the import of managed devices container data
            print("Importing managed devices container data.")
            managed_devices_container_list = security_device_object.get_container_info_from_device_conn(gvars.managed_device_container)
            
            # Log the import of security policy containers data
            print("Importing the security policy containers info.")
            security_policy_containers_list = security_device_object.get_container_info_from_device_conn(gvars.security_policy_container)

            # Log the import of NAT policy containers data
            print("Importing the NAT policy containers info.")
            security_policy_containers_list = security_device_object.get_container_info_from_device_conn(gvars.nat_policy_container)
            
            # Log the import of object data
            print("Importing the object data")
            general_logger.info(f"################## Getting the objects of device: <{device_name}>. ##################")
            
            # Iterate through each object container and import relevant data
            for object_container in object_containers_list:
                object_container_name = object_container.name
                
                # Log and import network objects
                general_logger.info(f"################## Getting the network objects of device: <{device_name}>. Container: <{object_container_name}> ##################")
                print("Import network objects.")
                security_device_object.get_object_info_from_device_conn(gvars.network_object, object_container)

                # Log and import network group objects
                general_logger.info(f"################## Getting the network group objects of device: <{device_name}>. Container: <{object_container_name}> ##################")
                print("Import network group objects.")
                security_device_object.get_object_info_from_device_conn(gvars.network_group_object, object_container)

                # Log and import port objects
                general_logger.info(f"################## Getting the port objects of device: <{device_name}>. Container: <{object_container_name}> ##################")
                print("Import port objects.")
                security_device_object.get_object_info_from_device_conn(gvars.port_object, object_container)
                
                # Log and import port group objects
                general_logger.info(f"################## Getting the port group objects of device: <{device_name}>. Container: <{object_container_name}> ##################")
                print("Import port group objects.")
                security_device_object.get_object_info_from_device_conn(gvars.port_group_object, object_container)
                
                # Log and import URL objects
                general_logger.info(f"################## Getting the URL objects of device: <{device_name}>. Container: <{object_container_name}> ##################")
                print("Import URL objects.")
                security_device_object.get_object_info_from_device_conn(gvars.url_object, object_container)
                
                # Log and import URL group objects
                general_logger.info(f"################## Getting the URL group objects of device: <{device_name}>. Container: <{object_container_name}> ##################")
                print("Import URL group objects.")
                security_device_object.get_object_info_from_device_conn(gvars.url_group_object, object_container)

                # Log and import schedule objects
                general_logger.info(f"################## Getting the schedule objects of device: <{device_name}>. Container: <{object_container_name}> ##################")
                print("Import the schedule objects.")
                security_device_object.get_object_info_from_device_conn(gvars.schedule_object, object_container)
            
            # Iterate through each zone container and import zone data
            for zone_container in zone_containers_list:
                print("Importing the interfaces/zones data.")
                security_device_object.get_object_info_from_device_conn(gvars.security_zone, zone_container)

            # Log and import managed devices
            general_logger.info(f"################## Getting the managed devices of device: <{device_name}>. ##################")
            print("Importing the managed devices data.")
            if managed_devices_container_list is not None:
                for managed_device_container in managed_devices_container_list:
                    security_device_object.get_object_info_from_device_conn(gvars.managed_device, managed_device_container)
            
            # Log and import security policies
            print("Importing security policies.")
            for security_policy_container in security_policy_containers_list:
                print(f"Processing policies of container {security_policy_container.name}")
                security_device_object.get_object_info_from_device_conn(gvars.security_policy, security_policy_container)

        else:
            # Log critical error and exit if device version retrieval fails
            general_logger.critical(f"Failed to retrieve version of the security device. Exiting...")
            sys.exit(1)
        
        # Close the cursors used to connect to the dbs
        landing_db_cursor.close()
        security_device_db_cursor.close()

    if pioneer_args['create_project [name]']:
        # Extract the project name from arguments
        project_name = pioneer_args['create_project [name]']
        creation_timestamp = datetime.now()

        # Open a connection to the landing db
        landing_db_cursor = PioneerDatabase.connect_to_db(db_user, landing_db, db_password, db_host, db_port)

        # Set the name for the project's db
        project_db_name = project_name + gvars.db_name_suffix

        # Create the project db
        migration_project_db = MigrationProjectDatabase(landing_db_cursor)
        migration_project_db.create_db(project_db_name)

        # Connect to the project's db and create the migration project object
        migration_project = MigrationProjectFactory.create_migration_project(db_user, project_name, db_password, db_host, db_port)

        # Create the migration project's tables
        migration_project.db.create_migration_project_tables()

        # Save general information about the project
        migration_project.save_general_info('TEST_DESC', creation_timestamp)

        # Close the cursors
        landing_db_cursor.close()
        migration_project.db.cursor.close()

    if pioneer_args['project [name]']:
        # Extract the project name from arguments
        project_name = pioneer_args['project [name]']
        migration_project = MigrationProjectFactory.create_migration_project(db_user, project_name, db_password, db_host, db_port)

        # Set source and target devices if provided
        if pioneer_args['set_source_device [name]'] and pioneer_args['set_target_device [name]']:
            source_device = SecurityDeviceFactory.create_security_device(db_user, pioneer_args['set_source_device [name]'], db_password, db_host, db_port)
            target_device = SecurityDeviceFactory.create_security_device(db_user, pioneer_args['set_target_device [name]'], db_password, db_host, db_port)
            migration_project.import_data(source_device, target_device)

        # Map containers if provided
        if pioneer_args['map_containers']:
            if pioneer_args['source_container_name'] and pioneer_args['target_container_name']:
                migration_project.map_containers(pioneer_args['source_container_name'], pioneer_args['target_container_name'])

        # Map zones if provided
        if pioneer_args.get('map_zones'):
            if pioneer_args.get('source_zone_name') and pioneer_args.get('target_zone_name'):
                migration_project.map_zones(pioneer_args['source_zone_name'], pioneer_args['target_zone_name'])

        # Set log manager if provided
        if pioneer_args.get('send_logs_to_manager'):
            log_manager_name = pioneer_args.get('send_logs_to_manager')
            migration_project.set_log_manager(log_manager_name)

        # Set security profile if provided
        if pioneer_args.get('set_security_profile'):
            security_profile_name = pioneer_args.get('set_security_profile')
            migration_project.set_security_profile(security_profile_name)

        # Perform migration if requested
        if pioneer_args['migrate']:
            migration_project = MigrationProjectFactory.build_migration_project(migration_project.name, migration_project.db)

            # Process and migrate security policy container if provided
            if pioneer_args['security_policy_container [container_name]']:
                security_policy_container = PioneerSecurityPolicyContainer(migration_project, pioneer_args['security_policy_container [container_name]'], None)
                security_policy_container.process_and_migrate()

if __name__ == "__main__":
    main()
