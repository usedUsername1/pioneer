# git ls-files | xargs wc -l
#TODO: use properties instead of getters and setters in python
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
from pkg.MigrationProject.PANMCMigrationProject import PANMCMigrationProject
# import psutil

import subprocess

# Disable logging for the 'fireREST' logger
helper.logging.getLogger('fireREST').setLevel(helper.logging.CRITICAL)

def main():
    db_user = gvars.pioneer_db_user
    db_password = gvars.pioneer_db_user_pass
    landing_db = gvars.landing_db
    db_host = gvars.db_host
    db_port = gvars.db_port

    # create the parser for the pioneer utilty
    pioneer_parser = helper.create_parser()

    # store the arguments passed by the user
    pioneer_args = pioneer_parser.parse_args()

    # convert the args to a dictionary in order to further process them
    pioneer_args = vars(pioneer_args)

    # the "--create-security-device" argument must be used with the "--type" argument
    # create a security device with the name and the type specified by the user
    # create folder where logs for the security device will be stored
    if pioneer_args["create_security_device [name]"] and pioneer_args["device_type [type]"] and pioneer_args["hostname [hostname]"] and pioneer_args["username [username]"] and pioneer_args["secret [secret]"]:
        # Extract information about the security device from pioneer_args
        security_device_name = pioneer_args["create_security_device [name]"]
        security_device_type = pioneer_args["device_type [type]"]
        security_device_hostname = pioneer_args["hostname [hostname]"]
        security_device_username = pioneer_args["username [username]"]
        security_device_secret = pioneer_args["secret [secret]"]
        security_device_port = pioneer_args["port [port]"]
        domain = pioneer_args["domain [fmc_domain]"]

        # Setup logging
        log_folder = helper.os.path.join('log', f'device_{security_device_name}')
        helper.setup_logging(log_folder, {gvars.general_logger: gvars.general_log_file,
                                          gvars.special_policies_logger: gvars.special_policies_logger_file})
        
        general_logger = helper.logging.getLogger(gvars.general_logger)

        # Log creation of new device
        general_logger.info(f"################## CREATING A NEW DEVICE: <{security_device_name}> ##################")
        general_logger.info(f"Got the following info about device from user, security device name: <{security_device_name}>, type <{security_device_type}>, hostname <{security_device_hostname}, username <{security_device_username}>, secret <>, port: <{security_device_port}>, domain <{domain}>.")

        # Connect to the landing device database
        LandingDBcursor = PioneerDatabase.connect_to_db(db_user, landing_db, db_password, db_host, db_port)
        # Create the security device database object using the landing database
        SecurityDeviceDB = SecurityDeviceDatabase(LandingDBcursor)

        security_device_uuid = helper.generate_uid()

        # try:
        general_logger.info(f"Connecting to the security device: <{security_device_name}>.")
        # Attempt to create the security device object based on the device type
        if '_api' in security_device_type:
            general_logger.info(f"The device <{security_device_name}> is an API device. Its API will be used for interacting with it.")
            SecurityDeviceObject = SecurityDeviceFactory.build_api_security_device(
                security_device_uuid, security_device_name, security_device_type, 
                SecurityDeviceDB, security_device_hostname, security_device_username, 
                security_device_secret, security_device_port, domain
            )
        else:
            general_logger.critical(f"Provided device type <{security_device_type}> is invalid.")
            sys.exit(1)
        
        # Get the version of the security device
        general_logger.info(f"################## Getting the device version for device: <{security_device_name}>. ##################")
        security_device_version = SecurityDeviceObject.get_device_version_from_device_conn()
        
        # If version retrieval is successful, proceed with database creation and data insertion
        if security_device_version:
            # Create the database
            security_device_db_name = security_device_name + '_db'
            general_logger.info(f"Connecting to the Postgres using, user: <{db_user}>, password ..., host: <{db_host}>, port: <{db_port}>, landing database: <{landing_db}>.")
            SecurityDeviceDB.create_database(security_device_db_name)

            # Connect to the newly created security device database
            SecurityDeviceDBcursor = PioneerDatabase.connect_to_db(db_user, security_device_db_name, db_password, db_host, db_port)
            SecurityDeviceDB = SecurityDeviceDatabase(SecurityDeviceDBcursor)

            # Create the tables in the device database
            SecurityDeviceDB.create_security_device_tables()

            SecurityDeviceObject.set_database(SecurityDeviceDB)

            # Insert general device info into the database
            general_logger.info(f"Inserting general device info in the database.")
            SecurityDeviceObject.save_general_info(
                SecurityDeviceObject.get_uid(), security_device_name, security_device_username, 
                security_device_secret, security_device_hostname, security_device_type, 
                security_device_port, security_device_version, domain
            )

            # Retrieve the information about the containers, interfaces and objects
            start_time = time.time()
            cpu_usage, ram_usage = helper.get_usage()
            print(f"CPU usage before: {cpu_usage}%")
            print(f"RAM usage before: {ram_usage}%")

            print("Importing the object container data.")
            # import and insert the object container first!
            general_logger.info(f"################## Getting the object containers of device: <{security_device_name}>. ##################")
            object_containers_list = SecurityDeviceObject.get_container_info_from_device_conn('object_container')
            print("Importing security zones container data.")
            zone_containers_list = SecurityDeviceObject.get_container_info_from_device_conn('security_zone_container')
            print("Importing managed devices container data.")
            managed_devices_container_list = SecurityDeviceObject.get_container_info_from_device_conn('managed_device_container')
            print("Importing the security policy containers info.")
            security_policy_containers_list = SecurityDeviceObject.get_container_info_from_device_conn('security_policy_container')
            print("Importing the object data")
            general_logger.info(f"################## Getting the objects of device: <{security_device_name}>. ##################")
            
            #TODO: when preloading data for creating the db relationships, make sure you preload the data from the current container!
            # make sure that the user is warned if he has duplicate policies by name - how tf is this even possible?
            # as objects have container scope
            # there are still problem with the url group objects and url objects
            for ObjectContainer in object_containers_list:
                object_container_name = ObjectContainer.get_name()
                general_logger.info(f"################## Getting the network objects of device: <{security_device_name}>. Container: <{object_container_name}> ##################")
                print("Import network objects.")
                SecurityDeviceObject.get_object_info_from_device_conn('network_object', ObjectContainer)

                general_logger.info(f"################## Getting the network group objects of device: <{security_device_name}>. Container: <{object_container_name}> ##################")
                print("Import network group objects.")
                SecurityDeviceObject.get_object_info_from_device_conn('network_group_object', ObjectContainer)
                # TODO: geolocation objects support
                # print("Importing geolocation objects.")
                # general_logger.info(f"################## Getting the geolocation objects of device: <{security_device_name}>. Container: <{object_container_name}> ##################")
                # SecurityDeviceObject.get_object_info_from_device_conn('geolocation_object', ObjectContainer)

                general_logger.info(f"################## Getting the port objects of device: <{security_device_name}>. Container: <{object_container_name}> ##################")
                print("Import port objects.")
                SecurityDeviceObject.get_object_info_from_device_conn('port_object', ObjectContainer)
                
                general_logger.info(f"################## Getting the port group objects of device: <{security_device_name}>. Container: <{object_container_name}> ##################")
                print("Import port group objects.")
                SecurityDeviceObject.get_object_info_from_device_conn('port_group_object', ObjectContainer)
                
                general_logger.info(f"################## Getting the URL objects of device: <{security_device_name}>. Container: <{object_container_name}> ##################")
                print("Import URL objects.")
                SecurityDeviceObject.get_object_info_from_device_conn('url_object', ObjectContainer)
                
                general_logger.info(f"################## Getting the URL group objects of device: <{security_device_name}>. Container: <{object_container_name}> ##################")
                print("Import URL group objects.")
                SecurityDeviceObject.get_object_info_from_device_conn('url_group_object', ObjectContainer)

                general_logger.info(f"################## Getting the schedule objects of device: <{security_device_name}>. Container: <{object_container_name}> ##################")
                print("Import the schedule objects.")
                SecurityDeviceObject.get_object_info_from_device_conn('schedule_object', ObjectContainer)
            
            for ZoneContainer in zone_containers_list:
                print("Importing the interfaces/zones data.")
                SecurityDeviceObject.get_object_info_from_device_conn('security_zone', ZoneContainer)

            # get the devices managed by the security device
            general_logger.info(f"################## Getting the managed devices of device: <{security_device_name}>. ##################")
            print("Importing the managed devices data.")
            if managed_devices_container_list is None:
                pass
            else:
                for ManagedDeviceContainer in managed_devices_container_list:
                    SecurityDeviceObject.get_object_info_from_device_conn('managed_device', ManagedDeviceContainer)
            
            print("Importing security policies.")
            #TODO: not sure if all the security devices return the index of the security policy as well
            # if not, make sure you keep track of every policy index here
            for SecurityPolicyContainer in security_policy_containers_list:
                print(f"processing policies of container {SecurityPolicyContainer._name}")
                SecurityDeviceObject.get_object_info_from_device_conn('security_policy_group', SecurityPolicyContainer)

            end_time = time.time()
            execution_time = end_time - start_time
            print(f"Execution time: {execution_time} seconds")
        else:
            general_logger.critical(f"Failed to retrieve version of the security device. Exiting...")
            sys.exit(1)
        
        # close the cursors used to connect to the database
        LandingDBcursor.close()
        SecurityDeviceDBcursor.close()

        # except Exception as e:
        #     general_logger.critical(f"Failed to connect to the security device or encountered an error: <{e}>.")
        #     sys.exit(1)

    # if the create_project argument is used, then create a project database with the name supplied by the user
    # when a project is created, a database for it gets created. the projects_metadata table also gets updated with the new info

    if pioneer_args['create_project [name]']:
        # Extract the name from argv
        project_name = pioneer_args['create_project [name]']
        creation_timestamp = datetime.now()
        
        # Open a connection to the landing database
        LandingDBcursor = PioneerDatabase.connect_to_db(db_user, landing_db, db_password, db_host, db_port)

        # Set the database name
        project_database_name = project_name + "_db"

        # Create the project database
        PioneerProjectDB = MigrationProjectDatabase(LandingDBcursor)
        PioneerProjectDB.create_database(project_database_name)
        
        # Connect to the project's database and create the migration project
        MigrationProjectObject = MigrationProjectFactory.create_migration_project(db_user, project_name, db_password, db_host, db_port)

        # Create the migration project's tables
        MigrationProjectObject.get_database().create_migration_project_tables()

        # Save general information about the project
        MigrationProjectObject.save_general_info('TEST_DESC', creation_timestamp)

        # Close the cursors
        LandingDBcursor.close()
        MigrationProjectObject.get_database().get_cursor().close()

    # the project objects must be created
    # the source and security device objects must be created here
    # exceptions for when user tries to use names of devices that
    # make sure there can only be two security devices in a project and make sure stuff can't get imported multiple times
    if pioneer_args['project [name]']:
        project_name = pioneer_args['project [name]']
        MigrationProjectObject = MigrationProjectFactory.create_migration_project(db_user, project_name, db_password, db_host, db_port)
        # create migration project object here
        if pioneer_args['set_source_device [name]'] and pioneer_args['set_target_device [name]']:
            SourceSecurityDevice = SecurityDeviceFactory.create_security_device(db_user, pioneer_args['set_source_device [name]'], db_password, db_host, db_port)
            TargetSecurityDevice = SecurityDeviceFactory.create_security_device(db_user, pioneer_args['set_target_device [name]'], db_password, db_host, db_port)
            #TODO: when importing data, zones and containers names might be duplicated. if there are duplicates, then what?
            MigrationProjectObject.import_data(SourceSecurityDevice, TargetSecurityDevice)

        if pioneer_args['map_containers']:
            if pioneer_args['source_container_name'] and pioneer_args['target_container_name']:
                MigrationProjectObject.map_containers(pioneer_args['source_container_name'], pioneer_args['target_container_name'])

        if pioneer_args.get('map_zones'):
            if pioneer_args.get('source_zone_name') and pioneer_args.get('target_zone_name'):
                MigrationProjectObject.map_zones(
                    pioneer_args['source_zone_name'], pioneer_args['target_zone_name'])
        
        if pioneer_args.get('send_logs_to_manager'):
            manager_name = pioneer_args.get('send_logs_to_manager')
            MigrationProjectObject.set_log_manager(manager_name)

        if pioneer_args.get('set_security_profile'):
            security_profile_name = pioneer_args.get('set_security_profile')
            MigrationProjectObject.set_security_profile(security_profile_name)
        
        #TODO: migration should be done on all mapped containers
            # how to avoid creating common objects more than once
        if pioneer_args['migrate']:
            # pass the database of the project here
            MigrationProjectDB = MigrationProjectObject.get_database()
            migration_project_name = MigrationProjectObject.get_name()
            MigrationProjectObject = MigrationProjectFactory.build_migration_project(migration_project_name, MigrationProjectDB)
            
            if pioneer_args['security_policy_container [container_name]']:
                #TODO: at some point, maybe get the parent of the container on which the Pioneer container is based on
                # also, perform migration of all the mapped entities
                SecurityPolicyContainer = PioneerSecurityPolicyContainer(MigrationProjectObject, pioneer_args['security_policy_container [container_name]'], None)
                SecurityPolicyContainer.process_and_migrate()

if __name__ == "__main__":
    main()

#TODO:
    # at some point, fix generating UIDs upon init of objects as it is a bad practice
    # don't forget to refactor the SecurityPolicy subclasses to remove the redundancy of attributes
    #test