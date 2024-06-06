# git ls-files | xargs wc -l
#TODO: use properties instead of getters and setters in python
import utils.helper as helper
import utils.gvars as gvars
import pkg.MigrationProject as MigrationProject
from pkg import PioneerDatabase
from pkg.SecurityDevice import SecurityDevice, SecurityDeviceDatabase 
from pkg.SecurityDevice.SecurityDeviceFactory import SecurityDeviceFactory
import sys
from datetime import datetime, timezone
import time
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

    # if the create_project argument is used, then create a project database with the name supplied by the user
    # when a project is created, a database for it gets created. the projects_metadata table also gets updated with the new info

    # if pioneer_args['create_project [name]']:
        
    #     # extract the name from argv
    #     project_name = pioneer_args['create_project [name]']

    #     # open a connection to the database
    #     database_conn = DBConnection(db_user, landing_database, db_password, db_host, db_port)

    #     # create a database cursor
    #     database_cursor = database_conn.create_cursor()

    #     # set the database name
    #     project_database_name = project_name + "_db"

    #     # create the project database
    #     PioneerProjectsDB = PioneerDatabase(database_cursor)
    #     PioneerProjectsDB.create_database(project_database_name)
    #     creation_timestamp = datetime.now()
    #     # print(f"Created project {project_name}.")

    #     # in the project_metadata table of the pioneer_projects database, insert the name of the project, the current devices names, the creation timestamp and the description
    #     # PioneerProjectsDB.insert_into_projects_metadata(project_name, project_devices, project_description, creation_timestamp)

    #     # close the cursor
    #     database_cursor.close()

    # # if the delete_project argument is used, then delete the project the user wants to delete
    # # when a project is deleted, its database gets deleted and the projects_metadata table gets updated
    # if pioneer_args['delete_project [name]']:
    #     project_name = pioneer_args['delete_project [name]']
    #     database_conn = DBConnection(db_user, landing_database, db_password, db_host, db_port)
    #     database_cursor = database_conn.create_cursor()
    #     project_database_name = project_name + "_db"
    #     PioneerProjectsDB = PioneerDatabase(database_cursor)
    #     PioneerProjectsDB.delete_database(project_database_name)
    #     # print(f"Deleted project {project_name}.")

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

#    try:
        general_logger.info(f"Connecting to the security device: <{security_device_name}>.")
        # Attempt to create the security device object based on the device type
        if '-api' in security_device_type:
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
            for ManagedDeviceContainer in managed_devices_container_list:
                SecurityDeviceObject.get_object_info_from_device_conn('managed_device', ManagedDeviceContainer)
            
            print("Importing security policies.")
            for SecurityPolicyContainer in security_policy_containers_list:
                SecurityDeviceObject.get_object_info_from_device_conn('security_policy_group', SecurityPolicyContainer)

            end_time = time.time()
            execution_time = end_time - start_time
            print(f"Execution time: {execution_time} seconds")
        else:
            general_logger.critical(f"Failed to retrieve version of the security device. Exiting...")
            sys.exit(1)

    # except Exception as e:
    #     general_logger.critical(f"Failed to connect to the security device or encountered an error: <{e}>.")
    #     sys.exit(1)

    # close the cursors used to connect to the database
    LandingDBcursor.close()
    SecurityDeviceDBcursor.close()

        
    # # TODO: everything below this is shit and it's just supposed to work. need to re-do it
    # # import the containers from the target device to the source device
    # if pioneer_args["migrate_config"]:
    # # get the target security device's name
    #     target_security_device_name = pioneer_args["target_device [target_device_name]"]
    #     TargetSecurityDevice = SecurityDeviceFactory.create_security_device(db_user, target_security_device_name, db_password, db_host, db_port)
                    
    #     # print the compatibility issues
    #     # SpecificTargetSecurityDeviceObject.print_compatibility_issues()

    #     # ask the user to : map the security policies container to its counter part in the target device
    #         # map only the child container and let the
    #         # program map all the other containers based on the hierarchy. a new table is needed for this
    #         # all containers will be mapped in the map_containers_function
    #         # mapping will be saved in the database table of the target device
    #     object_container, container_hierarchy_map = TargetSecurityDevice.map_containers()
    #     interface_map = TargetSecurityDevice.map_zones()
        
    #     TargetSecurityDevice.adapt_config(object_container, container_hierarchy_map, interface_map, SecurityDeviceObj)
    #     TargetSecurityDevice.migrate_config(SecurityDeviceObj)

if __name__ == "__main__":
    main()