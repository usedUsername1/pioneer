# git ls-files | xargs wc -l
#TODO: the entire database structure must be redone, stop using arrays
import utils.helper as helper
import utils.gvars as gvars
import pkg.MigrationProject as MigrationProject
from pkg import PioneerDatabase
from pkg.SecurityDevice import SecurityDevice, SecurityDeviceDatabase 
from pkg.SecurityDevice.SecurityDeviceFactory import SecurityDeviceFactory
import sys
from datetime import datetime, timezone

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

        # Try connecting to the security device and retrieving the version
        try:
            general_logger.info(f"Connecting to the security device: <{security_device_name}>.")
            # Attempt to create the security device object based on the device type
            if '-api' in security_device_type:
                general_logger.info(f"The device {security_device_name} is an API device. Its API will be used for interacting with it.")
                SecurityDeviceObject = SecurityDeviceFactory.build_api_security_device(security_device_name, security_device_type, SecurityDeviceDB, security_device_hostname, security_device_username, security_device_secret, security_device_port, domain)
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

                SecurityDeviceObject.save_general_info(security_device_name, security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain)

                # Retrieve information about the managed devices
                general_logger.info(f"################## Getting the managed devices of device: <{security_device_name}>. ##################")
                SecurityDeviceObject.get_managed_devices_info_from_device_conn()

            else:
                general_logger.critical(f"Failed to retrieve version of the security device. Exiting...")
                sys.exit(1)
        except Exception as e:
            general_logger.critical(f"Failed to connect to the security device or encountered an error: <{e}>.")
            sys.exit(1)
        
        # close the cursors used to connect to the database
        LandingDBcursor.close()
        SecurityDeviceDBcursor.close()

    # at this point, the backbone of the device is created, importing of data can start
    # the user used the --device option
    if pioneer_args["device_name [device_name]"]:
        security_device_name = pioneer_args["device_name [device_name]"]
        SecurityDeviceObj = SecurityDeviceFactory.create_security_device(db_user, security_device_name, db_password, db_host, db_port)

        # sub-if statements for importing and getting parameters
        # the import of the objects will be done for a specific policy container
        # after the policies are imported, all the policies are scanned for objects and the objects will be imported in the device's database
        # if the user wants to import config, the following will be imported:
            # the security policy containers. this is a generic name for the places different vendors store the firewall policies. for example, Cisco uses Access Control Policies (ACPs), PA uses device groups, etc
            # the nat policy containers. same as security policy containers
            # not all vendors implement containers. for example, cisco doesn't store objects in containers, as opposed to PA. to overcome this, everything that can't be containerized will be tied to a dummy container.
            # for example, security policies will be tied to a "dummy_container", and so on.
            # the security policies
            # the nat policies
            # all the objects (URLs, address objects, groups, etc)
            # user sources along with users databases
            # and pretty much the rest of the config (routing, VPNs, etc...)
        if pioneer_args["import_config"]:
            # import the policy containers of the device.
            if(pioneer_args["security_policy_container [container_name]"]):
                passed_container_names = pioneer_args["security_policy_container [container_name]"]
                passed_container_names_list = []
                passed_container_names_list.append(passed_container_names)
                print("Importing the security policy containers info.")
                print(f"I am now importing the policy container info for the following containers: <{passed_container_names_list}>.")
                
                # # retrieve the security policy containers along with the parents and insert them in the database
                SecurityDeviceObj.get_container_info_from_device_conn(passed_container_names_list, 'security_policies_container')
                print("Importing the security policies.")
                SecurityDeviceObj.get_policy_info_from_device_conn('security_policy', passed_container_names_list)

                print("Importing the object container data.")
                # import and insert the object container first!
                SecurityDeviceObj.get_container_info_from_device_conn(passed_container_names_list, 'objects_container')

                # TODO: before continuing with importing the objects, the database structure must be redone.
                # how to proceed with the import? should all the objects be imported first?
                # #TODO: the import functinoality must be independent of the policy type. so this part of the code should be taken out from here and put outside the import config if statement
                # print("Importing network object data.")

                # # # at this point all the security policy data is imported. it is time to import the object data.
                # network_objects_data = SecurityDeviceObj.get_object_info_from_device_conn('network_objects')

                # SecurityDeviceObj.insert_into_network_address_objects_table(network_objects_data[0]['network_objects'])
                # SecurityDeviceObj.insert_into_network_address_object_groups_table(network_objects_data[0]['network_group_objects'])
                # SecurityDeviceObj.insert_into_geolocation_table(network_objects_data[0]['geolocation_objects'])

                # print("Importing port object data.")

                # port_objects_data = SecurityDeviceObj.get_object_info_from_device_conn('port_objects')
                # print("Inserting port object data in the database.")
                # SecurityDeviceObj.insert_into_port_objects_table(port_objects_data[0]['port_objects'])
                # SecurityDeviceObj.insert_into_icmp_objects_table(port_objects_data[0]['icmp_port_objects'])
                # SecurityDeviceObj.insert_into_port_object_groups_table(port_objects_data[0]['port_group_objects'])

                # print("Skipping importing of schedule, users, URL categories and L7 apps since this is not yet supported!")
                # print("Importing URL object data.")

                # url_objects_data = SecurityDeviceObj.get_object_info_from_device_conn('url_objects')

                # SecurityDeviceObj.insert_into_url_objects_table(url_objects_data[0]['url_objects'])
                # SecurityDeviceObj.insert_into_url_object_groups_table(url_objects_data[0]['url_group_objects'])

                # print("Succesfully finished the import of the security device's data.")
                # close the cursor used to connect to the device's database
                # TODO: create close_cursor() function
                # SecurityDevceDBcursor.close()
        
        # no need to retrieve the source device, as it is already specified in the parameter
        # how the command should look like:
                # python3 pioneer.py --device-name 'sfmc_test' --migrate-config --target_device 'panmc_test'
        # TODO: logging of migration should be done on the target device
        # TODO: everything below this is shit and it's just supposed to work. need to re-do it
        # import the containers from the target device to the source device
        if pioneer_args["migrate_config"]:
        # get the target security device's name
            target_security_device_name = pioneer_args["target_device [target_device_name]"]
            TargetSecurityDevice = SecurityDeviceFactory.create_security_device(db_user, target_security_device_name, db_password, db_host, db_port)
                        
            # print the compatibility issues
            # SpecificTargetSecurityDeviceObject.print_compatibility_issues()

            # ask the user to : map the security policies container to its counter part in the target device
                # map only the child container and let the
                # program map all the other containers based on the hierarchy. a new table is needed for this
                # all containers will be mapped in the map_containers_function
                # mapping will be saved in the database table of the target device
            object_container, container_hierarchy_map = TargetSecurityDevice.map_containers()
            interface_map = TargetSecurityDevice.map_zones()
            
            TargetSecurityDevice.adapt_config(object_container, container_hierarchy_map, interface_map, SecurityDeviceObj)
            TargetSecurityDevice.migrate_config(SecurityDeviceObj)

if __name__ == "__main__":
    main()