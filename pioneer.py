# git ls-files | xargs wc -l
import utils.helper as helper
import pkg.MigrationProject as MigrationProject
from pkg import DBConnection, PioneerDatabase
from pkg.SecurityDevice import SecurityDevice, SecurityDeviceDatabase
from pkg.SecurityDevice.APISecurityDevice import APISecurityDeviceFactory
import sys
from datetime import datetime, timezone

# Disable logging for the 'fireREST' logger
helper.logging.getLogger('fireREST').setLevel(helper.logging.CRITICAL)

def main():
    db_user = "pioneer_admin"
    db_password = "2wsx#EDC"
    landing_database = "pioneer_projects"
    db_host = '127.0.0.1'
    db_port = 5432

    # create the parser for the pioneer utilty
    pioneer_parser = helper.create_parser()

    # store the arguments passed by the user
    pioneer_args = pioneer_parser.parse_args()

    # convert the args to a dictionary in order to further process them
    pioneer_args = vars(pioneer_args)

    # if the create_project argument is used, then create a project database with the name supplied by the user
    # when a project is created, a database for it gets created. the projects_metadata table also gets updated with the new info

    if pioneer_args['create_project [name]']:
        
        # extract the name from argv
        project_name = pioneer_args['create_project [name]']

        # open a connection to the database
        database_conn = DBConnection(db_user, landing_database, db_password, db_host, db_port)

        # create a database cursor
        database_cursor = database_conn.create_cursor()

        # set the database name
        project_database_name = project_name + "_db"

        # create the project database
        PioneerProjectsDB = PioneerDatabase(database_cursor)
        PioneerProjectsDB.create_database(project_database_name)
        creation_timestamp = datetime.now()
        # print(f"Created project {project_name}.")

        # in the project_metadata table of the pioneer_projects database, insert the name of the project, the current devices names, the creation timestamp and the description
        # PioneerProjectsDB.insert_into_projects_metadata(project_name, project_devices, project_description, creation_timestamp)

        # close the cursor
        database_cursor.close()

    # if the delete_project argument is used, then delete the project the user wants to delete
    # when a project is deleted, its database gets deleted and the projects_metadata table gets updated
    if pioneer_args['delete_project [name]']:
        project_name = pioneer_args['delete_project [name]']
        database_conn = DBConnection(db_user, landing_database, db_password, db_host, db_port)
        database_cursor = database_conn.create_cursor()
        project_database_name = project_name + "_db"
        PioneerProjectsDB = PioneerDatabase(database_cursor)
        PioneerProjectsDB.delete_database(project_database_name)
        # print(f"Deleted project {project_name}.")

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
        helper.setup_logging(log_folder, {'general': 'general.log', 'special_policies': 'special_policies.log'})
        general_logger = helper.logging.getLogger('general')

        # Log creation of new device
        general_logger.info(f"################## CREATING A NEW DEVICE: <{security_device_name}> ##################")
        general_logger.debug(f"Got the following info about device from user, security device name: <{security_device_name}>, type <{security_device_type}>, hostname <{security_device_hostname}, username <{security_device_username}>, secret <>, port: <{security_device_port}>, domain <{domain}>.")

        # Connect to the landing device database
        landing_db_conn = DBConnection(db_user, landing_database, db_password, db_host, db_port)
        general_logger.info(f"Connecting to device database: <{landing_database}>.")
        landing_cursor = landing_db_conn.create_cursor()

        # Create the security device database object using the landing database
        SecurityDeviceDB = SecurityDeviceDatabase(landing_cursor)

        # Try connecting to the security device and retrieving the version
        try:
            general_logger.info(f"Connecting to the security device...")
            print("Connecting to the security device...")
            # Attempt to create the security device object based on the device type
            if '-api' in security_device_type:
                general_logger.info(f"The device {security_device_name} is an API device. Its API will be used for interacting with it.")
                SecurityDeviceObject = APISecurityDeviceFactory.build_api_security_device(security_device_name, security_device_type, SecurityDeviceDB, security_device_hostname, security_device_username, security_device_secret, security_device_port, domain)
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
                general_logger.info(f"Creating device database: <{security_device_db_name}>.")
                general_logger.debug(f"Connecting to the Postgres using, user: <{db_user}>, password ..., host: <{db_host}>, port: <{db_port}>, landing database: <{landing_database}>.")
                SecurityDeviceDB.create_database(security_device_db_name)

                # Connect to the newly created security device database
                security_device_db_conn = DBConnection(db_user, security_device_db_name, db_password, db_host, db_port)
                security_device_cursor = security_device_db_conn.create_cursor()
                SecurityDeviceDB = SecurityDeviceDatabase(security_device_cursor)
                SecurityDeviceObject.set_database(SecurityDeviceDB)

                # Create the tables in the device database
                general_logger.info(f"Creating the tables in device database: <{security_device_db_name}>.")
                SecurityDeviceDB.create_security_device_tables()
                print("Created device database.")

                # Insert general device info into the database
                general_logger.info(f"Inserting general device info in the database.")
                SecurityDeviceObject.insert_into_general_table(security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain)

                #TODO: this must be moved when the ManagedDevices class is created
                # # Retrieve information about the managed devices
                # general_logger.info(f"################## Getting the managed devices of device: <{security_device_name}>. ##################")
                # managed_devices_info = SecurityDeviceObject.get_managed_devices_info_from_device_conn()

                # # Insert managed device info into the database
                # general_logger.info(f"Inserting managed device info in the database.")
                # SecurityDeviceObject.insert_into_managed_devices_table(managed_devices_info)
            else:
                general_logger.error(f"Failed to retrieve version of the security device. Exiting...")
                sys.exit(1)
        except Exception as e:
            general_logger.error(f"Failed to connect to the security device or encountered an error: {e}")
            sys.exit(1)
        
        # close the cursors used to connect to the database
        landing_cursor.close()
        security_device_cursor.close()

    # at this point, the backbone of the device is created, importing of data can start
    # the user used the --device option
    if pioneer_args["device_name [device_name]"]:
        security_device_name = pioneer_args["device_name [device_name]"]
        
        # Define the logging settings for general logging
        general_log_folder = helper.os.path.join('log', f'device_{security_device_name}')
        helper.setup_logging(general_log_folder, {'general': 'general.log'})
        general_logger = helper.logging.getLogger('general')
        general_logger.info("################## Security device data processing ##################")
        
        # Define the logging settings for special policies logging
        special_log_folder = helper.os.path.join('log', f'device_{security_device_name}')
        helper.setup_logging(special_log_folder, {'special_policies': 'special_policies.log'})

        general_logger.info(f"I am now processing security device <{security_device_name}>.")
        security_device_db_name = security_device_name + "_db"
        security_device_db_conn = DBConnection(db_user, security_device_db_name, db_password, db_host, db_port)
        security_device_cursor = security_device_db_conn.create_cursor()
        
        # instantiate and extract all the data from a generic security device
        # the data will be used further for creating the specific security device object
        SecurityDeviceDB = SecurityDeviceDatabase(security_device_cursor)

        GenericSecurityDevice = SecurityDevice(security_device_name, SecurityDeviceDB)

        # get the security device type
        security_device_type = GenericSecurityDevice.get_security_device_type_from_db()
        general_logger.info(f"Got device type <{security_device_type}>.")

        if '-api' in security_device_type:
            general_logger.info(f"<{security_device_name}> is an API device. Type: <{security_device_type}>")
            # get the security device hostname

            security_device_hostname = GenericSecurityDevice.get_security_device_hostname_from_db()

            # get the security device username
            security_device_username = GenericSecurityDevice.get_security_device_username_from_db()

            # get the security device secret
            security_device_secret = GenericSecurityDevice.get_security_device_secret_from_db()

            # get the security device port
            security_device_port = GenericSecurityDevice.get_security_device_port_from_db()

            # get the security device domain
            security_device_domain = GenericSecurityDevice.get_security_device_domain_from_db()

            # create the API security object based on the device type
            SpecificSecurityDeviceObject = APISecurityDeviceFactory.build_api_security_device(security_device_name, security_device_type, SecurityDeviceDB, security_device_hostname, security_device_username, security_device_secret, security_device_port, security_device_domain)

        elif '-config' in security_device_type:
            general_logger.info(f"{security_device_name} is an device that does not use API. Only its config file will be processed.")

        else:
            general_logger.critical(f"{security_device_name} is an invalid API device! Type: {security_device_type}")
            sys.exit(1)

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
            general_logger.info(f"################## IMPORTING CONFIGURATION OF <{security_device_name}>.##################")
            if(pioneer_args["security_policy_container [container_name]"]):
                passed_container_names = pioneer_args["security_policy_container [container_name]"]
                passed_container_names_list = []
                passed_container_names_list.append(passed_container_names)
                print("Importing the security policy containers info.")
                # print(f"I am now importing the policy container info for the following containers: {passed_container_names_list}.")
                
                # retrieve the security policy containers along with the parents
                # insert them in the database
                security_policy_containers_info = SpecificSecurityDeviceObject.get_containers_info_from_device_conn(passed_container_names_list, 'security_policies_container')
                SpecificSecurityDeviceObject.insert_into_security_policy_containers_table(security_policy_containers_info)
                # import the security policies (data) that are part of the imported security policy containers
                # the policy container info extracted earlier can be used here. we can use the child container entry since the child container
                # contains the information (thus the policies) it inherits from all the parents
                print("Importing the security policy data.")

                sec_policy_data = SpecificSecurityDeviceObject.get_policy_info_from_device_conn('security_policy', passed_container_names_list)
                general_logger.info("\n################## EXTRACTED INFO FROM THE SECURITY POLICIES, INSERTING IN THE DATABASE. ##################")
                # at this point, the data from all the security policies is extracted, it is time to insert it into the database
                SpecificSecurityDeviceObject.insert_into_security_policies_table(sec_policy_data)

                print("Importing the object container data.")
                general_logger.info("\n################## IMPORTING OBJECT CONTAINER DATA. ##################")
                # import and insert the object container first!
                object_containers_info = SpecificSecurityDeviceObject.get_containers_info_from_device_conn(passed_container_names_list, 'object_container')
                SpecificSecurityDeviceObject.insert_into_object_containers_table(object_containers_info)

                #TODO: the import functinoality must be independent of the policy type. so this part of the code should be taken out from here and put outside the import config if statement
                print("Importing network object data.")
                general_logger.info("\n################## IMPORTING NETWORK OBJECTS DATA. ##################")
                # # at this point all the security policy data is imported. it is time to import the object data.
                network_objects_data = SpecificSecurityDeviceObject.get_object_info_from_device_conn('network_objects')
                print("Inserting network object data in the database.")
                general_logger.info("\n################## INSERTING NETWORK OBJECTS DATA. ##################")                
                SpecificSecurityDeviceObject.insert_into_network_address_objects_table(network_objects_data[0]['network_objects'])
                SpecificSecurityDeviceObject.insert_into_network_address_object_groups_table(network_objects_data[0]['network_group_objects'])
                SpecificSecurityDeviceObject.insert_into_geolocation_table(network_objects_data[0]['geolocation_objects'])

                print("Importing port object data.")
                general_logger.info("\n################## IMPORTING PORT OBJECTS DATA. ##################")
                port_objects_data = SpecificSecurityDeviceObject.get_object_info_from_device_conn('port_objects')
                print("Inserting port object data in the database.")
                SpecificSecurityDeviceObject.insert_into_port_objects_table(port_objects_data[0]['port_objects'])
                SpecificSecurityDeviceObject.insert_into_icmp_objects_table(port_objects_data[0]['icmp_port_objects'])
                SpecificSecurityDeviceObject.insert_into_port_object_groups_table(port_objects_data[0]['port_group_objects'])

                print("Skipping importing of schedule, users, URL categories and L7 apps since this is not yet supported!")
                print("Importing URL object data.")
                general_logger.info("\n################## IMPORTING URL OBJECTS DATA. ##################")
                url_objects_data = SpecificSecurityDeviceObject.get_object_info_from_device_conn('url_objects')
                print("Inserting url object data in the database.")
                SpecificSecurityDeviceObject.insert_into_url_objects_table(url_objects_data[0]['url_objects'])
                SpecificSecurityDeviceObject.insert_into_url_object_groups_table(url_objects_data[0]['url_group_objects'])

                # close the cursor used to connect to the
                security_device_cursor.close()
                #TODO: create migration process. a temporary migration process will be created
                # in the temp migration process, the script will look into the database of the source device, extract the info, apply
                # all the naming and object definition restrictions and add the data to the database of the palo alto device
                # after that, make the necessary API calls to create all the info. there are some limitations: duplicate objects will be created,
                # as i cannot enforce the check of the duplicates efficiently.
                # in the final migration process, all the data from the device must be imported as well and added to a migration project 



if __name__ == "__main__":
    main()