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
        # extract the device name and the device type from the argv namespace
        security_device_name = pioneer_args["create_security_device [name]"]
        
        # define the logging settings
        log_folder = helper.os.path.join('log', f'device_{security_device_name}')
        log_file = 'general.logs'
        helper.setup_logging(log_folder, log_file)

        helper.logging.info("################## CREATING A NEW DEVICE ##################")

        security_device_type = pioneer_args["device_type [type]"]
        security_device_hostname = pioneer_args["hostname [hostname]"]
        security_device_username = pioneer_args["username [username]"]
        security_device_secret = pioneer_args["secret [secret]"]
        security_device_port = pioneer_args["port [port]"]
        domain = pioneer_args["domain [fmc_domain]"]
        
        # connect to the postgres, create cursor and security device database
        security_device_db_name = security_device_name + "_db"
        database_conn = DBConnection(db_user, landing_database , db_password, db_host, db_port)
        db_cursor = database_conn.create_cursor()
        PioneerProjectsDB = PioneerDatabase(db_cursor)

        helper.logging.info(f"Creating device database: {security_device_db_name}.")
        PioneerProjectsDB.create_database(security_device_db_name)
        
        # in order to succesfully create a security device, it needs to have valid data
        # security device data can be validated if the user can succsefully connect to the device and retrieve the version
        # connect to the device database and get a cursor for the database connection
        security_device_db_conn = DBConnection(db_user, security_device_db_name, db_password, db_host, db_port)
        
        helper.logging.info(f"Connecting to device database: {security_device_db_name}.")
        security_device_cursor = security_device_db_conn.create_cursor()

        # note: the reason a device connection can't be created here is because the connection is relying on the device type
        # a connection object cannot be created before the security device type is established

        # create the security device database object
        SecurityDeviceDB = SecurityDeviceDatabase(security_device_cursor)
        

        # and create the specific tables of the security device
        helper.logging.info(f"Creating the tables in device database: {security_device_db_name}.")
        SecurityDeviceDB.create_security_device_tables()

        # based on the device type, generate a security device object
        if('-api' in security_device_type):
            helper.logging.info(f"The device {security_device_name} is an API device. Its API will be used for interacting with it.")
            SecurityDeviceObject = APISecurityDeviceFactory.build_api_security_device(security_device_name, security_device_type, SecurityDeviceDB, security_device_hostname, security_device_username, security_device_secret, security_device_port, domain)

        # elif('-config' in security_device_type):
        #     SecurityDeviceObject = ConfigSecurityDeviceFactory.build_config_security_device()

        else:
            helper.logging.critical(f"Provided device type {security_device_type} is invalid.")
            sys.exit(1)
        
        # get version of the security device
        helper.logging.info(f"################## Getting the device version for device: {security_device_name}. ##################")
        security_device_version = SecurityDeviceObject.get_device_version()
        
        # insert the device name, username, secret, hostname, type and version into the general_data table
        helper.logging.info(f"Inserting general device info in the database.")
        SecurityDeviceObject.insert_into_general_table(security_device_username, security_device_secret, security_device_hostname, security_device_type, security_device_port, security_device_version, domain)
        # import other essential configuration here, so that the user is not required to enter it.
        # import managed devices

        # retrive the information about the managed devices. if the device is a standalone device, the managed device will be the standalone device
        helper.logging.info(f"################## Getting the managed devices of device: {security_device_name}. ##################")
        managed_devices_info = SecurityDeviceObject.get_managed_devices_info()

        # insert it into the table
        helper.logging.info(f"Inserting managed device info in the database.")
        SecurityDeviceObject.insert_into_managed_devices_table(managed_devices_info)


    # at this point, the backbone of the device is created, importing of data can start
    # the user used the --device option
    if pioneer_args["device_name [device_name]"]:
        security_device_name = pioneer_args["device_name [device_name]"]
        
        # define the logging settings
        log_folder = helper.os.path.join('log', f'device_{security_device_name}')
        log_file = 'general.log'
        helper.setup_logging(log_folder, log_file)
        general_logger = helper.logging.getLogger('general') 

        general_logger.info("################## Security device data processing ##################")
        general_logger.info(f"I am now processing security device {security_device_name}.")
        security_device_db_name = security_device_name + "_db"
        security_device_db_conn = DBConnection(db_user, security_device_db_name, db_password, db_host, db_port)
        security_device_cursor = security_device_db_conn.create_cursor()
        
        # instantiate and extract all the data from a generic security device
        # the data will be used further for creating the specific security device object
        SecurityDeviceDB = SecurityDeviceDatabase(security_device_cursor)

        GenericSecurityDevice = SecurityDevice(security_device_name, SecurityDeviceDB)

        # get the security device type
        security_device_type = GenericSecurityDevice.get_security_device_type()
        helper.logging.info(f"Got device type {security_device_type}.")

        if '-api' in security_device_type:
            helper.logging.info(f"{security_device_name} is an API device. Type: {security_device_type}")
            # get the security device hostname

            security_device_hostname = GenericSecurityDevice.get_security_device_hostname()

            # get the security device username
            security_device_username = GenericSecurityDevice.get_security_device_username()

            # get the security device secret
            security_device_secret = GenericSecurityDevice.get_security_device_secret()

            # get the security device port
            security_device_port = GenericSecurityDevice.get_security_device_port()

            # get the security device domain
            security_device_domain = GenericSecurityDevice.get_security_device_domain()

            # create the API security object based on the device type
            SpecificSecurityDeviceObject = APISecurityDeviceFactory.build_api_security_device(security_device_name, security_device_type, SecurityDeviceDB, security_device_hostname, security_device_username, security_device_secret, security_device_port, security_device_domain)

        elif '-config' in security_device_type:
            helper.logging.info(f"{security_device_name} is an device that does not use API. Only its config file will be processed.")

        else:
            helper.logging.critical(f"{security_device_name} is an invalid API device! Type: {security_device_type}")
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
            helper.logging.info(f"################## IMPORTING CONFIGURATION OF {security_device_name}.##################")
            if(pioneer_args["security_policy_container [container_name]"]):
                passed_container_names = pioneer_args["security_policy_container [container_name]"]
                passed_container_names_list = []
                passed_container_names_list.append(passed_container_names)
                print("Importing the security policy containers info.")
                # print(f"I am now importing the policy container info for the following containers: {passed_container_names_list}.")
                
                # retrieve the security policy containers along with the parents
                # insert them in the database
                security_policy_containers_info = SpecificSecurityDeviceObject.get_security_policy_containers_info(passed_container_names_list)
                SpecificSecurityDeviceObject.insert_into_security_policy_containers_table(security_policy_containers_info)

                # import the security policies (data) that are part of the imported security policy containers
                # the policy container info extracted earlier can be used here. we can use the child container entry since the child container
                # contains the information (thus the policies) it inherits from all the parents
                print("Importing the security policy data.")
                sec_policy_data = SpecificSecurityDeviceObject.get_sec_policies_data(passed_container_names_list)
                helper.logging.info("\n################## EXTRACTED INFO FROM THE SECURITY POLICIES, INSERTING IN THE DATABASE. ##################")
                # at this point, the data from all the security policies is extracted, it is time to insert it into the database
                SpecificSecurityDeviceObject.insert_into_security_policies_table(sec_policy_data)

                print("Importing the object container data.")
                helper.logging.info("\n################## IMPORTING OBJECT CONTAINER DATA. ##################")
                # import and insert the object container first!
                object_containers_info = SpecificSecurityDeviceObject.get_object_containers_info(security_policy_containers_info)
                SpecificSecurityDeviceObject.insert_into_object_containers_table(object_containers_info)

                print("Importing object data.")
                helper.logging.info("\n################## IMPORTING OBJECTS DATA. ##################")
                # at this point all the security policy data is imported. it is time to import the object data.
                network_objects_data, network_group_objects_data = SpecificSecurityDeviceObject.get_objects_data_info()
                
                # all the network objects and network group objects data has been extracted, now insert it into the database
                helper.logging.info("\n################## EXTRACTED OBJECTS DATA, INSERTING IN THE DATABASE. ##################")
                SpecificSecurityDeviceObject.insert_into_network_address_objects_table(network_objects_data)
                SpecificSecurityDeviceObject.insert_into_network_address_object_groups_table(network_group_objects_data)




            # # append the security policies names to the list with all the policies
            # policy_list.append(security_policies)
            # # should there be a function that imports only the objects? if so, that function will be used to parse the policy list and import the objects
            # # import the address objects

            # SpecificSecurityDeviceObject.import_objects(policy_list)
            # SpecificSecurityDeviceObject.import_network_address_objects(policy_list)

            # # import the address groups
            # SpecificSecurityDeviceObject.import_network_group_objects(policy_list)

            # # import the port objects
            # SpecificSecurityDeviceObject.import_port_objects(policy_list)

            # # import the port group objects
            # SpecificSecurityDeviceObject.import_port_group_objects(policy_list)

            # # import the URL objects
            # SpecificSecurityDeviceObject.import_url_objects(policy_list)







if __name__ == "__main__":
    main()

# logging:
# for every device and project, create a separate logging folder
# the logging folders should have the following files:
    # files containing the configuration being pulled from the security device. called smth like: {device}_objects_config.conf, {device}_security_policies.conf... etc
    # files keeping track of failed imported policies/rules. failed_imported_objects.log, failed_imported_security_policies.log, etc
    # files keeping track of the database operations (as well as the commands being issued)
    # a file that tracks all the policies using L7 apps
    # a file that tracks all the policies using vendor specific URL categories
    # a file that tracks all the policies using time objects
    # a file that tracks all the policies using users
    # TODO: better and prettier logging. right now it is pretty difficult to follow stuff when debugging -> looks better, wip


# TODO SOON:
# add description for both the device and the project
# ask the user if he is sure that he wants to delete the project
# add a timestamp for creation of the device and the project
# create --list functionality (both terse and verbose) for projects and security devices
    # listed device info: name, type, description, creation date
    # listed project info: name, the devices of the project, description, creation date
# create a verbose list functionality, in which the user can see all the info related to a security device, for example. extend this to more than just the security device
# tell the user what parameter he is missing when using the --craete-security-device
# make a list with valid device types and make sure only valid types are used
# adding a policy/object count per container/per device would be nice. adding the description of the security policy container would also be nice
# maybe the process functions could be defined in the SecurityDevice class, as they might not have any specific device attributes


# should there be classes for the security policies and security containers? if so, the objects should be instantiated using data from the databases.

# TODO ?? 
# there might be a need to create very specific tables for the firewall rules. these tables
# will be related to the device type
# for example, we might need a table for palo alto rules, which stores all the proprietary palo alto attributes of a firewall policy

# tell the user that the config of a device has already been imported and error out if they want to import it again
# should the security policies table be split into multiple tables based on the UML?
# find how to process the hitcount values for firewall managers, eventually get the last hit as well.
# add write functionality + input validation for the project
# project changelog, save and keep track of the actions happened in a project (when a device is added, when stuff is migrated, etc)
# fix the arguments mess and create proper mutually exclusive groups.
# decide on whether you should be able to create/delete multiple projects and set constraint to set only one project
# enable the user to specify the parameters to be used for the database connection
# find a way to perform operations on security objects directly on the migration object. do i actually need this?
# implement debugging messages
# check if arguments that should be used together with another argument are being used appropriately. for example "--type" must be used with "--create-security-device". if this is not the case, throw an error and inform the user # https://copyprogramming.com/howto/python-argparse-conditionally-required-arguments-based-on-the-value-of-another-argument
# see if you can do something about the --port parameter. fmc requires it to be https. can fmc run on another port?
# make sure the import of duplicaes is prevented in both the project database and the device database
# error messages when user tries to perfrom action on non-existing device/project
# ensure single quotes are always used when passing arguments
#POLICY CONTAINERS
    # list, delete of policy containers. 
    # support importing a list of containers

#MIGRATION
    # support for migrating managed devices. for example, migrate fw-01 managed by FMC to fw-01 managed by PANMC
    # progress bar 
    # mechanism for checking failed migration objects on policies. for example, for every policy you could make a diff between
    # how the policy looked like on the source device and how it looks on the target device
    #TODO: what to do with the URLs names and with other unsupported parameters? for example,
    # PA does not support "/" in the names of URL objects, like Cisco does. maybe we can use a function that will apply naming constraints when migrating.
    # by doing this, this becomes a migrating issue, not an importing issue. everything should be imported exactly as it is defined on the source device. naming constraints and existance of the name constrained objects should be done accoriding to the target's device constraints
    

#IMPORTING
    # caching is implemented somehow. all info about objects and policies is retrieved once.
    # duplicate policies name are both imported as long as they are part of different containers
    #TODO: MAYB geolocation support.

    #TODO: ICMP, schedules, url and app policies, are not tracked separately. However, csv reports are generated so that the user is aware that they exist.
    #TODO: get a count with the policies retrieved and the policies imported
    
    # maybe process the Failed to insert values into: security_policies_table. Reason: duplicate key value violates unique constraint in a better way

    #TODO:enable the import of every single container/config if "import-config --all"

    # track all protocols that are not TCP or UDP

    # MAYBE: support for creating interfaces and security zones

    # if there are problems with importing a policy/object of a policy and so on, track that policy, log it along with the reason why it failed


# CISCO FMC Security zones
    # add support for interface groups

# code in general:
    # is there anyway in which every security device classes can have their own code file?
    # add doc strings for the parameters to all functions

# DATABASE:
    # ensure the cursor and db conn are properly closed after executing database oprations
    # parameterize all the queries

# LOGGING:
    # make sure you don't log passwords!

# DEVICE CREATION:
    # catch the error when the device database is already created and prevent it from overwriting the log file!

# FIRST MILESTONE: perform a full migration of L4 firewall rules (without the migration of users) from FMC to PANMC
# SECOND MILESTONE: add support for migrating users as well
# THIRD MILESTONE: add IPv6 support for the firewall rules
# FOURTH MILESTONE: implement NAT migration
# FIFTH MILESTONE: implement migration of firewall/NAT rules from ASA to FMC
# SIXTH MILESTONE: implement migration of L7 apps and URL categories between FMC and PANMC
# SEVENTH MILESTONE: implement migration of routing configuration between FMC and PANMC
# EIGHT MILESTONE: implement migration of VPN tunnels between FMC and PANMC
# NINETH MILESTONE: implement migration between all of the following platforms: FMC, PANMC, FTD, PAN, ASA, Meraki, iOS, FortiManager, FortiGate, JunOS, Checkpoint
# TENTH MILESTONE: finish everythin in the long-term TODO list. actually, finish all the TODO lists.
