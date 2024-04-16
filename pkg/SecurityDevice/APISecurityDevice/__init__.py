from abc import abstractmethod
from pkg.SecurityDevice import SecurityDevice, SecurityDeviceDatabase
import sys
from .FMCSecurityDevice import FMCSecurityDevice
from .PANMCSecurityDevice import PANMCSecurityDevice
import utils.helper as helper
from pkg import PioneerDatabase

general_logger = helper.logging.getLogger('general')

class APISecurityDevice(SecurityDevice):
    def __init__(self, user, database, password, host, port):
        """
        Initialize an API Security Device.

        Args:
            user (str): The username for the security device.
            database (str): The database name for the security device.
            password (str): The password for the security device.
            host (str): The hostname of the security device.
            port (int): The port number for connecting to the security device.
        """
        general_logger.debug(f"Called APISecurityDevice::__init__().")
        super().__init__(user, database, password, host, port)


class SecurityDeviceFactory:
    @staticmethod
    def build_api_security_device(security_device_name, security_device_type, SecurityDeviceDB, security_device_hostname, security_device_username, security_device_secret, security_device_port, domain):
        """
        Build an API Security Device Python object based on its type.

        Args:
            security_device_name (str): The name of the security device.
            security_device_type (str): The type of the security device.
            SecurityDeviceDB (class): The database class for the security device.
            security_device_hostname (str): The hostname of the security device.
            security_device_username (str): The username for accessing the security device.
            security_device_secret (str): The secret for accessing the security device.
            security_device_port (int): The port number for connecting to the security device.
            domain (str): The domain of the security device.

        Returns:
            SecurityDevice: An instance of the appropriate API security device class.
        """
        general_logger.debug(f"Called APISecurityDeviceFactory::build_api_security_device().")
        match security_device_type:
            case "fmc-api":
                general_logger.info(f"Device <{security_device_name}> is a Firepower Management Center.")
                return FMCSecurityDevice(security_device_name, SecurityDeviceDB, security_device_username, security_device_secret, security_device_hostname, security_device_port, domain)

            case "panmc-api":
                general_logger.info(f"Device <{security_device_name}> is a Panorama Management Center.")
                return PANMCSecurityDevice(security_device_name, SecurityDeviceDB, security_device_username, security_device_secret, security_device_hostname, security_device_port)
            
            # default case
            case _:
                general_logger.critical(f"Device <{security_device_name}>, with type <{security_device_type}>, is an invalid API device.")
                sys.exit(1)

    # @staticmethod
    # def create_security_device(db_user, security_device_name, db_password, db_host, db_port):
    #     # Define the logging settings for general logging
    #     general_log_folder = helper.os.path.join('log', f'device_{security_device_name}')
    #     helper.setup_logging(general_log_folder, {'general': 'general.log'})
    #     general_logger = helper.logging.getLogger('general')
    #     general_logger.info("################## Security device data processing ##################")
        
    #     # Define the logging settings for special policies logging
    #     special_log_folder = helper.os.path.join('log', f'device_{security_device_name}')
    #     helper.setup_logging(special_log_folder, {'special_policies': 'special_policies.log'})

    #     general_logger.info(f"I am now processing security device <{security_device_name}>.")
    #     security_device_db_name = security_device_name + "_db"
    #     # Connect to the database of the security device
    #     SecurityDevceDBcursor = PioneerDatabase.connect_to_db(db_user, security_device_db_name, db_password, db_host, db_port)

    #     # instantiate and extract all the data from a generic security device
    #     # the data will be used further for creating the specific security device object
    #     SecurityDeviceDB = SecurityDeviceDatabase(SecurityDevceDBcursor)

    #     GenericSecurityDevice = SecurityDevice(security_device_name, SecurityDeviceDB)

    #     # get the security device type
    #     security_device_type = GenericSecurityDevice.get_security_device_type_from_db()
    #     general_logger.info(f"Got device type <{security_device_type}>.")

    #     # TODO: put this into a function
    #     if '-api' in security_device_type:
    #         general_logger.info(f"<{security_device_name}> is an API device. Type: <{security_device_type}>")
    #         # get the security device hostname

    #         security_device_hostname = GenericSecurityDevice.get_security_device_hostname_from_db()

    #         # get the security device username
    #         security_device_username = GenericSecurityDevice.get_security_device_username_from_db()

    #         # get the security device secret
    #         security_device_secret = GenericSecurityDevice.get_security_device_secret_from_db()

    #         # get the security device port
    #         security_device_port = GenericSecurityDevice.get_security_device_port_from_db()

    #         # get the security device domain
    #         security_device_domain = GenericSecurityDevice.get_security_device_domain_from_db()

    #         # create the API security object based on the device type
    #         SpecificSecurityDeviceObject = APISecurityDeviceFactory.build_api_security_device(security_device_name, security_device_type, SecurityDeviceDB, security_device_hostname, security_device_username, security_device_secret, security_device_port, security_device_domain)

    #     elif '-config' in security_device_type:
    #         general_logger.info(f"{security_device_name} is an device that does not use API. Only its config file will be processed.")

    #     else:
    #         general_logger.critical(f"{security_device_name} is an invalid API device! Type: {security_device_type}")
    #         sys.exit(1)
        
    #     return SpecificSecurityDeviceObject