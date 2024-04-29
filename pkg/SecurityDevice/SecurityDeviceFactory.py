from .FMCSecurityDevice import FMCSecurityDevice
# from .PANMCSecurityDevice import PANMCSecurityDevice
import utils.helper as helper
from pkg import PioneerDatabase
from pkg.SecurityDevice import SecurityDevice, SecurityDeviceDatabase
import fireREST
import sys

general_logger = helper.logging.getLogger('general')

class SecurityDeviceConnection:
    """
    A class representing a connection to a security device.
    """

    def __init__(self) -> None:
        """
        Initialize the SecurityDeviceConnection instance.
        """
        pass

class SecurityDeviceFactory:
    @staticmethod
    def build_api_security_device(security_device_uid, security_device_name, security_device_type, SecurityDeviceDB, security_device_hostname, security_device_username, security_device_secret, security_device_port, domain):
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
        match security_device_type:
            case "fmc-api":
                general_logger.info(f"Device <{security_device_name}> is a Firepower Management Center.")
                Connection = FMCDeviceConnection(security_device_username, security_device_secret, security_device_hostname, security_device_port, domain).connect_to_security_device()
                SecurityDeviceObj = FMCSecurityDevice(security_device_uid, security_device_name, SecurityDeviceDB, Connection)

            # case "panmc-api":
            #     general_logger.info(f"Device <{security_device_name}> is a Panorama Management Center.")
            #     return PANMCSecurityDevice(security_device_name, SecurityDeviceDB, security_device_username, security_device_secret, security_device_hostname, security_device_port)
            
            # default case
            case _:
                general_logger.critical(f"Device <{security_device_name}>, with type <{security_device_type}>, is an invalid API device.")
                sys.exit(1)
        
        return SecurityDeviceObj
        
    def create_security_device(db_user, security_device_name, db_password, db_host, db_port):
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
        # Connect to the database of the security device
        SecurityDevceDBcursor = PioneerDatabase.connect_to_db(db_user, security_device_db_name, db_password, db_host, db_port)

        # instantiate and extract all the data from a generic security device
        # the data will be used further for creating the specific security device object
        SecurityDeviceDB = SecurityDeviceDatabase(SecurityDevceDBcursor)

        # initialize the connection to None, as we don't know yet to what device we will connect to
        SecurityDeviceConn = None
        security_device_uid = None

        GenericSecurityDevice = SecurityDevice(security_device_uid, security_device_name, SecurityDeviceDB, SecurityDeviceConn)

        # get the security device type
        security_device_type = GenericSecurityDevice.get_general_data("type", "name", security_device_name)
        general_logger.info(f"Got device type <{security_device_type}>.")

        # TODO: put this into a function
        if '-api' in security_device_type:
            general_logger.info(f"<{security_device_name}> is an API device. Type: <{security_device_type}>")
            # get the security device hostname
            security_device_hostname = GenericSecurityDevice.get_general_data("hostname", "name", security_device_name)

            # get the security device username
            security_device_username = GenericSecurityDevice.get_general_data("username", "name", security_device_name)

            # get the security device secret
            security_device_secret = GenericSecurityDevice.get_general_data("secret", "name", security_device_name)

            # get the security device port
            security_device_port = GenericSecurityDevice.get_general_data("port", "name", security_device_name)

            # get the security device domain
            security_device_domain = GenericSecurityDevice.get_general_data("management_domain", "name", security_device_name)

            # get the security device uid
            security_device_uid = GenericSecurityDevice.get_general_data("uid", "name", security_device_name)

            # create the API security object based on the device type
            SpecificSecurityDeviceObject = SecurityDeviceFactory.build_api_security_device(security_device_uid, security_device_name, security_device_type, SecurityDeviceDB, security_device_hostname, security_device_username, security_device_secret, security_device_port, security_device_domain)

        elif '-config' in security_device_type:
            general_logger.info(f"{security_device_name} is an device that does not use API. Only its config file will be processed.")

        else:
            general_logger.critical(f"{security_device_name} is an invalid API device! Type: {security_device_type}")
            sys.exit(1)
        
        return SpecificSecurityDeviceObject

class APISecurityDeviceConnection(SecurityDeviceConnection):
    def __init__(self, api_username, api_secret, api_hostname, api_port):
        super().__init__()
        self._api_username = api_username
        self._api_secret = api_secret
        self._api_hostname = api_hostname
        self._api_port = api_port
    
    def return_security_device_conn_object(self):
        try:
            general_logger.info(f"I am trying to connect to the Security Device using username {self._api_username}, hostname {self._api_hostname}, port {self._api_port}.")
            device_conn = self.connect_to_security_device()
            general_logger.info(f"I have successfully connected to the device. {device_conn}")
            return device_conn
        except Exception as err:
            general_logger.critical(f"Could not connect to Security Device. Reason: {err}")
            sys.exit(1)

    def connect_to_security_device(self):
        # This method is a placeholder and should be implemented by subclasses
        raise NotImplementedError("Subclasses must implement connect_to_security_device method")

class FMCDeviceConnection(APISecurityDeviceConnection):
    """
    Represents a connection to a Firepower Management Center (FMC) device.
    """

    def __init__(self, api_username, api_secret, api_hostname, api_port, domain):
        """
        Initialize an FMCDeviceConnection instance.

        Parameters:
            api_username (str): The API username for the connection.
            api_secret (str): The API secret for the connection.
            api_hostname (str): The hostname of the FMC device.
            api_port (int): The port number for the connection.
            domain (str): The domain of the FMC device.
        """
        super().__init__(api_username, api_secret, api_hostname, api_port)
        self._domain = domain
        self._device_connection = self.return_security_device_conn_object()  # Initialize _device_connection with FMC object

    def connect_to_security_device(self):
        """
        Connect to the Firepower Management Center (FMC) device.

        Returns:
            fireREST.FMC: An FMC connection object.
        """
        # Implement connection to FMC specific to FMCDeviceConnection
        fmc_conn = fireREST.FMC(hostname=self._api_hostname, username=self._api_username, password=self._api_secret, domain=self._domain, protocol=self._api_port, timeout=30)
        return fmc_conn