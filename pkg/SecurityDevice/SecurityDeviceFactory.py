from .FMCSecurityDevice import FMCSecurityDevice
from .PANMCSecurityDevice import PANMCSecurityDevice
import utils.helper as helper
import utils.gvars as gvars
from pkg import PioneerDatabase
from pkg.SecurityDevice import SecurityDevice, SecurityDeviceDatabase
import fireREST
from panos.panorama import Panorama
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
    def build_api_security_device(security_device_uid, security_device_name, security_device_type, security_device_db, security_device_hostname, security_device_username, security_device_secret, security_device_port, domain):
        """
        Build an API Security Device Python object based on its type.

        Args:
            security_device_uid (str): The unique identifier for the security device.
            security_device_name (str): The name of the security device.
            security_device_type (str): The type of the security device.
            security_device_db (class): The database class for the security device.
            security_device_hostname (str): The hostname of the security device.
            security_device_username (str): The username for accessing the security device.
            security_device_secret (str): The secret for accessing the security device.
            security_device_port (int): The port number for connecting to the security device.
            domain (str): The domain of the security device.

        Returns:
            SecurityDevice: An instance of the appropriate API security device class.
        """
        match security_device_type:
            case gvars.fmc_device_type:
                general_logger.info(f"Device <{security_device_name}> is a Firepower Management Center.")
                connection = FMCDeviceConnection(security_device_username, security_device_secret, security_device_hostname, security_device_port, domain).connect_to_security_device()
                return FMCSecurityDevice(security_device_uid, security_device_name, security_device_db, connection)

            case gvars.panmc_device_type:
                general_logger.info(f"Device <{security_device_name}> is a Panorama Management Center.")
                connection = PANMCDeviceConnection(security_device_username, security_device_secret, security_device_hostname, security_device_port).connect_to_security_device()
                return PANMCSecurityDevice(security_device_uid, security_device_name, security_device_db, connection)

            # default case
            case _:
                general_logger.critical(f"Device <{security_device_name}>, with type <{security_device_type}>, is an invalid API device.")
                sys.exit(1)
        
    def create_security_device(db_user, security_device_name, db_password, db_host, db_port):
        """
        Create a security device object based on its type and extract all necessary data.

        Args:
            db_user (str): The username for accessing the database.
            security_device_name (str): The name of the security device.
            db_password (str): The password for accessing the database.
            db_host (str): The hostname of the database.
            db_port (int): The port number for connecting to the database.

        Returns:
            SecurityDevice: An instance of the specific security device class.
        """
        # Define the logging settings for general logging
        general_log_folder = helper.os.path.join('log', f'device_{security_device_name}')
        helper.setup_logging(general_log_folder, {gvars.general_logger: gvars.general_log_file})
        general_logger = helper.logging.getLogger('general')
        general_logger.info("################## Security device data processing ##################")

        # Define the logging settings for special policies logging
        special_log_folder = helper.os.path.join('log', f'device_{security_device_name}')
        helper.setup_logging(special_log_folder, {gvars.special_policies_logger: gvars.special_policies_logger_file})

        general_logger.info(f"I am now processing security device <{security_device_name}>.")
        security_device_db_name = security_device_name + gvars.db_name_suffix

        # Connect to the database of the security device
        security_device_db_cursor = PioneerDatabase.connect_to_db(db_user, security_device_db_name, db_password, db_host, db_port)

        # Instantiate and extract all the data from a generic security device
        # The data will be used further for creating the specific security device object
        security_device_db = SecurityDeviceDatabase(security_device_db_cursor)

        # Initialize the connection to None, as we don't know yet to what device we will connect to
        security_device_conn = None
        security_device_uid = None

        generic_security_device = SecurityDevice(security_device_uid, security_device_name, security_device_db, security_device_conn)

        # Get the security device type
        security_device_type = generic_security_device.get_general_data("type", "name", security_device_name)
        general_logger.info(f"Got device type <{security_device_type}>.")

        if '_api' in security_device_type:
            general_logger.info(f"<{security_device_name}> is an API device. Type: <{security_device_type}>")

            # Get the security device hostname
            security_device_hostname = generic_security_device.get_general_data("hostname", "name", security_device_name)

            # Get the security device username
            security_device_username = generic_security_device.get_general_data("username", "name", security_device_name)

            # Get the security device secret
            security_device_secret = generic_security_device.get_general_data("secret", "name", security_device_name)

            # Get the security device port
            security_device_port = generic_security_device.get_general_data("port", "name", security_device_name)

            # Get the security device domain
            security_device_domain = generic_security_device.get_general_data("management_domain", "name", security_device_name)

            # Get the security device UID
            security_device_uid = generic_security_device.get_general_data("uid", "name", security_device_name)

            # Create the API security object based on the device type
            specific_security_device_object = SecurityDeviceFactory.build_api_security_device(
                security_device_uid, security_device_name, security_device_type, security_device_db,
                security_device_hostname, security_device_username, security_device_secret,
                security_device_port, security_device_domain
            )

        elif '_config' in security_device_type:
            general_logger.info(f"{security_device_name} is a device that does not use API. Only its config file will be processed.")
            specific_security_device_object = None

        else:
            general_logger.critical(f"{security_device_name} is an invalid API device! Type: {security_device_type}")
            sys.exit(1)

        return specific_security_device_object

class APISecurityDeviceConnection(SecurityDeviceConnection):
    """
    A class representing a connection to an API-based security device.

    Args:
        api_username (str): The username for accessing the API.
        api_secret (str): The secret for accessing the API.
        api_hostname (str): The hostname of the API.
        api_port (int): The port number for connecting to the API.
    """

    def __init__(self, api_username, api_secret, api_hostname, api_port):
        """
        Initialize the APISecurityDeviceConnection instance.

        Args:
            api_username (str): The username for accessing the API.
            api_secret (str): The secret for accessing the API.
            api_hostname (str): The hostname of the API.
            api_port (int): The port number for connecting to the API.
        """
        super().__init__()
        self._api_username = api_username
        self._api_secret = api_secret
        self._api_hostname = api_hostname
        self._api_port = api_port

    def return_security_device_conn_object(self):
        """
        Attempt to connect to the security device and return the connection object.

        Returns:
            DeviceConnection: The connection object for the security device.

        Raises:
            SystemExit: If the connection to the security device fails.
        """
        try:
            # Log the attempt to connect to the security device
            general_logger.info(f"Attempting to connect to the security device using username {self._api_username}, hostname {self._api_hostname}, port {self._api_port}.")
            
            # Try to establish a connection to the security device
            device_connection = self.connect_to_security_device()
            
            # Log the successful connection
            general_logger.info(f"Successfully connected to the device. {device_connection}")
            
            # Return the connection object
            return device_connection
        except Exception as err:
            # Log the failure to connect and exit the program
            general_logger.critical(f"Could not connect to Security Device. Reason: {err}")
            sys.exit(1)

    def connect_to_security_device(self):
        """
        Establish a connection to the security device.

        This method should be implemented by subclasses to provide the actual
        connection logic for different types of security devices.

        Raises:
            NotImplementedError: If the method is not implemented by a subclass.
        """
        raise NotImplementedError("Subclasses must implement the connect_to_security_device method")

class PANMCDeviceConnection(APISecurityDeviceConnection):
    """
    A class representing a connection to a Panorama Management Center (PANMC) device.

    Args:
        api_username (str): The username for accessing the API.
        api_secret (str): The secret for accessing the API.
        api_hostname (str): The hostname of the API.
        api_port (int): The port number for connecting to the API.
    """

    def __init__(self, api_username, api_secret, api_hostname, api_port):
        """
        Initialize the PANMCDeviceConnection instance.

        Args:
            api_username (str): The username for accessing the API.
            api_secret (str): The secret for accessing the API.
            api_hostname (str): The hostname of the API.
            api_port (int): The port number for connecting to the API.
        """
        super().__init__(api_username, api_secret, api_hostname, api_port)
        self._device_connection = self.return_security_device_conn_object()

    def connect_to_security_device(self):
        """
        Establish a connection to the Panorama Management Center (PANMC) device.

        Returns:
            panmc_conn: The connection object for the PANMC device.
        """
        # Create a connection object for the Panorama Management Center (PANMC) device
        panmc_conn = Panorama(self._api_hostname, self._api_username, self._api_secret)
        return panmc_conn

class FMCDeviceConnection(APISecurityDeviceConnection):
    """
    Represents a connection to a Firepower Management Center (FMC) device.

    Args:
        api_username (str): The API username for the connection.
        api_secret (str): The API secret for the connection.
        api_hostname (str): The hostname of the FMC device.
        api_port (int): The port number for the connection.
        domain (str): The domain of the FMC device.

    Attributes:
        _domain (str): The domain of the FMC device.
        _device_connection (fireREST.FMC): The connection object to the FMC device.
    """

    def __init__(self, api_username, api_secret, api_hostname, api_port, domain):
        """
        Initialize an FMCDeviceConnection instance.

        Args:
            api_username (str): The API username for the connection.
            api_secret (str): The API secret for the connection.
            api_hostname (str): The hostname of the FMC device.
            api_port (int): The port number for the connection.
            domain (str): The domain of the FMC device.
        """
        super().__init__(api_username, api_secret, api_hostname, api_port)
        self._domain = domain
        self._device_connection = self.return_security_device_conn_object()

    def connect_to_security_device(self):
        """
        Connect to the Firepower Management Center (FMC) device.

        Returns:
            fireREST.FMC: An FMC connection object configured with the provided credentials.
        """
        # Create and return an FMC connection object with the provided details
        fmc_conn = fireREST.FMC(
            hostname=self._api_hostname,
            username=self._api_username,
            password=self._api_secret,
            domain=self._domain,
            protocol=self._api_port,
            timeout=30
        )
        return fmc_conn