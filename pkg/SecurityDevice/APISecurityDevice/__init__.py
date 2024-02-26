from abc import abstractmethod
from pkg.SecurityDevice import SecurityDevice
import sys
from .FMCSecurityDevice import FMCSecurityDevice
import utils.helper as helper

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
        helper.logging.debug(f"Called APISecurityDevice::__init__().")
        super().__init__(user, database, password, host, port)


class APISecurityDeviceFactory:
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
        helper.logging.debug(f"Called APISecurityDeviceFactory::build_api_security_device().")
        match security_device_type:
            case "fmc-api":
                helper.logging.info(f"Device <{security_device_name}> is a Firepower Management Center.")
                return FMCSecurityDevice(security_device_name, SecurityDeviceDB, security_device_username, security_device_secret, security_device_hostname, security_device_port, domain)

            # default case
            case _:
                helper.logging.critical(f"Device <{security_device_name}>, with type <{security_device_type}>, is an invalid API device.")
                sys.exit(1)

