from abc import abstractmethod
from pkg.SecurityDevice import SecurityDevice
import sys
from .FMCSecurityDevice import FMCSecurityDevice


class APISecurityDevice(SecurityDevice):
    def __init__(self, user, database, password, host, port):
        super().__init__(user, database, password, host, port)


class APISecurityDeviceFactory:
    @staticmethod
    def build_api_security_device(security_device_name, security_device_type, SecurityDeviceDB, security_device_hostname, security_device_username, security_device_secret, security_device_port, domain):
        match security_device_type:
            case "fmc-api":
                return FMCSecurityDevice(security_device_name, SecurityDeviceDB, security_device_username, security_device_secret, security_device_hostname, security_device_port, domain)

            # default case
            case _:
                print("Invalid API security device.")
                sys.exit(1)

