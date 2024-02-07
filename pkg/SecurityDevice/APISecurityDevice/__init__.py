from abc import abstractmethod
from pkg.SecurityDevice import SecurityDevice
import sys
from .FMCSecurityDevice import FMCSecurityDevice
import utils.helper as helper

class APISecurityDevice(SecurityDevice):
    def __init__(self, user, database, password, host, port):
        super().__init__(user, database, password, host, port)


class APISecurityDeviceFactory:
    @staticmethod
    def build_api_security_device(security_device_name, security_device_type, SecurityDeviceDB, security_device_hostname, security_device_username, security_device_secret, security_device_port, domain):
        helper.logging.debug(f"Called build_api_security_device() with the following parameters: device name {security_device_name}, device type {security_device_type}, device hostname {security_device_hostname}, username {security_device_username}, port {security_device_port}, domain {domain}.")
        match security_device_type:
            case "fmc-api":
                helper.logging.info(f"Device {security_device_name} in a Firepower Management Center.")
                return FMCSecurityDevice(security_device_name, SecurityDeviceDB, security_device_username, security_device_secret, security_device_hostname, security_device_port, domain)

            # default case
            case _:
                helper.logging.critical(f"Device {security_device_name}, with type {security_device_type}, is an invalid API device.")
                sys.exit(1)

