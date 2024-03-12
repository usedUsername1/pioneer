from pkg.SecurityDevice import SecurityDeviceConnection
import utils.helper as helper
import sys
general_logger = helper.logging.getLogger('general')

class APISecurityDeviceConnection(SecurityDeviceConnection):
    def __init__(self, api_username, api_secret, api_hostname, api_port):
        super().__init__()
        self._api_username = api_username
        self._api_secret = api_secret
        self._api_hostname = api_hostname
        self._api_port = api_port
    
    def return_security_device_conn_object(self):
        general_logger.debug(f"Called connect_to_security_device with parameters: username {self._api_username}, hostname {self._api_hostname}, port {self._api_port}, domain {self._domain}.")
        try:
            general_logger.info(f"I am trying to connect to the FMC device using username {self._api_username}, hostname {self._api_hostname}, port {self._api_port}, domain {self._domain}.")
            device_conn = self.connect_to_security_device()
            general_logger.info(f"I have successfully connected to the device. {device_conn}")
            return device_conn
        except Exception as err:
            general_logger.critical(f"Could not connect to FMC device. Reason: {err}")
            sys.exit(1)

    def connect_to_security_device(self):
        # This method is a placeholder and should be implemented by subclasses
        raise NotImplementedError("Subclasses must implement connect_to_security_device method")