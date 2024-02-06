from pkg.SecurityDevice import SecurityDeviceConnection

class APISecurityDeviceConnection(SecurityDeviceConnection):
    def __init__(self, api_username, api_secret, api_hostname, api_port):
        super().__init__()
        self._api_username = api_username
        self._api_secret = api_secret
        self._api_hostname = api_hostname
        self._api_port = api_port