from pkg.SecurityDevice.APISecurityDevice.APISecurityDeviceConnection import APISecurityDeviceConnection
from pkg.SecurityDevice import SecurityDevice
from panos.panorama import Panorama
import utils.helper as helper
from utils.exceptions import InexistentContainer
from pkg.Container import SecurityPolicyContainer, ObjectPolicyContainer

general_logger = helper.logging.getLogger('general')

class PANMCDeviceConnection(APISecurityDeviceConnection):
    def __init__(self, api_username, api_secret, api_hostname, api_port):
        super().__init__(api_username, api_secret, api_hostname, api_port)
        self._device_connection = self.return_security_device_conn_object()
        self._domain = None
    
    def connect_to_security_device(self):
        panmc_conn = Panorama(self._api_hostname, self._api_username, self._api_secret, None, self._api_port)
        return panmc_conn
    
# for the temp migration, only the policy containers and the object containers are needed
class PANMCSecurityDevice(SecurityDevice):
    def __init__(self, name, sec_device_database, security_device_username, security_device_secret, security_device_hostname, security_device_port):
        super().__init__(name, sec_device_database)
        self._sec_device_connection = PANMCDeviceConnection(security_device_username, security_device_secret, security_device_hostname, security_device_port).connect_to_security_device()

    def get_device_version(self):
        general_logger.debug("Called PANMCSecurityDevice::get_device_version()")
        return self._sec_device_connection.refresh_system_info().version

    def return_security_policy_container_object(self, container_name):
        general_logger.debug("Called PANMCSecurityDevice::return_security_policy_container_object()")
        """
        Returns the security policy container object.

        Args:
            container_name (str): The name of the container.

        Returns:
            PANMCPolicyContainer: The security policy container object.
        """
        # Refresh devices
        device_groups = self._sec_device_connection.refresh_devices()
        # Find the device group with the desired name
        desired_device_group = None
        for device_group in device_groups:
            if device_group.name == container_name:
                desired_device_group = device_group
                break
        
        if desired_device_group is not None:
            hierarchy_state = desired_device_group.OPSTATES['dg_hierarchy'](desired_device_group)
            hierarchy_state.refresh()  # Call refresh on an instance
            parent_device_group = hierarchy_state.parent
            dg_info = {"parent_device_group":parent_device_group, "child_device_group":desired_device_group.name}
        else:
            raise InexistentContainer
        
        print(dg_info)
        return PANMCPolicyContainer(dg_info)

class PANMCPolicyContainer(SecurityPolicyContainer):
    def __init__(self, container_info) -> None:
        super().__init__(container_info)

    def get_parent_name(self):
        return super().get_parent_name()
    
    def is_child_container(self):
        pass

    def get_name(self):
        return super().get_name()

class PANMCObjectContainer(ObjectPolicyContainer):
    pass