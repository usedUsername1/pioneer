from pkg.ManagedDevice import ManagedDevice
import utils.helper as helper

general_logger = helper.logging.getLogger('general')

class FMCManagedDevice(ManagedDevice):
    def __init__(self, ManagedDevicesContainer, managed_device_info) -> None:
        super().__init__(ManagedDevicesContainer, managed_device_info)
    
    def set_name(self):
        name = self._managed_device_info['name']
        return super().set_name(name)
    
    def set_assigned_security_policy_container_uid(self):
        assigned_security_policy_container_name = self._managed_device_info['accessPolicy']['name']
        return super().set_assigned_security_policy_container_uid(assigned_security_policy_container_name)
    
    def set_hostname(self):
        hostname = self._managed_device_info['hostName']
        return super().set_hostname(hostname)
    
    def set_cluster(self):
        # Check if the device is part of a cluster
        try:
            cluster = self._managed_device_info['metadata']['containerDetails']['name']
            general_logger.info(f"Managed device <{self._name}> is part of a cluster <{cluster}>.")
        except KeyError:
            general_logger.info(f"Managed device <{self._name}> is NOT part of a cluster.")
            cluster = None
        return super().set_cluster(cluster)
    