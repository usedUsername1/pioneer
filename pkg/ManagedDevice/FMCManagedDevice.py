from pkg.ManagedDevice import ManagedDevice
import utils.helper as helper

general_logger = helper.logging.getLogger('general')

class FMCManagedDevice(ManagedDevice):
    def __init__(self, ManagedDevicesContainer, managed_device_info) -> None:
        self._name = managed_device_info['name']
        self._assigned_security_policy_container_name = managed_device_info['accessPolicy']['name']
        self._hostname = managed_device_info['hostName']
        self._cluster = managed_device_info.get('metadata', {}).get('containerDetails', {}).get('name')

        super().__init__(ManagedDevicesContainer, managed_device_info, self._name, self._assigned_security_policy_container_name, self._hostname, self._cluster)
