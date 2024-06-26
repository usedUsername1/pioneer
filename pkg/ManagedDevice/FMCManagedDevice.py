from pkg.ManagedDevice import ManagedDevice
import utils.helper as helper

general_logger = helper.logging.getLogger('general')

class FMCManagedDevice(ManagedDevice):
    def __init__(self, ManagedDevicesContainer, managed_device_info) -> None:
        super().__init__(ManagedDevicesContainer, managed_device_info['name'], managed_device_info['accessPolicy']['name'], managed_device_info['hostName'], managed_device_info.get('metadata', {}).get('containerDetails', {}).get('name'))
