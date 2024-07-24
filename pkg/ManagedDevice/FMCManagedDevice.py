from pkg.ManagedDevice import ManagedDevice
import utils.helper as helper

general_logger = helper.logging.getLogger('general')

class FMCManagedDevice(ManagedDevice):
    def __init__(self, managed_devices_container, managed_device_info) -> None:
        """
        Initialize an FMCManagedDevice instance.

        Args:
            managed_devices_container (ManagedDevicesContainer): The container for managed devices.
            managed_device_info (dict): A dictionary containing the information about the managed device.
        """
        # Initialize the base ManagedDevice class with information from the provided dictionary
        super().__init__(
            managed_devices_container,
            managed_device_info.get('name'),
            managed_device_info.get('accessPolicy', {}).get('name'),
            managed_device_info.get('hostName'),
            managed_device_info.get('metadata', {}).get('containerDetails', {}).get('name')
        )
