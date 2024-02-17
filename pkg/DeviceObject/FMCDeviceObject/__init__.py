from DeviceObject import NetworkObject

class FMCNetworkObject(NetworkObject):
    def __init__(self, name, description, is_overridable, network_address_value, network_address_type) -> None:
        super().__init__(name, description, is_overridable, network_address_value, network_address_type)
    
    # get the description of the object from the API call to FMC
    def get_description(self):
        return super().get_description()

