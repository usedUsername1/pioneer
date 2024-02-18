import utils.helper as helper

class Container:
    def __init__(self, name, security_device_name, parent) -> None:
        self._name = name
        self._security_device_name = security_device_name
        self._parent = parent # parent is another Container

    def get_name(self):
        return self._name

    def get_parent_name(self):
        return self._parent.get_name()

    def get_security_device_name(self):
        return self._security_device_name

class SecurityDevicePolicyContainer(Container):
    def __init__(self, name, security_device_name, parent) -> None:
        super().__init__(name, security_device_name, parent)

    def process_container_info(self):
        try:
            container_processed_info = ({
                'security_policy_container_name': self.get_name(),
                'security_policy_parent': self.get_parent_name()
            })
        
        except AttributeError:
            container_processed_info = ({
                'security_policy_container_name': self.get_name(),
                'security_policy_parent': None
            })

        return container_processed_info