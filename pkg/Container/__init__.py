import utils.helper as helper

class Container:
    def __init__(self, container_info) -> None:
        # intialize this only with the container info
        # use setters for the rest of the attributes
        self._container_info = container_info
        self._name = None
        self._parent = None
    
    def set_name(self, name):
        self._name = name

    def set_parent(self, parent):
        self._parent = parent

    def get_name(self):
        return self._name

    def get_parent_name(self):
        return self._parent.get_name()

    def get_security_device_name(self):
        return self._security_device_name

class SecurityPolicyContainer(Container):
    def __init__(self, container_info) -> None:
        super().__init__(container_info)

    def get_device_container_info(self):
        pass

    def process_container_info(self):
        try:
            container_processed_info = ({
                'security_policy_container_name': self.get_name(),
                'security_policy_parent': self.get_parent_name()
            })
        
        # If the parent doesn't exist, then an Attribute Error exception will be raised
        except AttributeError:
            container_processed_info = ({
                'security_policy_container_name': self.get_name(),
                'security_policy_parent': None
            })

        return container_processed_info

class ObjectPolicyContainer(Container):
    def __init__(self, name, security_device_name, parent) -> None:
        super().__init__(name, security_device_name, parent)
    
    def process_container_info(self):
        try:
            container_processed_info = ({
                'object_container_name': self.get_name(),
                'object_container_parent': self.get_parent_name()
            })
        
        except AttributeError:
            container_processed_info = ({
                'object_container_name': self.get_name(),
                'object_container_parent': None
            })

        return container_processed_info

class NATPolicyContainer:
    pass