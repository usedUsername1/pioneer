import utils.helper as helper
class ManagedDevice():
    def __init__(self, ManagedDevicesContainer, managed_device_info) -> None:
        self._managed_device_info = managed_device_info
        self._uid = helper.generate_uid()
        self._name = None
        self._managed_devices_container_uid = ManagedDevicesContainer.get_uid()
        self._assigned_security_policy_container = None
        self._hostname = None
        self._cluster = None
    
    def get_name(self):
        return self._name

    def set_name(self, name):
        self._name = name

    def get_assigned_security_policy_container(self):
        return self._assigned_security_policy_container

    #TODO: see how to get the ID of a container by name
    def set_assigned_security_policy_container(self, container):
        self._assigned_security_policy_container = container

    def get_hostname(self):
        return self._hostname

    def set_hostname(self, hostname):
        self._hostname = hostname

    def get_cluster(self):
        return self._cluster

    def set_cluster(self, cluster):
        self._cluster = cluster
    
    def set_uid(self, uid):
        self._uid = uid

    def get_uid(self):
        return self._uid
    
    def get_managed_devices_container_uid(self):
        return self._managed_devices_container_uid
    
    def set_attributes(self):
        self.set_name()
        self.set_assigned_security_policy_container()
        self.set_hostname()
        self.set_cluster()

    def save(self, Database):
        ManagedDevicesTable = Database.get_managed_devices_table()
        ManagedDevicesTable.insert(self.get_uid(), self.get_name(), self.get_managed_devices_container_uid(), self.get_assigned_security_policy_container(), self.get_hostname(), self.get_cluster())