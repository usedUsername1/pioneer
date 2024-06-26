import utils.helper as helper
class ManagedDevice():
    def __init__(self, ManagedDevicesContainer, name, assigned_security_policy_container_name, hostname, cluster) -> None:
        self._uid = helper.generate_uid()
        self._name = name
        self._managed_devices_container_uid = ManagedDevicesContainer.get_uid()
        self._ManagedDevicesContainer = ManagedDevicesContainer
        self._assigned_security_policy_container_name = assigned_security_policy_container_name
        self._hostname = hostname
        self._cluster = cluster
    
    def get_name(self):
        return self._name

    def set_name(self, name):
        self._name = name

    def get_assigned_security_policy_container_uid(self):
        # get the container_uid by the name of the container and set object's value
        container_uid_raw = self._ManagedDevicesContainer.get_security_device().get_database().get_security_policy_containers_table().get('uid', 'name', self._assigned_security_policy_container_name)
        # extract the uid from the tuple
        container_uid = container_uid_raw[0][0]
        return container_uid
    
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

    def save(self, Database):
        ManagedDevicesTable = Database.get_managed_devices_table()
        ManagedDevicesTable.insert(self._uid, self._name, self._managed_devices_container_uid, self.get_assigned_security_policy_container_uid(), self._hostname, self._cluster)