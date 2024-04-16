class ManagedDevice():
    def __init__(self, managed_device_info) -> None:
        self._managed_device_info = managed_device_info
        self._name = None
        self._assigned_security_policy_container = None
        self._hostname = None
        self._cluster = None
    
    def get_name(self):
        return self._name

    def set_name(self, name):
        self._name = name

    def get_assigned_security_policy_container(self):
        return self._assigned_security_policy_container

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
    
    def save(self, database):
        # get the table with the ManagedDevices
        ManagedDevicesTable = database.get_managed_devices_table()
        ManagedDevicesTable.insert(self._name, self._assigned_security_policy_container, self._hostname, self._cluster)
        # insert the info in the table