import utils.helper as helper
class ManagedDevice:
    def __init__(self, managed_devices_container, name, assigned_security_policy_container_name, hostname, cluster) -> None:
        """
        Initialize a ManagedDevice instance.

        Args:
            managed_devices_container (ManagedDevicesContainer): The container for managed devices.
            name (str): The name of the managed device.
            assigned_security_policy_container_name (str): The name of the assigned security policy container.
            hostname (str): The hostname of the managed device.
            cluster (str): The cluster the managed device belongs to.
        """
        # Initialize properties
        self._uid = helper.generate_uid() 
        self._name = name  
        self._managed_devices_container_uid = managed_devices_container.uid
        self._managed_devices_container = managed_devices_container
        self._assigned_security_policy_container_name = assigned_security_policy_container_name
        self._hostname = hostname  
        self._cluster = cluster  

    @property
    def name(self):
        """Get or set the name of the managed device."""
        return self._name

    @name.setter
    def name(self, name: str):
        self._name = name

    @property
    def assigned_security_policy_container_uid(self):
        """
        Get the UID of the assigned security policy container.

        Returns:
            str: UID of the assigned security policy container.
        """
        # Retrieve the UID by querying the db with the container name
        container_uid_raw = self._managed_devices_container.security_device.db.security_policy_containers_table.get(
            'uid', 'name', self._assigned_security_policy_container_name
        )
        # Extract the UID from the result
        container_uid = container_uid_raw[0][0]
        return container_uid

    @property
    def hostname(self):
        """Get or set the hostname of the managed device."""
        return self._hostname

    @hostname.setter
    def hostname(self, hostname: str):
        self._hostname = hostname

    @property
    def cluster(self):
        """Get or set the cluster of the managed device."""
        return self._cluster

    @cluster.setter
    def cluster(self, cluster: str):
        self._cluster = cluster

    @property
    def uid(self):
        """Get or set the unique identifier of the managed device."""
        return self._uid

    @uid.setter
    def uid(self, uid: str):
        self._uid = uid

    @property
    def managed_devices_container_uid(self):
        """Get the UID of the managed devices container."""
        return self._managed_devices_container_uid

    def save(self, db):
        """
        Save the managed device to the db.

        Args:
            db (Database): The db instance where the device information will be saved.
        """
        db.managed_devices_table.insert(
            self.uid, 
            self.name, 
            self.managed_devices_container_uid, 
            self.assigned_security_policy_container_uid, 
            self.hostname, 
            self.cluster
        )