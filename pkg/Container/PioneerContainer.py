from pkg.Container import Container, SecurityPolicyContainer

            # don't forget to check if groups should be sorted based on depdendencies

# a Pioneer object belongs to a MigrationProject object so SecurityDevice is the MigrationProject
#TODO: at some point, get the uid of the source container
from pkg.Policy.PioneerPolicy import PioneerSecurityPolicy

class PioneerSecurityPolicyContainer(SecurityPolicyContainer):
    def __init__(self, SecurityDevice, name, parent_name) -> None:
        super().__init__(SecurityDevice, name, parent_name)
        self.set_uid(self.get_source_security_policy_container_uid())
    
    def get_source_security_policy_container_uid(self):
        SecurityDeviceDatabase = self._SecurityDevice.get_database()
        
        join = {
            "table": "migration_project_devices",
            "condition": "security_policy_containers.security_device_uid = migration_project_devices.source_device_uid"
        }
        
        return SecurityDeviceDatabase.get_security_policy_containers_table().get(
            columns=['*'],
            name_col='security_policy_containers.name',
            val=self._name,
            join=join
        )[0][0]
    
    def process_and_migrate(self):
        # Retrieve the security policy info from the database
        db = self._SecurityDevice.get_database()
        policies = db.get_security_policies_table().get('*', 'security_policy_container_uid', self.get_uid(), 'index')

        # Initialize sets to track different types of objects
        network_objects = set()
        network_group_objects = set()
        port_objects = set()
        icmp_objects = set()
        port_group_objects = set()
        url_objects = set()
        url_group_objects = set()

        # Process each security policy entry
        for entry in policies:
            policy = PioneerSecurityPolicy(self, entry)
            policy.log_special_parameters()

            # Update network-related objects
            network_objects.update(policy.get_source_network_objects())
            network_objects.update(policy.get_destination_network_objects())
            network_group_objects.update(policy.get_source_network_group_objects())
            network_group_objects.update(policy.get_destination_network_group_objects())

            # Process network group objects
            for group in list(network_group_objects):
                network_objects.update(group.get_object_members())
                network_group_objects.update(group.get_group_object_members())

            # Update port-related objects
            port_objects.update(policy.get_source_port_objects())
            port_objects.update(policy.get_destination_port_objects())
            icmp_objects.update(policy.get_source_icmp_objects())
            icmp_objects.update(policy.get_destination_icmp_objects())
            port_group_objects.update(policy.get_source_port_group_objects())
            port_group_objects.update(policy.get_destination_port_group_objects())

            # Process port group objects
            for group in list(port_group_objects):
                port_objects.update(group.get_object_members())
                port_group_objects.update(group.get_group_object_members())

            # Update URL-related objects
            url_objects.update(policy.get_url_objects_from_pioneer_policy())
            url_group_objects.update(policy.get_url_group_objects())

            # Process URL group objects
            for group in list(url_group_objects):
                url_objects.update(group.get_object_members())
                url_group_objects.update(group.get_group_object_members())
        
        #TODO: see if rearranging the set based on the group object dependencies is necessary.
        # all the policies have been processed. it is now the time to migrate all the groups and objects