from pkg.Container import Container

# a Pioneer object belongs to a MigrationProject object so SecurityDevice is the MigrationProject
#TODO: at some point, get the uid of the source container
from pkg.Policy.PioneerPolicy import PioneerSecurityPolicy
class PioneerContainer(Container):
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
    
    def rename_migrate_when_done_implementing(self):
        # retrieve the security policy info from the database
        SecurityDeviceDatabase = self._SecurityDevice.get_database()
        security_policies_info_db = SecurityDeviceDatabase.get_security_policies_table().get('*', 'security_policy_container_uid', self.get_uid(), 'index')
        
        # create the PioneerSecurityPolicy object with data extracted from the database
        # when the object is initialized, all the data about objects attached to it will be collected
        network_objects_uids = set()
        network_group_objects_uids = set()
        port_objects_uids = set()
        icmp_objects_uids = set()
        port_group_objects_uids = set()

        url_objects_uids = set()
        url_group_objects_uids = set()

        for security_policy_entry in security_policies_info_db:
            PioneerSecurityPolicyObject = PioneerSecurityPolicy(self, security_policy_entry)
            PioneerSecurityPolicyObject.log_special_parameters()
            network_objects_uids.update(PioneerSecurityPolicyObject.get_source_network_objects(), PioneerSecurityPolicyObject.get_destination_network_objects())
            network_group_objects_uids.update(PioneerSecurityPolicyObject.get_source_network_group_objects(), PioneerSecurityPolicyObject.get_destination_network_group_objects())


            # check the policy for special parameters as well!

            # now get the list of objects used on the policy and put it in a big set that will be used for migrating the objects

