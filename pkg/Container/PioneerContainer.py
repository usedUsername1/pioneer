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
        # retrieve the security policy info from the database
        SecurityDeviceDatabase = self._SecurityDevice.get_database()
        security_policies_info_db = SecurityDeviceDatabase.get_security_policies_table().get('*', 'security_policy_container_uid', self.get_uid(), 'index')
        
        # create the PioneerSecurityPolicy object with data extracted from the database
        # when the object is initialized, all the data about objects attached to it will be collected
        # multiple lists need to be kept, in case the target device supports bulk object creation
        # the list with the objects must be passed to it
        #TODO: maybe use a different data type here idk
        network_objects = set()
        network_group_objects = set()
        port_objects = set()
        icmp_objects = set()
        port_group_objects = set()

        url_objects = set()
        url_group_objects = set()

        for security_policy_entry in security_policies_info_db:
            # create the python object and collect all the data of the policy from the database
            PioneerSecurityPolicyObject = PioneerSecurityPolicy(self, security_policy_entry)
            
            # log the special paramteres such as L7 apps
            # is it possible to get all the data for a given uid, and not just the uid?
            PioneerSecurityPolicyObject.log_special_parameters()
            network_objects.update(PioneerSecurityPolicyObject.get_source_network_objects())
            network_objects.update(PioneerSecurityPolicyObject.get_destination_network_objects())

            network_group_objects.update(PioneerSecurityPolicyObject.get_source_network_group_objects())
            network_group_objects.update(PioneerSecurityPolicyObject.get_destination_network_group_objects())
            # there is a problem with adding data RuntimeError: Set changed size during iteration
            # # loop through the groups here, retrieve their members and update the network_objects set. it is the only way
            # for NetworkGroup in network_group_objects:
            #     network_group_objects.update(NetworkGroup.get_object_members())
            #     network_group_objects.update(NetworkGroup.get_group_object_members())

            port_objects.update(PioneerSecurityPolicyObject.get_source_port_objects())
            port_objects.update(PioneerSecurityPolicyObject.get_destination_port_objects())

            icmp_objects.update(PioneerSecurityPolicyObject.get_source_icmp_objects())
            icmp_objects.update(PioneerSecurityPolicyObject.get_destination_icmp_objects())

            port_group_objects.update(PioneerSecurityPolicyObject.get_source_port_group_objects())
            port_group_objects.update(PioneerSecurityPolicyObject.get_destination_port_group_objects())

            # there is something very weird going on with this function
            url_objects.update(PioneerSecurityPolicyObject.get_url_objects_from_pioneer_policy())
            url_group_objects.update(PioneerSecurityPolicyObject.get_url_group_objects())

            # ok, all the members of all the groups have been extracted. next question, how do you update
            # all the sets with the elements of the list and not with the array itself?
