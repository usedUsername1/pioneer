from pkg.Container import Container, SecurityPolicyContainer

            # don't forget to check if groups should be sorted based on depdendencies

# a Pioneer object belongs to a MigrationProject object so SecurityDevice is the MigrationProject
from pkg.Policy.PioneerPolicy import PioneerSecurityPolicy
import pkg.DeviceObject.PioneerDeviceObject as PioneerDeviceObject

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
        policies_list = []
        # Retrieve the security policy info from the database
        db = self._SecurityDevice.get_database()

        policies = db.get_security_policies_table().get(columns='*', name_col='security_policy_container_uid', val=self.get_uid(), order_param='index')

        # Initialize sets to track different types of objects
        network_objects = set()
        network_group_objects = set()
        port_objects = set()
        port_group_objects = set()
        url_objects = set()
        url_group_objects = set()
        policy_categories = set()


        # Process each security policy entry
        for entry in policies:
            policy = PioneerSecurityPolicy(self, entry)
            policy.log_special_parameters()

            # Update network-related objects
            network_objects.update(policy.get_source_network_objects())
            network_objects.update(policy.get_destination_network_objects())
            network_group_objects.update(policy.get_source_network_group_objects())
            network_group_objects.update(policy.get_destination_network_group_objects())

            # Update port-related objects
            port_objects.update(policy.get_source_port_objects())
            port_objects.update(policy.get_destination_port_objects())
            port_objects.update(policy.get_source_icmp_objects())
            port_objects.update(policy.get_destination_icmp_objects())
            port_group_objects.update(policy.get_source_port_group_objects())
            port_group_objects.update(policy.get_destination_port_group_objects())

            # # Update URL-related objects
            url_objects.update(policy.get_url_objects_from_pioneer_policy())
            url_group_objects.update(policy.get_url_group_objects())

            policy_categories.add(policy.get_category())
            
            # # add the policy to the list of policies that will be migrated
            policies_list.append(policy)
        
        # the problem is when group_object members are found.
        # basically, the same logic needs to be applied to them as well
        PioneerDeviceObject.recursive_update_objects_and_groups(network_objects, network_group_objects)
        
        # # migrate the network objects
        print("migrating network objects")
        self._SecurityDevice.migrate_network_objects(network_objects)
        self._SecurityDevice.migrate_network_group_objects(network_group_objects)

        PioneerDeviceObject.recursive_update_objects_and_groups(port_objects, port_group_objects)

        print("migrating port objects")
        self._SecurityDevice.migrate_port_objects(port_objects)
        print("migrating port group objects")
        self._SecurityDevice.migrate_port_group_objects(port_group_objects)

        PioneerDeviceObject.recursive_update_objects_and_groups(url_objects, url_group_objects)
        print("migrating url objects")
        self._SecurityDevice.migrate_url_objects(url_objects)
        print("migrating url group objects")
        self._SecurityDevice.migrate_url_group_objects(url_group_objects)

        print("migrating policy categories")
        self._SecurityDevice.migrate_policy_categories(policy_categories)

        print("migrating security policies")
        self._SecurityDevice.migrate_security_policies(policies_list)