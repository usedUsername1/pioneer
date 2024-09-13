from pkg.Container import Container, SecurityPolicyContainer, NATPolicyContainer
from pkg.Policy.PioneerPolicy import PioneerSecurityPolicy, PioneerNATPolicy
from pkg.DeviceObject import PioneerDeviceObject

class PioneerSecurityPolicyContainer(SecurityPolicyContainer):
    """
    Represents a security policy container specific to the Pioneer security device.
    """
    
    def __init__(self, security_device, name, parent_name) -> None:
        """
        Initializes a PioneerSecurityPolicyContainer instance.

        Args:
            security_device (SecurityDevice): The security device associated with this container.
            name (str): The name of the security policy container.
            parent_name (str): The name of the parent container.
        """
        super().__init__(security_device, name, parent_name)
        self._uid = self.get_container_uid()
    
    def get_container_uid(self) -> str:
        """
        Retrieves the source UID of the security policy container from the database.

        Returns:
            str: The source UID of the security policy container.
        """

        join_conditions = {
            "table": "migration_project_devices",
            "condition": "security_policy_containers.security_device_uid = migration_project_devices.source_device_uid"
        }

        result = self.security_device.db.security_policy_containers_table.get(
            columns=['*'],
            name_col='security_policy_containers.name',
            val=self._name,
            join=join_conditions
        )
        
        return result[0][0] if result else None
    
    def process_and_migrate(self) -> None:
        """
        Processes and migrates security policies, network objects, port objects, URL objects, and policy categories.
        """
        policies_list = []
        network_objects_set = set()
        network_group_objects_set = set()
        port_objects_set = set()
        port_group_objects_set = set()
        url_objects_set = set()
        url_group_objects_set = set()
        policy_categories_set = set()

        # Retrieve the security policy info from the database
        policies = self.security_device.db.security_policies_table.get(
            columns='*', 
            name_col='security_policy_container_uid', 
            val=self.uid, 
            order_param='index'
        )

        # Process each security policy entry
        for entry in policies:
            policy = PioneerSecurityPolicy(self, entry)
            policy.log_special_parameters()

            # Update network-related objects
            network_objects_set.update(policy.source_network_objects)
            network_objects_set.update(policy.destination_network_objects)
            network_group_objects_set.update(policy.source_network_group_objects)
            network_group_objects_set.update(policy.destination_network_group_objects)

            # Update port-related objects
            port_objects_set.update(policy.source_port_objects)
            port_objects_set.update(policy.destination_port_objects)
            port_objects_set.update(policy.source_icmp_objects)
            port_objects_set.update(policy.destination_icmp_objects)
            port_group_objects_set.update(policy.source_port_group_objects)
            port_group_objects_set.update(policy.destination_port_group_objects)

            # Update URL-related objects
            url_objects_set.update(policy.url_objects)
            url_group_objects_set.update(policy.url_group_objects)

            policy_categories_set.add(policy.category)
            
            # Add the policy to the list of policies that will be migrated
            policies_list.append(policy)

        # Migrate the network objects
        PioneerDeviceObject.recursive_update_objects_and_groups(network_objects_set, network_group_objects_set)
        if not network_objects_set:
            pass
        else:
            print("migrating network objects")
            self._security_device.migrate_network_objects(network_objects_set)

        # Migrate the network group objects
        if not network_group_objects_set:
            pass
        else:
            print("migrating network group objects")
            self._security_device.migrate_network_group_objects(network_group_objects_set)

        # Migrate the port objects
        PioneerDeviceObject.recursive_update_objects_and_groups(port_objects_set, port_group_objects_set)
        if not port_objects_set:
            pass
        else:
            print("migrating port objects")
            self._security_device.migrate_port_objects(port_objects_set)

        # Migrate the port group objects
        if not port_group_objects_set:
            pass
        else:
            print("migrating port group objects")
            self._security_device.migrate_port_group_objects(port_group_objects_set)

        PioneerDeviceObject.recursive_update_objects_and_groups(url_objects_set, url_group_objects_set)
        # Migrate the url objects
        if not url_objects_set:
            pass
        else:
            print("migrating url objects")
            self._security_device.migrate_url_objects(url_objects_set)

        # Migrate the url group objects
        if not url_group_objects_set:
            pass
        else:
            print("migrating url group objects")
            self._security_device.migrate_url_group_objects(url_group_objects_set)

        # Migrate the policy categories
        if not policy_categories_set:
            pass
        else:
            print("migrating policy categories")
            self._security_device.migrate_policy_categories(policy_categories_set)

        if not policies_list:
            pass
        else:
            print("migrating security policies")
            self._security_device.migrate_security_policies(policies_list)

class PioneerNATPolicyContainer(NATPolicyContainer):
    def __init__(self, security_device, name, parent_name) -> None:
        super().__init__(security_device, name, parent_name)
        self._uid = self.get_container_uid()
    
    def get_container_uid(self):
        """
        Retrieves the source UID of the NAT policy container from the database.

        Returns:
            str: The source UID of the NAT policy container.
        """

        join_conditions = {
            "table": "migration_project_devices",
            "condition": "nat_policy_containers.security_device_uid = migration_project_devices.source_device_uid"
        }

        result = self.security_device.db.nat_policy_containers_table.get(
            columns=['*'],
            name_col='nat_policy_containers.name',
            val=self._name,
            join=join_conditions
        )
        
        return result[0][0] if result else None

    def process_and_migrate(self):
        """
        Processes and migrates NAT policies, network objects, port objects associated with the to-be-migrated NAT policies.
        """
        policies_list = []
        network_objects_set = set()
        network_group_objects_set = set()
        port_objects_set = set()
        port_group_objects_set = set()

        # Retrieve the security policy info from the database
        policies = self.security_device.db.nat_policies_table.get(
            columns='*', 
            name_col='nat_policy_container_uid', 
            val=self.uid, 
            order_param='index'
        )

        # Process each security policy entry
        for entry in policies:
            policy = PioneerNATPolicy(self, entry)
            #TODO: this policy should log static NAT policies that use group objects
#            policy.log_special_parameters()

            #TODO: update the objects list with the objects used to define the NAT policies
            # Update network-related objects
            network_objects_set.update(policy.original_source_network)
            network_objects_set.update(policy.original_destination_network)
            network_objects_set.update(policy.translated_source_network)
            network_objects_set.update(policy.translated_destination_network)

            network_group_objects_set.update(policy.original_source_network_group_object)
            network_group_objects_set.update(policy.original_destination_network_group_object)
            network_group_objects_set.update(policy.translated_source_network_group_object)
            network_group_objects_set.update(policy.translated_destination_network_group_object)

            # Update port-related objects
            port_objects_set.update(policy.original_source_port_object)
            port_objects_set.update(policy.original_destination_port_object)
            port_objects_set.update(policy.translated_source_port_object)
            port_objects_set.update(policy.translated_destination_port_object)

            port_objects_set.update(policy.original_source_icmp_object)
            port_objects_set.update(policy.original_destination_icmp_object)
            port_objects_set.update(policy.translated_source_icmp_object)
            port_objects_set.update(policy.translated_destination_icmp_object)

            port_group_objects_set.update(policy.original_source_port_group_object)
            port_group_objects_set.update(policy.original_destination_port_group_object)
            port_group_objects_set.update(policy.translated_source_port_group_object)
            port_group_objects_set.update(policy.translated_destination_port_group_object)

            # Add the policy to the list of policies that will be migrated
            policies_list.append(policy)

        # Migrate the network objects
        PioneerDeviceObject.recursive_update_objects_and_groups(network_objects_set, network_group_objects_set)
        if not network_objects_set:
            pass
        else:
            print("migrating network objects")
            self._security_device.migrate_network_objects(network_objects_set)

        # Migrate the network group objects
        if not network_group_objects_set:
            pass
        else:
            print("migrating network group objects")
            self._security_device.migrate_network_group_objects(network_group_objects_set)

        # Migrate the port objects
        PioneerDeviceObject.recursive_update_objects_and_groups(port_objects_set, port_group_objects_set)
        if not port_objects_set:
            pass
        else:
            print("migrating port objects")
            self._security_device.migrate_port_objects(port_objects_set)

        # Migrate the port group objects
        if not port_group_objects_set:
            pass
        else:
            print("migrating port group objects")
            self._security_device.migrate_port_group_objects(port_group_objects_set)

        if not policies_list:
            pass
        else:
            print("migrating NAT policies")
            self._security_device.migrate_nat_policies(policies_list)