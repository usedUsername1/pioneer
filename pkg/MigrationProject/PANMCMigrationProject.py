from pkg.MigrationProject import MigrationProject
from pkg.Container.PANMCContainer import PANMCSecurityPolicyContainer
from pkg.DeviceObject.PioneerDeviceObject import PioneerICMPObject, PioneerPortGroupObject
import random
import re
from panos.panorama import DeviceGroup, Template
from panos.network import Zone
from panos.objects import AddressObject, AddressGroup, ServiceObject, ServiceGroup, CustomUrlCategory, Tag
from panos.policies import PreRulebase, PostRulebase, SecurityRule, NatRule
import utils.helper as helper
import utils.gvars as gvars

special_policies_log = helper.logging.getLogger(gvars.special_policies_logger)

class PANMCMigrationProject(MigrationProject):
    def __init__(self, name, db, source_security_device, target_security_device):
        """
        Initializes a PANMCMigrationProject instance.

        Args:
            name (str): The name of the migration project.
            db (MigrationProjectDatabase): The db instance for the migration project.
            source_security_device (SecurityDevice): The source security device object.
            target_security_device (SecurityDevice): The target security device object.
        """
        # Store the provided arguments
        self._source_security_device = source_security_device
        self._target_security_device = target_security_device
        self._db = db

        # Load various mappings and settings from the db
        self._security_policy_containers_map = self.load_containers_map()
        self._security_zones_map = self.load_security_zones_map()
        self._network_object_types_map = self.load_network_object_types_map()
        self._security_policy_actions_map = self.load_security_policies_actions_map()
        self._log_settings = self.load_log_settings()
        self._special_security_policy_parameters = self.load_special_security_policy_parameters()
        self._section_map = self.load_section_map()

        # Initialize the parent class
        super().__init__(name, db)
    
    # save it to the file file, don't print it
    def print_compatibility_issues(self):
        print("""You are migrating to a Panorama Management Center device. The following is a list with compatibility issues and how they will be fixed:
Object/Policy/Port/URL object names: All names will be cut to have less than 63 characters. In case a name is longer than 63 characters, only the first 60 characters will be kept and
a random suffix will be generated in order to avoid duplicates. All special characters will be removed and replaced with "_".
Security Policies restricting ping access: All policies that control ping access will be split in two. The original policy and the ping policy. This is needed because 
PA treats ping as an application. The second rule will keep the exact same source and destinations, but will have all port objects removed and application set to ping.""" + '\n')

    def migrate_network_objects(self, network_objects):
        """
        Migrates a list of network objects to the target security device.

        This method iterates over each network object, applies name constraints, 
        maps network object types, and adds the object to the target security device. 
        It then attempts to bulk create the network objects on the target device.

        Args:
            network_objects (list): A list of network objects to be migrated.

        Raises:
            Exception: If an error occurs during bulk creation of network objects.
        """
        last_obj = ''
        for net_obj in network_objects:
            # Adapt the name of the network object according to the naming constraints
            adapted_name = PANMCMigrationProject.apply_name_constraints(net_obj.name)
            net_obj.name = adapted_name

            # Map the network object type from source to target
            net_obj_type = self._network_object_types_map.get(net_obj.network_address_type)
            # Create a new AddressObject with the adapted name and mapped type
            updated_network_object = AddressObject(
                net_obj.name,
                net_obj.network_address_value,
                net_obj_type,
                net_obj.description
            )
            last_obj = updated_network_object
            # Add the updated network object to the target security device
            self._target_security_device.device_connection.add(updated_network_object)
        
        # Attempt to bulk create the network objects on the target device
        try:
            # Create similar objects in bulk based on the updated object's name
            self._target_security_device.device_connection.find(last_obj.name).create_similar()
        except Exception as e:
            print("Error occurred when bulk creating network address objects. More details: ", e)

    def migrate_network_group_objects(self, network_group_objects):
        """
        Migrates a list of network group objects to the target security device.

        This method iterates over each network group object, applies name constraints, 
        gathers group and object member names, and adds the group object to the target 
        security device. It then attempts to bulk create the network group objects on 
        the target device.

        Args:
            network_group_objects (list): A list of network group objects to be migrated.

        Raises:
            Exception: If an error occurs during bulk creation of network group objects.
        """
        last_obj = ''
        for net_group_obj in network_group_objects:
            # Adapt the name of the network group object according to the naming constraints
            adapted_name = PANMCMigrationProject.apply_name_constraints(net_group_obj.name)
            net_group_obj.name = adapted_name

            # Gather the names of all group and object members
            group_member_names = []
            # Find the group object member names
            for group_member in net_group_obj.group_object_members:
                group_member_names.append(group_member.name)
            # Find the object member names
            for obj_member in net_group_obj.object_members:
                group_member_names.append(obj_member.name)
            
            # Create a new AddressGroup with the adapted name, gathered member names, and description
            updated_network_group_object = AddressGroup(
                name=net_group_obj.name,
                static_value=group_member_names,
                description=net_group_obj.description
            )

            # Add the updated network group object to the target security device
            self._target_security_device.device_connection.add(updated_network_group_object)
            last_obj = updated_network_group_object

        # Attempt to bulk create the network group objects on the target device
        try:
            # Create similar objects in bulk based on the first network group object's name
            self._target_security_device.device_connection.find(last_obj.name).create_similar()
        except Exception as e:
            print("Error occurred when creating network group objects. More details: ", e)

    def migrate_port_objects(self, port_objects):
        """
        Migrates a list of port objects to the target security device.

        This method iterates over each port object, applies name constraints, 
        and creates a new `ServiceObject` for each valid port object. It then 
        adds the new port object to the target security device and attempts to 
        create similar objects on the target device in bulk.

        Args:
            port_objects (list): A list of port objects to be migrated.

        Raises:
            Exception: If an error occurs during the bulk creation of port objects.
        """
        last_obj = ''
        for port_obj in port_objects:
            if isinstance(port_obj, PioneerICMPObject):
                # Skip ICMP objects as they cannot be migrated
                continue

            # Apply name constraints to the port object name
            constrained_name = PANMCMigrationProject.apply_name_constraints(port_obj.name)
            port_obj.name = constrained_name

            # Create a new ServiceObject with the required attributes
            new_service_object = ServiceObject(
                name=port_obj.name,
                protocol=port_obj.port_protocol.lower(),
                destination_port=port_obj.destination_port,
                description=port_obj.description,
                tag=None
            )

            # Add the new service object to the target security device
            self._target_security_device.device_connection.add(new_service_object)
            last_obj = new_service_object

        try:
            self._target_security_device.device_connection.find(last_obj.name).create_similar()
        except Exception as e:
            print("Error occurred when bulk creating port objects. More details: ", e)

    def migrate_port_group_objects(self, port_group_objects):
        """
        Migrates a list of port group objects to the target security device.

        This method iterates over each port group object, applies name constraints, 
        and creates a new `ServiceGroup` for each port group object. It then adds 
        the new port group object to the target security device and attempts to 
        create similar objects on the target device.

        Args:
            port_group_objects (list): A list of port group objects to be migrated.

        Raises:
            Exception: If an error occurs during creation of port group objects.
        """
        last_obj = ''
        for port_group in port_group_objects:
            # Apply name constraints to the port group object name
            adapted_name = PANMCMigrationProject.apply_name_constraints(port_group.name)
            port_group.name = adapted_name

            # Initialize an empty list to store valid port group members
            valid_port_group_members = []

            # Process group object members and exclude ICMP members
            for member in port_group.group_object_members:
                if isinstance(member, PioneerICMPObject):
                    # Skip ICMP objects as they cannot be migrated
                    continue
                valid_port_group_members.append(member.name)
            
            # Add object members to the valid port group members list
            for member in port_group.object_members:
                valid_port_group_members.append(member.name)

            # Skip empty port groups to avoid migrating groups with no valid members
            if len(valid_port_group_members) == 0:
                continue

            # Create a new ServiceGroup object with valid members
            new_service_group = ServiceGroup(name=port_group.name, value=valid_port_group_members)

            # Add the new service group object to the target security device
            last_obj = new_service_group
            self._target_security_device.device_connection.add(new_service_group)

            # Attempt to create a similar object on the target device
            try:
                self._target_security_device.device_connection.find(last_obj.name).create_similar()
            except Exception as e:
                print("Error occurred when creating port group. More details: ", e)

    def migrate_url_objects(self, url_objects):
        """
        Migrates a list of URL objects to the target security device.

        This method iterates over each URL object, applies name and value constraints, 
        creates a new `CustomUrlCategory` object for each URL object, and adds it to 
        the target security device. It then attempts to bulk create similar URL objects 
        on the target device.

        Args:
            url_objects (list): A list of URL objects to be migrated.

        Raises:
            Exception: If an error occurs during the bulk creation of URL objects.
        """
        last_obj = ''
        for url_obj in url_objects:
            # Adapt the name and URL value of the URL object according to the constraints
            adapted_name = PANMCMigrationProject.apply_url_name_constraints(url_obj.name)
            url_obj.name = adapted_name
            adapted_url_value = PANMCMigrationProject.apply_url_value_constraints(url_obj.url_value)
            url_obj.url_value = adapted_url_value
            # Create a new CustomUrlCategory object with the adapted name and URL value
            new_url_object = CustomUrlCategory(
                name=adapted_name,
                url_value=adapted_url_value,
                description=url_obj.description,
                type='URL List'
            )

            last_obj = new_url_object
            # Add the new URL object to the target security device
            try:
                self._target_security_device.device_connection.add(new_url_object)
            except Exception as e:
                print(f"Error occurred when adding URL object '{adapted_name}'. More details: ", e)

        # Attempt to bulk create similar URL objects on the target device
        try:
            self._target_security_device.device_connection.find(last_obj.name).create_similar()
        except Exception as e:
            print("Error occurred when bulk creating URL objects. More details: ", e)

    def migrate_url_group_objects(self, url_group_objects):
        """
        Migrates a list of URL group objects to the target security device.

        This method iterates over each URL group object, applies name constraints, 
        and value constraints to its members. It then creates a new `CustomUrlCategory` 
        for each URL group object and adds it to the target security device. Finally, 
        it attempts to bulk create similar URL group objects on the target device.

        Args:
            url_group_objects (list): A list of URL group objects to be migrated.

        Raises:
            Exception: If an error occurs during bulk creation of URL group objects.
        """
        last_obj = ''
        for url_group in url_group_objects:
            # Apply name constraints to the URL group object
            adapted_group_name = PANMCMigrationProject.apply_url_name_constraints(url_group.name)
            url_group.name = adapted_group_name

            # Initialize a set to store unique URL member values
            url_member_values = set()

            # Get the members of the URL group
            if url_group.object_members:
                for member in url_group.object_members:
                    # Apply value constraints to the URL group member
                    adapted_member_value = PANMCMigrationProject.apply_url_value_constraints(member.url_value)
                    url_member_values.add(adapted_member_value)

                # Create a new CustomUrlCategory object with adapted values
                new_url_group = CustomUrlCategory(
                    name=url_group.name,
                    url_value=url_member_values,
                    description=url_group.description,
                    type='URL List'
                )

                # Add the new URL group object to the target security device
                last_obj = new_url_group
                self._target_security_device.device_connection.add(new_url_group)
            else:
                continue

        # Attempt to bulk create similar URL group objects on the target device
        try:
            self._target_security_device.device_connection.find(last_obj.name).create_similar()
        except Exception as e:
            print("Error occurred when bulk creating URL group objects. More details: ", e)

    def migrate_policy_categories(self, categories):
        """
        Migrates a list of policy categories to the target security device.

        This method iterates over each category name, creates a new `Tag` object, 
        and adds it to the target security device. It then attempts to bulk create 
        similar tag objects on the target device.

        Args:
            categories (list): A list of policy category names to be migrated.

        Raises:
            Exception: If an error occurs during the creation of tag objects.
        """
        last_obj = ''
        for category_name in categories:
            # Create a new Tag object for the category name
            tag_object = Tag(category_name)

            # Add the Tag object to the target security device
            last_obj = tag_object
            self._target_security_device.device_connection.add(tag_object)

        # Attempt to bulk create similar tag objects on the target device
        try:
            self._target_security_device.device_connection.find(last_obj.name).create_similar()
        except Exception as e:
            print("Error occurred when creating tag objects. More details: ", e)

    def get_rulebase(self, device_group, section):
        """
        Get the appropriate rulebase based on the policy section.

        :param device_group: Device group object.
        :param section: Policy section ('pre' or 'post').
        :return: Rulebase object.
        """
        section = self._section_map[section]
        if section == 'pre':
            return device_group.add(PreRulebase())
        elif section == 'post':
            return device_group.add(PostRulebase())

    #TODO: experiment with bulk creating
    # bulk creation should be possible as long as the rulebase object/device group object doesn't get instantiated each time for a new policy
    def migrate_security_policies(self, policies):
        """
        Migrate security policies from the source to the target system.

        :param policies: List of security policy objects to be migrated.
        """
        # Dictionary to keep track of created DeviceGroups
        created_device_groups = {}

        for policy in policies:
            print(f"Migrating policy: {policy.name}")
            if policy.status != True:
                continue

            unresolved_dependency = False

            # Get source security zones and handle unresolved dependencies
            source_zone_names = self.resolve_zone_names(policy.source_zones, 'source', policy.name)
            if source_zone_names is None:
                unresolved_dependency = True

            # Get destination security zones and handle unresolved dependencies
            destination_zone_names = self.resolve_zone_names(policy.destination_zones, 'destination', policy.name)
            if destination_zone_names is None:
                unresolved_dependency = True

            if unresolved_dependency:
                continue  # Skip to the next policy

            # Get source and destination network names
            source_network_names = self.reslove_network_object_names(policy.source_networks)
            destination_network_names = self.reslove_network_object_names(policy.destination_networks)

            # Get destination ports and check if ICMP is involved
            destination_port_names, has_icmp = self.resolve_port_object_names(policy.destination_ports)

            # Get URL names
            url_names = self.resolve_url_object_names(policy.urls)

            log_end = True

            # Map policy action
            policy_action = self._security_policy_actions_map[policy.action]

            #Duct tape solution to avoid having multiple device groups created
            if policy._policy_container.uid not in created_device_groups:
                device_group = DeviceGroup(self._security_policy_containers_map[policy._policy_container.uid])
                self._target_security_device.device_connection.add(device_group)
                created_device_groups[policy._policy_container.uid] = device_group
            else:
                device_group = created_device_groups[policy._policy_container.uid]

            # Determine the appropriate rulebase (pre or post)
            rulebase = self.get_rulebase(device_group, policy.section)

            # Adjust policy applications based on ICMP presence
            if has_icmp:
                policy.policy_apps = ['ping']
            else:
                policy.policy_apps = ['any']

            # Check if the policy is an 'any-any' policy
            if (source_network_names == ['any'] and
                destination_network_names == ['any'] and
                destination_port_names == ['any'] and
                url_names == ['any'] and
                policy.policy_apps == ['any']):
                special_policies_log.warn(f"Policy {policy.name} is an 'any-any' policy. Check on source device what special parameters it has.")

            # Apply name constraints
            policy.name = PANMCMigrationProject.apply_name_constraints(policy.name)

            # Create and add policy object to the rulebase
            self._add_security_policy_to_rulebase(rulebase, policy, source_zone_names, destination_zone_names,
                                        source_network_names, destination_network_names,
                                        destination_port_names, url_names, policy_action, log_end)

            # Attempt to create the policy object
            try:
                rulebase.find(policy.name).create_similar()
            except Exception as e:
                print("Error occurred when creating policy object. More details: ", e)
                special_policies_log.warn(f"Failed to create policy {policy.name}. Reason: {e}.\n")
            
            #TODO: empty the rulebase after the policies have been created, to prevent
            # the case where a policy that cannot be migrated prevents further policies from getting migrated

    def _add_security_policy_to_rulebase(self, rulebase, policy, from_zones, to_zones,
                               source_networks, destination_networks,
                               destination_ports, url_names, policy_action, log_end):
        """
        Create and add a policy object to the rulebase.

        :param rulebase: Rulebase object to add the policy to.
        :param policy: Policy object to be added.
        :param from_zones: List of source zone names.
        :param to_zones: List of destination zone names.
        :param source_networks: List of source network names.
        :param destination_networks: List of destination network names.
        :param destination_ports: List of destination port names.
        :param url_names: List of URL names.
        :param policy_action: Action for the policy.
        :param log_end: Boolean indicating if logging should end.
        """
        if policy.policy_apps != ['ping']:
            policy.policy_apps = ['any']
            policy_object = SecurityRule(
                name=policy.name,
                tag=[policy.category],
                group_tag=policy.category,
                disabled=False,
                fromzone=from_zones,
                tozone=to_zones,
                source=source_networks,
                destination=destination_networks,
                service=destination_ports,
                category=url_names,
                application=policy.policy_apps,
                description=policy.comments,
                log_setting=self._log_settings,
                log_end=log_end,
                action=policy_action,
                group=self._special_security_policy_parameters
            )
            rulebase.add(policy_object)

        elif policy.policy_apps == ['ping']:
            if destination_ports != ['any']:
                policy.policy_apps = ['any']
                policy_object = SecurityRule(
                    name=policy.name,
                    tag=[policy.category],
                    group_tag=policy.category,
                    disabled=False,
                    fromzone=from_zones,
                    tozone=to_zones,
                    source=source_networks,
                    destination=destination_networks,
                    service=destination_ports,
                    category={'any'},
                    application=policy.policy_apps,
                    description=policy.comments,
                    log_setting=self._log_settings,
                    log_end=log_end,
                    action=policy_action,
                    group=self._special_security_policy_parameters
                )
                rulebase.add(policy_object)

            # Create a separate ping policy
            policy.name = policy.name[:58] + '_PING'
            policy.policy_apps = ['ping']
            destination_ports = ['any']
            policy_object = SecurityRule(
                name=policy.name,
                tag=[policy.category],
                group_tag=policy.category,
                disabled=False,
                fromzone=from_zones,
                tozone=to_zones,
                source=source_networks,
                destination=destination_networks,
                service=destination_ports,
                category={'any'},
                application=policy.policy_apps,
                description=policy.comments,
                log_setting=self._log_settings,
                log_end=log_end,
                action=policy_action,
                group=self._special_security_policy_parameters
            )
            rulebase.add(policy_object)

    def migrate_nat_policies(self, policies):
        """
        Migrate NAT policies from the source to the target system.

        :param policies: List of NAT policy objects to be migrated.
        """
        for policy in policies:
            print(f"Migrating policy: {policy.name}")
            if policy.status != True:
                continue

            unresolved_dependency = False

            # Get source NAT zones and handle unresolved dependencies
            source_zone_names = self.resolve_zone_names(policy.source_zones, 'source', policy.name)
            if source_zone_names is None:
                unresolved_dependency = True

            # Get destination NAT zones and handle unresolved dependencies
            destination_zone_names = self.resolve_zone_names(policy.destination_zones, 'destination', policy.name)
            if destination_zone_names is None:
                unresolved_dependency = True

            if unresolved_dependency:
                continue  # Skip to the next policy

            # Get source and destination network names
            original_source_network_names = self.reslove_network_object_names(policy.original_source)
            original_source_port_names = self.resolve_port_object_names(policy.original_source_port)
            original_destination_network_names = self.reslove_network_object_names(policy.original_destination)
            original_destination_port_names = self.resolve_port_object_names(policy.original_destination_port)

            translated_source_network_names = self.reslove_network_object_names(policy.translated_source)
            translated_source_port_names = self.resolve_port_object_names(policy.translated_source_port)
            translated_destination_network_names = self.reslove_network_object_names(policy.translated_destination)
            translated_destination_port_names = self.resolve_port_object_names(policy.translated_destination_port)

            # create all policies in the PRE rulebase for now
            device_group = DeviceGroup(self._security_policy_containers_map[policy.policy_container.uid])
            self._target_security_device.device_connection.add(device_group)
            rulebase = device_group.add(PreRulebase())

            # now build the NAT policy. All migrated NAT policies will be: static/dynamic policies.
            # dynamic policies will have the following parameters: dynamic-ip-and-port SNAT, dynamic ip with session distribution and ip hash as distribution method for DNAT
            # Apply name constraints
            policy.name = PANMCMigrationProject.apply_name_constraints(policy.name)

            # Create and add policy object to the rulebase
            self._add_nat_policy_to_rulebase(rulebase, policy, source_zone_names, destination_zone_names,
                                        original_source_network_names, original_source_port_names, original_destination_network_names, original_destination_port_names,
                                        translated_source_network_names, translated_source_port_names, translated_destination_network_names, translated_destination_port_names)
            try:
                rulebase.find(policy.name).create_similar()
            except Exception as e:
                print("Error occurred when creating policy object. More details: ", e)
                special_policies_log.warn(f"Failed to create policy {policy.name}. Reason: {e}.\n")

    def _add_nat_policy_to_rulebase(self, rulebase, policy, source_zone_names, destination_zone_names,
                                        original_source_network_names, original_source_port_names, original_destination_network_names, original_destination_port_names,
                                        translated_source_network_names, translated_source_port_names, translated_destination_network_names, translated_destination_port_names):
        
        # there are multiple cases here:
        #   NAT policy is:
            # a static policy
                # using interface for SNAT (if interface_in_translated_source)
                # using interface for DNAT (if interface_in_original_destination)
            # a dynamic policy
                # using interface for SNAT (if interface_in_translated_source)
                # using interface for DNAT (if interface_in_original_destination)
            if(policy.interface_in_translated_source):
                source_translation_address_type = 'interface-address'
            else:
                source_translation_address_type = 'translated-address'

            policy_object = NatRule(name=policy.name,
                                    description=policy.description,
                                    fromzone=source_zone_names,
                                    tozone=destination_zone_names,
                                    service=original_source_port_names,
                                    source=original_source_network_names,
                                    destination=original_destination_network_names,
                                    source_translation_type=source_translation_address_type,
                                    )

    @staticmethod
    def apply_name_constraints(name):
        """
        Applies constraints to a given name by replacing invalid characters,
        removing trailing spaces, and truncating the name if necessary.

        Args:
            name (str): The original name to be constrained.

        Returns:
            str: The constrained name.
        """
        # Check if the first character is non-alphanumeric and replace it with 'a'
        # if name and not name[0].isalnum():
        #     name = 'a' + name[1:]

        # Replace all characters that are not space, '-', or '.' with '_'
        constrained_name = re.sub(r'[^a-zA-Z0-9\s_.-]', '_', name)
        
        # Remove the last character if it is a whitespace
        if constrained_name and constrained_name[-1].isspace():
            constrained_name = constrained_name[:-1]
        
        # Truncate the name if it exceeds 63 characters
        if len(constrained_name) > 63:
            truncated_name = constrained_name[:58]
            suffix = f"_{random.randint(100, 999)}"
            constrained_name = truncated_name + suffix
        
        return constrained_name
    
    @staticmethod
    def apply_url_name_constraints(name):
        """
        Applies constraints to a given URL name by replacing invalid characters,
        ensuring the name starts with an alphabet, and truncating the name if necessary.

        Args:
            name (str): The original URL name to be constrained.

        Returns:
            str: The constrained URL name.
        """
        # Replace all occurrences of '-' with '_'
        constrained_name = name.replace('-', '_')

        # Replace all characters that are not space, '_', '.', or '-' with '_'
        constrained_name = re.sub(r'[^a-zA-Z0-9\s_.-]', '_', constrained_name)

        # Ensure the name starts with an alphabet
        if not constrained_name[0].isalpha():
            constrained_name = 'a' + constrained_name
            
        # Truncate the name if it exceeds 31 characters
        if len(constrained_name) > 31:
            truncated_name = constrained_name[:27]
            suffix = f"_{random.randint(100, 999)}"
            constrained_name = truncated_name + suffix
        
        return constrained_name

    @staticmethod
    def apply_url_value_constraints(url_value):
        """
        Applies constraints to a given URL value by replacing certain patterns
        with their constrained equivalents. Specifically, it removes any '*' that 
        is not preceded or succeeded by a '.' and adjusts patterns like '.*' to '.'.

        Args:
            url_value (str): The original URL value to be constrained.

        Returns:
            str: The constrained URL value.
        """
        # If ".*" is found, change it to "."
        url_value = re.sub(r'\.\*', '.', url_value)

        # Remove any "*" that is not preceded or succeeded by "."
        url_value = re.sub(r'(?<!\.)\*(?!\.)', '', url_value)

        return url_value
