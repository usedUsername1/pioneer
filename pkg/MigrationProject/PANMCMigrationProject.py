from pkg.MigrationProject import MigrationProject
from pkg.Container.PANMCContainer import PANMCSecurityPolicyContainer
from pkg.DeviceObject.PioneerDeviceObject import PioneerICMPObject
import random
import re
from panos.panorama import DeviceGroup, Template
from panos.network import Zone
from panos.objects import AddressObject, AddressGroup, ServiceObject, ServiceGroup, CustomUrlCategory, Tag
from panos.policies import PreRulebase, PostRulebase, SecurityRule

#TODO: defining objects for source and target device might be needed here
#TODO: create everything in shared for the time being
class PANMCMigrationProject(MigrationProject):
    def __init__(self, name, Database, SourceSecurityDevice, TargetSecurityDevice):
        self._SourceSecurityDevice = SourceSecurityDevice
        self._TargetSecurityDevice = TargetSecurityDevice
        super().__init__(name, Database)

    # save it to the file file, don't print it
    def print_compatibility_issues(self):
        print("""You are migrating to a Panorama Management Center device. The following is a list with compatibility issues and how they will be fixed:
Object/Policy/Port/URL object names: All names will be cut to have less than 63 characters. In case a name is longer than 63 characters, only the first 60 characters will be kept and
a random suffix will be generated in order to avoid duplicates. All special characters will be removed and replaced with "_".
Security Policies restricting ping access: All policies that control ping access will be split in two. The original policy and the ping policy. This is needed because 
PA treats ping as an application. The second rule will keep the exact same source and destinations, but will have all port objects removed and application set to ping.""" + '\n')

    #TODO: mapping tables for actions, network types and so on
    def migrate_network_objects(self, network_objects):
        for network_object in network_objects:
            # adapt the name of the object
            network_object.set_name(PANMCMigrationProject.apply_name_constraints(network_object.get_name()))
            
            #TODO: these must be retrieved dynamically, based on the type of source security device
            if network_object.get_network_address_type() == 'Host' or network_object.get_network_address_type() == 'Network':
                network_object.set_network_address_type('ip-netmask')
            
            if network_object.get_network_address_type() == 'Range':
                network_object.set_network_address_type('ip-range')
        
            network_object = AddressObject(network_object.get_name(), network_object.get_network_address_value(), network_object.get_network_address_type().lower(), network_object.get_description())

            self._TargetSecurityDevice.get_device_connection().add(network_object)
        # bulk create the objects
        try:
            self._TargetSecurityDevice.get_device_connection().find(network_object.name).create_similar()
        except Exception as e:
            print("error occured when bulk creating network address. More details: ", e)

    def migrate_network_group_objects(self, network_group_objects):
        for network_group_object in network_group_objects:
            network_group_object.set_name(PANMCMigrationProject.apply_name_constraints(network_group_object.get_name()))
            network_group_members = []
            # find the group object member banes
            for network_group_object_member in network_group_object.get_group_object_members():
                network_group_members.append(network_group_object_member.get_name())
            # find the object member names
            for network_object_member in network_group_object.get_object_members():
                network_group_members.append(network_object_member.get_name())
            
            network_group_object = AddressGroup(name=network_group_object.get_name(), static_value=network_group_members,description=network_group_object.get_description())

            # set the device group for the panorama instance
            self._TargetSecurityDevice.get_device_connection().add(network_group_object)

        try:
            self._TargetSecurityDevice.get_device_connection().find(network_group_object.name).create_similar()
        except Exception as e:
            print("error occured when creating network group. More details: ", e)

    def migrate_port_objects(self, port_objects):
        # Get the device connection once
        device_connection = self._TargetSecurityDevice.get_device_connection()

        for port_object in port_objects:
            if isinstance(port_object, PioneerICMPObject):
                continue

            # Apply name constraints and create a new ServiceObject
            port_object.set_name(PANMCMigrationProject.apply_name_constraints(port_object.get_name()))
            new_port_object = ServiceObject(
                name=port_object.get_name(),
                protocol=port_object.get_port_protocol().lower(),
                destination_port=port_object.get_destination_port(),
                description=port_object.get_description(),
                tag=None
            )

            # Add the service object individually
            try:
                device_connection.add(new_port_object)
            except Exception as e:
                print(f"Error occurred when adding port object {new_port_object.name}. More details:", e)
                continue

            # Attempt to create similar objects
            try:
                found_object = device_connection.find(new_port_object.name)
                if found_object:
                    found_object.create_similar()
            except Exception as e:
                print(f"Error occurred when creating similar for port object {new_port_object.name}. More details:", e)

    def migrate_port_group_objects(self, port_group_objects):
        for port_group_object in port_group_objects:
            # print(port_group_object._name)
            port_group_object.set_name(PANMCMigrationProject.apply_name_constraints(port_group_object.get_name()))
            port_group_members = []
            # find the group object member banes
            for port_group_object_member in port_group_object.get_group_object_members():
                # make sure you remove any ICMP members from the groups, as they cannot be migrated in PA
                if isinstance(port_group_object_member, PioneerICMPObject):
                    continue
                else:
                    port_group_members.append(port_group_object_member.get_name())
            
            # find the object member names
            for port_object_member in port_group_object.get_object_members():
                # if object is ICMP, don't add the name here
                port_group_members.append(port_object_member.get_name())
            
            # make sure you don't migrate empty groups! there might be empty groups if all the members of the group are ICMP objects
            if len(port_group_members) == 0:
                continue

            else:
                port_group_object = ServiceGroup(name=port_group_object.get_name(), value=port_group_members)

                # set the device group for the panorama instance
                self._TargetSecurityDevice.get_device_connection().add(port_group_object)

            try:
                self._TargetSecurityDevice.get_device_connection().find(port_group_object.name).create_similar()
            except Exception as e:
                print("error occured when creating port group. More details: ", e)

    def migrate_url_objects(self, url_objects):
        for url_object in url_objects:
            # adapt the name of the object
            url_object.set_name(PANMCMigrationProject.apply_url_name_constraints(url_object.get_name()))
        
            url_object = CustomUrlCategory(name=url_object.get_name(), url_value=PANMCMigrationProject.apply_url_value_constraints(url_object.get_url_value()), description=url_object.get_description(), type='URL List')   

            self._TargetSecurityDevice.get_device_connection().add(url_object)
        # bulk create the objects
        try:
            self._TargetSecurityDevice.get_device_connection().find(url_object.name).create_similar()
        except Exception as e:
            print("error occured when bulk creating url address. More details: ", e)

    #TODO: don't forget that the URL groups can't be migrated, as Palo Alto does not have URL groups
    # instead, everything URL of a group must be placed in the PA URL category
    def migrate_url_group_objects(self, url_group_objects):
        for url_group_object in url_group_objects:
            url_group_object.set_name(PANMCMigrationProject.apply_url_name_constraints(url_group_object.get_name()))
            url_member_values = set()
            # get the members of the url group
            #TODO: don't know yet, but we might need yet another recursve processing here
            for url_group_member in url_group_object.get_object_members():
                url_member_values.add(PANMCMigrationProject.apply_url_value_constraints(url_group_member.get_url_value()))

            url_group_object = CustomUrlCategory(name=url_group_object.get_name(), url_value=url_member_values, description=url_group_object.get_description(), type='URL List')   

            self._TargetSecurityDevice.get_device_connection().add(url_group_object)
        # bulk create the objects
        try:
            self._TargetSecurityDevice.get_device_connection().find(url_group_object.name).create_similar()
        except Exception as e:
            print("error occured when bulk creating url address. More details: ", e)

            

    
    @staticmethod
    def apply_name_constraints(name):
        # Replace all characters that are not space, '-', or '.' with '_'
        name = re.sub(r'[^a-zA-Z0-9\s_.-]', '_', name)

        if len(name) > 63:
            truncated_name = name[:58]
            suffix = f"_{random.randint(100, 999)}"
            truncated_name += suffix
            return truncated_name
        else:
            return name

    @staticmethod
    # make sure it does not start with digit
    def apply_url_name_constraints(name):
        # Replace all occurrences of '-' with '_'
        name = name.replace('-', '_')
        # Replace all characters that are not space, '_', '.', or '-' with '_'
        name = re.sub(r'[^a-zA-Z0-9\s_.-]', '_', name)

        if not name[0].isalpha():
            name = 'a' + name
            
        if len(name) > 31:
            truncated_name = name[:27]
            suffix = f"_{random.randint(100, 999)}"
            truncated_name += suffix
            return truncated_name
        else:
            return name

    @staticmethod
    def apply_url_value_constraints(url_value):
        # If ".*" is found, change it to "*."
        url_value = re.sub(r'\.\*', '*.', url_value)

        # If a single wildcard character is found and not followed by a dot, add a dot after it
        url_value = re.sub(r'(?<!\*)\*(?!\.)', '*.', url_value)

        return url_value

#TODO: refactor below
    def migrate_tags(self, categories):
        print("migrating tag objects")
        for cat_name in categories:
            tag_object = Tag(cat_name)
            self._SecurityDeviceConnection.add(tag_object)
        # create the object
        try:
            self._SecurityDeviceConnection.find(cat_name).create_similar()
        except Exception as e:
            print("error occured when creating tag object. More details: ", e)
    
    # TODO: ensure that if you have policies with regions, they do not get migrated yet!
            # ensure that you combine the description and the comments into a single string, which will be the description of the palo alto policy
    def migrate_security_policies(self, security_policy_names, SourceDevice):
        print("migrating security policies")
        error_file = open("failed_policies.log", "w")

        for security_policy_name in security_policy_names:
            if 'Embargoed' in security_policy_name:
                continue

            # for each of the names, get all the details needed in order to create the policy
            
            # get the container name
            security_policy_container = SourceDevice.get_db_col_by_val('security_policy_container_name', 'security_policies_table', 'security_policy_name', security_policy_name)

            # get the security category
            security_policy_category = SourceDevice.get_db_col_by_val('security_policy_category', 'security_policies_table', 'security_policy_name', security_policy_name)

            # get the policy status
            security_policy_status = SourceDevice.get_db_col_by_val('security_policy_status', 'security_policies_table', 'security_policy_name', security_policy_name)
            
            is_disabled = False
            if security_policy_status != 'enabled':
                is_disabled = True

            # get the security zones
            security_policy_source_zones = SourceDevice.get_db_col_by_val('security_policy_source_zones', 'security_policies_table', 'security_policy_name', security_policy_name)
            security_policy_destination_zones = SourceDevice.get_db_col_by_val('security_policy_destination_zones', 'security_policies_table', 'security_policy_name', security_policy_name)

            # get the networks
            security_policy_source_networks = SourceDevice.get_db_col_by_val('security_policy_source_networks', 'security_policies_table', 'security_policy_name', security_policy_name)
            security_policy_destination_networks = SourceDevice.get_db_col_by_val('security_policy_destination_networks', 'security_policies_table', 'security_policy_name', security_policy_name)

            # get the destination ports
            security_policy_destination_ports = SourceDevice.get_db_col_by_val('security_policy_destination_ports', 'security_policies_table', 'security_policy_name', security_policy_name)
            
            # get the urls
            security_policy_urls = SourceDevice.get_db_col_by_val('security_policy_urls', 'security_policies_table', 'security_policy_name', security_policy_name)
            
            # get the apps
            security_policy_apps = SourceDevice.get_db_col_by_val('security_policy_l7_apps', 'security_policies_table', 'security_policy_name', security_policy_name)

            # get the description
            #### make a single string with whateever is here
            security_policy_description = SourceDevice.get_db_col_by_val('security_policy_description', 'security_policies_table', 'security_policy_name', security_policy_name)
            
            # get the comments
            security_policy_comments = SourceDevice.get_db_col_by_val('security_policy_comments', 'security_policies_table', 'security_policy_name', security_policy_name) 
            ######

            # set log forwarding to panorama
            log_forwarding = 'Panorama'

            # set to log at the end
            log_end = True
            
            # get the section of the polcy
            policy_section = SourceDevice.get_db_col_by_val('security_policy_section', 'security_policies_table', 'security_policy_name', security_policy_name)
            
            # get the action and make sure it maps to the proper PA action
            policy_action = SourceDevice.get_db_col_by_val('security_policy_action', 'security_policies_table', 'security_policy_name', security_policy_name)

            match policy_action:
                case 'ALLOW':
                    policy_action = 'allow'
                case 'TRUST':
                    policy_action = 'allow'
                case 'BLOCK':
                    policy_action = 'deny'
                case 'BLOCK_RESET':
                    policy_action = 'reset-client'

            dg_object = DeviceGroup(security_policy_container)
            # set the device group for the panorama instance
            self._SecurityDeviceConnection.add(dg_object)
            print("using device group: ", dg_object)

            print("creating policy: ", security_policy_name)

            if policy_section == 'Mandatory':
                rulebase = 'pre'
                rulebase_with_dg = dg_object.add(PreRulebase())
            elif policy_section == 'Default':
                rulebase = 'post'
                rulebase_with_dg = dg_object.add(PostRulebase())


            # the security_policy_apps must be any all the time, if they are not ping
            if security_policy_apps != ['ping']:
                security_policy_apps = ['any']

                # TODO: set the security group
                policy_object = SecurityRule(name=security_policy_name, tag=[security_policy_category], group_tag=security_policy_category, disabled=is_disabled, \
                                            fromzone = security_policy_source_zones, tozone=security_policy_destination_zones, source=security_policy_source_networks, \
                                            destination=security_policy_destination_networks, service=security_policy_destination_ports, category=security_policy_urls, application=security_policy_apps, \
                                            description=security_policy_comments, log_setting=log_forwarding, log_end=log_end, action=policy_action, group="DUMMY_SPG")
                
                # add the policy object to the device group
                
                rulebase_with_dg.add(policy_object)
                print(f"adding policy {security_policy_name}, container {security_policy_container} to rulebase {rulebase}")

            # TWO CASES HERE FFS, one in which there is ping and destination ports and one in which there is only ping
            elif security_policy_apps == ['ping']:
                # if there are destination ports and ping objects, create two policies
                # else create only the ping policy
                if security_policy_destination_ports != ['any']:
                    security_policy_apps = ['any']
                    policy_object = SecurityRule(name=security_policy_name, tag=[security_policy_category], group_tag=security_policy_category, disabled=is_disabled, \
                                                fromzone = security_policy_source_zones, tozone=security_policy_destination_zones, source=security_policy_source_networks, \
                                                destination=security_policy_destination_networks, service=security_policy_destination_ports, category=security_policy_urls, application=security_policy_apps, \
                                                description=security_policy_comments, log_setting=log_forwarding, log_end=log_end, action=policy_action, group="DUMMY_SPG")
                    
                    rulebase_with_dg.add(policy_object)
                    print(f"adding policy {security_policy_name}, container {security_policy_container} to rulebase {rulebase}")

                security_policy_name = security_policy_name[:58] + '_PING'
                security_policy_apps = ['ping']
                security_policy_destination_ports = ['any']
                policy_object = SecurityRule(name=security_policy_name, tag=[security_policy_category], group_tag=security_policy_category, disabled=is_disabled, \
                                            fromzone = security_policy_source_zones, tozone=security_policy_destination_zones, source=security_policy_source_networks, \
                                            destination=security_policy_destination_networks, service=security_policy_destination_ports, category=security_policy_urls, application=security_policy_apps, \
                                            description=security_policy_description, log_setting=log_forwarding, log_end=log_end, action=policy_action, group="DUMMY_SPG")

                rulebase_with_dg.add(policy_object)
                print(f"adding policy {security_policy_name}, container {security_policy_container} to rulebase {rulebase}")

            # create the object
            try:
                rulebase_with_dg.find(security_policy_name).create_similar()
            except Exception as e:
                print("error occured when creating policy object. More details: ", e)
                error_file.write(f"Failed to create policy {security_policy_name}. Reason: {e}.\n")