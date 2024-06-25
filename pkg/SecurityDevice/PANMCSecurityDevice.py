from pkg.SecurityDevice import SecurityDevice
from pkg.Container.PANMCContainer import PANMCSecurityPolicyContainer, PANMCObjectContainer
from panos.panorama import Panorama, DeviceGroup
from panos.objects import AddressObject, AddressGroup, ServiceObject, ServiceGroup, CustomUrlCategory, Tag
from panos.policies import PreRulebase, PostRulebase, SecurityRule
import utils.helper as helper
import utils.gvars as gvars
from utils.exceptions import InexistentContainer
from pkg.Container import SecurityPolicyContainer, ObjectContainer
import random
import re

#TODO: failed objects creation file text
#TODO: failed created policies file text

general_logger = helper.logging.getLogger('general')
    
# for the temp migration, only the policy containers and the object containers are needed
class PANMCSecurityDevice(SecurityDevice):
    def __init__(self, uid, name, SecurityDeviceDatabase, SecurityDeviceConnection):
        super().__init__(uid, name, SecurityDeviceDatabase, SecurityDeviceConnection)
        self._SecurityDeviceConnection = SecurityDeviceConnection

    def get_device_version(self):
        return self._SecurityDeviceConnection.refresh_system_info().version

    def return_container_object(self, container_name, container_type):
        # Refresh devices
        device_groups = self._SecurityDeviceConnection.refresh_devices()
        # Find the device group with the desired name
        desired_device_group = None
        for device_group in device_groups:
            if device_group.name == container_name:
                desired_device_group = device_group
                break
            
        if desired_device_group is not None:
            hierarchy_state = desired_device_group.OPSTATES['dg_hierarchy'](desired_device_group)
            hierarchy_state.refresh()  # Call refresh on an instance
            parent_device_group = hierarchy_state.parent
            if parent_device_group is None:
                parent_device_group = 'Shared'
            dg_info = {"parent_device_group":parent_device_group, "device_group_name":desired_device_group.name}
        else:
            raise InexistentContainer
        
        match container_type:
            # case 'security_policies_container':
            #     return PANMCPolicyContainer(dg_info)
            case 'object_container':
                return PANMCObjectContainer(dg_info)

    def return_device_group_info(self):
        device_group_info = []
        # Access the OPSTATES attribute to get the hierarchy class
        HierarchyObject = self._DeviceConnection.OPSTATES['dg_hierarchy']

        # Create an instance of PanoramaDeviceGroupHierarchy
        HierarchyInstance = HierarchyObject(self._DeviceConnection)

        # Call the fetch method on the instance
        hierarchy_data = HierarchyInstance.fetch()

        for key, value in hierarchy_data.items():
            device_group_info.append({"name": key, "parent": value})

        return device_group_info
    
    def return_object_container(self, container_entry):
        return PANMCObjectContainer(self, container_entry)

    def return_object_container_info(self):
        return self.return_device_group_info()

    def return_security_policy_container(self, container_entry):
        return PANMCSecurityPolicyContainer(self, container_entry)

    def return_security_policy_container_info(self):
        return self.return_device_group_info()

    def return_zone_container_info(self):
        pass

    def return_managed_device_container_info(self):
        pass
    
    def return_security_zone_info(self):
        pass
        
    def return_managed_device_info(self):
        pass

    def return_network_object_info(self):
        pass

    def return_network_group_object_info(self):
        pass

    def return_geolocation_object_info(self):
        pass

    def return_port_object_info(self):
        pass

    def return_port_group_object_info(self):
        pass

    def return_url_object_info(self):
        pass

    def return_url_group_object_info(self):
        pass

    def return_schedule_object_info(self):
        pass
    
    def print_compatibility_issues(self):
        print("""You are migrating to a Panorama Management Center device. The following is a list with compatibility issues and how they will be fixed:
Object/Policy/Port/URL object names: All names will be cut to have less than 63 characters. In case a name is longer than 63 characters, only the first 60 characters will be kept and
a random suffix will be generated in order to avoid duplicates. All special characters will be removed and replaced with "_".
Security Policies restricting ping access: All policies that control ping access will be split in two. The original policy and the ping policy. This is needed because 
PA treats ping as an application. The second rule will keep the exact same source and destinations, but will have all port objects removed and application set to ping.""" + '\n')
    
    def migrate_network_objects(self, network_object_names, SourceDevice):
        print("migrating network objects")
        for network_object_name in network_object_names:
            network_object_container = 'Global Internet'
            network_address_value = SourceDevice.get_db_col_by_val('network_address_value', 'network_address_objects_table', 'network_address_name', network_object_name)
            network_address_type = SourceDevice.get_db_col_by_val('network_address_type', 'network_address_objects_table', 'network_address_name', network_object_name)
            network_address_description = SourceDevice.get_db_col_by_val('network_address_description', 'network_address_objects_table', 'network_address_name', network_object_name)

            if network_address_type == 'Host' or network_address_type == 'Network':
                network_address_type = 'ip-netmask'
            
            if network_address_type == 'Range':
                network_address_type = 'ip-range'
        
            network_object = AddressObject(network_object_name, network_address_value, network_address_type.lower() , network_address_description)
            dg_object = DeviceGroup(network_object_container)

            self._SecurityDeviceConnection.add(dg_object)

            dg_object.add(network_object)

        # create the object
        try:
            dg_object.find(network_object_name).create_similar()
        except Exception as e:
            print("error occured when creating network address. More details: ", e)

    def migrate_network_group_objects(self, network_group_object_names, SourceDevice):
        print("migrating network group objects")
        for network_group_object_name in network_group_object_names:
            network_object_container = 'Global Internet'
            network_group_members = SourceDevice.get_db_col_by_val('network_address_group_members', 'network_address_object_groups_table', 'network_address_group_name', network_group_object_name)
            network_group_description = SourceDevice.get_db_col_by_val('network_address_group_description', 'network_address_object_groups_table', 'network_address_group_name', network_group_object_name)

            network_group_object = AddressGroup(name=network_group_object_name, static_value=network_group_members,description=network_group_description)
            dg_object = DeviceGroup(network_object_container)

            # set the device group for the panorama instance
            self._SecurityDeviceConnection.add(dg_object)

            # add the network object to the device group
            dg_object.add(network_group_object)

        try:
            dg_object.find(network_group_object_name).create_similar()
        except Exception as e:
            print("error occured when creating network group. More details: ", e)

    def migrate_port_objects(self, port_object_names, SourceDevice):
        print("migrating port objects")
        for port_object_name in port_object_names:
            port_object_container = 'Global Internet'

            port_protocol = SourceDevice.get_db_col_by_val('port_protocol', 'port_objects_table', 'port_name', port_object_name)
            port_number = SourceDevice.get_db_col_by_val('port_number', 'port_objects_table', 'port_name', port_object_name)
            port_description = SourceDevice.get_db_col_by_val('port_description', 'port_objects_table', 'port_name', port_object_name)

            port_object = ServiceObject(name=port_object_name, protocol=port_protocol.lower(), destination_port=port_number, description=port_description, tag=None)
            dg_object = DeviceGroup(port_object_container)

            # set the device group for the panorama instance
            if 'None' in port_object_name:
                continue
            self._SecurityDeviceConnection.add(dg_object)
            
            # add the network object to the device group
            dg_object.add(port_object)

        try:
            dg_object.find(port_object_name).create_similar()
        except Exception as e:
            print("error occured when creating port object. More details: ", e)

    def migrate_port_group_objects(self, port_group_object_names, SourceDevice):
        print("migrating port group objects")
        for port_group_name in port_group_object_names:
            port_object_container = 'Global Internet'
            port_group_members = SourceDevice.get_db_col_by_val('port_group_members', 'port_object_groups_table', 'port_group_name', port_group_name)
            port_group_description = SourceDevice.get_db_col_by_val('port_group_description', 'port_object_groups_table', 'port_group_name', port_group_name)

            network_group_object = ServiceGroup(port_group_name, port_group_members)
            dg_object = DeviceGroup(port_object_container)

            # set the device group for the panorama instance
            self._SecurityDeviceConnection.add(dg_object)

            # add the network object to the device group
            dg_object.add(network_group_object)

        try:
            dg_object.find(port_group_name).create_similar()
        except Exception as e:
            print("error occured when creating port group object. More details: ", e)

    def migrate_url_objects(self, url_object_names, SourceDevice, type):
        if type == 'url_object':
            print("migrating url objects")
            for url_object_name in url_object_names:
                url_object_container = 'Global Internet'
                url_object_value = SourceDevice.get_db_col_by_val('url_value', 'url_objects_table', 'url_object_name', url_object_name)
                url_object_description = SourceDevice.get_db_col_by_val('url_object_description', 'url_objects_table', 'url_object_name', url_object_name)
                url_object = CustomUrlCategory(name=url_object_name, url_value=url_object_value, description=url_object_description, type='URL List')
                dg_object = DeviceGroup(url_object_container)
            
                # set the device group for the panorama instance
                self._SecurityDeviceConnection.add(dg_object)
                
                # add the network object to the device group
                dg_object.add(url_object)
        
        elif type == 'url_group':
            print("migrating url group objects")
            for url_object_name in url_object_names:
                url_object_container = 'Global Internet'
                url_members = SourceDevice.get_db_col_by_val('url_object_members', 'url_object_groups_table', 'url_object_group_name', url_object_name)
                url_object_description = SourceDevice.get_db_col_by_val('url_group_object_description', 'url_object_groups_table', 'url_object_group_name', url_object_name)

                url_object = CustomUrlCategory(name=url_object_name, url_value=url_members, description=url_object_description, type='URL List')
                dg_object = DeviceGroup(url_object_container)
            
                # set the device group for the panorama instance
                self._SecurityDeviceConnection.add(dg_object)
                
                # add the network object to the device group
                dg_object.add(url_object)

        # create the object
        try:
            dg_object.find(url_object_name).create_similar()
        except Exception as e:
            print("error occured when creating url object. More details: ", e)
    
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

    # create the files that will keep track of all the failed objects/policies
    # keep a count of: all objects of all types that will be created, all theo bjects created. do the same with the policies
    
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
    def apply_url_constraints(url_value):
        # If ".*" is found, change it to "*."
        url_value = re.sub(r'\.\*', '*.', url_value)

        # If a single wildcard character is found and not followed by a dot, add a dot after it
        url_value = re.sub(r'(?<!\*)\*(?!\.)', '*.', url_value)

        return url_value
    
    @staticmethod
    def is_icmp_object(port_object, icmp_objects):
        if port_object in icmp_objects:
            return True
        else:
            return False
    
    @staticmethod
    def is_port_group(port_object, port_group_objects):
        if port_object in port_group_objects:
            return True
        else:
            return False
        