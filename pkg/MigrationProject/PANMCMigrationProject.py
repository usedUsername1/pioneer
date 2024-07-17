from pkg.MigrationProject import MigrationProject
from pkg.Container.PANMCContainer import PANMCSecurityPolicyContainer
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


    #TODO: don't forget that the URL groups can't be migrated, as Palo Alto does not have URL groups
    # instead, everything URL of a group must be placed in the PA URL category
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