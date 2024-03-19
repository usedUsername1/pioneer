from pkg.SecurityDevice.APISecurityDevice.APISecurityDeviceConnection import APISecurityDeviceConnection
from pkg.SecurityDevice import SecurityDevice
from panos.panorama import Panorama
import utils.helper as helper
import utils.gvars as gvars
from utils.exceptions import InexistentContainer
from pkg.Container import SecurityPolicyContainer, ObjectContainer
import random
import re

general_logger = helper.logging.getLogger('general')

class PANMCDeviceConnection(APISecurityDeviceConnection):
    def __init__(self, api_username, api_secret, api_hostname, api_port):
        super().__init__(api_username, api_secret, api_hostname, api_port)
        self._device_connection = self.return_security_device_conn_object()
        self._domain = None
    
    def connect_to_security_device(self):
        panmc_conn = Panorama(self._api_hostname, self._api_username, self._api_secret, None, self._api_port)
        return panmc_conn
    
# for the temp migration, only the policy containers and the object containers are needed
class PANMCSecurityDevice(SecurityDevice):
    def __init__(self, name, sec_device_database, security_device_username, security_device_secret, security_device_hostname, security_device_port):
        super().__init__(name, sec_device_database)
        self._sec_device_connection = PANMCDeviceConnection(security_device_username, security_device_secret, security_device_hostname, security_device_port).connect_to_security_device()

    def get_device_version(self):
        general_logger.debug("Called PANMCSecurityDevice::get_device_version()")
        return self._sec_device_connection.refresh_system_info().version

    def return_container_object(self, container_name, container_type):
        # Refresh devices
        device_groups = self._sec_device_connection.refresh_devices()
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
            case 'security_policies_container':
                return PANMCPolicyContainer(dg_info)
            case 'object_container':
                return PANMCObjectContainer(dg_info)

    def return_security_policy_object(self, container_name):
       print("Processing and importing of security policies is not yet supported for Panorama! Skipping this...")
       return []

    def return_network_objects(self, dummy):
       print("Processing and importing of network objects is not yet supported for Panorama! Skipping this...")
       return []

    def return_port_objects(self, dummy):
       print("Processing and importing of port objects is not yet supported for Panorama! Skipping this...")
       return []
    
    def return_url_objects(self, dummy):
       print("Processing and importing of URL objects is not yet supported for Panorama! Skipping this...")
       return []

    def print_compatibility_issues(self):
        print("""You are migrating to a Panorama Management Center device. The following is a list with compatibility issues and how they will be fixed:
Object/Policy/Port/URL object names: All names will be cut to have less than 63 characters. In case a name is longer than 63 characters, only the first 60 characters will be kept and
a random suffix will be generated in order to avoid duplicates. All special characters will be removed and replaced with "_".
Security Policies restricting ping access: All policies that control ping access will be split in two. The original policy and the ping policy. This is needed because 
PA treats ping as an application. The second rule will keep the exact same source and destinations, but will have all port objects removed and application set to ping.""" + '\n')
    
    #TODO: only for temp migration, modify later
    # def map_containers_todo(self, SourceSecurityDevice):
        # print("In order to continue, you are required to map the device groups you want to migrate to the ACP from the source device. All its parents will be automatically mapped.")
        # source_container = input("Please specify the name of the ACP you imported from FMC: ")
        # target_container = input("Please specify the target device group on PANMC: ")
        
        # # retrieve the containers info from the db for the source device
        # source_device_container_hierarchy = SourceSecurityDevice.get_security_policies_container_info_from_db()

        # # retrieve the containers info form the db of the target device
        # destination_device_container_hierarhcy = self.get_security_policies_container_info_from_db()

        # # loop through the source_device_container_hierarchy and match every element with the current destination_device_container_hierarhcy
        # for i in len(source_device_container_hierarchy):
        #     container_mapping = {source_device_container_hierarchy[i]:destination_device_container_hierarhcy[i]}
        
        # container_mapping = ''
        # highest_target_container = ''

        # print("All the objects will be imported into the highest device group parent in the hierarchy.")
        

        # return highest_target_container, container_mapping
    #TODO: only for temp migration, modify later
    def map_containers(self):
        #TODO: uncomment in prod
        # dg_mapping = {'Azure: DEV EUN Internet Access Policy': 'Azure DEV - Internet',
        #                'Azure: DEV EUN VPN Access Policy': 'Azure DEV - VPN',
        #                'Azure: Global VPN Policy': 'Global VPN',
        #                'Global Internet Access Policy': 'Global Internet'}
                
        dg_mapping = {'debug3':'Debug'}

        object_container = 'Global Internet'

        return object_container, dg_mapping
    
    def map_zones(self):
        return {'FTD-INSIDE':'ZONE-LAN', 'FTD-OUTSIDE':'ZONE-WAN'}

    #TODO: throwaway code
    # modify the source database info

    # def update_db_value(self, table, column, old_value, new_value)

    def adapt_config(self, object_container, container_hierarchy_map, interface_map, SourceSecurityDeviceObject):
        # insert the target object containers inth the source device database
        object_container_data = [{'object_container_name':object_container,
                                  'object_container_parent':None}]
        
        SourceSecurityDeviceObject.insert_into_object_containers_table(object_container_data)

        # now loop through container_hierarchy_map, and, based on the key, insert the value
        #TODO: uncomment when in prod
        # sec_pol_container_data = [{'security_policy_container_name': 'Azure DEV - Internet',
        #                            'security_policy_parent':'Azure DEV - VPN'},
                                   
        #                            {'security_policy_container_name':'Azure DEV - VPN',
        #                             'security_policy_parent':'Global VPN'},

        #                             {'security_policy_container_name':'Global VPN',
        #                             'security_policy_parent':'Global Internet'},

        #                             {'security_policy_container_name':'Global Internet',
        #                             'security_policy_parent':'Shared'}
        #                             ]

        sec_pol_container_data = [{'security_policy_container_name': 'Debug',
                                   'security_policy_parent': None}]
        
        SourceSecurityDeviceObject.insert_into_security_policy_containers_table(sec_pol_container_data)

        # insert the target security policy containers into the source device database
        security_policy_container_data = []
        # modify the network/port group/objects table, change the original object container to object_container
        SourceSecurityDeviceObject.update_db_value('network_address_objects_table', 'object_container_name', 'virtual_object_container', object_container)
        SourceSecurityDeviceObject.update_db_value('network_address_object_groups_table', 'object_container_name', 'virtual_object_container', object_container)
        SourceSecurityDeviceObject.update_db_value('port_objects_table', 'object_container_name', 'virtual_object_container', object_container)
        SourceSecurityDeviceObject.update_db_value('port_object_groups_table', 'object_container_name', 'virtual_object_container', object_container)
        SourceSecurityDeviceObject.update_db_value('url_objects_table', 'object_container_name', 'virtual_object_container', object_container)
        SourceSecurityDeviceObject.update_db_value('url_object_groups_table', 'object_container_name', 'virtual_object_container', object_container)
        
        # change the security policies data, modify the containers and the names of the policies
        # loop through the container_hierarchy_map and replace old_Value (key) with new_value (value) for all security policies
        for key, value in container_hierarchy_map.items():
            SourceSecurityDeviceObject.update_db_value('security_policies_table', 'security_policy_container_name', key, value)

        #TODO: fix this as it doesnt work
        # change the interface map
        # for key, value in interface_map:
        #     SourceSecurityDeviceObject.update_db_value('security_policies_table', 'security_policy_source_zones', key, value)
        #     SourceSecurityDeviceObject.update_db_value('security_policies_table', 'security_policy_destination_zones', key, value)

        # finally, change the names of the objects both from the object tables and in the security policies table
            # retrieve all the object names. upon updating the name, make sure you update the name in the array of security_policies_table
        network_address_object_names = SourceSecurityDeviceObject.get_db_objects_from_table('network_address_name', 'network_address_objects_table')
        network_address_group_objects_names = SourceSecurityDeviceObject.get_db_objects_from_table('network_address_group_name', 'network_address_object_groups_table')
        port_object_names = SourceSecurityDeviceObject.get_db_objects_from_table('port_name', 'port_objects_table')
        port_object_group_names = SourceSecurityDeviceObject.get_db_objects_from_table('port_group_name', 'port_object_groups_table')
        
        # remove all url names containig interbangs
        url_object_names = SourceSecurityDeviceObject.get_db_objects_from_table('url_object_name', 'url_objects_table')

        url_object_groups_names = SourceSecurityDeviceObject.get_db_objects_from_table('url_object_group_name', 'url_object_groups_table')
        security_policy_names = SourceSecurityDeviceObject.get_db_objects_from_table('security_policy_name', 'security_policies_table')

        # loop through all the names and for each name, call the apply_name_constraints and after applying constraints, change the value of the name in the database
        for name in network_address_object_names:
            new_name = PANMCSecurityDevice.apply_name_constraints(name)
            # replace the name in the database
            #table, column_name, old_value, new_value
            SourceSecurityDeviceObject.update_db_value('network_address_objects_table', 'network_address_name', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_source_networks', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_destination_networks', name, new_name)
            # and update the array value in the security policies table

        for name in network_address_group_objects_names:
            new_name = PANMCSecurityDevice.apply_name_constraints(name)
            SourceSecurityDeviceObject.update_db_value('network_address_object_groups_table', 'network_address_group_name', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_source_networks', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_destination_networks', name, new_name)
            
        for name in port_object_names:
            new_name = PANMCSecurityDevice.apply_name_constraints(name)
            SourceSecurityDeviceObject.update_db_value('port_objects_table', 'network_address_name', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_source_ports', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_destination_ports', name, new_name)

        for name in port_object_group_names:
            new_name = PANMCSecurityDevice.apply_name_constraints(name)
            SourceSecurityDeviceObject.update_db_value('port_object_groups_table', 'network_address_name', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_source_ports', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_destination_ports', name, new_name)

        for name in url_object_names:
            # remove all the names containing special characters
            new_name = PANMCSecurityDevice.apply_name_constraints(name)
            SourceSecurityDeviceObject.update_db_value('url_objects_table', 'url_object_name', name, new_name)

        for name in url_object_groups_names:
            new_name = PANMCSecurityDevice.apply_name_constraints(name)
            SourceSecurityDeviceObject.update_db_value('url_object_groups_table', 'url_object_group_name', name, new_name)

        for name in security_policy_names:
            new_name = PANMCSecurityDevice.apply_name_constraints(name)
            SourceSecurityDeviceObject.update_db_value('security_policies_table', 'security_policy_name', name, new_name)

    @staticmethod
    def apply_name_constraints(name):
        # Replace all characters that are not alphanumeric, '-', or '_' with '_'
        name = re.sub(r'[^a-zA-Z0-9-_.]', '_', name)  # Include '.' in the character set

        if len(name) > 63:
            truncated_name = name[:60]
            suffix = f"_random_{random.randint(100, 999)}_id"
            truncated_name += suffix
            return truncated_name
        else:
            return name

    
    @staticmethod
    def apply_url_constraints(name):
        pass

    @staticmethod
    def remove_interbang_elements(list):
        pass


class PANMCPolicyContainer(SecurityPolicyContainer):
    def __init__(self, container_info) -> None:
        super().__init__(container_info)

    def get_parent_name(self):
        return self._container_info['parent_device_group']
    
    def is_child_container(self):
        is_child = True
        if self._container_info['parent_device_group'] == 'Shared':
            is_child = False
        
        return is_child

    def get_name(self):
        return self._container_info['device_group_name']

class PANMCObjectContainer(ObjectContainer, PANMCPolicyContainer):
    def __init__(self, container_info) -> None:
        super().__init__(container_info)