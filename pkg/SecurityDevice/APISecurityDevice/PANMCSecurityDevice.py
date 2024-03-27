from pkg.SecurityDevice.APISecurityDevice.APISecurityDeviceConnection import APISecurityDeviceConnection
from pkg.SecurityDevice import SecurityDevice
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
        print("adapting the config from the source device to the target device")
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

        # change the interface map
        for key, value in interface_map.items():
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_source_zones', key, value)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_destination_zones', key, value)

        # finally, change the names of the objects both from the object tables and in the security policies table
            # retrieve all the object names. upon updating the name, make sure you update the name in the array of security_policies_table
        network_address_object_names = SourceSecurityDeviceObject.get_db_objects_from_table('network_address_name', 'network_address_objects_table')
        network_address_group_objects_names = SourceSecurityDeviceObject.get_db_objects_from_table('network_address_group_name', 'network_address_object_groups_table')
        port_object_names = SourceSecurityDeviceObject.get_db_objects_from_table('port_name', 'port_objects_table')
        port_object_group_names = SourceSecurityDeviceObject.get_db_objects_from_table('port_group_name', 'port_object_groups_table')
        
        url_object_names = SourceSecurityDeviceObject.get_db_objects_from_table('url_object_name', 'url_objects_table')
        url_object_values = SourceSecurityDeviceObject.get_db_objects_from_table('url_value', 'url_objects_table')

        url_object_groups_names = SourceSecurityDeviceObject.get_db_objects_from_table('url_object_group_name', 'url_object_groups_table')
        security_policy_names = SourceSecurityDeviceObject.get_db_objects_from_table('security_policy_name', 'security_policies_table')
        icmp_objects = SourceSecurityDeviceObject.get_db_objects_from_table('icmp_name', 'icmp_objects_table')
        # loop through all the names and for each name, call the apply_name_constraints and after applying constraints, change the value of the name in the database
        # remove icmp objects from the policy (and from the port objects that contain ping objects)
        ping_policy_list = self.remove_ping_url_from_policy_and_return_ping_policies_list(security_policy_names, SourceSecurityDeviceObject, icmp_objects, port_object_group_names)

        for name in security_policy_names:
            new_name = PANMCSecurityDevice.apply_name_constraints(name)
            SourceSecurityDeviceObject.update_db_value('security_policies_table', 'security_policy_name', name, new_name)

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
            SourceSecurityDeviceObject.update_db_value('port_objects_table', 'port_name', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_source_ports', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_destination_ports', name, new_name)

        for name in port_object_group_names:
            new_name = PANMCSecurityDevice.apply_name_constraints(name)
            SourceSecurityDeviceObject.update_db_value('port_object_groups_table', 'port_group_name', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_source_ports', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_destination_ports', name, new_name)

        for name in url_object_names:
            # remove all the names containing special characters
            new_name = PANMCSecurityDevice.apply_url_name_constraints(name)
            SourceSecurityDeviceObject.update_db_value('url_objects_table', 'url_object_name', name, new_name)
            SourceSecurityDeviceObject.update_array_value('security_policies_table', 'security_policy_urls', name, new_name)
            # update also the url group array
            SourceSecurityDeviceObject.update_array_value('url_object_groups_table', 'url_object_members', name, new_name)
        
        # reformat URLs in order to match PA's standards
        for old_url_value in url_object_values:
            new_url_value = PANMCSecurityDevice.apply_url_constraints(old_url_value)
            SourceSecurityDeviceObject.update_db_value('url_objects_table', 'url_value', old_url_value, new_url_value)

        # PA does not support URL groups. Therefore, we need to create an URL object, which will contain all the values of the member objects of a URL group object from the other platform
        # loop through the URL groups
        for url_group_name in url_object_groups_names:
            new_member_list = []
            url_group_members = SourceSecurityDeviceObject.get_db_col_by_val('url_object_members', 'url_object_groups_table', 'url_object_group_name', url_group_name)
            
            # for each of the members, find its value in the url objects table and add it to the new list
            try:
                for member_name in url_group_members:
                    member_value = SourceSecurityDeviceObject.get_db_col_by_val('url_value', 'url_objects_table', 'url_object_name', member_name)
                    new_member_list.append(member_value)
            except:
                continue
            
            # Construct the string representation of the list
            formatted_list = "{" + ",".join(new_member_list) + "}"

            # now update the members of the group with the new list
            SourceSecurityDeviceObject.set_url_group_members(formatted_list, url_group_name)
            
    
    # remove the URL categories here as well
    def remove_ping_url_from_policy_and_return_ping_policies_list(self, security_policy_names, SourceSecurityDeviceObject, icmp_objects, port_object_group_names):
        ping_policy_list = []
        for security_policy_name in security_policy_names:
            is_ping_policy = False
            security_policy_destination_ports = SourceSecurityDeviceObject.get_policy_param(security_policy_name, 'security_policy_destination_ports')
            security_policy_urls = SourceSecurityDeviceObject.get_policy_param(security_policy_name, 'security_policy_urls')

            for url_name_list in security_policy_urls:
                # Make a copy of the url_name_list
                copied_url_name_list = url_name_list.copy()
                # print(security_policy_name, copied_url_name_list)
                
                for url_name in url_name_list:
                    if url_name == 'any':
                        continue

                    if gvars.separator_character in url_name:
                        SourceSecurityDeviceObject.remove_array_value('security_policies_table', 'security_policy_urls', url_name)
                        copied_url_name_list.remove(url_name)

                        if len(copied_url_name_list) == 0:
                            SourceSecurityDeviceObject.set_policy_param('security_policies_table', security_policy_name, 'security_policy_urls', "{any}")

            for port_object_list in security_policy_destination_ports:
               # print("SP:", security_policy_name, ", Dports:", port_object_list)
                ports_to_remove = []  # List to store ports to be removed
                for port_object in port_object_list:
                #    print(f"Checking port object: {port_object}")
                    if port_object == 'any':
                        continue
                    
                    # check if the current port_object is an icmp object
                    if PANMCSecurityDevice.is_icmp_object(port_object, icmp_objects):
                 #       print(f"{port_object} is ICMP")
                        ports_to_remove.append(port_object)
                        is_ping_policy = True
                    
                    # if it is not an icmp object, check if it is a port group.
                    elif PANMCSecurityDevice.is_port_group(port_object, port_object_group_names):
                  #      print(f"{port_object} is a port group. Looking for members")
                        # if it is a port group, get its members
                        port_group_members = SourceSecurityDeviceObject.get_port_group_members('port_object_groups_table', port_object)
                        # look through its members
                        for member_port_list in port_group_members:
                   #         print(f"members are {member_port_list}")
                            for member_port in member_port_list:
                    #            print(f"checking member: {member_port}")
                                if PANMCSecurityDevice.is_icmp_object(member_port, icmp_objects):
                                    ports_to_remove.append(member_port)
                                    is_ping_policy = True
                    
                # Remove the ICMP ports after iteration to avoid modifying the list while iterating
                # Remove ICMP members from port groups
                # Create copies of the lists
                copied_port_object_list = port_object_list.copy()
                copied_ports_to_remove = ports_to_remove.copy()

                for port_group in port_object_list:
                    if PANMCSecurityDevice.is_port_group(port_group, port_object_group_names):
                        port_group_members = SourceSecurityDeviceObject.get_port_group_members('port_object_groups_table', port_group)
                        copied_port_group_members = port_group_members.copy()
                        
                        for member_port_list in port_group_members:
                            copied_member_port_list = member_port_list.copy()
                            
                            for member_port in member_port_list:
                                if PANMCSecurityDevice.is_icmp_object(member_port, icmp_objects):
                                    copied_member_port_list.remove(member_port)
                                    
                            # Update the copied port group members
                            copied_port_group_members[copied_port_group_members.index(member_port_list)] = copied_member_port_list
                            
                        # Update the port group in the copied port object list
                        if not any(copied_port_group_members):
                            copied_port_object_list.remove(port_group)
                            SourceSecurityDeviceObject.delete_referenced_objects(port_group)
                            SourceSecurityDeviceObject.remove_port_group(port_group)
                        else:
                            # Convert the member lists to string format
                            formatted_members = ', '.join([f"{port}" for port_list in copied_port_group_members for port in port_list])
                            formatted_members = f"{{{formatted_members}}}"
                            # Update the port group members in the port_object_groups_table
                            SourceSecurityDeviceObject.set_port_members('port_object_groups_table', port_group, 'port_group_members', formatted_members)
                                
                # Remove ports from the copied port object list
                for port_to_remove in copied_ports_to_remove:
                    if port_to_remove in copied_port_object_list:
                        copied_port_object_list.remove(port_to_remove)
                        
                if not copied_port_object_list:
                    SourceSecurityDeviceObject.set_policy_param('security_policies_table', security_policy_name, 'security_policy_destination_ports', "{any}")
                else:
                    # Format the modified destination ports array as a set
                    formatted_ports = ', '.join([f"{port}" for port in copied_port_object_list])
                    formatted_ports = f"{{{formatted_ports}}}"
                    # Update the security policy with the modified destination ports array
                    SourceSecurityDeviceObject.set_policy_param('security_policies_table', security_policy_name, 'security_policy_destination_ports', formatted_ports)

                # if the current policy has been identified to contain ping elements, change the application to 'ping'
                if is_ping_policy:
                    SourceSecurityDeviceObject.set_policy_param('security_policies_table', security_policy_name, 'security_policy_l7_apps', "{ping}")
                    ping_policy_list.append(security_policy_name)

        # Return the list of policies affected by ICMP object removal after iterating through all security policy names
        return ping_policy_list
    
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

            self._sec_device_connection.add(dg_object)

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

            network_group_object = AddressGroup(network_group_object_name, network_group_members, network_group_description)
            dg_object = DeviceGroup(network_object_container)

            # set the device group for the panorama instance
            self._sec_device_connection.add(dg_object)

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

            port_object = ServiceObject(port_object_name, protocol=port_protocol.lower(), destination_port=port_number, description=port_description)
            dg_object = DeviceGroup(port_object_container)

            # set the device group for the panorama instance
            self._sec_device_connection.add(dg_object)
            
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

            network_group_object = ServiceGroup(port_group_name, port_group_members, port_group_description)
            dg_object = DeviceGroup(port_object_container)

            # set the device group for the panorama instance
            self._sec_device_connection.add(dg_object)

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
                self._sec_device_connection.add(dg_object)
                
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
                self._sec_device_connection.add(dg_object)
                
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
            self._sec_device_connection.add(tag_object)
        # create the object
        try:
            self._sec_device_connection.find(cat_name).create_similar()
        except Exception as e:
            print("error occured when creating tag object. More details: ", e)

    # create the files that will keep track of all the failed objects/policies
    # keep a count of: all objects of all types that will be created, all theo bjects created. do the same with the policies
    def migrate_security_policies(self, security_policy_names, SourceDevice):
        print("migrating security policies")
        for security_policy_name in security_policy_names:
            # for each of the names, get all the details needed in order to create the policy
            
            # get the container name
            security_policy_container = SourceDevice.get_db_col_by_val('security_policy_container_name', 'security_policies_table', 'security_policy_name', security_policy_name)

            # get the security category
            security_policy_category = SourceDevice.get_db_col_by_val('security_policy_category', 'security_policies_table', 'security_policy_name', security_policy_name)

            # get the policy status
            security_policy_status = SourceDevice.get_db_col_by_val('security_policy_status', 'security_policies_table', 'security_policy_name', security_policy_name)
            
            is_enabled = True
            if security_policy_status != 'enabled':
                is_enabled = False

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

            if policy_section == 'Mandatory':
                rulebase = self._sec_device_connection.add(PreRulebase())
            else:
                rulebase = self._sec_device_connection.add(PostRulebase())

            dg_object = DeviceGroup(security_policy_container)
        
            # set the device group for the panorama instance
            self._sec_device_connection.add(dg_object)

            # set the rulebase
            self._sec_device_connection.add(rulebase)

            if security_policy_apps == ['ping'] and security_policy_destination_ports != ['any']:
                security_policy_destination_ports = ['any']
                
                # slice the name to be up to 58 characters and add "_PING"
                security_policy_name = security_policy_name[:58] + '_PING'
                policy_object = SecurityRule(name=security_policy_name, tag=[security_policy_category], group_tag=security_policy_category, disabled=is_enabled, \
                                            fromzone = security_policy_source_zones, tozone=security_policy_destination_zones, source=security_policy_source_networks, \
                                            destination=security_policy_destination_networks, service=security_policy_destination_ports, category=security_policy_urls, application=security_policy_apps, \
                                            description=security_policy_description, log_setting=log_forwarding, log_end=log_end, action=policy_action)

            # print('PING_POL... ','name:', security_policy_name, 'tag:', security_policy_category, 'group_tag:', security_policy_category, 'disabled:', is_enabled,
            #     'fromzone:', security_policy_source_zones, 'tozone:', security_policy_destination_zones, 'source:', security_policy_source_networks,
            #     'destination:', security_policy_destination_networks, 'service:', security_policy_destination_ports, 'category:', security_policy_urls, 'application:', security_policy_apps,
            #     'description:', security_policy_description, 'log_setting:', log_forwarding, 'log_end:', log_end, 'action:', policy_action)
            
            # the security_policy_apps must be any all the time, except for when it should be ping (Already covered)
            security_policy_apps = ['any']

            # TODO: set the security group
            policy_object = SecurityRule(name=security_policy_name, tag=[security_policy_category], group_tag=security_policy_category, disabled=is_enabled, \
                                        fromzone = security_policy_source_zones, tozone=security_policy_destination_zones, source=security_policy_source_networks, \
                                        destination=security_policy_destination_networks, service=security_policy_destination_ports, category=security_policy_urls, application=security_policy_apps, \
                                        description=security_policy_description, log_setting=log_forwarding, log_end=log_end, action=policy_action)
            
            # add the policy object to the device group
            dg_object.add(policy_object)
            
            # print('name:', security_policy_name, 'tag:', security_policy_category, 'group_tag:', security_policy_category, 'disabled:', is_enabled,
            #     'fromzone:', security_policy_source_zones, 'tozone:', security_policy_destination_zones, 'source:', security_policy_source_networks,
            #     'destination:', security_policy_destination_networks, 'service:', security_policy_destination_ports, 'category:', security_policy_urls, 'application:', security_policy_apps,
            #     'description:', security_policy_description, 'log_setting:', log_forwarding, 'log_end:', log_end, 'action:', policy_action)
        # create the object
        try:
            self._sec_device_connection.find(security_policy_name).create_similar()
        except Exception as e:
            print("error occured when creating policy object. More details: ", e)

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
        # Replace all characters that are not space, '-', or '.' with '_'
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