from pkg.SecurityDevice import SecurityDevice
from pkg.Container.PANMCContainer import PANMCSecurityPolicyContainer, PANMCObjectContainer, PANMCSecurityZoneContainer, PANMCNATContainer
from pkg.SecurityZone.PANMCSecurityZone import PANMCSecurityZone
from panos.panorama import DeviceGroup, Template
from panos.network import Zone
from panos.objects import AddressObject, AddressGroup, ServiceObject, ServiceGroup, CustomUrlCategory, Tag
from panos.policies import PreRulebase, PostRulebase, SecurityRule
import utils.helper as helper
import utils.gvars as gvars
from utils.exceptions import InexistentContainer
from pkg.Container import SecurityPolicyContainer, ObjectContainer
import random
import re

general_logger = helper.logging.getLogger('general')

#TODO: import NAT containers
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
        hierarchy_object = self.device_connection.OPSTATES['dg_hierarchy']

        # Create an instance of PanoramaDeviceGroupHierarchy
        HierarchyInstance = hierarchy_object(self.device_connection)

        # Call the fetch method on the instance
        hierarchy_data = HierarchyInstance.fetch()

        for key, value in hierarchy_data.items():
            device_group_info.append({"name": key, "parent": value})

        return device_group_info

    def return_object_container_object(self, container_entry):
        return PANMCObjectContainer(self, container_entry)

    def return_object_container_info(self):
        return self.return_device_group_info()

    def return_security_policy_container_object(self, container_entry):
        return PANMCSecurityPolicyContainer(self, container_entry)

    def return_nat_policy_container_object(self, container_entry):
        return PANMCNATContainer(self, container_entry)

    def return_zone_container_object(self, container_entry):
        return PANMCSecurityZoneContainer(self, container_entry)
    
    def return_security_zone_object(self, ZoneContainer, zone_entry):
        return PANMCSecurityZone(ZoneContainer, zone_entry)

    def return_security_policy_container_info(self):
        return self.return_device_group_info()

    def return_nat_policy_container_info(self):
        return self.return_device_group_info()

    def return_template_info(self):
        templates_info = []
        templates = Template.refreshall(parent=self.device_connection)
        for template in templates:
            templates_info.append({'name':template.name, 'parent':None})
        
        return templates_info

    def return_zone_container_info(self):
        return self.return_template_info()

    def return_managed_device_container_info(self):
        print("Importing managed device containers not supported yet for PANMC.")
        return None
    
    def return_security_zone_info(self):
        zones_info = []
        templates = Template.refreshall(parent=self.device_connection)
        for template in templates:
            zones = Zone.refreshall(template)
            for zone in zones:
                zones_info.append({'name':zone.name})
        return zones_info
        
    def return_managed_device_info(self):
        pass

    def return_network_object_info(self):
        print("Importing this object is not supported yet for PANMC.")
        return None

    def return_network_group_object_info(self):
        print("Importing this object is not supported yet for PANMC.")
        return None

    def return_geolocation_object_info(self):
        print("Importing this object is not supported yet for PANMC.")
        return None

    def return_port_object_info(self):
        print("Importing this object is not supported yet for PANMC.")
        return None

    def return_port_group_object_info(self):
        print("Importing this object is not supported yet for PANMC.")
        return None

    def return_url_object_info(self):
        print("Importing this object is not supported yet for PANMC.")
        return None

    def return_url_group_object_info(self):
        print("Importing this object is not supported yet for PANMC.")
        return None

    def return_schedule_object_info(self):
        print("Importing this object is not supported yet for PANMC.")
        return None
    
    def return_security_policy_info(self, ObjectContainer):
        print("Importing this object is not supported yet for PANMC.")
        return None

    def return_nat_policy_info(self, ObjectContainer):
        print("Importing this object is not supported yet for PANMC.")
        return None