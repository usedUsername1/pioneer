from pkg.SecurityDevice.APISecurityDevice.APISecurityDeviceConnection import APISecurityDeviceConnection
from pkg.SecurityDevice import SecurityDevice
from panos.panorama import Panorama
import utils.helper as helper
from utils.exceptions import InexistentContainer
from pkg.Container import SecurityPolicyContainer, ObjectContainer

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
Object names:
Policy names:
Port objects:
URL objects:
Security Policies restricting ping access: """)
    
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
        dg_mapping = {'Azure: DEV EUN Internet Access Policy': 'Azure DEV - Internet',
                       'Azure: DEV EUN VPN Access Policy': 'Azure DEV - VPN',
                       'Azure: Global VPN Policy': 'Global VPN',
                       'Global Internet Access Policy': 'Global Internet'}
        
        dg_mapping = {'debug3':'Debug'}

        object_container = 'Global Internet'

        return object_container, dg_mapping

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