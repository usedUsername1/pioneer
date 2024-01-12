from abc import abstractmethod
from pkg.SecurityDevice import SecurityDevice, SecurityDeviceDatabase, SecurityDeviceConnection
import utils.helper as helper
import fireREST
import sys

class APISecurityDeviceConnection(SecurityDeviceConnection):
    def __init__(self, api_username, api_secret, api_hostname, api_port):
        super().__init__()
        self._api_username = api_username
        self._api_secret = api_secret
        self._api_hostname = api_hostname
        self._api_port = api_port


class APISecurityDevice(SecurityDevice):
    def __init__(self, user, database, password, host, port):
        super().__init__(user, database, password, host, port)


class FMCDeviceConnection(APISecurityDeviceConnection):
    def __init__(self, api_username, api_secret, api_hostname, api_port, domain):
        super().__init__(api_username, api_secret, api_hostname, api_port)
        self._domain = domain
    
    def connect_to_security_device(self):
        try:
            fmc_conn = fireREST.FMC(hostname=self._api_hostname, username=self._api_username, password=self._api_secret, domain=self._domain, protocol=self._api_port, timeout=30)
            return fmc_conn
        except Exception as err:
            print(f'Could not connect to FMC device: {self._api_username}. Reason: {err}')
            sys.exit(1)
        

class FMCSecurityDevice(SecurityDevice):
    def __init__(self, name, sec_device_database, security_device_username, security_device_secret, security_device_hostname, security_device_port, domain):
        super().__init__(name, sec_device_database)
        self._api_connection = FMCDeviceConnection(security_device_username, security_device_secret, security_device_hostname, security_device_port, domain).connect_to_security_device()

#     def import_nat_policy_containers(self):
#         pass

#     def import_object_containers(self):
#         pass
    def import_objects(self, policy_list):
        pass

    # this function takes the list with policy container names and loops through each of them.
    # for every container, it tries to find the container parent. if the parent container is a child of another container, it will find that parent too
    # ACP = access control policy = the security policy container used by FMC
    def get_sec_policy_container_info(self, policy_container_names_list):
        
        # loop through the policy containers provided by the user
        for policy_container_name in policy_container_names_list:
            try:
                # create the list that will store the dictionary that will store the child_acp -> parent_acp mapping
                child_parent_list = []

                # retrieve the info for the current acp
                acp_info = self._api_connection.policy.accesspolicy.get(name=policy_container_name)

                # try to retrieve the parent of the policy. there is a "inherit" boolean attribute in the acp_info response. if it is equal to 'true', then the policy has a parent
                while acp_info['metadata']['inherit'] == True:
                    # get the name of the current ACP name
                    current_acp_name = acp_info['name']

                    # get the parent of the current ACP
                    acp_parent = acp_info['metadata']['parentPolicy']['name']

                    print(f"Container: {current_acp_name} is the child of a container. Its parent is: {acp_parent}.")
                    # update the list containing info about the parents/children ACPs
                    child_parent_list.append([current_acp_name, acp_parent])

                    # go back to while and check if the parent of the policy has a parent
                    acp_info = self._api_connection.policy.accesspolicy.get(name=acp_parent)
                
                # if the parent policy does not have a parent, then map the ACP to None
                else:
                    child_parent_list.append([acp_parent, None])

                return child_parent_list
            
            except Exception as err:
                print(f'Could not retrieve info regarding the container {policy_container_name}. Reason: {err}.')
                sys.exit(1)


    def get_device_version(self):
        try:
            device_system_info = self._api_connection.system.info.serverversion.get()
            device_version = device_system_info[0]['serverVersion']
            return device_version
        except Exception as err:
            print(f'Could not retrieve platform version. Reason: {err}')
            sys.exit(1)

    

class APISecurityDeviceFactory:
    @staticmethod
    def build_api_security_device(security_device_name, security_device_type, SecurityDeviceDB, security_device_hostname, security_device_username, security_device_secret, security_device_port, domain):
        match security_device_type:
            case "fmc-api":
                return FMCSecurityDevice(security_device_name, SecurityDeviceDB, security_device_username, security_device_secret, security_device_hostname, security_device_port, domain)

            # default case
            case _:
                print("Invalid API security device.")
                sys.exit(1)
            
class ConfigSecurityDeviceFactory:
    @staticmethod
    def build_config_security_device():
        pass
            