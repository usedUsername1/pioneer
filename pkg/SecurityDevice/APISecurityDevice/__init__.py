from abc import abstractmethod
from pkg.SecurityDevice import SecurityDevice, SecurityDeviceDatabase, SecurityDeviceConnection
import utils.helper as helper
import fireREST
import sys
import ipaddress
import utils.exceptions as PioneerExceptions

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
            # check if the current container name was already imported
            is_duplicate_acp = self.verify_duplicate('security_policy_containers_table', 'security_policy_container_name', policy_container_name)
            if(is_duplicate_acp):
                print(f"Container: {policy_container_name} is already imported. Skipping it...")
                continue

            try:
                # create the list that will store the dictionary that will store the child_acp -> parent_acp mapping
                child_parent_list = []

                # retrieve the info for the current acp
                acp_info = self._api_connection.policy.accesspolicy.get(name=policy_container_name)
                
                # if the policy does not have a parent policy at all, then return a mapping with the current policy name and None to the caller
                if acp_info['metadata']['inherit'] == False:
                    child_parent_list.append([policy_container_name, None])
                    return child_parent_list

                else: 
                    # try to retrieve the parent of the policy. there is a "inherit" boolean attribute in the acp_info response. if it is equal to 'true', then the policy has a parent
                    while acp_info['metadata']['inherit'] == True:
                        # get the name of the current ACP name
                        current_acp_name = acp_info['name']

                        # get the name of the acp parent 
                        acp_parent = acp_info['metadata']['parentPolicy']['name']

                        print(f"Container: {current_acp_name} is the child of a container. Its parent is: {acp_parent}.")    

                        # check if the parent ACP is already imported in the database. if a parent is already present, then it means the rest of the parents are present
                        # create the mapping of the current child and its parent, and return it to the caller
                        is_duplicate_acp = self.verify_duplicate('security_policy_containers_table', 'security_policy_container_name', acp_parent)
                        if(is_duplicate_acp):
                            print(f"Parent container: {acp_parent} is already imported. I have only imported its child. I will skip further processing.")
                            child_parent_list.append([current_acp_name, acp_parent])
                            return child_parent_list   

                        # retrieve the parent info to be processed in the next iteration of the loop
                        acp_info = self._api_connection.policy.accesspolicy.get(name=acp_parent)

                        # update the list containing info about the parents/children ACPs
                        child_parent_list.append([current_acp_name, acp_parent])
                    
                    # if the parent policy does not have a parent, then map the ACP to None
                    else:
                        child_parent_list.append([acp_parent, None])

                    return child_parent_list
                
            except Exception as err:
                print(f'Could not retrieve info regarding the container {policy_container_name}. Reason: {err}.')
                sys.exit(1)
        
    
    # this function extracts all the data from the security policies of a policy container.
    # the data is returned in a list containing JSON
    # TODO: should process functions be followed by importing the processed objects?
    def get_sec_policies_data(self, sec_policy_container):
        # execute the request to get all the security policies from the policy container
        sec_policies = self._api_connection.policy.accesspolicy.accessrule.get(container_name=sec_policy_container)

        # array that will be used for storing the information for each policy
        sec_policy_info = []
        # now loop through the policies
        for sec_policy in sec_policies:

            # retrieve the name of the policy
            sec_policy_name = sec_policy['name']
            
            # get the name of the container where the policy belongs
            sec_policy_container_name = sec_policy['metadata']['accessPolicy']['name']
            print(f"I am now processing the policy: {sec_policy_name} from the policy_container: {sec_policy_container_name}.")
            
            # get the category in which the security policy is placed
            sec_policy_category = sec_policy['metadata']['category']
            
            # retrieve the status of the security policy (enabled/disabled)
            sec_policy_status = ''
            if sec_policy['enabled'] == True:
                sec_policy_status = 'enabled'
            else:
                sec_policy_status = 'disabled'
            

            # get the names of the source and destination zones
            sec_policy_source_zones = self.process_security_zones(sec_policy, 'sourceZones')
            sec_policy_destination_zones = self.process_security_zones(sec_policy, 'destinationZones')

            # get the names of the network objects of the policy.
            # there is a special case regarding literals. literals are values hard-coded on the policy itself. they are not objects
            # however, not all security platforms support this implementation. literal values should be treated as objects
            # every literal will be processed like this: the value of the literal, along with the literal type (host, network, etc...)
            # will be retrieved and stored in the database using a convention for literal values.
            # for example, literal value is 1.1.1.1. network objects will look something like this:
            # NO_LV_1.1.1.1_32 (NetworkObject_LiteralValue_IP_CIDRMASK). 
            # moreover, all of them will have a description of "Originally a literal value in FMC. Converted to object"
            sec_policy_source_networks = self.process_network_objects(sec_policy, 'sourceNetworks') 
            sec_policy_destination_networks = self.process_network_objects(sec_policy, 'destinationNetworks')

            # retrieve the source/destination ports of the policy
            sec_policy_source_ports = self.process_ports_objects(sec_policy, 'sourcePorts')
            sec_policy_destination_ports = self.process_ports_objects(sec_policy, 'destinationPorts')

            # retrieve the time range objects of the policy
            sec_policy_schedule_objects = self.process_schedule_objects(sec_policy)

            # retrieve the users defined on the policy
            sec_policy_users = self.process_policy_users(sec_policy)

            # retrieve the URLs of the policy
            sec_policy_urls = self.process_policy_urls(sec_policy)
            
            sec_policy_apps = self.process_policy_apps(sec_policy)
            
            sec_policy_description = ''
            try:
                print(f"I am looking for a policy description.")
                sec_policy_description = sec_policy['description']
                print(f"I have found the following description: {sec_policy_description}.")
            except KeyError:
                print(f"It looks like this policy has no description.")

            sec_policy_comments = self.process_policy_comments(sec_policy)

            # look for the policy logging settings
            sec_policy_log_settings = []
            if sec_policy['sendEventsToFMC'] == True:
                sec_policy_log_settings.append('FMC')
            
            #TODO: see how to process the logging to syslog setting
            if sec_policy['enableSyslog'] == True:
                sec_policy_log_settings.append('Syslog')

            sec_policy_log_start = sec_policy['logBegin']
            sec_policy_log_end = sec_policy['logEnd']
            sec_policy_section = sec_policy['metadata']['section']
            sec_policy_action = sec_policy['action']

            sec_policy_entry = {"sec_policy_name": sec_policy_name,
                                    "sec_policy_container_name": sec_policy_container_name,
                                    "sec_policy_category": sec_policy_category,
                                    "sec_policy_status": sec_policy_status,
                                    "sec_policy_source_zones": sec_policy_source_zones,
                                    "sec_policy_destination_zones": sec_policy_destination_zones,
                                    "sec_policy_source_networks": sec_policy_source_networks,
                                    "sec_policy_destination_networks": sec_policy_destination_networks,
                                    "sec_policy_source_ports": sec_policy_source_ports,
                                    "sec_policy_destination_ports": sec_policy_destination_ports,
                                    "sec_policy_schedules": sec_policy_schedule_objects,
                                    "sec_policy_users": sec_policy_users,
                                    "sec_policy_urls": sec_policy_urls,
                                    "sec_policy_apps": sec_policy_apps,
                                    "sec_policy_description": sec_policy_description,
                                    "sec_policy_comments": sec_policy_comments,
                                    "sec_policy_log_settings": sec_policy_log_settings,
                                    "sec_policy_log_start": sec_policy_log_start,
                                    "sec_policy_log_end": sec_policy_log_end,
                                    "sec_policy_section": sec_policy_section,
                                    "sec_policy_action": sec_policy_action,
                                    }
    
            # after all the info is retrieved from the security policy, append it to the list that will be returned to main
            sec_policy_info.append(sec_policy_entry)
        
        return sec_policy_info

    def get_device_version(self):
        try:
            device_system_info = self._api_connection.system.info.serverversion.get()
            device_version = device_system_info[0]['serverVersion']
            return device_version
        except Exception as err:
            print(f'Could not retrieve platform version. Reason: {err}')
            sys.exit(1)

    # this function is responsible for processing the zone information. it takes the current security policy that the program is processing
    # the zone type (sourceZones or destinationZones). the zone_list array contains the info with the zones names
    # when the parameter for source/destination zones is set to "Any" in the policy, then there is no
    # 'sourceZones'/'destinationZones' attribute in the response and a KeyError will be generated.
    # this is true for most of the configuration options which have the 'Any' parameter, therefore the retrieval of all
    # configuration options will be processed in try except KeyError blocks
    def process_security_zones(self, sec_policy, zone_type):
        print(f"####### ZONE PROCESSING ####### ")
        zone_list = []
        
        try:
            print(f"I am looking for {zone_type} objects...")
            zone_objects = sec_policy[zone_type]['objects']
            print(f"I have found {zone_type} objects: {zone_objects}. I will now start to process them...")
            
            # loop through the zone objects
            for zone_object in zone_objects:

                # retrieve the zone name
                zone_name = zone_object['name']

                # append it to the list
                zone_list.append(zone_name)
                print(f"I am done processing {zone_object}. I have extracted the following data: name: {zone_name}")
        
        except KeyError:
            print(f"It looks like there are no {zone_type} objects defined on this policy.")
            # if there are no zones defined on the policy, then return 'any'
            zone_list = ['any']
        
        return zone_list

    # this function does pretty much the same thing like the function above.
    # there is a small problem here, we might enocunter literal values in the source/destination networks config of the policy
    def process_network_objects(self, sec_policy, network_object_type):
        print(f"####### NETWORK OBJECTS PROCESSING ####### ")
        network_objects_list = []

        # Flag to check if any objects or literals are found
        found_objects_or_literals = False

        try:
            print(f"I am looking for {network_object_type} objects...")
            network_objects = sec_policy[network_object_type]['objects']
            print(f"I have found {network_object_type} objects. These are: {network_objects}. I will now start to process them...")
            for network_object in network_objects:
                network_object_name = network_object['name']
                network_objects_list.append(network_object_name)
            
            found_objects_or_literals = True
        
        except KeyError:
            print(f"It looks like there are no {network_object_type} objects on this policy.")

        # now check for literal values.
        try:
            print(f"I am looking for {network_object_type} literals...")
            network_literals = sec_policy[network_object_type]['literals']
            print(f"I have found {network_object_type} literals. These are: {network_literals}. I will now start to process them...")
            
            # loop through the network literals.
            for network_literal in network_literals:

                # extract the value of the network literal
                literal_value = network_literal['value']

                # extract the type of the network literal. can be either "Host" or "Network"
                # the name of the converted object will depend on based on the network literal type
                literal_type = network_literal['type'] 
                
                # the literal type can be either a host or a network
                if literal_type == 'Network':
                    # Define the CIDR notation IP address
                    ip_cidr = literal_value

                    # Create an IPv4 network object
                    network = ipaddress.ip_network(ip_cidr, strict=False)

                    # Extract the network address and netmask
                    network_address = network.network_address
                    netmask = network.netmask

                elif literal_type == 'Host':
                    netmask = '32'
                    network_address = literal_value  # Assuming literal_value is the host address
                
                else:
                    print("Invalid literal type. Literal is not either 'Host' or 'Network.")
                    continue

                # create the name of the object (NL_networkaddress_netmask)
                network_object_name = "NL_" + str(network_address) + "_" + str(netmask)
            
            found_objects_or_literals = True

        except KeyError:
            print(f"It looks like there are no {network_object_type} literals on this policy.")
        
        # Append 'any' only if neither objects nor literals are found
        if not found_objects_or_literals:
            network_objects_list.append('any')

        return network_objects_list
    
    def process_ports_objects(self, sec_policy, port_object_type):
        print(f"####### PORT OBJECTS PROCESSING ####### ")
        port_objects_list = []
        found_objects_or_literals = False

        try:
            print(f"I am looking for {port_object_type} objects...")
            port_objects = sec_policy[port_object_type]['objects']
            print(f"I have found {port_object_type} objects. These are: {port_objects}. I will now start to process them...")
            for port_object in port_objects:
                port_object_name = port_object['name']
                port_objects_list.append(port_object_name)
            
            found_objects_or_literals = True
        
        except KeyError:
            print(f"It looks like there are no {port_object_type} objects on this policy.")

        # now check for literal values
        try:
            print(f"I am looking for {port_object_type} literals...")
            port_literals = sec_policy[port_object_type]['literals']
            print(f"I have found {port_object_type} literals. These are: {port_literals}. I will now start to process them...")
            
            for port_literal in port_literals:

                literal_protocol = port_literal['protocol']
                literal_port_nr = port_literal['port']
                # there are actually two types of literals: PortLiterals and ICMP literals (which can pe ICMPv4 or ICMPv6)
                # the protocol value is an integer representing a protocol code according to IANA
                # it needs to be mapped to a string value in order to create a proper protocol name
                # for the literal
                
                # if the passed protocol number is unkown, an exception will be raised, the processing
                # of the current port object will be skipped, the policy that contains this object
                # will be marked with an warning
                try:
                    literal_protocol_keyword = helper.protocol_number_to_keyword(literal_protocol)
                    # if the protocol number is 1 or 58, then pioneer has encountered an ICMP-type protocol. there is no "port" key for such objects
                    # however, there is an "icmpType" key. the following code treats this situation, and uses the icmptype as the port value
                    # which will be further used by the program.
                    if literal_protocol == "1" or literal_protocol == "58":
                        print(f"I have encountered an ICMP literal: {port_literal['type']}.")
                        literal_port_nr = port_literal['icmpType']
                except PioneerExceptions.UnknownProtocolNumber:
                    print(f"Protocol number: {literal_port_nr} cannot be converted to a known IANA keyword.")
                    continue

                # extract the type of the network literal. can be either "Host" or "Network"
                # the name of the converted object will depend on based on the network literal type
                literal_port_nr = port_literal['port']

                # create the name of the object (NL_networkaddress_netmask)
                port_object_name = "PL_" + str(literal_protocol_keyword) + "_" + str(literal_port_nr)

                # and append it to the port object list
                port_objects_list.append(port_object_name)
            
            found_objects_or_literals = True 

        except KeyError:
            print(f"It looks like there are no {port_object_type} literals on this policy.")
        
        # Append 'any' only if neither objects nor literals are found
        if not found_objects_or_literals:
            port_objects_list.append('any')

        return port_objects_list


    def process_schedule_objects(self, sec_policy):
        print(f"####### SCHEDULE OBJECTS PROCESSING ####### ")
        schedule_object_list = []
        
        try:
            print(f"I am looking for schedule objects...")
            schedule_objects = sec_policy['timeRangeObjects']
            print(f"I have found schedule objects: {schedule_objects}. I will now start to process them...")
            
            # loop through the schedule_object objects
            for schedule_object_object in schedule_objects:

                # retrieve the schedule_object name
                schedule_object_name = schedule_object_object['name']

                # append it to the list
                schedule_object_list.append(schedule_object_name)
                print(f"I am done processing {schedule_object_object}. I have extracted the following data: name: {schedule_object_name}")
        
        except KeyError:
            print(f"It looks like there are no schedule objects defined on this policy.")
            # if there are no schedules defined on the policy, then return 'any'
            schedule_object_list = ['any']
        
        return schedule_object_list

    # TODO: maybe i need to process more stuff than names here
    def process_policy_users(self, sec_policy):
        print(f"####### USERS PROCESSING ####### ")
        policy_user_list = []
        
        try:
            print(f"I am looking for policy users...")
            policy_users = sec_policy['timeRangeObjects']
            print(f"I have found policy users: {policy_users}. I will now start to process them...")
            
            # loop through the policy_user objects
            for policy_user_object in policy_users:

                # retrieve the policy_user name
                policy_user_name = policy_user_object['name']

                # append it to the list
                policy_user_list.append(policy_user_name)
                print(f"I am done processing {policy_user_object}. I have extracted the following data: name: {policy_user_name}")
        
        except KeyError:
            print(f"It looks like there are no policy users defined on this policy.")
            # if there are no users defined on the policy, then return 'any'
            policy_user_list = ['any']
        
        return policy_user_list

    # there are three cases which need to be processed here. the url can be an object, a literal, or a category with reputation
    def process_policy_urls(self, sec_policy):
        print(f"####### URL PROCESSING ####### ")
        policy_url_list = []
        found_objects_or_literals = False

        try:
            print(f"I am looking for policy URL objects...")
            policy_url_objects = sec_policy['urls']['objects']
            print(f"I have found URL objects: {policy_url_objects}. I will now start to process them...")

            for policy_url_object in policy_url_objects:
                policy_url_object_name = policy_url_object['name']
                policy_url_list.append(policy_url_object_name)
            
            found_objects_or_literals = True
        
        except KeyError:
            print(f"It looks like there are no URL objects on this policy.")
        
        try:
            print(f"I am looking for policy URL literals...")
            policy_url_literals = sec_policy['urls']['literals']
            print(f"I have found policy URL literals: {policy_url_literals}. I will now start to process them...")

            for policy_url_literal in policy_url_literals:
                policy_url_literal_value = policy_url_literal['literals']
                policy_url_list.append(policy_url_literal_value)
            
            found_objects_or_literals = True
        
        except KeyError:
            print(f"It looks like there are no URL literals on this policy.")
        
        try:
            print(f"I am looking for policy URL categories...")
            policy_url_categories = sec_policy['urls']['urlCategoriesWithReputation']
            print(f"I have found policy URL categories: {policy_url_categories}. I will now start to process them...")
            found_objects_or_literals = True

            for policy_url_category in policy_url_categories:
                category_name = policy_url_category['category']['name']
                
                # TODO: decide if the reputation is actually needed
                category_reputation = policy_url_category['reputation']

                policy_url_list.append(category_name)
        
            found_objects_or_literals = True
        
        except KeyError:
            print(f"It looks like there are no URL categories on this policy.")

        # Append 'any' only if neither objects nor literals are found
        if not found_objects_or_literals:
            policy_url_list.append('any')

        return policy_url_list


    def process_policy_apps(self, sec_policy):
        print(f"####### APPS PROCESSING ####### ")
        policy_l7_apps_list = []
        found_objects_or_literals = False

        try:
            print(f"I am looking for policy L7 apps...")
            policy_l7_apps = sec_policy['applications']['applications']
            print(f"I have found L7 apps: {policy_l7_apps}. I will now start to process them...")

            for policy_l7_app in policy_l7_apps:
                policy_l7_name = policy_l7_app['name']
                policy_l7_apps_list.append(policy_l7_name)
            
            found_objects_or_literals = True
        
        except KeyError:
            print(f"It looks like there are no L7 apps on this policy.")

        try:
            print(f"I am looking for L7 application filters ...")
            policy_l7_app_filters = sec_policy['applications']['applicationFilters']
            print(f"I have found L7 application filters: {policy_l7_app_filters}. I will now start to process them...")

            for policy_l7_app_filter in policy_l7_app_filters:
                policy_l7_app_filter_name = policy_l7_app_filter['name']
                policy_l7_apps_list.append(policy_l7_app_filter_name)
            
            found_objects_or_literals = True
        
        except KeyError:
            print(f"It looks like there are no URL literals on this policy.")

        # there are multiple inline app filters keys (risks, tags, types, categories, etc...)
        # this part of the code will loop through the inline app filter keys and retrieve the name
        # of the inline filter
        # TODO: test this really well
        try:
            print(f"I am looking for Inline L7 application filters...")
            policy_inline_l7_app_filters = sec_policy['applications']['inlineApplicationFilters']
            print(f"I have found Inline L7 application filters...: {policy_inline_l7_app_filters}. I will now start to process them...")

            for policy_inline_l7_app_filter_key in policy_inline_l7_app_filters.keys():
                # now loop through the elements mapped to this key. for example, loop through the inline l7 application filters that are grouped by tags
                for policy_inline_l7_app_filter in policy_inline_l7_app_filters[policy_inline_l7_app_filter_key]:
                    policy_inline_l7_app_filter_name = policy_inline_l7_app_filter['name']
                    # append the name to the list
                    policy_l7_apps_list.append(policy_inline_l7_app_filter_name)
        
            found_objects_or_literals = True
        
        except KeyError:
            print(f"It looks like there are no L7 inline application filters on this policy.")

        # Append 'any' only if nothing is found
        if not found_objects_or_literals:
            policy_l7_apps_list.append('any')

        return policy_l7_apps_list
    

    def process_policy_comments(self, sec_policy):
        print(f"####### COMMENTS PROCESSING ####### ")
        comments_list = []
        
        try:
            print(f"I am looking for policy comments comments...")
            comments = sec_policy['commentHistoryList']
            print(f"I have found policy comments... {comments}. I will now start to process them")
            for comment in comments:
                # retrieve the user that made the comment
                comment_user = comment['user']['name']

                # retrieve the content of the comment
                comment_content = comment['comment']

                # append a dictionary with the user who mande the comment and the content of the comment
                comments_list.append({comment_user: comment_content})
        except KeyError:
            print(f"It looks like there are no comments on this policy")
            comments_list = []

        return comments_list


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
