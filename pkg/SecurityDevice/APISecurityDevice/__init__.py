from abc import abstractmethod
from pkg.SecurityDevice import SecurityDevice, SecurityDeviceConnection
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
        
    def get_managed_devices_info(self):
        # execute the request to retrieve the info about the devices
        print(f"########################## GETTING MANAGED DEVICES INFO ##########################")
        managed_devices = self._api_connection.device.devicerecord.get()
        managed_devices_info = []
        # loop through the info
        for managed_device in managed_devices:
            device_name = managed_device['name']
            assigned_security_policy_container = managed_device['accessPolicy']['name']
            device_hostname = managed_device['hostName']
            device_cluster = None
            # if the device is part of a cluster, then the 'containerDetails' key is present in the 'metadata' JSON response
            try:
                device_cluster = managed_device['metadata']['containerDetails']['name']
            except KeyError:
                print(f"Device {device_name} is not part of a device cluster.")

            # this will be returned back to the caller, the info here will be inserted in the database
            managed_device_entry = {"managed_device_name":device_name,
                                    "assigned_security_policy_container":assigned_security_policy_container,
                                    "hostname":device_hostname,
                                    "cluster":device_cluster}
            
            # append the managed devices info to the list that will be returned to the caller
            managed_devices_info.append(managed_device_entry)
        
        # return the list to the caller
        return managed_devices_info

    # this function takes the list with policy container names and loops through each of them.
    # for every container, it tries to find the container parent. if the parent container is a child of another container, it will find that parent too
    # ACP = access control policy = the security policy container used by FMC
    def get_sec_policy_container_info(self, policy_container_names_list):
        # loop through the policy containers provided by the user
        for policy_container_name in policy_container_names_list:
            # check if the current container name was already imported
            is_duplicate_acp = self.verify_duplicate('security_policy_containers_table', 'security_policy_container_name', policy_container_name)
            print(is_duplicate_acp)
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
    def get_sec_policies_data(self, sec_policy_container_list):
        # execute the request to get all the security policies from the policy container
        for sec_policy_container in sec_policy_container_list:
            sec_policies = self._api_connection.policy.accesspolicy.accessrule.get(container_name=sec_policy_container)
            print(f"##########################{sec_policy_container}##########################")

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
                    netmask = str(network.prefixlen)  # Extract the prefix length instead of full netmask

                elif literal_type == 'Host':
                    netmask = '32'
                    network_address = literal_value  # Assuming literal_value is the host address

                else:
                    print("Invalid literal type. Literal is not either 'Host' or 'Network.")
                    continue

                # create the name of the object (NL_networkaddress_netmask)
                network_object_name = "NL_" + str(network_address) + "_" + str(netmask)
                network_objects_list.append(network_object_name)
            
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

        # Check for objects in the security policy
        try:
            print(f"I am looking for {port_object_type} objects...")
            port_objects = sec_policy[port_object_type]['objects']
            print(f"I have found {port_object_type} objects. These are: {port_objects}. I will now start to process them...")

            # Process each port object
            for port_object in port_objects:
                port_object_name = port_object['name']
                port_objects_list.append(port_object_name)
            found_objects_or_literals = True
        
        except KeyError:
            print(f"It looks like there are no {port_object_type} objects on this policy.")

        # Check for literal values in the security policy
        try:
            print(f"I am looking for {port_object_type} literals...")
            port_literals = sec_policy[port_object_type]['literals']
            print(f"I have found {port_object_type} literals. These are: {port_literals}. I will now start to process them...")
            found_objects_or_literals = True 

            # Process each port literal
            for port_literal in port_literals:
                literal_protocol = port_literal['protocol']

                # Handle ICMP literals separately
                if literal_protocol in ["1", "58"]:
                    print(f"I have encountered an ICMP literal: {port_literal['type']}.")
                    literal_port_nr = port_literal['icmpType']
                else:
                    literal_port_nr = port_literal['port']

                # Convert protocol number to a known IANA keyword
                try:
                    literal_protocol_keyword = helper.protocol_number_to_keyword(literal_protocol)
                except PioneerExceptions.UnknownProtocolNumber:
                    print(f"Protocol number: {literal_protocol} cannot be converted to a known IANA keyword.")
                    continue

                # Create the name of the port object
                port_object_name = f"PL_{literal_protocol_keyword}_{literal_port_nr}"
                port_objects_list.append(port_object_name)

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
            policy_users = sec_policy['users']['objects']
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

            # Access the Inline L7 application filters from the 'sec_policy' dictionary
            policy_inline_l7_app_filters = sec_policy['applications']['inlineApplicationFilters']

            print(f"I have found Inline L7 application filters...: {policy_inline_l7_app_filters}. I will now start to process them...")

            # Extract the keys from the first dictionary in the 'policy_inline_l7_app_filters' list. 
            # These keys represent the different categories or types in the Inline L7 application filters.
            policy_inline_l7_app_filter_keys_list = list(policy_inline_l7_app_filters[0].keys())

            # Iterate over each key/category in the Inline L7 application filter keys list.
            for policy_inline_l7_app_filter_key in policy_inline_l7_app_filter_keys_list:
                # Loop through each dictionary in 'policy_inline_l7_app_filters' list.
                for index in range(len(policy_inline_l7_app_filters)):
                    # Access the list of filter elements (like apps, URLs, etc.) under the current category specified by 'policy_inline_l7_app_filter_key'.
                    policy_inline_l7_app_filter_elements = policy_inline_l7_app_filters[index][policy_inline_l7_app_filter_key]            
                    
                    # Iterate over each filter element in the current category of Inline L7 application filter.
                    for policy_inline_l7_app_filter_element in policy_inline_l7_app_filter_elements:
                        # Append the name of each filter element (e.g., specific app name) to the 'policy_l7_apps_list'.
                        # This list accumulates all the app names from different categories in the Inline L7 application filters.
                        policy_l7_apps_list.append(policy_inline_l7_app_filter_element['name'])

            found_objects_or_literals = True
        
        except KeyError:
            print(f"It looks like there are no L7 inline application filters on this policy.")

        # Append 'any' only if nothing is found
        if not found_objects_or_literals:
            policy_l7_apps_list.append('any')

        return policy_l7_apps_list
    
    # TODO: process comments, don't return them as dict, maybe as list with user_comment
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
            comments_list = None

        return comments_list
    

    # def get_zone_objects_info(self):
    #     pass
    def process_network_literals(self, network_address_literals):
        if len(network_address_literals) == 0:
            return
        
        processed_network_literals_info = []
        object_container_name = "virtual_object_container"
        literal_object_description = "Originally a literal value. Converted to object by Pioneer."
        
        # literals cannot be overriden
        is_overridable_object = False
        # loop through the network literals
        for current_network_literal in network_address_literals:
            # for the current network literal, split the string by the "_" in order to extract the subnet and the netmask. example output ['NL', '10.10.10.10', '32']
            split_network_literal = current_network_literal.split('_')
            network_literal_subnet = split_network_literal[1]
            network_literal_netmask = split_network_literal[2]
            network_address_type = 'Host'
            if network_literal_netmask != '32':
                network_address_type = 'Network'
            
            # create the object value string
            network_object_value = str(network_literal_subnet) + '/' + str(network_literal_netmask)
            
            processed_network_literal_entry = {"network_address_name":current_network_literal,
                                               "object_container_name":object_container_name,
                                               "network_address_value":network_object_value,
                                               "network_address_description":literal_object_description,
                                               "network_address_type":network_address_type,
                                               "overridable_object":is_overridable_object}

            processed_network_literals_info.append(processed_network_literal_entry)
        
        return processed_network_literals_info
            

    def process_network_address_objects(self, network_address_objects_list, network_address_objects_info_dict):
        if len(network_address_objects_list) == 0:
            return
        
        # loop through the network address objects
        processed_network_object_info = []
        object_container_name = "virtual_object_container"

        for network_address_object_name in network_address_objects_list:
            # look it up in the dictionary containing the network address object information
            matching_address_object_entry = network_address_objects_info_dict.get(network_address_object_name)

            # now, extract all the required data from the entry
            network_address_value = matching_address_object_entry['value']

            network_address_object_description = None
            try:
                network_address_object_description = matching_address_object_entry['description']
            except KeyError:
                print(f"No description for this object {network_address_object_name}.")

            network_address_object_type = matching_address_object_entry['type']
            is_overridable_object = matching_address_object_entry['overridable']

            processed_network_object_entry = {"network_address_name":network_address_object_name,
                                               "object_container_name":object_container_name,
                                               "network_address_value":network_address_value,
                                               "network_address_description":network_address_object_description,
                                               "network_address_type":network_address_object_type,
                                               "overriden_object":is_overridable_object}
            
            processed_network_object_info.append(processed_network_object_entry)
        
        return processed_network_object_info

    # be aware, you need to process:
        # objects that are part of a group. those objects could not be on the policy, therefore they are not in the DB yet
        # groups that are part of object groups. some recursive shit needs to be done here
    def process_network_address_group_objects(self, network_address_group_objects_list, network_address_group_objects_info_dict, network_address_objects_info_dict):
        if len(network_address_group_objects_list) == 0:
            return
        
        print("I am now processing group objects...")
        print(network_address_group_objects_list)
        processed_network_address_group_object_info = []
        object_container_name = "virtual_object_container"

        # this list will store the names of all the object members in all groups
        object_member_list = []

        # this list will store the names of the group members in all groups
        group_object_member_list = []

        # this list will store the names of the literal objects in all groups
        literal_group_member_list = []
        
        for network_address_group_object_name in network_address_group_objects_list:
            print(f"I am now processing the following group object {network_address_group_object_name}.")
            matching_address_group_object = network_address_group_objects_info_dict.get(network_address_group_object_name)

            # this list will store the names of all the members found for the current network group
            network_address_group_members = []
            network_address_group_description = None
            try:
                network_address_group_description = matching_address_group_object['description']
            except KeyError:
                print(f"No description for group object {network_address_group_object_name}")
            overriden_object = matching_address_group_object['overridable']

            # now we need to process the members. be aware, there are two types of members here:
            # objects and literals. they must be processed separately
            # they will be processed, stored in lists and these lists will be passed to the processing functions
            try:
                print(f"I have found group object members: {matching_address_group_object['objects']}. I will start to process them...")
                for object_member in matching_address_group_object['objects']:
                    # append it to the list tracking all the members of the group
                    network_address_group_members.append(object_member['name'])

                    # if the current member is a network group, add it to the list keeping track of network groups
                    if object_member['type'] == 'NetworkGroup':
                        group_object_member_list.append(object_member['name'])
                    
                    # otherwise, append it to the other list
                    else:
                        object_member_list.append(object_member['name'])

            except KeyError:
                print(f"No object members found for object group {network_address_group_object_name}.")
            
            try:
                print(f"I have found literal members: {matching_address_group_object['literals']}. I will now start to process them")
                for literal_group_member in matching_address_group_object['literals']:
                    # extract the value of the network literal
                    literal_value = literal_group_member['value']

                    # extract the type of the network literal. can be either "Host" or "Network"
                    # the name of the converted object will depend on based on the network literal type
                    literal_type = literal_group_member['type'] 
                    
                    # the literal type can be either a host or a network
                    if literal_type == 'Network':
                        # Define the CIDR notation IP address
                        ip_cidr = literal_value

                        # Create an IPv4 network object
                        network = ipaddress.ip_network(ip_cidr, strict=False)

                        # Extract the network address and netmask
                        network_address = network.network_address
                        netmask = str(network.prefixlen)  # Extract the prefix length instead of full netmask

                    elif literal_type == 'Host':
                        netmask = '32'
                        network_address = literal_value  # Assuming literal_value is the host address

                    else:
                        print("Invalid literal type. Literal is not either 'Host' or 'Network.")
                        continue

                    # create the name of the object (NL_networkaddress_netmask)
                    literal_network_object_name = "NL_" + str(network_address) + "_" + str(netmask)
                    literal_group_member_list.append(literal_network_object_name)

                    # append it to the member list of the object
                    network_address_group_members.append(literal_network_object_name)

            except KeyError:
                print(f"No literal members found for object group {network_address_group_object_name}.")

            # at this point, all the members should be processed, and two lists, one with literals and one with objects
            # should exist. now, these two lists need to be processed just like the non-group memebrs were processed
            processed_network_address_group_object_entry = {"network_address_name": network_address_group_object_name,
                                               "object_container_name": object_container_name,
                                               "network_address_members": network_address_group_members,
                                               "network_address_description": network_address_group_description,
                                               "network_address_type": network_address_group_members,
                                               "overriden_object": overriden_object
                                               }
            
            processed_network_address_group_object_info.append(processed_network_address_group_object_entry)
        
        processed_member_group_objects = []
        processed_member_literals = []
        processed_member_network_objects = []

        processed_member_group_objects.append(self.process_network_address_group_objects(group_object_member_list,  network_address_group_objects_info_dict, network_address_objects_info_dict))
        processed_member_literals.append(self.process_network_literals(literal_group_member_list))
        processed_member_network_objects.append(self.process_network_address_objects(object_member_list, network_address_objects_info_dict))
        
        print("#################GROUP OBJECTS###################",processed_member_group_objects)
        print("#################MEMBER LITERALS###################", processed_member_literals)
        print("#################NETWORK MEMBER OBJECTS ###################",processed_member_network_objects)
        print("#################### MEMBERS OF THE GROUP#################",network_address_group_members)
        return processed_member_group_objects, processed_member_network_objects, processed_member_literals


    def get_network_objects_info(self):
        # retrieve all the network object info from the database
        network_objects_db = self.get_db_objects('network_objects')

        # there are three types of network objects in this case: network address objects, network address group objects and literals
        # literals are not objects that have been explicitly defined, therefore they won't be present in the FMC's database

        # get the information of all network address objects from FMC
        network_address_objects_info = self._api_connection.object.networkaddress.get()
        
        # get the information of all network group objects from FMC
        network_address_group_objects_info = self._api_connection.object.networkgroup.get()

        # in order to process the network addres objects and the network group address objects, we need to know what is what, based on the object names (might use the IDs at some point).
        # we will retrieve all the names of the objects and the group objects
        # we will remove the network literals from the network objects in the db
        # we will look for all the common elements in the names from network_address_objects_info and from network_objects_db. after they are found, they will be removed from the list
        # at this point, we have three additional lists: a list with the literals, a list with the network address objects and al ist with the network group objects
        # the list with address objects and the list with group objects will be proccesed by the process functions. they will return all the information necessary
        # the list with the literals will be merged with the list of network_address_objects since they are kind of the same thing
        
        # retrieve the names of all the network address objects
        fmc_network_objects_list = []
        for fmc_network_object in network_address_objects_info:
            fmc_network_objects_list.append(fmc_network_object['name'])
        
        # retrieve the names of all the network address group objects
        fmc_network_group_objects_list = []
        for fmc_network_group_object in network_address_group_objects_info:
            fmc_network_group_objects_list.append(fmc_network_group_object['name'])

        # convert this to a dictionary for more efficient lookups
        network_address_group_objects_info = {entry['name']: entry for entry in network_address_group_objects_info}
        network_address_objects_info = {entry['name']: entry for entry in network_address_objects_info}

        # Retrieve all network literals from the database
        network_object_literals_list = [network_literal for network_literal in network_objects_db if "NL_" in network_literal]

        # remove all the network literals from the original list
        network_objects_db = [obj for obj in network_objects_db if not obj.startswith("NL_")]

        # find all the network address objects
        network_address_objects_list = [network_object for network_object in network_objects_db if network_object in fmc_network_objects_list]

        # now remove all the network objects
        network_objects_db = [network_object for network_object in network_objects_db if network_object not in network_address_objects_list]

        # this leaves us only with the network group objects in the network_objects_db variable
        # now it is time to process all the objects in order to get the info that will be stored in the database
        
        # process_network_address_group_objects returns all the member objects of all groups in lists. these lists can be
        # added to the existent lists and be procecssed by the network literals and network addres objects processor functions
        # make sure you have unique values in the lists!
        processed_network_group_objects_info, processed_network_members_info, processed_literal_member_info = self.process_network_address_group_objects(network_objects_db, network_address_group_objects_info, network_address_objects_info) or []

        processed_network_literals_info = self.process_network_literals(network_object_literals_list) or []
        
        processed_network_objects_info = self.process_network_address_objects(network_address_objects_list, network_address_objects_info) or []

        # extend the original processed_network_objects_info with the processed_network_literals_info. network objects and literals will be treated in the same way when added to the database
        # extend it with the network members and network literal members of all the group objects
        processed_network_objects_info = processed_network_objects_info + processed_network_literals_info + processed_network_members_info + processed_literal_member_info
        
        # return the info back to the caller
        return processed_network_objects_info, processed_network_group_objects_info

            

    # this function aggregates multiple functions, each responsible for getting data from different objects
    # store all the info as a json, and return the json back to main, which will be responsible for adding it
    # to the database
    def get_objects_data_info(self):
        print(f"I will now start to retrieve information about all the objects.")
        
        # get the zone objects data
        # print(f"######### ZONE INFO RETRIEVAL #########")
        # self.get_zone_objects_info()
    
        # get the network address objects data
        print(f"######### NETWORK OBJECTS INFO RETRIEVAL #########")
        # TODO: make sure you process the geo-location objects!
        network_objects, network_group_objects = self.get_network_objects_info()
        return network_objects, network_group_objects
        # get the port objects data
        print(f"######### PORT OBJECTS INFO RETRIEVAL")

        # get the schedule objects data
        print(f"######### SCHEDULE OBJECTS INFO RETRIEVAL")

        # get the policy users data
        print(f"######### POLICY USERS INFO RETRIEVAL")

        # get the url objects data
        print(f"######### URL OBJECTS INFO RETRIEVAL")

        # get the applications
        print(f"######### L7 APPS INFO RETRIEVAL")
        pass


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
