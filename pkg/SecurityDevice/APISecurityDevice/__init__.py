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
        """
        Retrieve information about managed devices.

        Returns:
            list: List of dictionaries containing information about managed devices.
        """
        print("########################## GETTING MANAGED DEVICES INFO ##########################")

        # Execute the request to retrieve information about the devices
        managed_devices = self._api_connection.device.devicerecord.get()

        # Initialize an empty list to store managed devices info
        managed_devices_info = []

        # Loop through the information about managed devices
        for managed_device in managed_devices:
            device_name = managed_device['name']
            assigned_security_policy_container = managed_device['accessPolicy']['name']
            device_hostname = managed_device['hostName']
            device_cluster = None

            # Check if the device is part of a cluster
            try:
                device_cluster = managed_device['metadata']['containerDetails']['name']
            except KeyError:
                print(f"Device {device_name} is not part of a device cluster.")

            # Create a dictionary for the managed device entry
            managed_device_entry = {
                "managed_device_name": device_name,
                "assigned_security_policy_container": assigned_security_policy_container,
                "hostname": device_hostname,
                "cluster": device_cluster
            }

            # Append the managed devices info to the list
            managed_devices_info.append(managed_device_entry)

        # Return the list to the caller
        return managed_devices_info

    # this function takes the list with policy container names and loops through each of them.
    # for every container, it tries to find the container parent. if the parent container is a child of another container, it will find that parent too
    # ACP = access control policy = the security policy container used by FMC
    def get_sec_policy_container_info(self, policy_container_names_list):
        """
        Retrieve information about security policy containers and their parent-child relationships.

        Args:
            policy_container_names_list (list): List of security policy container names.

        Returns:
            list: List of lists containing child-parent mappings for the security policy containers.
        """
        # Loop through the policy containers provided by the user
        for policy_container_name in policy_container_names_list:
            # Check if the current container name was already imported
            is_duplicate_acp = self.verify_duplicate('security_policy_containers_table', 'security_policy_container_name', policy_container_name)
            print(is_duplicate_acp)
            if is_duplicate_acp:
                print(f"Container: {policy_container_name} is already imported. Skipping it...")
                continue

            try:
                # Create the list that will store the dictionary that will store the child_acp -> parent_acp mapping
                child_parent_list = []

                # Retrieve the info for the current acp
                acp_info = self._api_connection.policy.accesspolicy.get(name=policy_container_name)

                # If the policy does not have a parent policy at all, then return a mapping with the current policy name and None to the caller
                if not acp_info['metadata']['inherit']:
                    child_parent_list.append([policy_container_name, None])
                    return child_parent_list
                else:
                    # Try to retrieve the parent of the policy. There is an "inherit" boolean attribute in the acp_info response. If it is equal to 'true', then the policy has a parent
                    while acp_info['metadata']['inherit']:
                        # Get the name of the current ACP name
                        current_acp_name = acp_info['name']

                        # Get the name of the acp parent
                        acp_parent = acp_info['metadata']['parentPolicy']['name']

                        print(f"Container: {current_acp_name} is the child of a container. Its parent is: {acp_parent}.")

                        # Check if the parent ACP is already imported in the database. If a parent is already present, then it means the rest of the parents are present
                        # Create the mapping of the current child and its parent, and return it to the caller
                        is_duplicate_acp = self.verify_duplicate('security_policy_containers_table', 'security_policy_container_name', acp_parent)
                        if is_duplicate_acp:
                            print(f"Parent container: {acp_parent} is already imported. I have only imported its child. I will skip further processing.")
                            child_parent_list.append([current_acp_name, acp_parent])
                            return child_parent_list

                        # Retrieve the parent info to be processed in the next iteration of the loop
                        acp_info = self._api_connection.policy.accesspolicy.get(name=acp_parent)

                        # Update the list containing info about the parents/children ACPs
                        child_parent_list.append([current_acp_name, acp_parent])

                    # If the parent policy does not have a parent, then map the ACP to None
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
        """
        Retrieve information about security policies from the specified policy containers.

        Args:
            sec_policy_container_list (list): List of security policy container names.

        Returns:
            list: List of dictionaries containing information about security policies.
        """
        # Loop through the policy containers provided by the user
        sec_policy_info = []

        for sec_policy_container in sec_policy_container_list:
            sec_policies = self._api_connection.policy.accesspolicy.accessrule.get(container_name=sec_policy_container)
            print(f"##########################{sec_policy_container}##########################")

            # Now loop through the policies
            for sec_policy in sec_policies:
                # Retrieve information for each policy
                sec_policy_entry = self.process_sec_policy_entry(sec_policy, sec_policy_container)
                sec_policy_info.append(sec_policy_entry)

        return sec_policy_info

    def process_sec_policy_entry(self, sec_policy, sec_policy_container_name):
        """
        Process and extract information for a single security policy.

        Args:
            sec_policy (dict): Security policy information.
            sec_policy_container_name (str): Name of the security policy container.

        Returns:
            dict: Dictionary containing information about the security policy.
        """
        # Retrieve information for each policy
        sec_policy_name = sec_policy['name']
        sec_policy_category = sec_policy['metadata']['category']
        sec_policy_status = 'enabled' if sec_policy['enabled'] else 'disabled'

        sec_policy_source_zones = self.process_security_zones(sec_policy, 'sourceZones')
        sec_policy_destination_zones = self.process_security_zones(sec_policy, 'destinationZones')
        sec_policy_source_networks = self.process_network_objects(sec_policy, 'sourceNetworks')
        sec_policy_destination_networks = self.process_network_objects(sec_policy, 'destinationNetworks')
        sec_policy_source_ports = self.process_ports_objects(sec_policy, 'sourcePorts')
        sec_policy_destination_ports = self.process_ports_objects(sec_policy, 'destinationPorts')
        sec_policy_schedule_objects = self.process_schedule_objects(sec_policy)
        sec_policy_users = self.process_policy_users(sec_policy)
        sec_policy_urls = self.process_policy_urls(sec_policy)
        sec_policy_apps = self.process_policy_apps(sec_policy)

        sec_policy_description = sec_policy.get('description', '')
        sec_policy_comments = self.process_policy_comments(sec_policy)
        sec_policy_log_settings = ['FMC'] if sec_policy['sendEventsToFMC'] else []
        sec_policy_log_settings += ['Syslog'] if sec_policy['enableSyslog'] else []
        sec_policy_log_start = sec_policy['logBegin']
        sec_policy_log_end = sec_policy['logEnd']
        sec_policy_section = sec_policy['metadata']['section']
        sec_policy_action = sec_policy['action']

        # Create a dictionary for the security policy entry
        sec_policy_entry = {
            "sec_policy_name": sec_policy_name,
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

        return sec_policy_entry
    

    def get_device_version(self):
        """
        Retrieve the version of the device's server.

        Returns:
            str: Version of the device's server.
        """
        try:
            # Retrieve device system information to get the server version
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
        """
        Process security zones defined in the security policy.

        Args:
            sec_policy (dict): Security policy information.
            zone_type (str): Type of security zones ('sourceZones' or 'destinationZones').

        Returns:
            list: List of security zone names.
        """
        print(f"####### ZONE PROCESSING ####### ")
        zone_list = []

        try:
            print(f"I am looking for {zone_type} objects...")
            zone_objects = sec_policy[zone_type]['objects']
            print(f"I have found {zone_type} objects: {zone_objects}. I will now start to process them...")

            # Loop through the zone objects
            for zone_object in zone_objects:
                # Retrieve the zone name
                zone_name = zone_object['name']

                # Append it to the list
                zone_list.append(zone_name)
                print(f"I am done processing {zone_object}. I have extracted the following data: name: {zone_name}")

        except KeyError:
            print(f"It looks like there are no {zone_type} objects defined on this policy.")
            # If there are no zones defined on the policy, then return 'any'
            zone_list = ['any']

        return zone_list


    def convert_network_literals_to_objects(self, network_literals):
        """
        Convert network literals to objects.

        Args:
            network_literals (list): List of network literals.

        Returns:
            list: List of network object names.
        """
        network_objects_list = []

        # Loop through the network literals.
        for network_literal in network_literals:

            # Extract the value of the network literal
            literal_value = network_literal['value']

            # Extract the type of the network literal. Can be either "Host" or "Network"
            # The name of the converted object will depend on the network literal type
            literal_type = network_literal['type']

            # The literal type can be either a host or a network
            if literal_type == 'Network':
                # Define the CIDR notation IP address
                ip_cidr = literal_value

                # Create an IPv4 network object
                network = ipaddress.ip_network(ip_cidr, strict=False)

                # Extract the network address and netmask
                network_address = network.network_address
                netmask = str(network.prefixlen)  # Extract the prefix length instead of the full netmask

            elif literal_type == 'Host':
                netmask = '32'
                network_address = literal_value  # Assuming literal_value is the host address

            else:
                print("Invalid literal type. Literal is not either 'Host' or 'Network.")
                continue

            # Create the name of the object (NL_networkaddress_netmask)
            network_object_name = "NL_" + str(network_address) + "_" + str(netmask)
            network_objects_list.append(network_object_name)

        return network_objects_list


    def process_network_objects(self, sec_policy, network_object_type):
        """
        Process network objects and literals defined in the security policy.

        Args:
            sec_policy (dict): Security policy information.
            network_object_type (str): Type of network objects ('sourceNetworks' or 'destinationNetworks').

        Returns:
            list: List of network object names.
        """
        print(f"####### NETWORK OBJECTS PROCESSING ####### ")
        network_objects_list = []

        # Check for objects
        try:
            print(f"I am looking for {network_object_type} objects...")
            network_objects = sec_policy[network_object_type]['objects']
            network_objects_list.extend(obj['name'] for obj in network_objects)
        except KeyError:
            print(f"It looks like there are no {network_object_type} objects on this policy.")

        # Check for literals
        try:
            print(f"I am looking for {network_object_type} literals...")
            network_literals = sec_policy[network_object_type]['literals']
            print(f"I have found {network_object_type} literals. These are: {network_literals}. "
                f"I will now start to process them...")
            network_objects_list += self.convert_network_literals_to_objects(network_literals)
        except KeyError:
            print(f"It looks like there are no {network_object_type} literals on this policy.")

        # Append 'any' only if neither objects nor literals are found
        if not network_objects_list:
            network_objects_list.append('any')

        return network_objects_list


    def process_ports_objects(self, sec_policy, port_object_type):
        """
        Process port objects and literals defined in the security policy.

        Args:
            sec_policy (dict): Security policy information.
            port_object_type (str): Type of port objects ('sourcePorts' or 'destinationPorts').

        Returns:
            list: List of port object names.
        """
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
        """
        Process schedule objects defined in the security policy.

        Args:
            sec_policy (dict): Security policy information.

        Returns:
            list: List of schedule object names.
        """
        print(f"####### SCHEDULE OBJECTS PROCESSING ####### ")
        schedule_object_list = []

        try:
            print(f"I am looking for schedule objects...")
            schedule_objects = sec_policy['timeRangeObjects']
            print(f"I have found schedule objects: {schedule_objects}. I will now start to process them...")

            # Loop through the schedule objects
            for schedule_object in schedule_objects:
                # Retrieve the schedule object name
                schedule_object_name = schedule_object['name']

                # Append it to the list
                schedule_object_list.append(schedule_object_name)
                print(f"I am done processing {schedule_object}. I have extracted the following data: name: {schedule_object_name}")

        except KeyError:
            print(f"It looks like there are no schedule objects defined on this policy.")
            # If there are no schedules defined on the policy, then return 'any'
            schedule_object_list = ['any']

        return schedule_object_list

    # TODO: maybe i need to process more stuff than names here
    def process_policy_users(self, sec_policy):
        """
        Process policy users defined in the security policy.

        Args:
            sec_policy (dict): Security policy information.

        Returns:
            list: List of policy user names.
        """
        print(f"####### USERS PROCESSING ####### ")
        policy_user_list = []

        try:
            print(f"I am looking for policy users...")
            policy_users = sec_policy['users']['objects']
            print(f"I have found policy users: {policy_users}. I will now start to process them...")

            # Loop through the policy user objects
            for policy_user_object in policy_users:
                # Retrieve the policy user name
                policy_user_name = policy_user_object['name']

                # Append it to the list
                policy_user_list.append(policy_user_name)
                print(f"I am done processing {policy_user_object}. I have extracted the following data: name: {policy_user_name}")

        except KeyError:
            print(f"It looks like there are no policy users defined on this policy.")
            # If there are no users defined on the policy, then return 'any'
            policy_user_list = ['any']

        return policy_user_list

    # there are three cases which need to be processed here. the url can be an object, a literal, or a category with reputation
    def process_policy_urls(self, sec_policy):
        """
        Process policy URLs defined in the security policy.

        Args:
            sec_policy (dict): Security policy information.

        Returns:
            list: List of policy URL names, literals, or categories.
        """
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

                # TODO: Decide if the reputation is actually needed
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
        """
        Process Layer 7 (L7) applications defined in the security policy.

        Args:
            sec_policy (dict): Security policy information.

        Returns:
            list: List of Layer 7 application names.
        """
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
            print(f"It looks like there are no L7 application filters on this policy.")

        try:
            print(f"I am looking for Inline L7 application filters...")

            # Access the Inline L7 application filters from the 'sec_policy' dictionary
            policy_inline_l7_app_filters = sec_policy['applications']['inlineApplicationFilters']

            print(f"I have found Inline L7 application filters...: {policy_inline_l7_app_filters}. I will now start to process them...")

            # Extract the keys from the first dictionary in the 'policy_inline_l7_app_filters' list.
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
        """
        Process comments from the security policy.

        Args:
            sec_policy (dict): Security policy information.

        Returns:
            list: List of dictionaries with comment user and content.
                  Returns None if no comments are found.
        """
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

                # append a dictionary with the user who made the comment and the content of the comment
                comments_list.append([comment_user, comment_content])
        except KeyError:
            print(f"It looks like there are no comments on this policy")
            comments_list = None

        return comments_list
    

    # def get_zone_objects_info(self):
    #     pass

    def process_network_literals(self, network_address_literals):
        """
        Process network address literals.

        Args:
            network_address_literals (list): List of network address literals.

        Returns:
            list: List of dictionaries containing processed network literals information.
        """
        if not network_address_literals:
            return []

        processed_network_literals_info = []
        object_container_name = "virtual_object_container"
        literal_object_description = "Originally a literal value. Converted to object by Pioneer."

        for current_network_literal in network_address_literals:
            # Split the string by the "_" to extract subnet and netmask.
            # Example output: ['NL', '10.10.10.10', '32']
            split_network_literal = current_network_literal.split('_')
            network_literal_subnet, network_literal_netmask = split_network_literal[1], split_network_literal[2]

            # Determine the network address type (Host or Network)
            network_address_type = 'Host' if network_literal_netmask == '32' else 'Network'

            # Create the object value string
            network_object_value = f"{network_literal_subnet}/{network_literal_netmask}"

            # Build the processed network literal entry
            processed_network_literal_entry = {
                "network_address_name": current_network_literal,
                "object_container_name": object_container_name,
                "network_address_value": network_object_value,
                "network_address_description": literal_object_description,
                "network_address_type": network_address_type,
                "overridable_object": False  # Literals cannot be overridden
            }

            processed_network_literals_info.append(processed_network_literal_entry)

        return processed_network_literals_info
            

    def process_network_address_objects(self, network_address_objects_list, network_address_objects_info_dict):
        """
        Process network address objects.

        Args:
            network_address_objects_list (list): List of network address object names.
            network_address_objects_info_dict (dict): Dictionary containing information about network address objects.

        Returns:
            list: List of dictionaries containing processed network objects information.
        """
        if not network_address_objects_list:
            return []

        processed_network_object_info = []
        object_container_name = "virtual_object_container"

        for network_address_object_name in network_address_objects_list:
            # Look up the object in the dictionary containing the network address object information
            matching_address_object_entry = network_address_objects_info_dict.get(network_address_object_name, {})

            # Extract all the required data from the entry
            network_address_value = matching_address_object_entry.get('value', '')
            network_address_object_description = matching_address_object_entry.get('description', None)
            network_address_object_type = matching_address_object_entry.get('type', '')
            is_overridable_object = matching_address_object_entry.get('overridable', False)

            # Build the processed network object entry
            processed_network_object_entry = {
                "network_address_name": network_address_object_name,
                "object_container_name": object_container_name,
                "network_address_value": network_address_value,
                "network_address_description": network_address_object_description,
                "network_address_type": network_address_object_type,
                "overriden_object": is_overridable_object
            }

            processed_network_object_info.append(processed_network_object_entry)

        return processed_network_object_info

    # be aware, you need to process:
        # objects that are part of a group. those objects could not be on the policy, therefore they are not in the DB yet
        # groups that are part of object groups. some recursive shit needs to be done here
    def process_network_address_group_objects(self, network_address_group_objects_list, network_address_group_objects_info_dict):
        """
        Process network address group objects.

        Args:
            network_address_group_objects_list (list): List of network address group object names.
            network_address_group_objects_info_dict (dict): Dictionary containing information about network address group objects.

        Returns:
            tuple: A tuple containing processed network group objects information, object members list,
                   and literal group members list.
        """
        if not network_address_group_objects_list:
            return [], [], []

        print("I am now processing group objects...")
        print(network_address_group_objects_list)
        processed_network_address_group_object_info = []
        object_container_name = "virtual_object_container"

        # Lists to store names of all object members, group members, and literal members
        object_member_list, group_object_member_list, literal_group_member_list = [], [], []

        for network_address_group_object_name in network_address_group_objects_list:
            print(f"I am now processing the following group object {network_address_group_object_name}.")
            matching_address_group_object = network_address_group_objects_info_dict.get(network_address_group_object_name, {})

            network_address_group_members = matching_address_group_object.get('objects', [])
            network_address_group_description = matching_address_group_object.get('description', None)
            overriden_object = matching_address_group_object.get('overridable', False)

            for object_member in network_address_group_members:
                print(network_address_group_members)
                network_address_group_members.append(object_member['name'])
                if object_member['type'] == 'NetworkGroup':
                    group_object_member_list.append(object_member['name'])
                else:
                    object_member_list.append(object_member['name'])

            literals = matching_address_group_object.get('literals', [])
            literal_objects_list = self.convert_network_literals_to_objects(literals)
            literal_group_member_list.extend(literal_objects_list)
            network_address_group_members.extend(literal_objects_list)

            processed_network_address_group_object_entry = {
                "network_address_group_name": network_address_group_object_name,
                "object_container_name": object_container_name,
                "network_address_group_members": network_address_group_members,
                "network_address_group_description": network_address_group_description,
                "overriden_object": overriden_object
            }

            processed_network_address_group_object_info.append(processed_network_address_group_object_entry)

        nested_group_objects, nested_objects, nested_literals = self.process_network_address_group_objects(group_object_member_list, network_address_group_objects_info_dict)

        object_member_list.extend(nested_objects)
        literal_group_member_list.extend(nested_literals)
        processed_network_address_group_object_info.extend(nested_group_objects)

        print(processed_network_address_group_object_info, object_member_list, literal_group_member_list)

        return processed_network_address_group_object_info, object_member_list, literal_group_member_list

    # TODO: Should the elements of the list be unique when returned?
    # TODO: Process the geo-location objects separately
    def get_network_objects_info(self):
        # Retrieve all network object info from the database
        network_objects_db = self.get_db_objects('network_objects')

        # Get the information of all network address objects from FMC
        network_address_objects_info = self._api_connection.object.networkaddress.get()
        
        # Get the information of all network group objects from FMC
        network_address_group_objects_info = self._api_connection.object.networkgroup.get()

        # Retrieve the names of all network address objects
        fmc_network_objects_list = [fmc_network_object['name'] for fmc_network_object in network_address_objects_info]
        
        # Convert these to dictionaries for more efficient lookups
        network_address_group_objects_info = {entry['name']: entry for entry in network_address_group_objects_info}
        network_address_objects_info = {entry['name']: entry for entry in network_address_objects_info}

        # Retrieve all network literals from the database
        network_object_literals_list = [network_literal for network_literal in network_objects_db if "NL_" in network_literal]

        # Remove all the network literals from the original list
        network_objects_db = [obj for obj in network_objects_db if not obj.startswith("NL_")]

        # Find all the network address objects
        network_address_objects_list = [network_object for network_object in network_objects_db if network_object in fmc_network_objects_list]

        # Remove all the network objects, leaving only the network group objects in the network_objects_db variable
        network_objects_db = [network_object for network_object in network_objects_db if network_object not in network_address_objects_list]

        # Process all the network objects to get the info that will be stored in the database
        processed_network_group_objects_info, network_members_list, literal_members_list = [], [], []
        # try:
        processed_network_group_objects_info, network_members_list, literal_members_list = self.process_network_address_group_objects(network_objects_db, network_address_group_objects_info)
        # except Exception as err:
        #     print(err)

        # Extend the network_object_literals_list and network_address_objects_list with the members that were previously found
        network_object_literals_list.extend(literal_members_list)

        # Send the full new list to processing
        processed_network_literals_info = self.process_network_literals(network_object_literals_list) or []
        
        network_address_objects_list.extend(network_members_list)
        processed_network_objects_info = self.process_network_address_objects(network_address_objects_list, network_address_objects_info) or []

        # Extend the original processed_network_objects_info with the processed_network_literals_info.
        # Network objects and literals will be treated in the same way when added to the database.
        # Extend it with the network members and network literal members of all the group objects
        processed_network_objects_info.extend(processed_network_literals_info)

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
