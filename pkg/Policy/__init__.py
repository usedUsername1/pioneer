import utils.helper as helper

class Policy:
    def __init__(self, policy_info) -> None:
        self._policy_info = policy_info
        self._name = None
        self._container_name = None
        self._container_index = None
        self._status = None
        self._policy_container = None
        self._source_zones = None
        self._destination_zones = None
        self._description = None
        self._comments = None
        self._log_start = None
        self._log_end = None
        self._log_settings = None

    # Define setters and getters directly
    
    def get_name(self):
        return self._name
    
    def set_name(self, name):
        self._name = name

    def set_container_name(self, name):
        self._container_name = name

    def get_container_name(self):
        return self._container_name
    
    def set_container_index(self, index):
        self._container_index = index
    
    def get_container_index(self):
        return self._container_index

    def get_status(self):
        return self._status

    def set_status(self, status):
        self._status = status

    def get_processed_source_zones(self):
        return self.process_security_zones('source_networks')

    def set_source_zones(self, source_zones):
        self._source_zones = source_zones

    def get_processed_destination_zones(self):
        return self.process_security_zones('destination_networks')

    def set_destination_zones(self, destination_zones):
        self._destination_zones = destination_zones

    def get_description(self):
        return self._description

    def set_description(self, description):
        self._description = description

    def get_processed_comments(self, comments):
        self._comments = comments

    def set_comments(self, comments):
        self._comments = comments

    def get_log_start(self):
        return self._log_start

    def set_log_start(self, log_start):
        self._log_start = log_start

    def get_log_end(self):
        return self._log_end

    def set_log_end(self, log_end):
        self._log_end = log_end

    def get_processed_log_settings(self):
        return self._log_setting

    def set_log_setting(self, log_setting):
        self._log_setting = log_setting
    
    # the processor functions are responsible for processing the output which will be returned to the getter functions
    def process_security_zones(self, zone_type):
        helper.logging.debug("Called extract_security_zones()")
        """
        Process security zones defined in the security policy.

        Args:
            zone_type (str): Type of security zones ('sourceZones' or 'destinationZones').

        Returns:
            list: List of security zone names.
        """
        helper.logging.info("################## SECURITY ZONE PROCESSING ##################.")
        zone_list = []

        try:
            helper.logging.info(f"I am looking for {zone_type} objects.")

            # Determine which type of zones to retrieve based on zone_type
            if zone_type == 'source_zones':
                zone_objects = self.get_processed_source_zones()
            elif zone_type == 'destination_zones':
                zone_objects = self.get_processed_destination_zones()

            helper.logging.info(f"I have found {zone_type} objects. I will now start to process them.")
            helper.logging.debug(f"Zone objects found: {zone_objects}.")

            # Loop through the zone objects
            for zone_object in zone_objects:
                helper.logging.debug(f"Processing zone object: {zone_object}.")
                # Retrieve the zone name
                processed_zone_name = self.extract_zones_info(zone_object)
                helper.logging.info(f"Processed zone object: {processed_zone_name}.")

                # Append it to the list
                zone_list.append(processed_zone_name)
                helper.logging.debug(f"I am done processing {zone_object}. I have extracted the following data: name: {processed_zone_name}")

        except KeyError:
            helper.logging.info(f"It looks like there are no {zone_type} objects defined on this policy.")
            # If there are no zones defined on the policy, then return 'any'
            zone_list = ['any']
        
        helper.logging.debug(f"Finished processing all the zones. This is the list with the processed list {zone_list}.")
        return zone_list

    def extract_zones_info(zone_object):
        pass

    def extract_network_objects_info():
        pass

    def extract_port_object_info():
        pass

class SecurityPolicy(Policy):
    def __init__(self, policy_info) -> None:
        super().__init__(policy_info)
        self._category = None
        self._container_index = None
        self._source_networks = None
        self._destination_networks = None
        self._source_ports = None
        self._destination_ports = None
        self._schedule_objects = None
        self._users = None
        self._urls = None
        self._policy_apps = None
        self._section = None
        self._action = None

    def set_category(self, category):
        self._category = category

    def get_category(self):
        return self._category

    def set_source_networks(self, source_networks):
        self._source_networks = source_networks

    def get_processed_source_networks(self):
        return self._source_networks

    def set_destination_networks(self, destination_networks):
        self._destination_networks = destination_networks

    def get_processed_destination_networks(self):
        return self._destination_networks

    def set_source_ports(self, source_ports):
        self._source_ports = source_ports

    def get_processed_source_ports(self):
        return self._source_ports

    def set_destination_ports(self, destination_ports):
        self._destination_ports = destination_ports

    def get_processed_destination_ports(self):
        return self._destination_ports

    def set_schedule_objects(self, schedule_objects):
        self._schedule_objects = schedule_objects

    def get_processed_schedule_objects(self):
        return self._schedule_objects

    def set_users(self, users):
        self._users = users

    def get_processed_users(self):
        return self._users

    def set_urls(self, urls):
        self._urls = urls

    def get_processed_urls(self):
        return self._urls

    def set_policy_apps(self, policy_apps):
        self._policy_apps = policy_apps

    def get_processed_policy_apps(self):
        return self._policy_apps

    def set_section(self, section):
        self._section = section

    def get_section(self):
        return self._section

    def set_action(self, action):
        self._action = action

    def get_action(self):
        return self._action
    
    # implement try and excepts here!, not in setters
    def process_sec_policy_info(self):
        """
        Process and extract information for a single security policy.

        Returns:
            dict: Dictionary containing information about the security policy.
        """
        helper.logging.debug("Called process_sec_policy_info()")

        # The values set here are the raw values info. It needs to be fully processed before it gets inserted in the database
        # The getter implementation should process the raw values and return whatever is needed in order to be inserted in the database
        self.set_name()
        self.set_container_name()
        self.set_container_index()
        self.set_status()
        self.set_category()
        self.set_source_zones()
        self.set_destination_zones()
        self.set_source_networks()
        self.set_destination_networks()
        self.set_source_ports()
        self.set_destination_ports()
        self.set_schedule_objects()
        self.set_users()
        self.set_urls()
        self.set_policy_apps()
        self.set_description()
        self.set_comments()
        self.set_log_setting()
        self.set_log_start()
        self.set_log_end()
        self.set_section()
        self.set_action()

        helper.logging.info(f"\n\n################## PROCESSING SECURITY POLICY: {self._name}. CONTAINER:  {self._container_name}. RULE INDEX: {self._container_index}.##################")
        helper.logging.debug(f"Security policy data: {self._policy_info}")

        processed_policy_entry = {
            "sec_policy_name": self._name(),
            "sec_policy_container_name": self._container_name(),
            "security_policy_index": self._container_index,
            "sec_policy_category": self._category(),
            "sec_policy_status": self._status(),
            "sec_policy_source_zones": self.get_processed_source_zones(),
            "sec_policy_destination_zones": self.get_processed_destination_zones(),
            "sec_policy_source_networks": self.get_processed_source_networks(),
            "sec_policy_destination_networks": self.get_processed_destination_networks(),
            "sec_policy_source_ports": self.get_processed_source_ports(),
            "sec_policy_destination_ports": self.get_processed_destination_ports(),
            "sec_policy_schedules": self.get_processed_schedule_objects(),
            "sec_policy_users": self.get_processed_users(),
            "sec_policy_urls": self.get_processed_urls(),
            "sec_policy_apps": self.get_processed_policy_apps(),
            "sec_policy_description": self._description(),
            "sec_policy_comments": self.get_processed_comments(),
            "sec_policy_log_settings": self.get_processed_log_settings(),
            "sec_policy_log_start": self._log_start(),
            "sec_policy_log_end": self._log_end(),
            "sec_policy_section": self._section(),
            "sec_policy_action": self._action(),
        }

        helper.logging.info(f"Processed policy {self.get_name()}. Processed entry: {processed_policy_entry}")
        return processed_policy_entry

class NATPolicy:
    pass