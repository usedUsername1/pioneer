import utils.helper as helper

# A problem faced at this step is that we can't create objects with the data we get, as the only thing
# we can get and process is mainly a list with the objects that are defined on the policy
# We could, for each object, retrieve all the data about it and process it, however, this would break the modularity
# of the code. The code must be as modular as possible and perform only one operation at time, for as much as possible.
# for example, the workflow is like this: extract all the info, insert it into the database, extract the info about the objects, insert it into the database, and so so on...

# creating objects for each of the elements here at this point wouldn't scale really well, as we would have to have objects for security policies, nat policies and so on.
# since the obejct data is stored differently in each one of them... wait, this will be set via the setter. but even so, the process method will need to be overriden
# which means you'll end up having a shitload of classes for objects.
# i think the best approach whould be to have processor functions for each of the different entity processed (sec policy, nat policy, routing, and other places where the objects are used)

# what if i override the extract_object method based on the policy type? so like, i could have the xtract_object method implemented on the FMCSecurityPolicy class
# in this way, i could keep a single processor function, and I will be able to extracft objects for different types of policies
# extract object info could serve as a central place to hold different functions and it will extract objects based on the parameters passed in to the extract_object

# what if i use objects and initialize them with the info you get from the policy you are processing?
# then i would have somehting like SecurityPolicyObjects, NATPolicyObjects... RoutingObjects and so on... that would be a lot of classes to create and maintain
# plus, they are not really different objects per se, it's just a different way of storing the info

# in order to use process_objects and the other functions in other places, very simple: create a new class and put them in there
class Policy:
    def __init__(self, policy_info) -> None:
        self._policy_info = policy_info
        self._name = None
        self._source_zones = None
        self._destination_zones = None
        self._container_name = None
        self._container_index = None
        self._status = None
        self._policy_container = None
        self._description = None
        self._comments = None
        self._log_start = None
        self._log_end = None
        self._log_settings = None
    
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

    def get_source_zones(self):
        return self.process_objects('security_zone', 'source')

    def set_source_zones(self, source_zones):
        self._source_zones = source_zones

    def get_destination_zones(self):
        return self.process_objects('security_zone', 'destination')

    def set_destination_zones(self, destination_zones):
        self._destination_zones = destination_zones

    def get_description(self):
        return self._description

    def set_description(self, description):
        self._description = description

    def get_comments(self):
        return self._comments

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

    def get_log_settings(self):
        return self._log_setting

    def set_log_setting(self, log_setting):
        self._log_setting = log_setting
    
    def process_objects(self, object_type, flow_direction):
        helper.logging.debug("Called extract_security_zones()")
        """
        Process security zones defined in the security policy.

        Args:
            zone_type (str): Type of security zones ('sourceZones' or 'destinationZones').

        Returns:
            list: List of security zone names.
        """
        helper.logging.info(f"################## {object_type} processing ##################.")
        processed_objects_list = []

        if flow_direction is not None:
            helper.logging.info(f"I am looking for {flow_direction} objects.")

        raw_objects = self.get_raw_objects_info(object_type, flow_direction)

        if raw_objects == ['any']:
            helper.logging.info(f"No explicit: {object_type}, flow: {flow_direction} defined on this policy. Defaulting to 'any'.")
            return ['any']

        # Loop through the zone objects
        for raw_object in raw_objects:
            helper.logging.info(f"Processing object: {raw_object}.")
            # Retrieve the zone name
            processed_zone_name = self.extract_object_info(raw_object, object_type)
            helper.logging.info(f"Processed object: {processed_zone_name}.")

            # Append it to the list
            processed_objects_list.append(processed_zone_name)
            helper.logging.info(f"I am done processing {raw_object}.")

        helper.logging.debug(f"Finished processing all the {object_type} objects. This is the list with the processed list {processed_objects_list}.")
        return processed_objects_list

    def extract_object_info(raw_object, object_type):
        pass
    
    def get_raw_objects_info(object_type, flow_direction):
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
        self._url_objects = None
        self._l7_apps = None
        self._section = None
        self._action = None
    
    def set_category(self, category):
        self._category = category

    def set_source_networks(self, source_networks):
        self._source_networks = source_networks

    def get_source_networks(self):
        return self.process_objects("network_address_object", "source")

    def set_destination_networks(self, destination_networks):
        self._destination_networks = destination_networks

    def get_destination_networks(self):
        return self.process_objects("network_address_object", "destination")

    def set_source_ports(self, source_ports):
        self._source_ports = source_ports

    def get_source_ports(self):
        return self.process_objects("port_object", "source")

    def set_destination_ports(self, destination_ports):
        self._destination_ports = destination_ports

    def get_destination_ports(self):
        return self.process_objects("port_object", "destination")

    def set_schedule_objects(self, schedule_objects):
        self._schedule_objects = schedule_objects

    def get_schedule_objects(self):
        return self.process_objects("schedule_object", None)

    def set_users(self, users):
        self._users = users

    def get_users(self):
        return self.process_objects("user_object", None)

    def set_urls(self, urls):
        self._url_objects = urls

    def get_urls(self):
        return self.process_objects("url_object", None)

    def set_policy_apps(self, policy_apps):
        self._l7_apps = policy_apps

    def get_policy_apps(self):
        return self.process_objects("l7_app_object", None)

    def set_section(self, section):
        self._section = section
    
    def get_section(self):
        return self._section
    
    def set_action(self, action):
        self._action = action
    
    def get_action(self):
        return self._action

    def get_raw_objects_info(self, object_type, flow_direction):
        raw_objects = []
        
        if flow_direction == 'source':
            match object_type:
                case "security_zone":
                    raw_objects = self._source_zones
                case "network_address_object":
                    raw_objects = self._source_networks
                case "port_object":
                    raw_objects = self._source_ports
                
        elif flow_direction == 'destination':
            match object_type:
                case "security_zone":
                    raw_objects = self._destination_zones
                case "network_address_object":
                    raw_objects = self._destination_networks
                case "port_object":
                    raw_objects = self._destination_ports
        else:
            match object_type:
                case "user_object":
                    raw_objects = self._users
                case "schedule_object":
                    raw_objects = self._schedule_objects
                case "url_objects":
                    raw_objects = self._url_objects
                case "l7_app_object":
                    raw_objects = self._l7_apps

        return raw_objects

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
            "sec_policy_name": self._name,
            "sec_policy_container_name": self._container_name,
            "security_policy_index": self._container_index,
            "sec_policy_category": self._category,
            "sec_policy_status": self._status,
            "sec_policy_source_zones": self.get_source_zones(),
            "sec_policy_destination_zones": self.get_destination_zones(),
            #TODO: continue processing from here
            "sec_policy_source_networks": self.get_source_networks(),
            "sec_policy_destination_networks": self.get_destination_networks(),
            "sec_policy_source_ports": self.get_source_ports(),
            "sec_policy_destination_ports": self.get_destination_ports(),
            "sec_policy_schedules": self.get_schedule_objects(),
            "sec_policy_users": self.get_users(),
            "sec_policy_urls": self.get_urls(),
            "sec_policy_apps": self.get_policy_apps(),
            "sec_policy_description": self._description,
            "sec_policy_comments": self.get_comments(),
            "sec_policy_log_settings": self.get_log_settings(),
            "sec_policy_log_start": self._log_start,
            "sec_policy_log_end": self._log_end,
            "sec_policy_section": self._section,
            "sec_policy_action": self._action,
        }

        helper.logging.info(f"Processed policy {self._name}. Processed entry: {processed_policy_entry}")
        return processed_policy_entry

class NATPolicy:
    pass