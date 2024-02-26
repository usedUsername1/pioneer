import utils.helper as helper
from abc import abstractmethod

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
class Rule:
    pass

class Policy:
    """
    Class representing a policy.

    This class serves as a base class for different types of policies.

    Args:
        policy_info (dict): Information about the policy.

    Attributes:
        _policy_info (dict): Information about the policy.
        _name (str): Name of the policy.
        _source_zones (list): List of source security zones associated with the policy.
        _destination_zones (list): List of destination security zones associated with the policy.
        _container_name (str): Name of the container holding the policy.
        _container_index (int): Index of the container holding the policy.
        _status (str): Status of the policy.
        _description (str): Description of the policy.
        _comments (str): Comments associated with the policy.
        _log_start (datetime): Start time for logging.
        _log_end (datetime): End time for logging.
        _log_settings (str): Logging settings for the policy.
    """

    def __init__(self, policy_info) -> None:
        """
        Initialize a Policy object with the given policy information.

        Args:
            policy_info (dict): Information about the policy.
        """
        helper.logging.debug("Called Policy::__init__()")
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
    
    def get_policy_info(self):
        """
        Retrieve the policy information stored in the object.

        Returns:
            Any: The policy information stored in the object.
        """
        helper.logging.debug("Called Policy::get_policy_info()")
        return self._policy_info

    def get_name(self):
        """
        Retrieve the name of the policy.

        Returns:
            str: The name of the policy.
        """
        helper.logging.debug("Called Policy::get_name()")
        return self._name

    def set_name(self, name):
        """
        Set the name of the policy.

        Args:
            name (str): The name to set for the policy.
        """
        helper.logging.debug("Called Policy::set_name()")
        self._name = name

    def set_container_name(self, name):
        """
        Set the name of the container holding the policy.

        Args:
            name (str): The name of the container.
        """
        helper.logging.debug("Called Policy::set_container_name()")
        self._container_name = name

    def get_container_name(self):
        """
        Retrieve the name of the container holding the policy.

        Returns:
            str: The name of the container.
        """
        helper.logging.debug("Called Policy::get_container_name()")
        return self._container_name

    def set_container_index(self, index):
        """
        Set the index of the container holding the policy.

        Args:
            index (int): The index of the container.
        """
        helper.logging.debug("Called Policy::set_container_index()")
        self._container_index = index

    def get_container_index(self):
        """
        Retrieve the index of the container holding the policy.

        Returns:
            int: The index of the container.
        """
        helper.logging.debug("Called Policy::get_container_index()")
        return self._container_index

    def get_status(self):
        """
        Retrieve the status of the policy.

        Returns:
            str: The status of the policy.
        """
        helper.logging.debug("Called Policy::get_status()")
        return self._status

    def set_status(self, status):
        """
        Set the status of the policy.

        Args:
            status (str): The status to set for the policy.
        """
        helper.logging.debug("Called Policy::set_status()")
        self._status = status

    def get_source_zones(self):
        """
        Retrieve the source security zones associated with the policy.

        Returns:
            list: List of source security zones.
        """
        helper.logging.debug("Called Policy::get_source_zones()")
        return self.process_policy_objects('security_zone', 'source')

    def set_source_zones(self, source_zones):
        """
        Set the source security zones associated with the policy.

        Args:
            source_zones (list): List of source security zones.
        """
        helper.logging.debug("Called Policy::set_source_zones()")
        self._source_zones = source_zones

    def get_destination_zones(self):
        """
        Retrieve the destination security zones associated with the policy.

        Returns:
            list: List of destination security zones.
        """
        helper.logging.debug("Called Policy::get_destination_zones()")
        return self.process_policy_objects('security_zone', 'destination')

    def set_destination_zones(self, destination_zones):
        """
        Set the destination security zones associated with the policy.

        Args:
            destination_zones (list): List of destination security zones.
        """
        helper.logging.debug("Called Policy::set_destination_zones()")
        self._destination_zones = destination_zones

    def get_description(self):
        """
        Retrieve the description of the policy.

        Returns:
            str: The description of the policy.
        """
        helper.logging.debug("Called Policy::get_description()")
        return self._description

    def set_description(self, description):
        """
        Set the description of the policy.

        Args:
            description (str): The description of the policy.
        """
        helper.logging.debug("Called Policy::set_description()")
        self._description = description

    def get_comments(self):
        """
        Retrieve the comments associated with the policy.

        Returns:
            str: The comments associated with the policy.
        """
        helper.logging.debug("Called Policy::get_comments()")
        return self.process_policy_objects('comment', None)

    def set_comments(self, comments):
        """
        Set the comments associated with the policy.

        Args:
            comments (str): The comments associated with the policy.
        """
        helper.logging.debug("Called Policy::set_comments()")
        self._comments = comments

    def get_log_start(self):
        """
        Retrieve the start time for logging.

        Returns:
            datetime: The start time for logging.
        """
        helper.logging.debug("Called Policy::get_log_start()")
        return self._log_start

    def set_log_start(self, log_start):
        """
        Set the start time for logging.

        Args:
            log_start (datetime): The start time for logging.
        """
        helper.logging.debug("Called Policy::set_log_start()")
        self._log_start = log_start

    def get_log_end(self):
        """
        Retrieve the end time for logging.

        Returns:
            datetime: The end time for logging.
        """
        helper.logging.debug("Called Policy::get_log_end()")
        return self._log_end

    def set_log_end(self, log_end):
        """
        Set the end time for logging.

        Args:
            log_end (datetime): The end time for logging.
        """
        helper.logging.debug("Called Policy::set_log_end()")
        self._log_end = log_end

    def get_processed_log_settings(self):
        """
        Retrieve the logging settings for the policy.

        Returns:
            str: The logging settings for the policy.
        """
        helper.logging.debug("Called Policy::get_processed_log_settings()")
        return self._log_settings

    def set_log_setting(self, log_settings):
        """
        Set the logging settings for the policy.

        Args:
            log_setting (str): The logging settings for the policy.
        """
        helper.logging.debug("Called Policy::set_log_setting()")
        self._log_settings = log_settings
    
    # This function is responsible for processing the object info. Based on the object_type and on the flow_direction
    # it will retrieve the raw information about the object_type and then extract the info from it.
    # the raw information is retrieved and stored in a dictionary
    def process_policy_objects(self, object_type, flow_direction):
        """
        Process security objects defined in the security policy.

        This function retrieves and processes security objects based on the specified object type.

        Args:
            object_type (str): Type of security objects to process ('sourceObjects' or 'destinationObjects').
            flow_direction (str): Direction of flow for which objects are being processed.

        Returns:
            list: List of processed security objects.
        """
        # Log debug message indicating the function has been called
        helper.logging.debug("Called Policy::process_policy_objects()")
        
        # Log information message indicating the start of processing for the specified object type
        helper.logging.info(f"################## Processing policy objects info, processing the following objects: <{object_type}> of policy: <{self._name}> ##################.")
        
        # Initialize an empty list to store processed security objects
        processed_objects_list = []

        # Check if a specific flow direction is provided
        if flow_direction is not None:
            # Log information message indicating the direction of flow being processed
            helper.logging.info(f"I am looking for <{flow_direction}> objects on policy: <{self._name}>.")
        
        # Retrieve raw objects information based on the specified object type and flow direction
        raw_object_info = self.get_raw_policy_objects_info(object_type, flow_direction)

        # Check if the raw_object_info list contains only the 'any' keyword or if the raw_object_info is 'None'
        if raw_object_info == ['any'] or raw_object_info is None:
            # Log information message indicating no explicit object defined, defaulting to 'any'
            helper.logging.info(f"No explicit <{object_type}> defined for flow <{flow_direction}> policy: <{self._name}>.")
            # Return a list containing only 'any'
            return ['any'] if raw_object_info == ['any'] else None
        else:
            # Log information message indicating the presence of defined objects for the specified object type and flow direction
            helper.logging.info(f"Found {object_type} objects defined for flow <{flow_direction}> policy: <{self._name}>.")
            # Log debug message displaying the raw objects information
            helper.logging.debug(f"This is the {object_type} object's info: <{raw_object_info}>.")
            
        for raw_object_entry in raw_object_info:
            # Log information message indicating the start of processing for the current raw object
            helper.logging.info(f"Processing raw info object entry: {raw_object_entry}.")
            
            # Extract information from the raw object
            processed_objects_list = self.extract_policy_object_info(raw_object_entry, object_type)
            
            # Log information message indicating the processed object
            helper.logging.info(f"Finished processing object info for object type <{object_type}>.")
            helper.logging.debug(f"Processed info entry: <{processed_objects_list}>.")
        
        # Return the list of processed objects
        return processed_objects_list

    @abstractmethod
    def extract_policy_object_info(raw_object, object_type):
        """
        This function is overridden in the Policy child class. It will extract all the necessary information about a single object of type object_type that is being passed to it. 

        Args:
            raw_object: The raw object from which information needs to be extracted.
            object_type (str): The type of the object from which information is to be extracted.

        Returns:
            None
        """
        pass

# TODO: continue doc here
class SecurityPolicy(Policy):
    """
    Class representing a security policy.

    This class extends the base Policy class and provides methods to process and extract information 
    from a security policy.

    Args:
        policy_info (dict): Information about the security policy.

    Attributes:
        _category (str): Category of the security policy.
        _container_index (int): Index of the security policy container.
        _source_networks (list): List of source network objects.
        _destination_networks (list): List of destination network objects.
        _source_ports (list): List of source port objects.
        _destination_ports (list): List of destination port objects.
        _schedule_objects (list): List of schedule objects.
        _users (list): List of user objects.
        _url_objects (list): List of URL objects.
        _l7_apps (list): List of Layer 7 application objects.
        _section (str): Section of the security policy.
        _action (str): Action associated with the security policy.

    """

    def __init__(self, policy_info) -> None:
        """
        Initialize a SecurityPolicy object with the given policy information.

        Args:
            policy_info (dict): Information about the security policy.
        """
        helper.logging("Called SecurityPolicy::__init__()")
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
        """
        Set the category of the security policy.

        Args:
            category (str): The category to set for the security policy.
        """
        self._category = category
    
    def get_category(self):
        """
        Get the category of the security policy.

        Returns:
            The category to get for the security policy.
        """
        return self._category
    
    def set_source_networks(self, source_networks):
        """
        Set the source networks for the security policy.

        Args:
            source_networks (list): List of source network objects to set.
        """
        self._source_networks = source_networks

    def get_source_networks(self):
        """
        Retrieve the source networks associated with the security policy.

        Returns:
            list: List of source network objects.
        """
        return self.process_policy_objects("network_address_object", "source")

    def set_destination_networks(self, destination_networks):
        """
        Set the destination networks for the security policy.

        Args:
            destination_networks (list): List of destination network objects to set.
        """
        self._destination_networks = destination_networks

    def get_destination_networks(self):
        """
        Retrieve the destination networks associated with the security policy.

        Returns:
            list: List of destination network objects.
        """
        return self.process_policy_objects("network_address_object", "destination")

    def set_source_ports(self, source_ports):
        """
        Set the source ports for the security policy.

        Args:
            source_ports (list): List of source port objects to set.
        """
        self._source_ports = source_ports

    def get_source_ports(self):
        """
        Retrieve the source ports associated with the security policy.

        Returns:
            list: List of source port objects.
        """
        return self.process_policy_objects("port_object", "source")

    def set_destination_ports(self, destination_ports):
        """
        Set the destination ports for the security policy.

        Args:
            destination_ports (list): List of destination port objects to set.
        """
        self._destination_ports = destination_ports

    def get_destination_ports(self):
        """
        Retrieve the destination ports associated with the security policy.

        Returns:
            list: List of destination port objects.
        """
        return self.process_policy_objects("port_object", "destination")

    def set_schedule_objects(self, schedule_objects):
        """
        Set the schedule objects for the security policy.

        Args:
            schedule_objects (list): List of schedule objects to set.
        """
        self._schedule_objects = schedule_objects

    def get_schedule_objects(self):
        """
        Retrieve the schedule objects associated with the security policy.

        Returns:
            list: List of schedule objects.
        """
        return self.process_policy_objects("schedule_object", None)

    def set_users(self, users):
        """
        Set the user objects for the security policy.

        Args:
            users (list): List of user objects to set.
        """
        self._users = users

    def get_users(self):
        """
        Retrieve the user objects associated with the security policy.

        Returns:
            list: List of user objects.
        """
        return self.process_policy_objects("user_object", None)

    def set_urls(self, urls):
        """
        Set the URL objects for the security policy.

        Args:
            urls (list): List of URL objects to set.
        """
        self._url_objects = urls

    def get_urls(self):
        """
        Retrieve the URL objects associated with the security policy.

        Returns:
            list: List of URL objects.
        """
        return self.process_policy_objects("url_object", None)

    def set_policy_apps(self, policy_apps):
        """
        Set the Layer 7 application objects for the security policy.

        Args:
            policy_apps (list): List of Layer 7 application objects to set.
        """
        self._l7_apps = policy_apps

    def get_policy_apps(self):
        """
        Retrieve the Layer 7 application objects associated with the security policy.

        Returns:
            list: List of Layer 7 application objects.
        """
        return self.process_policy_objects("l7_app_object", None)

    def set_section(self, section):
        """
        Set the section of the security policy.

        Args:
            section (str): The section to set for the security policy.
        """
        self._section = section
    
    def get_section(self):
        """
        Retrieve the section of the security policy.

        Returns:
            str: The section of the security policy.
        """
        return self._section
    
    def set_action(self, action):
        """
        Set the action of the security policy.

        Args:
            action (str): The action to set for the security policy.
        """
        self._action = action
    
    def get_action(self):
        """
        Retrieve the action of the security policy.

        Returns:
            str: The action of the security policy.
        """
        return self._action

    def get_raw_policy_objects_info(self, object_type, flow_direction):
        """
        Retrieve raw objects information based on the specified object type and flow direction.

        This method retrieves raw objects information from the respective attribute based on the provided object type
        and flow direction.

        Args:
            object_type (str): Type of object to retrieve information for ('security_zone', 'network_address_object', 
                            'port_object', 'user_object', 'schedule_object', 'url_objects', 'l7_app_object').
            flow_direction (str): Direction of flow for which objects are being retrieved ('source' or 'destination').

        Returns:
            list: List of raw objects information based on the specified object type and flow direction.
        """
        raw_objects = []

        # Determine the attribute to retrieve raw objects from based on object type and flow direction
        if flow_direction == 'source':
            if object_type == 'security_zone':
                raw_objects = self._source_zones
            elif object_type == 'network_address_object':
                raw_objects = self._source_networks
            elif object_type == 'port_object':
                raw_objects = self._source_ports
        elif flow_direction == 'destination':
            if object_type == 'security_zone':
                raw_objects = self._destination_zones
            elif object_type == 'network_address_object':
                raw_objects = self._destination_networks
            elif object_type == 'port_object':
                raw_objects = self._destination_ports
        else:
            if object_type == 'user_object':
                raw_objects = self._users
            elif object_type == 'schedule_object':
                raw_objects = self._schedule_objects
            elif object_type == 'url_object':
                raw_objects = self._url_objects
            elif object_type == 'l7_app_object':
                raw_objects = self._l7_apps
            elif object_type == 'comment':
                raw_objects = self._comments

        return raw_objects

    def process_policy_info(self):
        """
        Process and extract information for a single security policy.

        This method processes the raw information of a security policy and extracts relevant details 
        to be inserted into the database.

        Returns:
            dict: A dictionary containing information about the security policy.
        """
        helper.logging.debug("Called SecurityPolicy::process_sec_policy_info()")
        
        # Setters are necessary because the objects' attributes are not set upon their creation. We can only get this data after we construct the object with the data from the security device.
        self.set_name()
        self.set_container_name()
        self.set_container_index()
        
        # Log information about the security policy being processed
        helper.logging.info(f"\n\n################## PROCESSING SECURITY POLICY: <{self._name}>. CONTAINER: <{self._container_name}>. RULE INDEX: <{self._container_index}>.##################")
        helper.logging.debug(f"Security policy raw data: {self._policy_info}")

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

        # Construct the processed policy entry dictionary
        processed_policy_entry = {
            "sec_policy_name": self.get_name(),
            "sec_policy_container_name": self.get_container_name(),
            "security_policy_index": self.get_container_index(),
            "sec_policy_category": self.get_category(),
            "sec_policy_status": self.get_status(),
            "sec_policy_source_zones": self.get_source_zones(),
            "sec_policy_destination_zones": self.get_destination_zones(),
            "sec_policy_source_networks": self.get_source_networks(),
            "sec_policy_destination_networks": self.get_destination_networks(),
            "sec_policy_source_ports": self.get_source_ports(),
            "sec_policy_destination_ports": self.get_destination_ports(),
            "sec_policy_schedules": self.get_schedule_objects(),
            "sec_policy_users": self.get_users(),
            "sec_policy_urls": self.get_urls(),
            "sec_policy_apps": self.get_policy_apps(),
            "sec_policy_description": self.get_description(),
            "sec_policy_comments": self.get_comments(),
            "sec_policy_log_settings": self.get_processed_log_settings(),
            "sec_policy_log_start": self.get_log_start(),
            "sec_policy_log_end": self.get_log_end(),
            "sec_policy_section": self.get_section(),
            "sec_policy_action": self.get_action(),
        }

        # Log information about the processed policy entry
        helper.logging.info(f"Processed security policy: <{self._name}>.")
        helper.logging.debug(f"Processed security policy data: <{processed_policy_entry}>.")
                            
        return processed_policy_entry

class NATPolicy:
    pass