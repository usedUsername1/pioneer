import utils.helper as helper
from abc import abstractmethod

general_logger = helper.logging.getLogger('general')
special_policies_logger = helper.logging.getLogger('special_policies')

class Policy:
    """
    Class representing a policy.

    This class serves as a base class for different types of policies.

    Args:
        PolicyContainer (type): The type of the policy container.
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
        _log_start: Start logging at the beginning of the session.
        _log_end: End logging at the beginning of the session.
        _log_to_manager (bool): Log to mananger.
        _log_to_syslog (bool): Log to syslog
    """

    def __init__(
        self,
        PolicyContainer,
        policy_info,
        name,
        source_zones,
        destination_zones,
        container_index,
        status,
        description,
        comments,
        log_to_manager,
        log_to_syslog
    ) -> None:
        """
        Initialize a Policy object with the given policy information.

        Args:
            PolicyContainer (type): The type of the policy container.
            policy_info (dict): Information about the policy.
        """
        self._PolicyContainer = PolicyContainer
        self._policy_info = policy_info
        self._name = name
        self._uid = helper.generate_uid()
        self._source_zones = source_zones
        self._destination_zones = destination_zones
        self._container_uid = PolicyContainer.get_uid()
        self._container_index = container_index
        self._status = status
        self._description = description
        self._comments = comments
        self._log_to_manager = log_to_manager
        self._log_to_syslog = log_to_syslog

    def get_uid(self):
        return self._uid

    def get_policy_info(self):
        """
        Retrieve the policy information stored in the object.

        Returns:
            Any: The policy information stored in the object.
        """
        return self._policy_info

    def get_name(self):
        """
        Retrieve the name of the policy.

        Returns:
            str: The name of the policy.
        """
        return self._name

    def set_name(self, name):
        """
        Set the name of the policy.

        Args:
            name (str): The name to set for the policy.
        """
        self._name = name

    def set_container_name(self, name):
        """
        Set the name of the container holding the policy.

        Args:
            name (str): The name of the container.
        """
        self._container_name = name

    def get_container_uid(self):
        """
        Retrieve the uid of the container holding the policy.

        Returns:
            str: The uid of the container.
        """
        return self._container_uid

    def set_container_index(self, index):
        """
        Set the index of the container holding the policy.

        Args:
            index (int): The index of the container.
        """
        self._container_index = index

    def get_container_index(self):
        """
        Retrieve the index of the container holding the policy.

        Returns:
            int: The index of the container.
        """
        return self._container_index

    def get_status(self):
        """
        Retrieve the status of the policy.

        Returns:
            str: The status of the policy.
        """
        return self._status

    def set_status(self, status):
        """
        Set the status of the policy.

        Args:
            status (str): The status to set for the policy.
        """
        self._status = status

    def get_source_zones(self):
        """
        Retrieve the source security zones associated with the policy.

        Returns:
            list: List of source security zones.
        """
        return self._source_zones

    def set_source_zones(self, source_zones):
        """
        Set the source security zones associated with the policy.

        Args:
            source_zones (list): List of source security zones.
        """
        self._source_zones = source_zones

    def get_destination_zones(self):
        """
        Retrieve the destination security zones associated with the policy.

        Returns:
            list: List of destination security zones.
        """
        return self._destination_zones

    def set_destination_zones(self, destination_zones):
        """
        Set the destination security zones associated with the policy.

        Args:
            destination_zones (list): List of destination security zones.
        """
        self._destination_zones = destination_zones

    def get_description(self):
        """
        Retrieve the description of the policy.

        Returns:
            str: The description of the policy.
        """
        return self._description

    def set_description(self, description):
        """
        Set the description of the policy.

        Args:
            description (str): The description of the policy.
        """
        self._description = description

    def get_comments(self):
        """
        Retrieve the comments associated with the policy.

        Returns:
            str: The comments associated with the policy.
        """
        return self._comments

    def set_comments(self, comments):
        """
        Set the comments associated with the policy.

        Args:
            comments (str): The comments associated with the policy.
        """
        self._comments = comments

    def get_log_start(self):
        """
        Retrieve the start time for logging.

        Returns:
            datetime: The start time for logging.
        """
        return self._log_start

    def set_log_start(self, log_start):
        """
        Set the start time for logging.

        Args:
            log_start (datetime): The start time for logging.
        """
        self._log_start = log_start

    def get_log_end(self):
        """
        Retrieve the end time for logging.

        Returns:
            datetime: The end time for logging.
        """
        return self._log_end

    def set_log_end(self, log_end):
        """
        Set the end time for logging.

        Args:
            log_end (datetime): The end time for logging.
        """
        self._log_end = log_end

    def get_log_to_manager(self):
        return self._log_to_manager

    def get_log_to_syslog(self):
        return self._log_to_syslog

    def set_log_setting(self, log_settings):
        """
        Set the logging settings for the policy.

        Args:
            log_setting (str): The logging settings for the policy.
        """
        self._log_settings = log_settings
    
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

    def __init__(
        self,
        PolicyContainer,
        policy_info,
        name,
        container_index,
        status,
        category,
        source_zones,
        destination_zones,
        source_networks,
        destination_networks,
        source_ports,
        destination_ports,
        schedule_objects,
        users,
        urls,
        policy_apps,
        description,
        comments,
        log_to_manager,
        log_to_syslog,
        log_start,
        log_end,
        section,
        action
    ) -> None:
        """
        Initialize a SecurityPolicy object with the given policy information.

        Args:
            policy_info (dict): Information about the security policy.
        """
        super().__init__(PolicyContainer, policy_info, name, source_zones, destination_zones, container_index, status, description, comments, log_to_manager, log_to_syslog)
        self._category = category
        self._container_index = container_index
        self._source_networks = source_networks
        self._destination_networks = destination_networks
        self._source_ports = source_ports
        self._destination_ports = destination_ports
        self._schedule = schedule_objects
        self._users = users
        self._url_objects = urls
        self._l7_apps = policy_apps
        self._section = section
        self._action = action
        self._log_start = log_start
        self._log_end = log_end

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
        return self._source_networks

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
        return self._destination_networks

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
        return self._source_ports

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
        return self._destination_ports

    def set_schedule_objects(self, schedule):
        """
        Set the schedule objects for the security policy.

        Args:
            schedule_objects (list): List of schedule objects to set.
        """
        self._schedule = schedule

    def get_schedule(self):
        """
        Retrieve the schedule objects associated with the security policy.

        Returns:
            list: List of schedule objects.
        """
        return self._schedule

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
        return self._users

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
        return self._url_objects

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
        return self._l7_apps

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

    def save(self, Database):
        SecurityPoliciesTable = Database.get_security_policies_table()
        SecurityPoliciesTable.insert(
            self.get_uid(),
            self.get_name(),
            self.get_container_uid(),
            self.get_container_index(),
            self.get_category(),
            self.get_schedule(),
            self.get_status(),
            self.get_log_start(),
            self.get_log_end(),
            self.get_section(),
            self.get_action(),
            self.get_comments(),
            self.get_description()
        )

    # TODO get the names of the paramteres defined on the policies and put everything in a dict
    # do the lookup by name and find the uid
    def create_relationships_in_db(self, Database, preloaded_data):
        uid = self.get_uid()
        # Insert source and destination zones
        insert_zones(self.get_source_zones(), 'source')
        insert_zones(self.get_destination_zones(), 'destination')
        source_networks_names = self.get_source_networks()
        destination_networks_names = self.get_destination_networks()
        source_port_names = self.get_source_ports()
        destination_port_names = self.get_destination_ports()
        schedule_names = self.get_schedule()
        policy_user_names = self.get_users()
        url_names = self.get_urls()
        l7_app_names = self.get_policy_apps()
        description = self.get_description()
        comments = self.get_comments()
        log_to_manager = self.get_log_to_manager()
        log_to_syslog = self.get_log_to_syslog()
        log_start = self.get_log_start()
        log_end = self.get_log_end()
        category = self.get_category()
        action = self.get_action()
        
        # Insert source and destination zones
        insert_zones(self.get_source_zones(), 'source')
        insert_zones(self.get_destination_zones(), 'destination')
        
        # Insert source and destination networks
        insert_networks(self.get_source_networks(), 'source')
        insert_networks(self.get_destination_networks(), 'destination')  

        # Helper function to insert zone data
        def insert_zones(zone_names, zone_type):
            SecurityPolicyZonesTable = Database.get_security_zones_table()
            if not zone_names:
                SecurityPolicyZonesTable.insert(uid, None, zone_type)
            else:
                for zone_name in zone_names:
                    zone_uid = preloaded_data['security_zones'].get(zone_name)
                    SecurityPolicyZonesTable.insert(uid, zone_uid, zone_type)
        
        # Helper function to insert network data
        def insert_networks(network_names, network_type):
            SecurityPolicyNetworksTable = Database.get_security_policy_networks_table()
            if not network_names:
                SecurityPolicyNetworksTable.insert(uid, None, None, None, None, network_type)
            else:
                for network_name in network_names:
                    object_uid = preloaded_data['network_objects'].get(network_name)
                    group_uid = preloaded_data['network_group_objects'].get(network_name)
                    country_uid = preloaded_data['country_objects'].get(network_name)
                    geolocation_uid = preloaded_data['geolocation_objects'].get(network_name)
                    SecurityPolicyNetworksTable.insert(uid, object_uid, group_uid, country_uid, geolocation_uid, network_type)



class NATPolicy:
    pass