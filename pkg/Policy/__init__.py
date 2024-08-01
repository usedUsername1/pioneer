import utils.helper as helper
import utils.gvars as gvars
from abc import abstractmethod

general_logger = helper.logging.getLogger('general')
special_policies_logger = helper.logging.getLogger('special_policies')

class Policy:
    """
    Class representing a policy.

    This class serves as a base class for different types of policies.

    Args:
        policy_container (type): The type of the policy container.
        name (str): Name of the policy.
        source_zones (list): List of source security zones associated with the policy.
        destination_zones (list): List of destination security zones associated with the policy.
        container_index (int): Index of the container holding the policy.
        status (str): Status of the policy.
        description (str): Description of the policy.
        comments (str): Comments associated with the policy.
        log_to_manager (bool): Log to manager.
        log_to_syslog (bool): Log to syslog.

    Attributes:
        _policy_info (dict): Information about the policy.
        _uid (str): Unique identifier for the policy.
        _source_zones (list): List of source security zones associated with the policy.
        _destination_zones (list): List of destination security zones associated with the policy.
        _container_uid (str): Unique identifier of the container holding the policy.
        _container_index (int): Index of the container holding the policy.
        _status (str): Status of the policy.
        _description (str): Description of the policy.
        _comments (str): Comments associated with the policy.
        _log_start (datetime): Start time for logging.
        _log_end (datetime): End time for logging.
        _log_to_manager (bool): Whether to log to the manager.
        _log_to_syslog (bool): Whether to log to syslog.
    """

    def __init__(
        self,
        policy_container,
        name,
        source_zones,
        destination_zones,
        container_index,
        status,
        description,
        comments,
        log_to_manager,
        log_to_syslog,
        ) -> None:
        """
        Initialize a Policy object with the given policy information.

        Args:
            policy_container (type): The type of the policy container.
            name (str): Name of the policy.
            source_zones (list): List of source security zones.
            destination_zones (list): List of destination security zones.
            container_index (int): Index of the container holding the policy.
            status (str): Status of the policy.
            description (str): Description of the policy.
            comments (str): Comments associated with the policy.
            log_to_manager (bool): Log to manager.
            log_to_syslog (bool): Log to syslog.
        """
        self._policy_container = policy_container
        self._name = name
        self._uid = helper.generate_uid()
        self._source_zones = source_zones
        self._destination_zones = destination_zones
        self._container_uid = policy_container.uid
        self._container_index = container_index
        self._status = status
        self._description = description
        self._comments = comments
        self._log_to_manager = log_to_manager
        self._log_to_syslog = log_to_syslog
        self._log_start = None
        self._log_end = None
        self._target_device_uid = None

    @property
    def uid(self):
        """Get or set the unique identifier of the policy."""
        return self._uid

    @uid.setter
    def uid(self, value):
        self._uid = value

    @property
    def name(self):
        """Get or set the name of the policy."""
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def source_zones(self):
        """Get or set the source security zones associated with the policy."""
        return self._source_zones

    @source_zones.setter
    def source_zones(self, value):
        self._source_zones = value

    @property
    def destination_zones(self):
        """Get or set the destination security zones associated with the policy."""
        return self._destination_zones

    @destination_zones.setter
    def destination_zones(self, value):
        self._destination_zones = value

    @property
    def container_uid(self):
        """Get the unique identifier of the container holding the policy."""
        return self._container_uid

    @property
    def container_index(self):
        """Get or set the index of the container holding the policy."""
        return self._container_index

    @container_index.setter
    def container_index(self, value):
        self._container_index = value

    @property
    def status(self):
        """Get or set the status of the policy."""
        return self._status

    @status.setter
    def status(self, value):
        self._status = value

    @property
    def description(self):
        """Get or set the description of the policy."""
        return self._description

    @description.setter
    def description(self, value):
        self._description = value

    @property
    def comments(self):
        """Get or set the comments associated with the policy."""
        return self._comments

    @comments.setter
    def comments(self, value):
        self._comments = value

    @property
    def log_start(self):
        """Get or set the start time for logging."""
        return self._log_start

    @log_start.setter
    def log_start(self, value):
        self._log_start = value

    @property
    def log_end(self):
        """Get or set the end time for logging."""
        return self._log_end

    @log_end.setter
    def log_end(self, value):
        self._log_end = value

    @property
    def log_to_manager(self):
        """Get or set the logging to manager setting."""
        return self._log_to_manager

    @log_to_manager.setter
    def log_to_manager(self, value):
        self._log_to_manager = value

    @property
    def log_to_syslog(self):
        """Get or set the logging to syslog setting."""
        return self._log_to_syslog

    @log_to_syslog.setter
    def log_to_syslog(self, value):
        self._log_to_syslog = value

    @property
    def target_device_uid(self):
        """Get or set the target device uid."""
        return self._target_device_uid

    @target_device_uid.setter
    def target_device_uid(self, value):
        self._target_device_uid = value

class SecurityPolicy(Policy):
    """
    Class representing a security policy.

    This class extends the base Policy class and provides methods to process and extract information 
    from a security policy.

    Args:
        policy_container (type): The type of the policy container.
        name (str): Name of the policy.
        container_index (int): Index of the security policy container.
        status (str): Status of the policy.
        category (str): Category of the security policy.
        source_zones (list): List of source security zones associated with the policy.
        destination_zones (list): List of destination security zones associated with the policy.
        source_networks (list): List of source network objects.
        destination_networks (list): List of destination network objects.
        source_ports (list): List of source port objects.
        destination_ports (list): List of destination port objects.
        schedule_objects (list): List of schedule objects.
        users (list): List of user objects.
        urls (list): List of URL objects.
        policy_apps (list): List of Layer 7 application objects.
        description (str): Description of the policy.
        comments (str): Comments associated with the policy.
        log_to_manager (bool): Log to manager.
        log_to_syslog (bool): Log to syslog.
        log_start (datetime): Start time for logging.
        log_end (datetime): End time for logging.
        section (str): Section of the security policy.
        action (str): Action associated with the security policy.

    Attributes:
        _category (str): Category of the security policy.
        _container_index (int): Index of the security policy container.
        _source_networks (list): List of source network objects.
        _destination_networks (list): List of destination network objects.
        _source_ports (list): List of source port objects.
        _destination_ports (list): List of destination port objects.
        _schedule (list): List of schedule objects.
        _users (list): List of user objects.
        _url_objects (list): List of URL objects.
        _l7_apps (list): List of Layer 7 application objects.
        _section (str): Section of the security policy.
        _action (str): Action associated with the security policy.
        _log_start (datetime): Start time for logging.
        _log_end (datetime): End time for logging.
    """

    def __init__(
        self,
        policy_container,
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
            policy_container (type): The type of the policy container.
            name (str): Name of the policy.
            container_index (int): Index of the security policy container.
            status (str): Status of the policy.
            category (str): Category of the security policy.
            source_zones (list): List of source security zones associated with the policy.
            destination_zones (list): List of destination security zones associated with the policy.
            source_networks (list): List of source network objects.
            destination_networks (list): List of destination network objects.
            source_ports (list): List of source port objects.
            destination_ports (list): List of destination port objects.
            schedule_objects (list): List of schedule objects.
            users (list): List of user objects.
            urls (list): List of URL objects.
            policy_apps (list): List of Layer 7 application objects.
            description (str): Description of the policy.
            comments (str): Comments associated with the policy.
            log_to_manager (bool): Log to manager.
            log_to_syslog (bool): Log to syslog.
            log_start (datetime): Start time for logging.
            log_end (datetime): End time for logging.
            section (str): Section of the security policy.
            action (str): Action associated with the security policy.
        """
        super().__init__(policy_container, name, source_zones, destination_zones, container_index, status, description, comments, log_to_manager, log_to_syslog)
        self._category = category
        self._source_networks = source_networks
        self._destination_networks = destination_networks
        self._source_ports = source_ports
        self._destination_ports = destination_ports
        self._schedule = schedule_objects
        self._users = users
        self._urls = urls
        self.l7_policy_apps = policy_apps
        self._section = section
        self._action = action
        self._log_start = log_start
        self._log_end = log_end

    @property
    def category(self):
        """Get or set the category of the security policy."""
        return self._category

    @category.setter
    def category(self, value):
        self._category = value

    @property
    def source_networks(self):
        """Get or set the source networks associated with the security policy."""
        return self._source_networks

    @source_networks.setter
    def source_networks(self, value):
        self._source_networks = value

    @property
    def destination_networks(self):
        """Get or set the destination networks associated with the security policy."""
        return self._destination_networks

    @destination_networks.setter
    def destination_networks(self, value):
        self._destination_networks = value

    @property
    def source_ports(self):
        """Get or set the source ports associated with the security policy."""
        return self._source_ports

    @source_ports.setter
    def source_ports(self, value):
        self._source_ports = value

    @property
    def destination_ports(self):
        """Get or set the destination ports associated with the security policy."""
        return self._destination_ports

    @destination_ports.setter
    def destination_ports(self, value):
        self._destination_ports = value

    @property
    def schedule(self):
        """Get or set the schedule objects associated with the security policy."""
        return self._schedule

    @schedule.setter
    def schedule(self, value):
        self._schedule = value

    @property
    def users(self):
        """Get or set the users associated with the security policy."""
        return self._users

    @users.setter
    def users(self, value):
        self._users = value

    @property
    def urls(self):
        """Get or set the URL objects associated with the security policy."""
        return self._urls

    @urls.setter
    def urls(self, value):
        self._urls = value

    @property
    def policy_apps(self):
        """Get or set the Layer 7 application objects associated with the security policy."""
        return self.l7_policy_apps

    @policy_apps.setter
    def policy_apps(self, value):
        self.l7_policy_apps = value

    @property
    def section(self):
        """Get or set the section of the security policy."""
        return self._section

    @section.setter
    def section(self, value):
        self._section = value

    @property
    def action(self):
        """Get or set the action of the security policy."""
        return self._action

    @action.setter
    def action(self, value):
        self._action = value

    def save(self, db):
        """
        Save the security policy to the db.

        Args:
            db (Database): The db instance to save the policy to.
        """
        db.security_policies_table.insert(
            self.uid,
            self.name,
            self.container_uid,
            self.container_index,
            self.category,
            self.status,
            self.log_start,
            self.log_end,
            self.log_to_manager,
            self.log_to_syslog,
            self.section,
            self.action,
            self.comments,
            self.description,
            self.target_device_uid,
        )

    def create_relationships_in_db(self, db, preloaded_data):
        """
        Create relationships in the db for the security policy.

        Args:
            db (Database): The db instance to create relationships in.
            preloaded_data (dict): Preloaded data for creating relationships.
        """
        def insert_zones(zone_names, flow):
            """
            Insert zone data into the db.

            Args:
                zone_names (list): List of zone names.
                flow (str): Flow direction ('source' or 'destination').
            """
            if not zone_names:
                db.security_policy_zones_table.insert(self.uid, None, flow)
            else:
                for zone_name in zone_names:
                    zone_uid = preloaded_data[gvars.security_zone].get(zone_name)
                    db.security_policy_zones_table.insert(self.uid, zone_uid, flow)

        def insert_networks(network_names, flow):
            """
            Insert network data into the db.

            Args:
                network_names (list): List of network names.
                flow (str): Flow direction ('source' or 'destination').
            """
            if not network_names:
                db.security_policy_networks_table.insert(self.uid, None, None, None, None, flow)
            else:
                for network_name in network_names:
                    object_uid = preloaded_data[gvars.network_object].get(network_name)
                    group_uid = preloaded_data[gvars.network_group_object].get(network_name)
                    country_uid = preloaded_data[gvars.country_object].get(network_name)
                    geolocation_uid = preloaded_data[gvars.geolocation_object].get(network_name)
                    db.security_policy_networks_table.insert(self.uid, object_uid, group_uid, country_uid, geolocation_uid, flow)

        def insert_ports(port_names, flow):
            """
            Insert port data into the db.

            Args:
                port_names (list): List of port names.
                flow (str): Flow direction ('source' or 'destination').
            """
            if not port_names:
                db.security_policy_ports_table.insert(self.uid, None, None, None, flow)
            else:
                for port_name in port_names:
                    object_uid = preloaded_data[gvars.port_object].get(port_name)
                    icmp_uid = preloaded_data[gvars.icmp_object].get(port_name)
                    group_uid = preloaded_data[gvars.port_group_object].get(port_name)
                    db.security_policy_ports_table.insert(self.uid, object_uid, icmp_uid, group_uid, flow)

        def insert_users(user_names):
            """
            Insert user data into the db.

            Args:
                user_names (list): List of user names.
            """
            if not user_names:
                db.security_policy_users_table.insert(self.uid, None)
            else:
                for user_name in user_names:
                    user_uid = preloaded_data[gvars.policy_user_object].get(user_name)
                    db.security_policy_users_table.insert(self.uid, user_uid)

        def insert_urls(url_names):
            """
            Insert URL data into the db.

            Args:
                url_names (list): List of URL names.
            """
            if not url_names:
                db.security_policy_urls_table.insert(self.uid, None, None, None)
            else:
                for url_name in url_names:
                    object_uid = preloaded_data[gvars.url_object].get(url_name)
                    group_uid = preloaded_data[gvars.url_group_object].get(url_name)
                    category_uid = preloaded_data[gvars.url_category_object].get(url_name)
                    db.security_policy_urls_table.insert(self.uid, object_uid, group_uid, category_uid)

        def insert_l7_apps(app_names):
            """
            Insert Layer 7 application data into the db.

            Args:
                app_names (list): List of application names.
            """
            if not app_names:
                db.security_policy_l7_apps_table.insert(self.uid, None, None, None)
            else:
                for app_name in app_names:
                    app_uid = preloaded_data[gvars.l7_app_object].get(app_name)
                    app_filter_uid = preloaded_data[gvars.l7_app_filter_object].get(app_name)
                    app_group_uid = preloaded_data[gvars.l7_app_group_object].get(app_name)
                    db.security_policy_l7_apps_table.insert(self.uid, app_uid, app_filter_uid, app_group_uid)

        def insert_schedule(schedule_name):
            """
            Insert schedule data into the db.

            Args:
                schedule_name (list): List of schedule names.
            """
            if not schedule_name:
                db.security_policy_schedule_table.insert(self.uid, None)
            else:
                schedule_uid = preloaded_data[gvars.schedule_object].get(schedule_name[0])
                db.security_policy_schedule_table.insert(self.uid, schedule_uid)

        # Insert source and destination zones
        insert_zones(self.source_zones, 'source')
        insert_zones(self.destination_zones, 'destination')

        # Insert source and destination networks
        insert_networks(self.source_networks, 'source')
        insert_networks(self.destination_networks, 'destination')

        # Insert source and destination ports
        insert_ports(self.source_ports, 'source')
        insert_ports(self.destination_ports, 'destination')

        # Insert users
        insert_users(self.users)

        # Insert URLs
        insert_urls(self.urls)

        # Insert Layer 7 applications
        insert_l7_apps(self.l7_policy_apps)

        # Insert schedule
        insert_schedule(self.schedule)


class NATPolicy(Policy):
    def __init__(self, policy_container, name, source_zones, destination_zones, container_index, status, description, comments, log_to_manager, log_to_syslog, category, section, static_or_dynamic, object_or_manual_nat) -> None:
        super().__init__(policy_container, name, source_zones, destination_zones, container_index, status, description, comments, log_to_manager, log_to_syslog)
        self._static_or_dynamic = static_or_dynamic
        self._object_or_manual_nat = object_or_manual_nat
        self._category = category
        self._section = section

    @property
    def static_or_dynamic(self):
        """
        str: Indicates whether the configuration is static or dynamic.
        """
        return self._static_or_dynamic

    @static_or_dynamic.setter
    def static_or_dynamic(self, value):
        self._static_or_dynamic = value

    @property
    def object_or_manual_nat(self):
        """
        str: Specifies whether the NAT configuration is object-based or manual.
        """
        return self._object_or_manual_nat

    @object_or_manual_nat.setter
    def object_or_manual_nat(self, value):
        self._object_or_manual_nat = value

    @property
    def category(self):
        """
        str: The category of the item or configuration.
        """
        return self._category

    @category.setter
    def category(self, value):
        self._category = value

    @property
    def section(self):
        """
        str: The section of the item or configuration.
        """
        return self._section

    @section.setter
    def section(self, value):
        self._section = value


    def save(self, db):
        """
        Save the security policy to the db.

        Args:
            db (Database): The db instance to save the policy to.
        """
        db.security_policies_table.insert(
            self.uid,
            self.name,
            self.container_uid,
            self.container_index,
            self.category,
            self.status,
            self.log_to_manager,
            self.log_to_syslog,
            self.section,
            self.comments,
            self.description,
            self.static_or_dynamic,
            self.object_or_manual_nat,
            self.target_device_uid,
        )

    #TODO: create relationships db table