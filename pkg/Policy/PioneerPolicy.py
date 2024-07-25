from pkg.Policy import SecurityPolicy
import utils.helper as helper
import utils.gvars as gvars
from pkg.DeviceObject.PioneerDeviceObject import ObjectCache, PioneerNetworkObject, PioneerNetworkGroupObject, PioneerPortObject, PioneerICMPObject, \
PioneerPortGroupObject, PioneerURLObject, PioneerURLGroupObject

special_policies_log = helper.logging.getLogger(gvars.special_policies_logger)
# I have no better idea of storing and keeping track of what source/destination networks/ports/etc are objects/groups/special objects besides
# having different attributes

# python objects will be used for storing the policy parameter data that will be migrated (network and port objects)
class PioneerSecurityPolicy(SecurityPolicy):
    _network_table = None
    _zone_table = None
    _port_table = None
    _user_table = None
    _schedule_table = None
    _url_table = None
    _l7_app_table = None
    _network_group_members_table = None
    _port_group_members_table = None
    _url_group_members_table = None

    _country_table = None
    _geolocation_table = None
    _schedule_objects_table = None
    _policy_user_table = None
    _url_category_table = None
    _l7_app_objects_table = None
    _l7_app_filter_table = None
    _l7_app_group_table = None

    _db = None
    _initialized = False  # Initialization flag

    # Class-level cache
    _object_cache = ObjectCache()

    @classmethod
    def initialize_class_variables(cls, policy_container):
        """
        Initialize class variables if they are not already initialized.

        Parameters:
            policy_container (PolicyContainer): The container holding policy information.

        """
        if not cls._initialized:
            cls._network_table = policy_container.security_device.db.security_policy_networks_table
            cls._zone_table = policy_container.security_device.db.security_policy_zones_table
            cls._port_table = policy_container.security_device.db.security_policy_ports_table
            cls._user_table = policy_container.security_device.db.security_policy_users_table
            cls._schedule_table = policy_container.security_device.db.security_policy_schedule_table
            cls._url_table = policy_container.security_device.db.security_policy_urls_table
            cls._l7_app_table = policy_container.security_device.db.security_policy_l7_apps_table
            cls._country_table = policy_container.security_device.db.country_objects_table
            cls._geolocation_table = policy_container.security_device.db.geolocation_objects_table
            cls._schedule_objects_table = policy_container.security_device.db.schedule_objects_table
            cls._policy_user_table = policy_container.security_device.db.policy_user_objects_table
            cls._url_category_table = policy_container.security_device.db.url_category_objects_table
            cls._l7_app_objects_table = policy_container.security_device.db.l7_app_objects_table
            cls._l7_app_filter_table = policy_container.security_device.db.l7_app_filter_objects_table
            cls._l7_app_group_table = policy_container.security_device.db.l7_app_group_objects_table
            cls._network_group_members_table = policy_container.security_device.db.network_group_objects_members_table
            cls._port_group_members_table = policy_container.security_device.db.port_group_objects_members_table
            cls._url_group_members_table = policy_container.security_device.db.url_group_objects_members_table
            cls._initialized = True

    def __init__(self, PolicyContainer, policy_info) -> None:
        """
        Initialize a PioneerSecurityPolicy instance.

        Parameters:
            PolicyContainer (PolicyContainer): The policy container for the security policy.
            policy_info (tuple): A tuple containing policy information.
        """
        self._uid = policy_info[0]
        self._name = policy_info[1]
        self._PolicyContainer = PolicyContainer

        PioneerSecurityPolicy.initialize_class_variables(PolicyContainer)

        # Initialize security policy attributes
        self._source_zones = self.extract_security_zone_object_info('source')
        self._destination_zones = self.extract_security_zone_object_info('destination')
        
        self._source_network_objects = self.extract_network_address_object_info('object_uid', 'source')
        self._source_network_group_objects = self.extract_network_address_object_info('group_object_uid', 'source')
        self._destination_network_objects = self.extract_network_address_object_info('object_uid', 'destination')
        self._destination_network_group_objects = self.extract_network_address_object_info('group_object_uid', 'destination')
        
        self._source_networks = self._source_network_objects | self._source_network_group_objects
        self._destination_networks = self._destination_network_objects | self._destination_network_group_objects
        
        self._source_country_objects = self.extract_network_address_object_info('country_object_uid', 'source')
        self._source_geolocation_objects = self.extract_network_address_object_info('geolocation_object_uid', 'source')
        self._destination_country_objects = self.extract_network_address_object_info('country_object_uid', 'destination')
        self._destination_geolocation_objects = self.extract_network_address_object_info('geolocation_object_uid', 'destination')

        self._source_port_objects = self.extract_port_object_info('object_uid', 'source')
        self._source_icmp_objects = self.extract_port_object_info('icmp_object_uid', 'source')
        self._source_port_group_objects = self.extract_port_object_info('group_object_uid', 'source')
        
        self._destination_port_objects = self.extract_port_object_info('object_uid', 'destination')
        self._destination_icmp_objects = self.extract_port_object_info('icmp_object_uid', 'destination')
        self._destination_port_group_objects = self.extract_port_object_info('group_object_uid', 'destination')

        # Combine port objects and ICMP objects
        self._source_ports = self._source_port_objects | self._source_port_group_objects | self._source_icmp_objects
        self._destination_ports = self._destination_port_objects | self._destination_port_group_objects | self._destination_icmp_objects

        self._schedule_objects = self.extract_schedule_object_info()
        self._users = self.extract_user_object_info()

        self._url_objects = self.extract_url_object_info('object')
        self._url_groups = self.extract_url_object_info('group')
        self._url_categories = self.extract_url_object_info('url_category')
        self._urls = self._url_objects | self._url_groups

        self._policy_apps = self.extract_l7_app_object_info('l7_app_uid')
        self._policy_app_filters = self.extract_l7_app_object_info('l7_app_filter_uid')
        self._policy_app_groups = self.extract_l7_app_object_info('l7_app_group_uid')

        # Extract additional policy information
        self._index = policy_info[3]
        self._category = policy_info[4]
        self._status = policy_info[5]
        self._log_start = policy_info[6]
        self._log_end = policy_info[7]
        self._log_to_manager = policy_info[8]
        self._log_to_syslog = policy_info[9]
        self._section = policy_info[10]
        self._action = policy_info[11]
        self._comments = policy_info[12]
        self._description = policy_info[13]

        super().__init__(
            self._PolicyContainer,
            self._name,
            self._index,
            self._status,
            self._category,
            self._source_zones,
            self._destination_zones,
            self._source_networks,
            self._destination_networks,
            self._source_ports,
            self._destination_ports,
            self._schedule_objects,
            self._users,
            self._urls,
            self._policy_apps,
            self._description,
            self._comments,
            self._log_to_manager,
            self._log_to_syslog,
            self._log_start,
            self._log_end,
            self._section,
            self._action
        )

    @property
    def source_network_objects(self):
        """
        Get the source network objects.

        Returns:
            set: A set of source network objects.
        """
        return self._source_network_objects

    @property
    def destination_network_objects(self):
        """
        Get the destination network objects.

        Returns:
            set: A set of destination network objects.
        """
        return self._destination_network_objects

    @property
    def source_network_group_objects(self):
        """
        Get the source network group objects.

        Returns:
            set: A set of source network group objects.
        """
        return self._source_network_group_objects

    @property
    def destination_network_group_objects(self):
        """
        Get the destination network group objects.

        Returns:
            set: A set of destination network group objects.
        """
        return self._destination_network_group_objects

    @property
    def source_port_objects(self):
        """
        Get the source port objects.

        Returns:
            set: A set of source port objects.
        """
        return self._source_port_objects

    @property
    def destination_port_objects(self):
        """
        Get the destination port objects.

        Returns:
            set: A set of destination port objects.
        """
        return self._destination_port_objects

    @property
    def source_port_group_objects(self):
        """
        Get the source port group objects.

        Returns:
            set: A set of source port group objects.
        """
        return self._source_port_group_objects

    @property
    def destination_port_group_objects(self):
        """
        Get the destination port group objects.

        Returns:
            set: A set of destination port group objects.
        """
        return self._destination_port_group_objects

    @property
    def urls(self):
        """
        Get the URL objects.

        Returns:
            set: A set of URL objects.
        """
        return self._urls

# there is something very strange going on here if there paramters is set to self._url_objects. investigate this
    @property
    def url_objects(self):
        """
        Get URL objects specifically from the Pioneer policy.

        Returns:
            set: A set of URL objects from Pioneer policy.
        """
        return  self._url_objects

    @property
    def url_group_objects(self):
        """
        Get URL group objects.

        Returns:
            set: A set of URL group objects.
        """
        return self._url_groups

    @property
    def source_icmp_objects(self):
        """
        Get the source ICMP objects.

        Returns:
            set: A set of source ICMP objects.
        """
        return self._source_icmp_objects

    @property
    def destination_icmp_objects(self):
        """
        Get the destination ICMP objects.

        Returns:
            set: A set of destination ICMP objects.
        """
        return self._destination_icmp_objects

    def extract_security_zone_object_info(self, flow):
        """
        Extract security zone object information based on the flow type.

        Parameters:
            flow (str): The type of flow (e.g., 'source' or 'destination').

        Returns:
            list: A list of security zone UIDs.
        """
        security_policy_zones = self._zone_table.get(
            columns='zone_uid',
            name_col=['security_policy_uid', 'flow'],
            val=[self._uid, flow],
            not_null_condition=True,
            multiple_where=True
        )
        return security_policy_zones

    def extract_network_address_object_info(self, object_type, flow):
        """
        Extract network address object information based on the object type and flow type.

        Parameters:
            object_type (str): The type of object to extract (e.g., 'object_uid', 'group_object_uid', 'country_object_uid', 'geolocation_object_uid').
            flow (str): The type of flow (e.g., 'source' or 'destination').

        Returns:
            set: A set of network address objects or names.
        """
        security_policy_networks = set()

        match object_type:
            case 'object_uid':
                join = {
                    "table": "network_address_objects",
                    "condition": "security_policy_networks.object_uid = network_address_objects.uid"
                }
                columns = (
                    "network_address_objects.uid, "
                    "network_address_objects.name, "
                    "network_address_objects.object_container_uid, "
                    "network_address_objects.value, "
                    "network_address_objects.description, "
                    "network_address_objects.type, "
                    "network_address_objects.overridable_object"
                )
                network_objects_info = self._network_table.get(
                    columns=columns,
                    name_col=['security_policy_uid', 'flow'],
                    val=[self._uid, flow],
                    join=join,
                    not_null_condition=False,
                    multiple_where=True
                )
                
                for object_info in network_objects_info:
                    uid = object_info[0]
                    name = object_info[1]
                    key = (uid, name)
                    
                    # Use cache to avoid creating duplicate objects
                    network_object = self._object_cache.get_or_create(
                        key, 
                        lambda: PioneerNetworkObject(None, object_info)
                    )
                    security_policy_networks.add(network_object)

            case 'group_object_uid':
                columns = (
                    "network_group_objects.uid, "
                    "network_group_objects.name, "
                    "network_group_objects.object_container_uid, "
                    "network_group_objects.description, "
                    "network_group_objects.overridable_object"
                )
                join = {
                    "table": "network_group_objects",
                    "condition": "security_policy_networks.group_object_uid = network_group_objects.uid"
                }
                network_objects_info = self._network_table.get(
                    columns=columns,
                    name_col=['security_policy_uid', 'flow'],
                    val=[self._uid, flow],
                    join=join,
                    not_null_condition=False,
                    multiple_where=True
                )
                
                for object_info in network_objects_info:
                    uid = object_info[0]
                    name = object_info[1]
                    key = (uid, name)
                    
                    # Use cache to avoid creating duplicate objects
                    network_object = self._object_cache.get_or_create(
                        key, 
                        lambda: PioneerNetworkGroupObject(None, object_info)
                    )
                    
                    network_object.extract_members('object', self._object_cache, self._network_group_members_table)
                    network_object.extract_members('group', self._object_cache, self._network_group_members_table)
                    security_policy_networks.add(network_object)

            case 'country_object_uid':
                join = {
                    "table": "security_policy_networks",
                    "condition": "country_objects.uid = security_policy_networks.country_object_uid"
                }
                country_names = self._country_table.get(
                    columns='name',
                    name_col=['security_policy_uid', 'flow'],
                    val=[self._uid, flow],
                    join=join,
                    not_null_condition=True,
                    multiple_where=True
                )
                security_policy_networks.update(country_names)  # Convert list to set by updating

            case 'geolocation_object_uid':
                join = {
                    "table": "security_policy_networks",
                    "condition": "geolocation_objects.uid = security_policy_networks.geolocation_object_uid"
                }
                geolocation_names = self._geolocation_table.get(
                    columns='name',
                    name_col=['security_policy_uid', 'flow'],
                    val=[self._uid, flow],
                    join=join,
                    not_null_condition=True,
                    multiple_where=True
                )
                security_policy_networks.update(geolocation_names)  # Convert list to set by updating

        return security_policy_networks

    def extract_port_object_info(self, object_type, flow):
        """
        Extract port-related object information based on the object type and flow type.

        Parameters:
            object_type (str): The type of port-related object to extract (e.g., 'object_uid', 'icmp_object_uid', 'group_object_uid').
            flow (str): The type of flow (e.g., 'source' or 'destination').

        Returns:
            set: A set of port-related objects.
        """
        security_policy_ports_info = set()

        match object_type:
            case 'object_uid':
                join = {
                    "table": "port_objects",
                    "condition": "security_policy_ports.object_uid = port_objects.uid"
                }
                columns = (
                    "port_objects.uid, "
                    "port_objects.name, "
                    "port_objects.object_container_uid, "
                    "port_objects.protocol, "
                    "port_objects.source_port_number, "
                    "port_objects.destination_port_number, "
                    "port_objects.description, "
                    "port_objects.overridable_object"
                )
                data = self._port_table.get(
                    columns=columns,
                    name_col=['security_policy_uid', 'flow'],
                    val=[self._uid, flow],
                    join=join,
                    not_null_condition=False,
                    multiple_where=True
                )

                for object_info in data:
                    uid = object_info[0]
                    name = object_info[1]
                    key = (uid, name)
                    port_object = self._object_cache.get_or_create(
                        key,
                        lambda: PioneerPortObject(None, object_info)
                    )
                    security_policy_ports_info.add(port_object)

            case 'icmp_object_uid':
                join = {
                    "table": "icmp_objects",
                    "condition": "security_policy_ports.icmp_object_uid = icmp_objects.uid"
                }
                columns = (
                    "icmp_objects.uid, "
                    "icmp_objects.name, "
                    "icmp_objects.object_container_uid, "
                    "icmp_objects.type, "
                    "icmp_objects.code, "
                    "icmp_objects.description, "
                    "icmp_objects.overridable_object"
                )
                data = self._port_table.get(
                    columns=columns,
                    name_col=['security_policy_uid', 'flow'],
                    val=[self._uid, flow],
                    join=join,
                    not_null_condition=False,
                    multiple_where=True
                )

                for object_info in data:
                    uid = object_info[0]
                    name = object_info[1]
                    key = (uid, name)
                    icmp_object = self._object_cache.get_or_create(
                        key,
                        lambda: PioneerICMPObject(None, object_info)
                    )
                    security_policy_ports_info.add(icmp_object)

            case 'group_object_uid':
                join = {
                    "table": "port_group_objects",
                    "condition": "security_policy_ports.group_object_uid = port_group_objects.uid"
                }
                columns = (
                    "port_group_objects.uid, "
                    "port_group_objects.name, "
                    "port_group_objects.object_container_uid, "
                    "port_group_objects.description, "
                    "port_group_objects.overridable_object"
                )
                data = self._port_table.get(
                    columns=columns,
                    name_col=['security_policy_uid', 'flow'],
                    val=[self._uid, flow],
                    join=join,
                    not_null_condition=False,
                    multiple_where=True
                )

                for object_info in data:
                    uid = object_info[0]
                    name = object_info[1]
                    key = (uid, name)
                    port_group_object = self._object_cache.get_or_create(
                        key,
                        lambda: PioneerPortGroupObject(None, object_info)
                    )
                    port_group_object.extract_members('object', self._object_cache, self._port_group_members_table)
                    port_group_object.extract_members('group', self._object_cache, self._port_group_members_table)
                    port_group_object.extract_members('icmp', self._object_cache, self._port_group_members_table)
                    security_policy_ports_info.add(port_group_object)

        return security_policy_ports_info
    
    def extract_schedule_object_info(self):
        """
        Extract schedule object information for the current security policy.

        Returns:
            set: A set of schedule object names associated with the security policy.
        """
        join_condition = {
            "table": "security_policy_schedule",
            "condition": "schedule_objects.uid = security_policy_schedule.schedule_uid"
        }
        
        schedule_names = self._schedule_table.get(
            columns='name',
            name_col='security_policy_uid',
            val=self._uid,
            join=join_condition
        )
        
        return schedule_names

    def extract_user_object_info(self):
        """
        Extract user object information for the current security policy.

        Returns:
            set: A set of user object names associated with the security policy.
        """
        # Define the join condition for retrieving user objects
        join_condition = {
            "table": "security_policy_users",
            "condition": "policy_users.uid = security_policy_users.user_uid"
        }
        
        # Retrieve user names associated with the current security policy
        user_names = self._policy_user_table.get(
            columns='name',
            name_col='security_policy_uid',
            val=self._uid,
            join=join_condition
        )
        
        return user_names

    def extract_url_object_info(self, object_type):
        """
        Extract URL object information based on the provided object type.

        Parameters:
            object_type (str): Type of URL object to extract. Can be 'object', 'group', or 'url_category'.

        Returns:
            set or list: A set of URL objects or URL group objects if `object_type` is 'object' or 'group'.
                         A list of URL category names if `object_type` is 'url_category'.
        """
        urls_info = set()
        
        match object_type:
            case 'object':
                join_condition = {
                    "table": "url_objects",
                    "condition": "security_policy_urls.object_uid = url_objects.uid"
                }
                columns = "url_objects.uid, url_objects.name, url_objects.object_container_uid, url_objects.url_value, url_objects.description, url_objects.overridable_object"
                data = self._url_group_members_table.get(
                    columns=columns,
                    name_col='security_policy_uid',
                    val=self._uid,
                    join=join_condition,
                    not_null_condition=False
                )

                for object_info in data:
                    uid = object_info[0]
                    name = object_info[1]
                    key = (uid, name)
                    url_object = self._object_cache.get_or_create(key, lambda: PioneerURLObject(None, object_info))
                    urls_info.add(url_object)

            case 'group':
                join_condition = {
                    "table": "url_group_objects",
                    "condition": "security_policy_urls.group_object_uid = url_group_objects.uid"
                }
                columns = "url_group_objects.uid, url_group_objects.name, url_group_objects.object_container_uid, url_group_objects.description, url_group_objects.overridable_object"
                data = self._url_group_members_table.get(
                    columns=columns,
                    name_col='security_policy_uid',
                    val=self._uid,
                    join=join_condition,
                    not_null_condition=False
                )
                
                for object_info in data:
                    uid = object_info[0]
                    name = object_info[1]
                    key = (uid, name)
                    url_group_object = self._object_cache.get_or_create(key, lambda: PioneerURLGroupObject(None, object_info))
                    url_group_object.extract_members('object', self._object_cache, self._URLGroupMembersTable)
                    url_group_object.extract_members('group', self._object_cache, self._URLGroupMembersTable)
                    urls_info.add(url_group_object)

            case 'url_category':
                join_condition = {
                    "table": "security_policy_urls",
                    "condition": "url_categories.uid = security_policy_urls.url_category_uid"
                }
                urls_info = self._url_categories_table.get(
                    columns='name',
                    name_col='security_policy_uid',
                    val=self._uid,
                    join=join_condition
                )

        return urls_info
    
    def extract_l7_app_object_info(self, object_type):
        """
        Extract Layer 7 application object information based on the provided object type.

        Parameters:
            object_type (str): Type of L7 application object to extract. Can be 'l7_app_uid', 'l7_app_filter_uid', or 'l7_app_group_uid'.

        Returns:
            set or list: A set of L7 application objects, filters, or groups based on the object type.
        """
        join_condition = {}
        table = None

        match object_type:
            case 'l7_app_uid':
                join_condition = {
                    "table": "l7_app_objects",
                    "condition": "l7_apps.uid = l7_app_objects.l7_app_uid"
                }
                table = self._l7_app_objects_table
            case 'l7_app_filter_uid':
                join_condition = {
                    "table": "l7_app_filter_objects",
                    "condition": "l7_app_filters.uid = l7_app_filter_objects.l7_app_filter_uid"
                }
                table = self._l7_app_filter_table
            case 'l7_app_group_uid':
                join_condition = {
                    "table": "l7_app_group_objects",
                    "condition": "l7_app_groups.uid = l7_app_group_objects.l7_app_group_uid"
                }
                table = self._l7_app_group_table

        if table is None:
            raise ValueError(f"Invalid object type: {object_type}")

        l7_app_objects = table.get(
            columns='name',
            name_col='security_policy_uid',
            val=self._uid,
            join=join_condition
        )
        return l7_app_objects

    def log_special_parameters(self):
        """
        Logs special parameters associated with the security policy.

        This includes source and destination country objects, geolocation objects, schedules, users,
        URL categories, Layer 7 apps, filters, and groups. The information is logged if any of these 
        parameters have non-null values.
        """
        # Dictionary of special parameters and their values
        special_parameters = {
            "Source country objects": self._source_country_objects,
            "Destination country objects": self._destination_country_objects,
            "Source geolocation objects": self._source_geolocation_objects,
            "Destination geolocation objects": self._destination_geolocation_objects,
            "Schedules": self._schedule,
            "Users": self._users,
            "URL Categories": self._url_categories,
            "L7 Apps": self._policy_apps,
            "L7 App filters": self._policy_app_filters,
            "L7 App groups": self._policy_app_groups,
        }

        # Check if any special parameters have values to log
        if any(special_parameters.values()):
            special_policies_log.info("########################################################################################################")
            special_policies_log.info(f"Security policy <{self._name}> in container <{self._PolicyContainer.get_name()}>, index <{self._container_index}> has special parameters:")

            # Log each parameter with a non-null value
            for param_name, param_value in special_parameters.items():
                if param_value:
                    special_policies_log.info(f"{param_name}: {param_value}")

            special_policies_log.info("########################################################################################################")
