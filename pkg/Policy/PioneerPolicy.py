from pkg.Policy import SecurityPolicy
import utils.helper as helper
import utils.gvars as gvars
special_policies_log = helper.logging.getLogger(gvars.special_policies_logger)
# I have no better idea of storing and keeping track of what source/destination networks/ports/etc are objects/groups/special objects besides
# having different attributes

# should I initialize objects for the policy's parameters or is returning UIDs enough?
# let's just keep the UIDs idea for the time being
class PioneerSecurityPolicy(SecurityPolicy):
    _SecurityPolicyNetworksTable = None
    _SecurityPolicyZonesTable = None
    _SecurityPolicyPortsTable = None
    _SecurityPolicyUsersTable = None
    _SecurityPolicySchedulesTable = None
    _SecurityPolicyUsersTable = None
    _SecurityPolicyURLsTable = None
    _SecurityPolicyL7AppsTable = None
    
    _CountryObjectsTable = None
    _GeolocationObjectsTable = None
    _ScheduleObjectsTable = None
    _PolicyUsersTable = None
    _URLCategoriesTable = None
    _L7AppsTable = None
    _L7AppFiltersTable = None
    _L7AppGroupsTable = None

    _Database = None
    _initialized = False  # Initialization flag

    @classmethod
    def initialize_class_variables(cls, PolicyContainer):
        """
        Initialize class variables if they are not already initialized.
        """
        if not cls._initialized:
            SecurityDevice = PolicyContainer.get_security_device()
            cls._Database = SecurityDevice.get_database()
            cls._SecurityPolicyNetworksTable = cls._Database.get_security_policy_networks_table()
            cls._SecurityPolicyZonesTable = cls._Database.get_security_policy_zones_table()
            cls._SecurityPolicyPortsTable = cls._Database.get_security_policy_ports_table()
            cls._SecurityPolicyUsersTable = cls._Database.get_security_policy_users_table()
            cls._SecurityPolicySchedulesTable = cls._Database.get_security_policy_schedule_table()
            cls._SecurityPolicyURLsTable = cls._Database.get_security_policy_urls_table()
            cls._SecurityPolicyL7AppsTable = cls._Database.get_security_policy_l7_apps_table()
            cls._CountryObjectsTable = cls._Database.get_country_objects_table()
            cls._GeolocationObjectsTable = cls._Database.get_geolocation_objects_table()
            cls._ScheduleObjectsTable = cls._Database.get_schedule_objects_table()
            cls._PolicyUsersTable = cls._Database.get_policy_user_objects_table()
            cls._URLCategoriesTable = cls._Database.get_url_category_objects_table()
            cls._L7AppsTable = cls._Database.get_l7_app_objects_table()
            cls._L7AppFiltersTable = cls._Database.get_l7_app_filter_objects_table()
            cls._L7AppGroupsTable = cls._Database.get_l7_app_group_objects_table()
            
            cls._initialized = True

    def __init__(self, PolicyContainer, policy_info) -> None:
        self._uid = policy_info[0]
        self._name = policy_info[1]
        self._PolicyContainer = PolicyContainer
        PioneerSecurityPolicy.initialize_class_variables(PolicyContainer)
        self._source_zones = self.extract_security_zone_object_info('source')
        self._destination_zones = self.extract_security_zone_object_info('destination')
        
        self._source_network_objects = self.extract_network_address_object_info('object_uid','source')
        self._source_network_group_objects = self.extract_network_address_object_info('group_object_uid','source')
        self._destination_network_objects = self.extract_network_address_object_info('object_uid','destination')
        self._destination_network_group_objects = self.extract_network_address_object_info('group_object_uid','destination')
        
        self._source_networks = [self._source_network_objects, self._source_network_group_objects]
        self._destination_networks = [self._destination_network_objects, self._destination_network_group_objects]
        
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

        # I'd rather keep the ICMP objects separately, just in case there are compatibility issues with migration between platforms
        self._source_ports = [self._source_port_objects, self._source_port_group_objects]
        self._destination_ports = [self._destination_port_objects, self._destination_port_group_objects]

        self._schedule_objects = self.extract_schedule_object_info()
        self._users = self.extract_user_object_info()

        self._url_objects = self.extract_url_object_info('object_uid')
        self._url_groups = self.extract_url_object_info('group_object_uid')
        self._url_categories = self.extract_url_object_info('url_category_uid')
        self._urls = [self._url_objects, self._url_groups]

        self._policy_apps = self.extract_l7_app_object_info('l7_app_uid')
        self._policy_app_filters = self.extract_l7_app_object_info('l7_app_filter_uid')
        self._policy_app_groups = self.extract_l7_app_object_info('l7_app_group_uid')


        security_policy_index = policy_info[3]
        security_policy_category = policy_info[4]
        security_policy_status = policy_info[5]
        security_policy_log_start = policy_info[6]
        security_policy_log_end = policy_info[7]
        security_policy_log_to_manager = policy_info[8]
        security_policy_log_to_syslog = policy_info[9]
        security_policy_section = policy_info[10]
        security_policy_action = policy_info[11]
        security_policy_comments = policy_info[12]
        security_policy_description = policy_info[13]

        super().__init__(
            self._PolicyContainer,
            self._name,
            security_policy_index,
            security_policy_status,
            security_policy_category,
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
            security_policy_description,
            security_policy_comments,
            security_policy_log_to_manager,
            security_policy_log_to_syslog,
            security_policy_log_start,
            security_policy_log_end,
            security_policy_section,
            security_policy_action
        )
    
    def extract_security_zone_object_info(self, flow):        
        security_policy_zones = self._SecurityPolicyZonesTable.get(columns='zone_uid', name_col=['security_policy_uid', 'flow'], val=[self._uid, flow], not_null_condition=True, multiple_where=True)
        return security_policy_zones
    
    def extract_network_address_object_info(self, object_type, flow):
        security_policy_networks = ''
        match object_type:
            case 'object_uid':
                security_policy_networks = self._SecurityPolicyNetworksTable.get(columns=object_type, name_col=['security_policy_uid', 'flow'], val=[self._uid, flow], not_null_condition=True, multiple_where=True)
            case 'country_object_uid':
                join = {"table": "security_policy_networks", "condition": "country_objects.uid = security_policy_networks.country_object_uid"}
                security_policy_networks = self._CountryObjectsTable.get(columns='name', name_col=['security_policy_uid', 'flow'], val=[self._uid, flow], join=join, not_null_condition=True, multiple_where=True)
            case 'geolocation_object_uid':
                join = {"table": "security_policy_networks", "condition": "geolocation_objects.uid = security_policy_networks.geolocation_object_uid"}
                security_policy_networks = self._GeolocationObjectsTable.get(columns='name', name_col=['security_policy_uid', 'flow'], val=[self._uid, flow], join=join, not_null_condition=True, multiple_where=True)
        
        return security_policy_networks

    def extract_port_object_info(self, object_type, flow):
        security_policy_ports = self._SecurityPolicyPortsTable.get(columns=object_type, name_col=['security_policy_uid', 'flow'], val=[self._uid, flow], not_null_condition=True, multiple_where=True)
        return security_policy_ports
    
    def extract_schedule_object_info(self):
            join = {
                "table": "security_policy_schedule",
                "condition": "schedule_objects.uid = security_policy_schedule.schedule_uid"
            }
            security_policy_schedule = self._ScheduleObjectsTable.get(columns='name', name_col='security_policy_uid', val=self._uid, join=join)
            return security_policy_schedule

    def extract_user_object_info(self):
            join = {
                "table": "security_policy_users",
                "condition": "policy_users.uid = security_policy_users.user_uid"
            }
            security_policy_users = self._PolicyUsersTable.get(columns='name', name_col='security_policy_uid', val=self._uid, join=join)
            return security_policy_users

    def extract_url_object_info(self, object_type):
        security_policy_urls = ''
        if object_type == 'url_category_uid':
            join = {
                "table": "security_policy_urls",
                "condition": "url_categories.uid = security_policy_urls.url_category_uid"
            }
            security_policy_urls = self._URLCategoriesTable.get(columns='name', name_col='security_policy_uid', val=self._uid, join=join)
        else:
            security_policy_urls = self._SecurityPolicyURLsTable.get(columns=object_type, name_col='security_policy_uid', val=self._uid, not_null_condition=True)

        return security_policy_urls
    
    def extract_l7_app_object_info(self, object_type):
        join = ''
        match object_type:
            case 'l7_app_uid':
                join = {
                    "table": "security_policy_l7_apps",
                    "condition": "l7_apps.uid = security_policy_l7_apps.l7_app_uid"
                }
                table = self._L7AppsTable
            case 'l7_app_filter_uid':
                join = {
                    "table": "security_policy_l7_apps",
                    "condition": "l7_app_filters.uid = security_policy_l7_apps.l7_app_filter_uid"
                }
                table = self._L7AppFiltersTable
            case 'l7_app_group_uid':
                join = {
                    "table": "security_policy_l7_apps",
                    "condition": "l7_app_groups.uid = security_policy_l7_apps.l7_app_group_uid"
                }
                table = self._L7AppGroupsTable

        security_policy_apps = table.get(columns='name', name_col='security_policy_uid', val=self._uid, join=join)
        return security_policy_apps

    def log_special_parameters(self):
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

        if any(special_parameters.values()):
            special_policies_log.info(f"########################################################################################################")
            special_policies_log.info(f"Security policy <{self._name}> in container <{self._PolicyContainer.get_name()}>, index <{self._container_index}> has special parameters:")

            for param_name, param_value in special_parameters.items():
                if param_value:
                    special_policies_log.info(f"{param_name}: <{param_value}>")
                
    def get_source_network_objects(self):
        return self._source_network_objects
    
    def get_destination_network_objects(self):
        return self._destination_network_objects
    
    def get_source_network_group_objects(self):
        return self._source_network_group_objects
    
    def get_destination_network_group_objects(self):
        return self._destination_network_group_objects