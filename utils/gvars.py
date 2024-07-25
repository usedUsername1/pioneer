network_literal_prefix = "NL_"
port_literal_prefix = "PL_"
url_literal_prefix = "UL_"
literal_objects_description = "Originally a literal value, converted to object."
virtual_container_name = "virtual_container"
db_name_suffix = "_db"

# LANDING DATABASE VARIABLES
pioneer_db_user = "pioneer_admin"
pioneer_db_user_pass = "2wsx#EDC"
landing_db = "pioneer_projects"
db_host = "127.0.0.1"
db_port = 5432

# LOGGING VARIABLES
general_logger = "general"
general_log_file = general_logger + ".log"
special_policies_logger = "special_policies"
special_policies_logger_file = special_policies_logger + ".log"

# DATABASE TABLE VARIABLES
general_data_table_name = "general_data"
security_policy_containers_table_name = "security_policy_containers"

# IMPORTING CONTAINER OBJECT TYPES VARIABLES
object_containers = 'object_container'
security_zone_container = 'security_zone_container'
managed_device_container = 'managed_device_container'
security_policy_container = 'security_policy_container'

# IMPORTING OBJECT VARIABLES
network_object = 'network_object'
network_group_object = 'network_group_object'
port_object = 'port_object'
port_group_object = 'port_group_object'
url_object = 'url_object'
url_group_object = 'url_group_object'
schedule_object = 'schedule_object'
security_zone = 'security_zone'
managed_device = 'managed_device'
country_object = 'country_object'
geolocation_object = 'geolocation_object'
icmp_object = 'icmp_object'
url_category_object = 'url_category_object'
policy_user_object = 'policy_user_object'
l7_app_object = 'l7_app_object'
l7_app_filter_object = 'l7_app_filter_object'
l7_app_group_object = 'l7_app_group_object'

# group is used here as a "flag" value. it marks the fact
# that the security policies will be processed as object groups
# also, only the security policies for a particular object container
# specified by the user will be returned
security_policy = 'security_policy_group'

# DEVICE TYPES VARIABLES
fmc_device_type = 'fmc_api'
panmc_device_type = 'panmc_api'
