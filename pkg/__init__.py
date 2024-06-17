from abc import ABC, abstractmethod
import psycopg2
import sys
import utils.helper as helper

general_logger = helper.logging.getLogger('general')
# there should still be functions in the helper module. the functions in helper will interact with postgres
# the function form here will interact with the objects databases
class DBConnection():
    def __init__(self, user, database, password, host, port):
        """
        Initialize a database connection.

        Args:
            user (str): The username for the database connection.
            database (str): The name of the database to connect to.
            password (str): The password for the database connection.
            host (str): The hostname of the database server.
            port (int): The port number for connecting to the database server.
        """
        self._user = user,
        self._Database = database,
        self._password = password,
        self._host = host,
        self._port = port,
    
    def create_cursor(self):
        """
        Create a cursor for interacting with the database.

        Returns:
            cursor: The database cursor.
        """
        # self parameters are returned as a tuple, they need to be extracted
        try:
            postgres_conn = psycopg2.connect(
                user = self._user[0],
                database = self._Database[0],
                password = self._password[0],
                host = self._host[0],
                port = self._port[0]
            )
            # set autocommit to True
            postgres_conn.autocommit = True

        # if the connection fails, catch the error and exit the program
        except psycopg2.Error as err:
            general_logger.critical(f"Error connecting to PostgreSQL Platform: {err}.")
            sys.exit(1)
        
        # initialize the db cursor
        database_cursor = postgres_conn.cursor()
        general_logger.debug(f"Succesfully created cursor {database_cursor}.")

        # return the cursor to the caller
        return database_cursor

class PioneerDatabase():
    def __init__(self, cursor):
        self._cursor = cursor

    @abstractmethod
    def table_factory(self):
        pass

    def create_database(self, name):
        # execute the request to create the database for the project. no need to specify the owner
        # as the owner will be the creator of the database.
        general_logger.info(f"Creating device database: <{name}>.")
        try:
            # execute the query to create the database
            query = """CREATE DATABASE {};""".format(name)
            general_logger.debug(f"Executing the following query: {query}.")
            self._cursor.execute(query)

            # inform the user that the execution succeeded
            general_logger.info(f"Succesfully created database: {name}")

        # catch the error and exit the program if database creation fails
        except psycopg2.Error as err:
            general_logger.critical(f"Error creating database: {name}. Reason: {err}")
            sys.exit(1)

    
    def delete_database(self, name):
        try:
            query = """DROP DATABASE {};""".format(name)
            general_logger.debug(f"Executing the following query: {query}.")
            self._cursor.execute(query)

            general_logger.info(f"Succesfully deleted database: {name}")
        
        except psycopg2.Error as err:
            general_logger.critical(f"Error deleting database: {name}. Reason: {err}")
            sys.exit(1)  

    def create_table(self, table_name, table_schema):
        command = f"""CREATE TABLE IF NOT EXISTS {table_name} ({table_schema});"""
        try:
            general_logger.info(f"Creating table: <{table_name}>.")
            self._cursor.execute(command)
        
        except psycopg2.Error as err:
            general_logger.critical(f"Error creating table: <{table_name}>. Reason: <{err}>.")
            sys.exit(1)
    
    def get_cursor(self):
        return self._cursor
    
    @staticmethod
    def flatten_query_result(query_result):
        # Flatten both lists within each tuple and handle any number of sublists
        flattened_list = [item for tuple_item in query_result for sublist_part in tuple_item for item in sublist_part]

        # Convert the list to a set to remove duplicate values and then back to a list
        unique_values_list = list(set(flattened_list))

        # Return the list with unique values
        general_logger.info(f"Flattened the query result.")
        return unique_values_list

    @staticmethod
    def connect_to_db(db_user, database, db_password, db_host, db_port):
        """
        Connects to the security device database.

        Args:
            db_user (str): Database username.
            db_password (str): Password for the database user.
            db_host (str): Hostname of the database server.
            db_port (int): Port number of the database server.
            security_device_name (str): Name of the security device.

        Returns:
            cursor: Cursor object for database operations.
        """
        DatabaseConnection = DBConnection(db_user, database, db_password, db_host, db_port)
        general_logger.info(f"Connecting to device database: <{database}>.")
        cursor = DatabaseConnection.create_cursor()
        return cursor
    
    #TODO: should this be made a class method for objects which need to have their data preloaded?
    # make sure that you preload the data for a specific container, not for all of them!
    # objects and policies have container scope
    @staticmethod
    def preload_object_data(object_type, Database):
            def get_table_data(table, columns):
                """
                Helper function to get data from a table and convert it to a dictionary.
                """
                values_tuple_list = table.get(columns=columns)
                return dict(values_tuple_list)

            members_dict_from_db = {}

            if object_type == 'network_group_object':
                tables_to_fetch = [
                    Database.get_network_address_objects_table(),
                    Database.get_network_group_objects_table()
                ]
            elif object_type == 'port_group_object':
                tables_to_fetch = [
                    Database.get_port_objects_table(),
                    Database.get_port_group_objects_table(),
                    Database.get_icmp_objects_table()
                ]
            elif object_type == 'url_group_object':
                tables_to_fetch = [
                    Database.get_url_objects_table(),
                    Database.get_url_group_objects_table()
                ]

            #TODO: stuff might be duplicated here (names of the objects, elements should be retrieved individually, not in the same place)
            elif object_type == 'security_policy_group':
                tables_to_fetch = {
                    'security_zones': Database.get_security_zones_table(),
                    'network_objects': Database.get_network_address_objects_table(),
                    'network_group_objects': Database.get_network_group_objects_table(),
                    'country_objects':Database.get_country_objects_table(),
                    'geolocation_objects': Database.get_geolocation_objects_table(),
                    'port_objects': Database.get_port_objects_table(),
                    'port_group_objects': Database.get_port_group_objects_table(),
                    'icmp_objects': Database.get_icmp_objects_table(),
                    'url_objects': Database.get_url_objects_table(),
                    'url_group_objects': Database.get_url_group_objects_table(),
                    'url_category_objects':Database.get_url_category_objects_table(),
                    'schedule_objects': Database.get_schedule_objects_table(),
                    'policy_user_objects': Database.get_policy_user_objects_table(),
                    'l7_app_objects': Database.get_l7_app_objects_table(),
                    'l7_app_filter_objects': Database.get_l7_app_filter_objects_table(),
                    'l7_app_group_objects': Database.get_l7_app_group_objects_table()
                }
                # Fetch data for each table and store it in members_dict_from_db with the table name as key
                for table_name, table in tables_to_fetch.items():
                    members_dict_from_db[table_name] = get_table_data(table, ['name', 'uid'])
                return members_dict_from_db
            
            else:
                tables_to_fetch = []

            for table in tables_to_fetch:
                members_dict_from_db.update(get_table_data(table, ['name', 'uid']))
            
            return members_dict_from_db

class PioneerTable():
    _table_columns = None
    def __init__(self, Database):
        self._name = None
        self._table_columns = None
        self._Database = Database

    def create(self):
        self._Database.create_table(self._name, self.get_schema())
    
    def get_schema(self):
        table_schema = ", ".join([f"{col[0]} {col[1]}" for col in self._table_columns])
        return table_schema

    def get_columns(self):
        # Extract only the column names from the table columns excluding foreign keys
        column_names = [col[0] for col in self._table_columns if not (col[0].startswith("CONSTRAINT") or col[0].startswith("PRIMARY"))]
        # Join the column names into a string
        table_columns_str = ", ".join(column_names)
        return table_columns_str

    def insert(self, *values):
        columns = self.get_columns()
        
        # Construct placeholders for the values in the SQL query
        placeholders = ', '.join(['%s'] * len(values))
        
        insert_command = f"INSERT INTO {self._name} ({columns}) VALUES ({placeholders}) ON CONFLICT DO NOTHING;"
        try:
            cursor = self._Database.get_cursor()
            
            # Execute the insert command with the actual values
            cursor.execute(insert_command, values)
            
            general_logger.info(f"Succesfully inserted values into table <{self._name}>.")
            
        except psycopg2.Error as err:
            general_logger.error(f"Failed to insert values <{values}> into: <{self._name}>. Reason: {err}")
   
    # move the get_table_value code here. the code must be rewritten in such a way
    # to permit multiple select queries
    # this function doesn't need an override
    def get(self, columns, name_col=None, val=None, order_param=None, join=None):
        # Ensure columns is either a string (single column) or a list/tuple (multiple columns)
        if isinstance(columns, str):
            columns_str = columns
        elif isinstance(columns, (list, tuple)):
            columns_str = ', '.join(columns)
        else:
            raise ValueError("columns parameter must be a string, list, or tuple of column names")

        join_clause = ""
        if join:
            join_clause = f" JOIN {join['table']} ON {join['condition']}"

        if name_col and val:
            # Construct the SELECT query with a WHERE clause
            select_query = f"SELECT {columns_str} FROM {self._name}{join_clause} WHERE {name_col} = %s;"
            params = (val,)
        else:
            # Construct the SELECT query without a WHERE clause
            if order_param:
                select_query = f"SELECT {columns_str} FROM {self._name}{join_clause} ORDER BY {order_param};"
            else:
                select_query = f"SELECT {columns_str} FROM {self._name}{join_clause};"
            params = ()

        try:
            cursor = self._Database.get_cursor()
            
            # Execute the select command with the actual values
            cursor.execute(select_query, params)
            # print(select_query)
        except psycopg2.Error as err:
            general_logger.error(f"Failed to select values from table: <{self._name}>. Reason: {err}")
            # sys.exit(1) or raise an exception if needed

        # Fetch the returned query values
        postgres_cursor_data = cursor.fetchall()
        general_logger.info(f"Successfully retrieved values from table: <{self._name}>.")
        return postgres_cursor_data

    # this function updates values into a table
    # def update(self, table_name, update_command):
    #     try:
    #         cursor.execute(update_command)

    #     except psycopg2.Error as err:
    #         general_logger.error(f"Failed to update values for: <{table_name}>. Reason: <{err}>")
    #         sys.exit(1)

# security_zones_table, urls_categories_table, l7_apps_table, schedule_objects_table
class GeneralDataTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "general_security_device_data"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL UNIQUE"),  # Adding UNIQUE constraint to ensure uniqueness
            ("username", "TEXT NOT NULL"),
            ("secret", "TEXT NOT NULL"),
            ("hostname", "TEXT NOT NULL"),
            ("type", "TEXT NOT NULL"),
            ("port", "TEXT NOT NULL"),
            ("version", "TEXT NOT NULL"),
            ("management_domain", "TEXT NOT NULL") 
        ]

class SecurityPolicyContainersTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "security_policy_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class NATPolicyContainersTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "nat_policy_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class ObjectContainersTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "object_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class SecurityZoneContainersTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "security_zone_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class ManagedDeviceContainersTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "managed_device_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]
class ManagedDevicesTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "managed_devices"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("managed_device_container_uid", "TEXT"),
            ("assigned_security_policy_container_uid", "TEXT"),
            ("hostname", "TEXT"),
            ("cluster", "TEXT"),
            ("CONSTRAINT fk_managed_device_container_uid FOREIGN KEY (managed_device_container_uid)", "REFERENCES managed_device_containers (uid)"),
            ("CONSTRAINT fk_assigned_security_policy_container_uid FOREIGN KEY (assigned_security_policy_container_uid)", "REFERENCES security_policy_containers (uid)"),
            ("CONSTRAINT uc_managed_device_container_uid", "UNIQUE (name, managed_device_container_uid)")
        ]

class SecurityPoliciesTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "security_policies"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_policy_container_uid", "TEXT NOT NULL"),
            ("index", "INT"),
            ("category", "TEXT"),
            ("status", "TEXT NOT NULL"),
            ("log_start", "BOOLEAN NOT NULL"),
            ("log_end", "BOOLEAN NOT NULL"),
            ("log_to_manager", "BOOLEAN NOT NULL"),
            ("log_to_syslog", "BOOLEAN NOT NULL"),
            ("section", "TEXT"),
            ("action", "TEXT"),
            ("comments", "TEXT"),
            ("description", "TEXT"),
            ("CONSTRAINT fk_security_policy_container FOREIGN KEY(security_policy_container_uid)", "REFERENCES security_policy_containers(uid)"),
            ("CONSTRAINT uc_security_policy_container_uid1", "UNIQUE (name, security_policy_container_uid)")
        ]

# class PoliciesHitcountTable(PioneerTable):
#     def __init__(self, Database):
#         super().__init__(Database)
#         self._name = "policies_hitcount"
#         self._table_columns = [
#             ("security_policy_container_uid", "TEXT NOT NULL"),
#             ("security_policy_container_name", "TEXT NOT NULL"),
#             ("security_policy_hitcount", "INTEGER"),
#             ("security_policy_last_hit", "TIMESTAMP"),
#             ("nat_policy_name", "TEXT NOT NULL"),
#             ("nat_policy_container_name", "TEXT NOT NULL"),
#             ("nat_policy_hitcount", "INTEGER"),
#             ("nat_policy_last_hit", "TIMESTAMP"),
#             ("assigned_device_name", "TEXT NOT NULL"),
#             ("CONSTRAINT fk_security_policy_container FOREIGN KEY(security_policy_container_uid)", "REFERENCES security_policy_containers(uid)"),
#             ("CONSTRAINT fk_nat_policy_container_uid FOREIGN KEY(nat_policy_container_uid)", "REFERENCES nat_policy_containers(uid)")
#         ]

class SecurityZonesTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "security_zones"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("zone_container_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_zone_container_uid FOREIGN KEY(zone_container_uid)", "REFERENCES security_zone_containers(uid)"),
            ("CONSTRAINT uc_zone_container_uid", "UNIQUE (name, zone_container_uid)")
        ]

class URLObjectsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "url_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("url_value", "TEXT"),
            ("description", "TEXT"),
            ("overridable_object", "BOOLEAN NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid6", "UNIQUE (name, object_container_uid)")
        ]

class NetworkAddressObjectsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "network_address_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("value", "TEXT"),
            ("description", "TEXT"),
            ("type", "TEXT"),
            ("overridable_object", "BOOLEAN NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid8", "UNIQUE (name, object_container_uid)")
        ]

class NetworkGroupObjectsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "network_group_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("description", "TEXT"),
            ("overridable_object", "BOOLEAN NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid9", "UNIQUE (name, object_container_uid)")
        ]

class PortGroupObjectsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "port_group_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("description", "TEXT"),
            ("overridable_object", "BOOLEAN NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid10", "UNIQUE (name, object_container_uid)")
        ]

class URLGroupObjectsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "url_group_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("description", "TEXT"),
            ("overridable_object", "BOOLEAN NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid12", "UNIQUE (name, object_container_uid)")
        ]

class NetworkGroupObjectsMembersTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "network_group_objects_members"
        self._table_columns = [
            ("group_uid", "TEXT NOT NULL"),
            ("object_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_group FOREIGN KEY(group_uid)", "REFERENCES network_group_objects(uid)")
        ]

class PortGroupObjectsMembersTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "port_group_objects_members"
        self._table_columns = [
            ("group_uid", "TEXT NOT NULL"),
            ("object_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_group FOREIGN KEY(group_uid)", "REFERENCES port_group_objects(uid)")
        ]

class URLGroupObjectsMembersTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "url_group_objects_members"
        self._table_columns = [
            ("group_uid", "TEXT NOT NULL"),
            ("object_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_group FOREIGN KEY(group_uid)", "REFERENCES url_group_objects(uid)")
        ]

#TODO: proper support for this
class GeolocationObjectsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "geolocation_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid13", "UNIQUE (name, object_container_uid)")
        ]

#Fuck you, Cisco and fuck you, Firepower Management Center
class CountryObjectsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "country_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid34", "UNIQUE (name, object_container_uid)")
        ]

class PortObjectsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "port_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("protocol", "TEXT"),
            ("source_port_number", "TEXT"),
            ("destination_port_number", "TEXT"),
            ("description", "TEXT"),
            ("overridable_object", "BOOLEAN NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid16", "UNIQUE (name, object_container_uid)")
        ]

class ICMPObjectsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "icmp_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("type", "TEXT"),
            ("code", "TEXT"),
            ("description", "TEXT"),
            ("overridable_object", "BOOLEAN NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid14", "UNIQUE (name, object_container_uid)")
        ]

#TODO: proper support for schedule objects and all objects below
class ScheduleObjectsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "schedule_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("description", "TEXT"),
            # ("recurring", "BOOLEAN"),
            # ("start_date", "TEXT"),
            # ("start_time", "TEXT"),
            # ("end_date", "TEXT"),
            # ("end_time", "TEXT"),
            # ("reccurence_type", "TEXT"),
            # ("daily_start", "TEXT"),
            # ("daily_end", "TEXT"),
            # ("week_day", "TEXT"),
            # ("week_day_start", "TEXT"),
            # ("week_day_end", "TEXT"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid15", "UNIQUE (name, object_container_uid)")
        ]

# class UserRealms(PioneerTable):
#     def __init__(self, Database):
#         super().__init__(Database)
#         self._name = "user_realms"
#         self._table_columns = [
#             ("uid", "TEXT PRIMARY KEY"),
#             ("name", "TEXT NOT NULL"),
#             ("object_container_uid", "TEXT NOT NULL"),
#             ("description", "TEXT"),
#             ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
#             ("CONSTRAINT uc_object_container_uid18", "UNIQUE (name, object_container_uid)")
#         ]

class PolicyUsersTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "policy_users"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid20", "UNIQUE (name, object_container_uid)")
        ]

class L7AppsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "l7_apps"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid19", "UNIQUE (name, object_container_uid)")
        ]

class L7AppFiltersTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "l7_app_filters"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("type", "TEXT NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid23", "UNIQUE (name, object_container_uid)")
        ]

class L7AppGroupsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "l7_app_groups"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid29", "UNIQUE (name, object_container_uid)")
        ]

class L7AppGroupMembersTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "l7_app_group_members"
        self._table_columns = [
            ("group_uid", "TEXT NOT NULL"),
            ("object_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_group FOREIGN KEY(group_uid)", "REFERENCES l7_app_groups(uid)"),
            ("PRIMARY KEY(group_uid, object_uid)", "")
        ]

class URLCategoriesTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "url_categories"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("reputation", "TEXT"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid22", "UNIQUE (name, object_container_uid)")
        ]

# security policies tables
class SecurityPolicyZonesTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "security_policy_zones"
        self._table_columns = [
            ("security_policy_uid", "TEXT NOT NULL"),
            ("zone_uid", "TEXT"),
            ("flow", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)")
        ]

class SecurityPolicyNetworksTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "security_policy_networks"
        self._table_columns = [
            ("security_policy_uid", "TEXT NOT NULL"),
            ("object_uid", "TEXT"),
            ("group_object_uid", "TEXT"),
            ("country_object_uid", "TEXT"),
            ("geolocation_object_uid", "TEXT"),
            ("flow", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)"),
            ("CONSTRAINT fk_object_uid FOREIGN KEY (object_uid)", "REFERENCES network_address_objects (uid)"),
            ("CONSTRAINT fk_group_object_uid FOREIGN KEY (group_object_uid)", "REFERENCES network_group_objects (uid)"),
            ("CONSTRAINT fk_geolocation_object_uid FOREIGN KEY (geolocation_object_uid)", "REFERENCES geolocation_objects (uid)")
        ]

class SecurityPolicyPortsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "security_policy_ports"
        self._table_columns = [
            ("security_policy_uid", "TEXT NOT NULL"),
            ("object_uid", "TEXT"),
            ("icmp_object_uid", "TEXT"),
            ("group_object_uid", "TEXT"),
            ("flow", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)"),
            ("CONSTRAINT fk_object_uid FOREIGN KEY (object_uid)", "REFERENCES port_objects (uid)"),
            ("CONSTRAINT fk_icmp_object_uid FOREIGN KEY (icmp_object_uid)", "REFERENCES icmp_objects (uid)"),
            ("CONSTRAINT fk_group_object_uid FOREIGN KEY (group_object_uid)", "REFERENCES port_group_objects (uid)")
        ]

class SecurityPolicyUsersTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "security_policy_users"
        self._table_columns = [
            ("security_policy_uid", "TEXT NOT NULL"),
            ("user_uid", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)"),
            ("CONSTRAINT fk_user_uid FOREIGN KEY (user_uid)", "REFERENCES policy_users (uid)")
        ]

class SecurityPolicyURLsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "security_policy_urls"
        self._table_columns = [
            ("security_policy_uid", "TEXT NOT NULL"),
            ("object_uid", "TEXT"),
            ("group_object_uid", "TEXT"),
            ("url_category_uid", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)"),
            ("CONSTRAINT fk_object_uid FOREIGN KEY (object_uid)", "REFERENCES url_objects (uid)"),
            ("CONSTRAINT fk_group_object_uid FOREIGN KEY (group_object_uid)", "REFERENCES url_group_objects (uid)"),
            ("CONSTRAINT fk_url_category_uid FOREIGN KEY (url_category_uid)", "REFERENCES url_categories (uid)")
        ]

class SecurityPolicyL7AppsTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "security_policy_l7_apps"
        self._table_columns = [
            ("security_policy_uid", "TEXT"),
            ("l7_app_uid", "TEXT"),
            ("l7_app_filter_uid", "TEXT"),
            ("l7_app_group_uid", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)"),
            ("CONSTRAINT fk_l7_app_uid FOREIGN KEY (l7_app_uid)", "REFERENCES l7_apps (uid)"),
            ("CONSTRAINT fk_l7_app_filter_uid FOREIGN KEY (l7_app_filter_uid)", "REFERENCES l7_app_filters (uid)"),
            ("CONSTRAINT fk_l7_app_group_uid FOREIGN KEY (l7_app_group_uid)", "REFERENCES l7_app_groups (uid)")
        ]

class SecurityPolicyScheduleTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "security_policy_schedule"
        self._table_columns = [
            ("security_policy_uid", "TEXT"),
            ("schedule_uid", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)"),
            ("CONSTRAINT fk_schedule_uid FOREIGN KEY (schedule_uid)", "REFERENCES schedule_objects (uid)")
        ]

# migration projects table
class MigrationProjectGeneralDataTable(PioneerTable):
    def __init__(self, Database) -> None:
        super().__init__(Database)
        self._name = "migration_project_general_data"
        self._table_columns = [
            ("name", "TEXT NOT NULL"),
            ("description", "TEXT"),
            ("creation_date", "TIMESTAMP")
        ]

class MigrationProjectDevicesTable(PioneerTable):
    def __init__(self, Database):
        super().__init__(Database)
        self._name = "migration_project_devices"
        self._table_columns = [
            ("source_device_uid", "TEXT NOT NULL"),
            ("target_device_uid", "TEXT NOT NULL"),
            ("PRIMARY KEY (source_device_uid, target_device_uid)", "")
        ]

class SecurityDeviceInterfaceMap(PioneerTable):
    def __init__(self, Database) -> None:
        super().__init__(Database)
        self._name = "security_zones_map"
        self._table_columns = [
            ("source_security_zone", "TEXT"),
            ("target_security_zone", "TEXT"),
            ("CONSTRAINT fk_source_security_zone FOREIGN KEY (source_security_zone)", "REFERENCES security_zones (uid)"),
            ("CONSTRAINT fk_target_security_zone FOREIGN KEY (target_security_zone)", "REFERENCES security_zones (uid)")
        ]

class SecurityPolicyContainersMapTable(PioneerTable):
    def __init__(self, Database) -> None:
        super().__init__(Database)
        self._name = "security_policy_containers_map"
        self._table_columns = [
            ("source_security_policy_container_uid", "TEXT"),
            ("target_security_policy_container_uid", "TEXT"),
            ("CONSTRAINT fk_source_security_policy_container FOREIGN KEY (source_security_policy_container_uid)", "REFERENCES security_policy_containers (uid)"),
            ("CONSTRAINT fk_target_security_policy_container FOREIGN KEY (target_security_policy_container_uid)", "REFERENCES security_policy_containers (uid)")
        ]

