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
        self._database = database,
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
                database = self._database[0],
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
    
    @staticmethod
    def create_db_relationships(object_groups, object_type, Database):
        members_dict_from_db = {}

        match object_type:
            case 'network_group_object':
                network_address_table = Database.get_network_address_objects_table()
                values_from_network_address_table_tuple_list = network_address_table.get(columns=['name', 'uid'])
                values_from_network_address_table_dict = dict(values_from_network_address_table_tuple_list)
                members_dict_from_db.update(values_from_network_address_table_dict)

                network_address_groups_table = Database.get_object_groups_table()
                values_from_object_groups_tuple_list = network_address_groups_table.get(columns=['name', 'uid'], name_col='group_type', val='network')
                values_from_object_groups_table_dict = dict(values_from_object_groups_tuple_list)
                members_dict_from_db.update(values_from_object_groups_table_dict)

        # retrieve the table storing the relationships between objects
        object_group_members_table = Database.get_object_group_members_table()

        # at this stage we assume that all the members of group objects for the current group type
        # have been saved in the database.
        # we can now retrieve the UIDs of members based on their names
        # loop through the object_groups
        for object_group in object_groups:
            # get the member names of the current object
            # for each member, retrieve its uid based on name
            # insert the relationship between the group uid and members uid in the database
            group_member_names = object_group.get_group_member_names()

            for group_member_name in group_member_names:
                group_member_uid = members_dict_from_db.get(group_member_name)
                object_group_members_table.insert(object_group.get_uid(), group_member_uid)

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

# TODO: implement this class
# each child of this object should be associated with a firewall object.
# for example. if i get the data of a firewall object, i want to do something like object.insert(), and the
# implementation of insert() for that object should be called
class PioneerTable():
    _table_columns = None
    def __init__(self, database):
        self._name = None
        self._table_columns = None
        self._database = database

    def create(self):
        self._database.create_table(self._name, self.get_schema())
    
    def get_schema(self):
        table_schema = ", ".join([f"{col[0]} {col[1]}" for col in self._table_columns])
        return table_schema

    def get_columns(self):
        # Extract only the column names from the table columns excluding foreign keys
        column_names = [col[0] for col in self._table_columns if not (col[0].startswith("CONSTRAINT") or col[0].startswith("PRIMARY"))]
        # Join the column names into a string
        table_columns_str = ", ".join(column_names)
        return table_columns_str

    #TODO: verify duplicate
    def insert(self, *values):
        columns = self.get_columns()
        
        # Construct placeholders for the values in the SQL query
        placeholders = ', '.join(['%s'] * len(values))
        
        insert_command = f"INSERT INTO {self._name} ({columns}) VALUES ({placeholders}) ON CONFLICT DO NOTHING;"
        try:
            cursor = self._database.get_cursor()
            
            # Execute the insert command with the actual values
            cursor.execute(insert_command, values)
            
            general_logger.info(f"Succesfully inserted values into table <{self._name}>.")
            
        except psycopg2.Error as err:
            general_logger.error(f"Failed to insert values <{values}> into: <{self._name}>. Reason: {err}")
   
    # move the get_table_value code here. the code must be rewritten in such a way
    # to permit multiple select queries
    # this function doesn't need an override
    def get(self, columns, name_col=None, val=None, order_param=None):
        # Ensure columns is either a string (single column) or a list/tuple (multiple columns)
        if isinstance(columns, str):
            columns_str = columns
        elif isinstance(columns, (list, tuple)):
            columns_str = ', '.join(columns)
        else:
            raise ValueError("columns parameter must be a string, list, or tuple of column names")

        if name_col and val:
            # Construct the SELECT query with a WHERE clause
            select_query = f"SELECT {columns_str} FROM {self._name} WHERE {name_col} = %s;"
            params = (val,)
        else:
            # Construct the SELECT query without a WHERE clause
            if order_param:
                select_query = f"SELECT {columns_str} FROM {self._name} ORDER BY {order_param};"
            else:
                select_query = f"SELECT {columns_str} FROM {self._name};"
            params = ()

        try:
            cursor = self._database.get_cursor()
            
            # Execute the select command with the actual values
            cursor.execute(select_query, params)
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

# the following are not supported, no need to create tables: policies_hitcount_table, nat_policies_table, user_source_table, policy_users_table
# security_zones_table, urls_categories_table, l7_apps_table, schedule_objects_table
class GeneralDataTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
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
    def __init__(self, database):
        super().__init__(database)
        self._name = "security_policy_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT UNIQUE NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class NATPolicyContainersTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "nat_policy_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT UNIQUE NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class ObjectContainersTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "object_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT UNIQUE NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class SecurityZoneContainersTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "security_zone_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT UNIQUE NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class ManagedDeviceContainersTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "managed_device_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT UNIQUE NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]
class ManagedDevicesTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
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

#TODO: find out what to do with regions and url categories.
class SecurityPoliciesTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "security_policies"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_policy_container_uid", "TEXT NOT NULL"),
            ("index", "INT"),
            ("category", "TEXT"),
            ("schedule", "TEXT"),
            ("status", "TEXT NOT NULL"),
            ("log_start", "BOOLEAN NOT NULL"),
            ("log_end", "BOOLEAN NOT NULL"),
            ("section", "TEXT"),
            ("action", "TEXT"),
            ("comments", "TEXT"),
            ("description", "TEXT"),
            ("CONSTRAINT fk_security_policy_container FOREIGN KEY(security_policy_container_uid)", "REFERENCES security_policy_containers(uid)"),
            ("CONSTRAINT uc_security_policy_container_uid1", "UNIQUE (name, security_policy_container_uid)")
        ]

class PoliciesHitcountTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "policies_hitcount"
        self._table_columns = [
            ("security_policy_name", "TEXT NOT NULL"),
            ("security_policy_container_name", "TEXT NOT NULL"),
            ("security_policy_hitcount", "INTEGER"),
            ("security_policy_last_hit", "TIMESTAMP"),
            ("nat_policy_name", "TEXT NOT NULL"),
            ("nat_policy_container_name", "TEXT NOT NULL"),
            ("nat_policy_hitcount", "INTEGER"),
            ("nat_policy_last_hit", "TIMESTAMP"),
            ("assigned_device_name", "TEXT NOT NULL"),
            ("CONSTRAINT fk_security_policy_container FOREIGN KEY(security_policy_container_uid)", "REFERENCES security_policy_containers(uid"),
            ("CONSTRAINT fk_nat_policy_container_uid FOREIGN KEY(nat_policy_container_uid)", "REFERENCES nat_policy_containers(uid)")
        ]

class SecurityZonesTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "security_zones"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("zone_container_uid", "TEXT NOT NULL"),
            ("description", "TEXT"),
            ("CONSTRAINT fk_zone_container_uid FOREIGN KEY(zone_container_uid)", "REFERENCES zone_container_uid(uid)"),
            ("CONSTRAINT uc_zone_container_uid", "UNIQUE (name, zone_container_uid)")
        ]

class URLObjectsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "url_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("url_value", "TEXT"),
            ("description", "TEXT"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid6", "UNIQUE (name, object_container_uid)")
        ]

class NetworkAddressObjectsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
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

# all groups will be stored in the same table since group objects
# don't have any particular value that distinguishes them from the rest of the object groups
class ObjectGroupsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "object_groups"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("description", "TEXT"),
            ("overridable_object", "BOOLEAN NOT NULL"),
            # this column defines the type of the group (etc network group, port group, etc)
            ("group_type", "TEXT NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid", "UNIQUE (name, object_container_uid)")
        ]

class ObjectGroupMembersTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "object_group_members"
        self._table_columns = [
            ("group_uid", "TEXT NOT NULL"),
            ("object_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_group FOREIGN KEY(group_uid)", "REFERENCES object_groups(uid)"),
            ("PRIMARY KEY(group_uid, object_uid)", "")
        ]

class GeolocationObjectsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "geolocation_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("continents", "TEXT[]"),
            ("countries", "TEXT[]"),
            ("countries_alpha2_codes", "TEXT[]"),
            ("countries_alpha3_codes", "TEXT[]"),
            ("countries_numeric_codes", "TEXT[]"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid10", "UNIQUE (name, object_container_uid)")
        ]

#TODO: source_port and destination_ports are needed here
class PortObjectsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
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
            ("CONSTRAINT uc_object_container_uid11", "UNIQUE (name, object_container_uid)")
        ]

class ICMPObjectsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
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
            ("CONSTRAINT uc_object_container_uid12", "UNIQUE (name, object_container_uid)")
        ]

class ScheduleObjectsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "schedule_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("recurring", "BOOLEAN NOT NULL"),
            ("start_date", "TEXT"),
            ("start_time", "TEXT"),
            ("end_date", "TEXT"),
            ("end_time", "TEXT"),
            ("reccurence_type", "TEXT"),
            ("daily_start", "TEXT"),
            ("daily_end", "TEXT"),
            ("week_day", "TEXT"),
            ("week_day_start", "TEXT"),
            ("week_day_end", "TEXT"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid14", "UNIQUE (name, object_container_uid)")
        ]


# import the zone data from the device. use an ID for the zones. ID will be primary key. import only the names for now
# import all the object data from the security device. use an ID for all the objects. the ID will be primary key
# don't forget that literals can also be used for defining object group data!
# both zone and object data should be imported after importing the security device

# scan policy data. find all literals first and insert them in the tables storing the object info.
# how to find all literals?
# now insert the policy data in the tables containing policy data and the referenced objects.

# security policies tables
class SecurityPolicyZones(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "policy_zones"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("security_policy_uid", "TEXT"),
            ("name", "TEXT NOT NULL"),
            ("flow", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)")
        ]

class SecurityPolicyObjects(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "policy_networks"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("security_policy_uid", "TEXT"),
            ("name", "TEXT NOT NULL"),
            ("flow", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)")
            
        ]

class SecurityPolicyServices(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "policy_services"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("security_policy_uid", "TEXT"),
            ("name", "TEXT NOT NULL"),
            ("flow", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)")
        ]

class PolicyUsers(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "policy_networks"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_policy_uid", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)")
        ]

class SecurityPolicyURLS(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "policy_networks"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_policy_uid", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)")
        ]

class SecurityPolicyL7Apps(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "policy_networks"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_policy_uid", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)")
        ]

# nat policies params

    # # this function inserts the metadata regarding the pioneer projects. will be overridden with "pass" by sub-classes in order to "stop" it from being inherited
    # def insert_into_projects_metadata(self, project_name, project_devices, project_description, creation_timestamp):
    #     insert_command = """INSERT INTO projects_metadata (project_name, project_devices, project_description, project_creation_time)
    #                                 VALUES ('{}', '{}', '{}', '{}')""".format(project_name, project_devices, project_description, creation_timestamp)

    #     self.insert_table_value('projects_metadata', insert_command)
        

    # # this function inserts the metadata regarding the devices created in pioneer. will be overridden with "pass" by sub-classes in order to "stop" it from being inherited
    # def insert_into_devices_metadata(self, device_name, device_type, device_description, creation_time):
    #     self.insert_table_value('projects_metadata', insert_command)
    #     insert_command = """INSERT INTO devices_metadata (project_name, project_devices, project_description, project_creation_time)
    #                                 VALUES ('{}', '{}', '{}', '{}')""".format(device_name, device_type, device_description, creation_time)

    #     self.insert_table_value('devices_metadata', insert_command)
    

