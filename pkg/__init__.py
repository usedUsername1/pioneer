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
        general_logger.debug(f"Called DBConnection.__init__()")
    
    def create_cursor(self):
        """
        Create a cursor for interacting with the database.

        Returns:
            cursor: The database cursor.
        """
        general_logger.debug(f"Called DBConnection.create_cursor().")
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

#TODO: refactor these functions as well!
class PioneerDatabase():
    def __init__(self, cursor):
        self._cursor = cursor
        general_logger.debug(f"Called PioneerDatabase.__init__().")

    @abstractmethod
    def table_factory(self):
        pass
    
    def create_database(self, name):
        # execute the request to create the database for the project. no need to specify the owner
        # as the owner will be the creator of the database.
        general_logger.debug(f"Called PioneerDatabase.create_database().")
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
        general_logger.debug(f"Called PioneerDatabase.delete_database().")
        try:
            query = """DROP DATABASE {};""".format(name)
            general_logger.debug(f"Executing the following query: {query}.")
            self._cursor.execute(query)

            general_logger.info(f"Succesfully deleted database: {name}")
        
        except psycopg2.Error as err:
            general_logger.critical(f"Error deleting database: {name}. Reason: {err}")
            sys.exit(1)  

    def create_table(self, table_name, table_schema):
        general_logger.debug(f"Called PioneerDatabase.create_table(table_name, table_schema). With parameters: <table_name>: <{table_name}>, <table_schema>: <{table_schema}>.")
        command = f"""CREATE TABLE IF NOT EXISTS {table_name} ({table_schema});"""
        
        try:
            general_logger.info(f"Creating table: <{table_name}>.")
            self._cursor.execute(command)
        
        except psycopg2.Error as err:
            general_logger.critical(f"Error creating table: <{table_name}>. Reason: <{err}>.")
            sys.exit(1)
    
    def get_table_value(self, table_name, select_command, parameters=None):
        general_logger.debug(f"Called PioneerDatabase.get_table_value().")
        """
        Retrieve values from the specified table using the given SQL select command.

        Args:
            table_name (str): The name of the table to query.
            select_command (str): The SQL select command.
            parameters (tuple): The parameters to be used in the SQL query.

        Returns:
            list: A list of tuples containing the results of the query.
        """
        try:
            if parameters:
                self._cursor.execute(select_command, parameters)
            else:
                self._cursor.execute(select_command)
        except psycopg2.Error as err:
            general_logger.error(f"Failed to select values from table {table_name}. Reason: {err}")
            # sys.exit(1)

        # Fetch the returned query values
        postgres_cursor_data = self._cursor.fetchall()
        general_logger.info(f"Succesfully retrieved values from table {table_name}.")
        return postgres_cursor_data

    # this function updates values into a table
    def update_table_value(self, table_name, update_command):
        try:
            self._cursor.execute(update_command)

        except psycopg2.Error as err:
            general_logger.error(f"Failed to update values for: <{table_name}>. Reason: <{err}>")
            sys.exit(1)

    def flatten_query_result(self, query_result):
        general_logger.debug(f"Called PioneerDatabase.flatten_query_result().")
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
    def __init__(self, database):
        general_logger.debug(f"Called PioneerTable.__init__().")
        self._name = None
        self._table_schema = None
        self._database = database

    def create(self):
        self._database.create_table(self._name, self._table_schema)

    # move the insert_into_table code here
    def insert_row(self):
        """
        Insert values into a specified table of the database.

        Parameters:
        - table_name (str): Name of the table.
        - insert_command (str): SQL command for insertion.
        - values (tuple): Values to be inserted into the table. Default is None.

        Returns:
        None
        """
        general_logger.debug(f"Called PioneerDatabase.insert_table_value().")
        insert_command = """
            INSERT INTO general_data_table (
                security_device_name, 
                security_device_username, 
                security_device_secret,
                security_device_hostname, 
                security_device_type, 
                security_device_port, 
                security_device_version, 
                security_device_domain
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s
            )
        """

        values = (
            self._name, 
            security_device_username, 
            security_device_secret, 
            security_device_hostname, 
            security_device_type, 
            security_device_port, 
            security_device_version, 
            domain
        )
        try:
            if values is not None:
                self._cursor.execute(insert_command, values)
            else:
                self._cursor.execute(insert_command)
            general_logger.info(f"Succesfully inserted values into table {self._name}.")
            
        except psycopg2.Error as err:
            general_logger.error(f"Failed to insert values {values} into: {self._name}. Reason: {err}")
            # sys.exit(1)
    
    # move the get_table_value code here. the code must be rewritten in such a way
    # to permit multiple select queries
    # this function doesn't need an override
    def select_value():
        pass

    def update_value():
        pass

class TableRow():
    def __init__(self, table) -> None:
        self._table = table
    
    def insert():
        pass

class GeneralDataTableRow(TableRow):
    def __init__(self, table) -> None:
        super().__init__(table)
        self._security_device_name = None
        self._security_device_username = None
        self._security_device_secret = None
        self._security_device_hostname = None
        self._security_device_type = None
        self._security_device_port = None
        self._security_device_version = None
        self._security_device_domain = None
    

# the following are not supported, no need to create tables: policies_hitcount_table, nat_policies_table, user_source_table, policy_users_table
# security_zones_table, urls_categories_table, l7_apps_table, schedule_objects_table
class GeneralDataTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "general_data"
        self._table_schema = """security_device_name TEXT PRIMARY KEY,
                security_device_username TEXT NOT NULL,
                security_device_secret TEXT NOT NULL,
                security_device_hostname TEXT NOT NULL,
                security_device_type TEXT NOT NULL,
                security_device_port TEXT NOT NULL,
                security_device_version TEXT NOT NULL,
                security_device_domain TEXT NOT NULL"""
        
        
        self._insert_params = """
            INSERT INTO general_data_table (
                security_device_name, 
                security_device_username, 
                security_device_secret,
                security_device_hostname, 
                security_device_type, 
                security_device_port, 
                security_device_version, 
                security_device_domain
            ) VALUES (
                %s, %s, %s, %s, %s, %s, %s, %s
            )"""

    # call insert_row to insert stuff
    # should this insert() be a function defined on the Object/Policy classes?
    def insert():
        pass

class SecurityPolicyContainersTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "security_policy_containers"
        self._table_schema = """security_device_name TEXT NOT NULL,
            security_policy_container_name TEXT PRIMARY KEY,
            security_policy_container_parent TEXT,
            FOREIGN KEY(security_device_name) REFERENCES general_data(security_device_name)"""

    def insert():
        pass

class NATPolicyContainersTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "nat_policy_containers"
        self._table_schema = """security_device_name TEXT NOT NULL,
            nat_policy_container_name TEXT PRIMARY KEY,
            nat_policy_container_parent TEXT,
            FOREIGN KEY(security_device_name) REFERENCES general_data(security_device_name)"""
        
class ObjectContainersTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "object_containers"
        self._table_schema = """security_device_name TEXT NOT NULL,
            object_container_name TEXT PRIMARY KEY,
            object_container_parent TEXT,
            FOREIGN KEY(security_device_name) REFERENCES general_data(security_device_name)"""

class SecurityPoliciesTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "security_policies"
        self._table_schema = """ security_device_name TEXT NOT NULL,
            security_policy_name TEXT NOT NULL,
            security_policy_container_name TEXT NOT NULL,
            security_policy_index INT,
            security_policy_category TEXT,
            security_policy_status TEXT NOT NULL,
            security_policy_source_zones TEXT[] NOT NULL,
            security_policy_destination_zones TEXT[] NOT NULL,
            security_policy_source_networks TEXT[] NOT NULL,
            security_policy_destination_networks TEXT[] NOT NULL,
            security_policy_source_ports TEXT[] NOT NULL,
            security_policy_destination_ports TEXT[] NOT NULL,
            security_policy_schedules TEXT[] NOT NULL,
            security_policy_users TEXT[] NOT NULL,
            security_policy_urls TEXT[] NOT NULL,
            security_policy_l7_apps TEXT[] NOT NULL,
            security_policy_description TEXT,
            security_policy_comments TEXT[],
            security_policy_log_setting TEXT[],
            security_policy_log_start BOOLEAN NOT NULL,
            security_policy_log_end BOOLEAN NOT NULL,
            security_policy_section TEXT,
            security_policy_action TEXT,
            FOREIGN KEY(security_policy_container_name) REFERENCES security_policy_containers_table(security_policy_container_name) """

class PoliciesHitcountTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "policies_hitcount"
        self._table_schema = """security_device_name TEXT NOT NULL,
            security_policy_name TEXT NOT NULL,
            security_policy_container_name TEXT NOT NULL,
            security_policy_hitcount INTEGER,
            security_policy_last_hit TIMESTAMP,
            nat_policy_name TEXT NOT NULL,
            nat_policy_container_name TEXT NOT NULL,
            nat_policy_hitcount INTEGER,
            nat_policy_last_hit TIMESTAMP,
            assigned_device_name TEXT NOT NULL,
            FOREIGN KEY(security_policy_container_name) REFERENCES security_policy_containers_table(security_policy_container_name),
            FOREIGN KEY(nat_policy_container_name) REFERENCES security_policy_containers_table(security_policy_container_name)"""

class SecurityZonesTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "security_zones"
        self._table_schema = """security_zone_name TEXT PRIMARY KEY,
            security_device_name TEXT NOT NULL,
            object_container_name TEXT NOT NULL,
            security_zone_assigned_device TEXT,
            security_zone_mapped_interfaces TEXT[],
            security_zone_description TEXT,
            FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)"""

class URLObjectsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "url_objects"
        self._table_schema = """url_object_name TEXT PRIMARY KEY,
            security_device_name TEXT NOT NULL,
            object_container_name TEXT NOT NULL,
            url_value TEXT,
            url_object_description TEXT,
            FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)"""

class URLObjectGroupsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "url_object_groups"
        self._table_schema = """url_object_group_name TEXT PRIMARY KEY,
            security_device_name TEXT NOT NULL,
            object_container_name TEXT NOT NULL,
            url_object_members TEXT[],
            url_group_object_description TEXT,
            FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)"""

class NetworkAddressObjectsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "network_address_objects"
        self._table_schema = """network_address_name TEXT PRIMARY KEY,
            security_device_name TEXT NOT NULL,
            object_container_name TEXT NOT NULL,
            network_address_value TEXT,
            network_address_description TEXT,
            network_address_type TEXT,
            overridable_object BOOLEAN NOT NULL,
            FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)"""

class NetworkAddressObjectGroupsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "network_address_object_groups"
        self._table_schema = """network_address_group_name TEXT PRIMARY KEY,
            security_device_name TEXT NOT NULL,
            object_container_name TEXT NOT NULL,
            network_address_group_members TEXT[],
            network_address_group_description TEXT,
            overridable_object BOOLEAN NOT NULL,
            FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)"""
        

class GeolocationObjectsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "geolocation_objects"
        self._table_schema = """geolocation_object_name TEXT PRIMARY KEY,
            security_device_name TEXT NOT NULL,
            object_container_name TEXT NOT NULL,
            continent_member_names TEXT[],
            country_member_names TEXT[],
            country_member_alpha2_codes TEXT[],
            country_member_alpha3_codes TEXT[],
            country_member_numeric_codes TEXT[],
            FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)"""
        

class PortObjectsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "port_objects"
        self._table_schema = """port_name TEXT PRIMARY KEY,
            security_device_name TEXT NOT NULL,
            object_container_name TEXT NOT NULL,
            port_protocol TEXT,
            port_number TEXT,
            port_description TEXT,
            overridable_object BOOLEAN NOT NULL,
            FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)"""

class ICMPObjectsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "icmp_objects"
        self._table_schema = """icmp_name TEXT PRIMARY KEY,
            security_device_name TEXT NOT NULL,
            object_container_name TEXT NOT NULL,
            icmp_type TEXT,
            icmp_code TEXT,
            icmp_description TEXT,
            overridable_object BOOLEAN NOT NULL,
            FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)"""

class PortObjectGroupsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "port_object_groups"
        self._table_schema = """port_group_name TEXT PRIMARY KEY,
            security_device_name TEXT NOT NULL,
            object_container_name TEXT NOT NULL,
            port_group_members TEXT[],
            port_group_description TEXT,
            overridable_object BOOLEAN NOT NULL,
            FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)"""

class ScheduleObjectsTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "schedule_objects"
        self._table_schema = """schedule_object_name TEXT PRIMARY KEY,
            security_device_name TEXT NOT NULL,
            object_container_name TEXT NOT NULL,
            recurring BOOLEAN NOT NULL,
            start_date TEXT,
            start_time TEXT,
            end_date TEXT,
            end_time TEXT,
            reccurence_type TEXT,
            daily_start TEXT,
            daily_end TEXT,
            week_day TEXT,
            week_day_start TEXT,
            week_day_end TEXT,
            FOREIGN KEY(object_container_name) REFERENCES object_containers_table(object_container_name)"""

class ManagedDevicesTable(PioneerTable):
    def __init__(self, database):
        super().__init__(database)
        self._name = "managed_devices"
        self._table_schema = """security_device_name TEXT NOT NULL,
            managed_device_name TEXT PRIMARY KEY,
            assigned_security_policy_container TEXT,
            hostname TEXT,
            cluster TEXT,
            FOREIGN KEY(security_device_name) REFERENCES general_data_table(security_device_name)"""

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
    

