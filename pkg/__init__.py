from abc import ABC, abstractmethod
import psycopg2
import sys
import utils.helper as helper
import utils.gvars as gvars

general_logger = helper.logging.getLogger('general')

class DBConnection:
    def __init__(self, user, db, password, host, port):
        """
        Initialize a db connection instance.

        Args:
            user (str): The username for the db connection.
            db (str): The name of the db to connect to.
            password (str): The password for the db connection.
            host (str): The hostname of the db server.
            port (int): The port number for connecting to the db server.
        """
        self._user = user
        self._db = db
        self._password = password
        self._host = host
        self._port = port
    
    @property
    def user(self):
        """str: The username for the db connection."""
        return self._user

    @user.setter
    def user(self, value):
        self._user = value
    
    @property
    def db(self):
        """str: The name of the db to connect to."""
        return self._db

    @db.setter
    def db(self, value):
        self._db = value
    
    @property
    def password(self):
        """str: The password for the db connection."""
        return self._password

    @password.setter
    def password(self, value):
        self._password = value
    
    @property
    def host(self):
        """str: The hostname of the db server."""
        return self._host

    @host.setter
    def host(self, value):
        self._host = value
    
    @property
    def port(self):
        """int: The port number for connecting to the db server."""
        return self._port

    @port.setter
    def port(self, value):
        self._port = value

    def create_cursor(self):
        """
        Create a cursor for interacting with the db.

        Returns:
            cursor: A cursor object for the db connection.

        Raises:
            SystemExit: If there is an error connecting to the db.
        """
        try:
            # Establish connection to the PostgreSQL db
            postgres_connection = psycopg2.connect(
                user=self._user,
                database=self._db,
                password=self._password,
                host=self._host,
                port=self._port
            )
            # Set autocommit to True for the connection
            postgres_connection.autocommit = True
        
        except psycopg2.Error as error:
            # Log the error and exit the program if connection fails
            general_logger.critical(f"Error connecting to PostgreSQL Platform: {error}.")
            sys.exit(1)
        
        # Initialize and return the db cursor
        db_cursor = postgres_connection.cursor()
        general_logger.debug(f"Successfully created cursor {db_cursor}.")
        
        return db_cursor

class PioneerDatabase():
    def __init__(self, cursor):
        """
        Initialize the PioneerDatabase instance with a cursor.

        Args:
            cursor: The db cursor used for executing SQL commands.
        """
        self._cursor = cursor

    @abstractmethod
    def table_factory(self):
        """
        Abstract method to be implemented by subclasses to create tables.

        This method should define how tables are created based on the specific db schema.
        """
        pass

    def create_db(self, name):
        """
        Create a new db.

        Args:
            name (str): The name of the db to create.

        Raises:
            SystemExit: If an error occurs while creating the db.
        """
        general_logger.info(f"Creating device db: <{name}>.")
        try:
            # Create a query to create the db
            query = f"CREATE DATABASE {name};"
            general_logger.debug(f"Executing the following query: {query}.")
            self._cursor.execute(query)

            general_logger.info(f"Successfully created db: {name}")

        except psycopg2.Error as err:
            general_logger.critical(f"Error creating db: {name}. Reason: {err}")
            sys.exit(1)

    def delete_db(self, name):
        """
        Delete an existing db.

        Args:
            name (str): The name of the db to delete.

        Raises:
            SystemExit: If an error occurs while deleting the db.
        """
        try:
            # Create a query to delete the db
            query = f"DROP DATABASE {name};"
            general_logger.debug(f"Executing the following query: {query}.")
            self._cursor.execute(query)

            general_logger.info(f"Successfully deleted db: {name}")

        except psycopg2.Error as err:
            general_logger.critical(f"Error deleting db: {name}. Reason: {err}")
            sys.exit(1)

    def create_table(self, table_name, table_schema):
        """
        Create a table if it does not already exist.

        Args:
            table_name (str): The name of the table to create.
            table_schema (str): The SQL schema defining the table structure.

        Raises:
            SystemExit: If an error occurs while creating the table.
        """
        command = f"CREATE TABLE IF NOT EXISTS {table_name} ({table_schema});"
        try:
            general_logger.info(f"Creating table: <{table_name}>.")
            self._cursor.execute(command)

        except psycopg2.Error as err:
            general_logger.critical(f"Error creating table: <{table_name}>. Reason: <{err}>.")
            sys.exit(1)

    @property
    def cursor(self):
        """
        Get the db cursor.

        Returns:
            cursor: The db cursor.
        """
        return self._cursor

    @staticmethod
    def connect_to_db(user, db, password, host, port):
        """
        Connect to a PostgreSQL db and return a cursor object.

        Args:
            user (str): db username.
            db (str): Name of the db.
            password (str): Password for the db user.
            host (str): Hostname of the db server.
            port (int): Port number of the db server.

        Returns:
            cursor: Cursor object for db operations.

        Raises:
            SystemExit: If there is an error connecting to the db.
        """
        # Create a DBConnection instance
        db_connection = DBConnection(user, db, password, host, port)
        general_logger.info(f"Connecting to device db: <{db}>.")
        cursor = db_connection.create_cursor()
        return cursor
    
    @staticmethod
    def preload_object_data(object_type, db):
        """
        Preload data from various tables based on the object type and return it as a dictionary.

        This method retrieves data from different tables depending on the type of object specified.
        It fetches data from each relevant table and organizes it into a dictionary for easy access.

        Parameters:
            object_type (str): The type of object for which to preload data.
            db (Database): An instance of the database from which to fetch the data.

        Returns:
            dict: A dictionary containing the preloaded data with table names as keys and dictionaries of name-uid mappings as values.
        """
        def get_table_data(table, columns):
            """
            Helper function to get data from a table and convert it to a dictionary.

            Parameters:
                table (Table): The table from which to retrieve data.
                columns (list): The list of columns to retrieve.

            Returns:
                dict: A dictionary mapping column values to their corresponding uids.
            """
            values_tuple_list = table.get(columns=columns)
            return dict(values_tuple_list)

        members_dict_from_db = {}

        if object_type == 'network_group_object':
            tables_to_fetch = [
                db.network_address_objects_table,
                db.network_group_objects_table
            ]
        elif object_type == 'port_group_object':
            tables_to_fetch = [
                db.port_objects_table,
                db.port_group_objects_table,
                db.icmp_objects_table
            ]
        elif object_type == 'url_group_object':
            tables_to_fetch = [
                db.url_objects_table,
                db.url_group_objects_table
            ]
        elif object_type == 'security_policy_group':
            tables_to_fetch = {
                gvars.security_zone: db.security_zones_table,
                gvars.network_object: db.network_address_objects_table,
                gvars.network_group_object: db.network_group_objects_table,
                gvars.country_object: db.country_objects_table,
                gvars.geolocation_object: db.geolocation_objects_table,
                gvars.port_object: db.port_objects_table,
                gvars.port_group_object: db.port_group_objects_table,
                gvars.icmp_object: db.icmp_objects_table,
                gvars.url_object: db.url_objects_table,
                gvars.url_group_object: db.url_group_objects_table,
                gvars.url_category_object: db.url_categories_table,
                gvars.schedule_object: db.schedule_objects_table,
                gvars.policy_user_object: db.policy_users_table,
                gvars.l7_app_object: db.l7_apps_table,
                gvars.l7_app_filter_object: db.l7_app_filters_table,
                gvars.l7_app_group_object: db.l7_app_groups_table
            }
            # Fetch data for each table and store it in members_dict_from_db with the table name as key
            for table_name, table in tables_to_fetch.items():
                members_dict_from_db[table_name] = get_table_data(table, ['name', 'uid'])
            return members_dict_from_db
        else:
            tables_to_fetch = []

        # Fetch data for non-security policy object types
        for table in tables_to_fetch:
            members_dict_from_db.update(get_table_data(table, ['name', 'uid']))

        return members_dict_from_db

class PioneerTable:
    def __init__(self, db):
        """
        Initialize the PioneerTable instance with a db connection.

        Args:
            db (PioneerDatabase): An instance of the PioneerDatabase class used for executing SQL commands.
        """
        self._name = None
        self._table_columns = None
        self._db = db

    @property
    def name(self):
        """
        Get or set the table name.

        Returns:
            str: The name of the table.
        """
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def table_columns(self):
        """
        Get or set the table columns.

        Returns:
            list: List of tuples where each tuple represents a column (name, type).
        """
        return self._table_columns

    @table_columns.setter
    def table_columns(self, value):
        self._table_columns = value

    @property
    def db(self):
        """
        Get the db instance.

        Returns:
            PioneerDatabase: The db instance.
        """
        return self._db

    @db.setter
    def db(self, value):
        self._db = value

    def create(self):
        """
        Create the table in the db using the specified name and schema.
        """
        self._db.create_table(self._name, self.get_schema())

    def get_schema(self):
        """
        Generate the schema string for the table.

        Returns:
            str: The schema string for the table.
        """
        # Create the schema string by joining column definitions
        table_schema = ", ".join([f"{col[0]} {col[1]}" for col in self._table_columns])
        return table_schema

    def get_columns(self):
        """
        Get the column names from the table columns, excluding constraints and primary keys.

        Returns:
            str: A comma-separated string of column names.
        """
        # Extract only the column names from the table columns, excluding constraints and primary keys
        column_names = [col[0] for col in self._table_columns if not (col[0].startswith("CONSTRAINT") or col[0].startswith("PRIMARY"))]
        # Join the column names into a string
        table_columns_str = ", ".join(column_names)
        return table_columns_str

    def insert(self, *values):
        """
        Insert values into the table.

        Args:
            *values: Values to be inserted into the table.
        """
        columns = self.get_columns()
        
        # Construct placeholders for the values in the SQL query
        placeholders = ', '.join(['%s'] * len(values))
        
        # Create the insert command with ON CONFLICT DO NOTHING to avoid errors on duplicate keys
        insert_command = f"INSERT INTO {self._name} ({columns}) VALUES ({placeholders}) ON CONFLICT DO NOTHING;"
        try:
            cursor = self._db.cursor
            
            # Execute the insert command with the actual values
            cursor.execute(insert_command, values)
            
            general_logger.info(f"Successfully inserted values into table <{self._name}>.")
            
        except psycopg2.Error as err:
            general_logger.error(f"Failed to insert values <{values}> into table <{self._name}>. Reason: {err}")

    def get(self, columns, name_col=None, val=None, order_param=None, join=None, not_null_condition=False, multiple_where=False):
        """
        Retrieve records from the table based on the specified criteria.

        Args:
            columns (str, list, tuple): Columns to select. Can be a string (single column) or a list/tuple (multiple columns).
            name_col (str, list, optional): Column name(s) for the WHERE clause.
            val (str, list, optional): Value(s) for the WHERE clause.
            order_param (str, optional): Column to sort the results by.
            join (dict, list of dict, optional): JOIN conditions. Each dict should have 'table' and 'condition' keys.
            not_null_condition (bool, optional): If True, adds an IS NOT NULL condition.
            multiple_where (bool, optional): If True, multiple WHERE conditions will be applied.

        Returns:
            list: List of records matching the query.
        
        Raises:
            ValueError: If the columns parameter is not a valid type.
        """
        # Ensure columns is either a string (single column) or a list/tuple (multiple columns)
        if isinstance(columns, str):
            columns_str = columns
        elif isinstance(columns, (list, tuple)):
            columns_str = ', '.join(columns)
        else:
            raise ValueError("columns parameter must be a string, list, or tuple of column names")

        # Construct the JOIN clause if joins are provided
        join_clause = ""
        if join:
            if isinstance(join, dict):
                join = [join]  # Convert to list if single join is provided as a dict

            join_clauses = [f"JOIN {j['table']} ON {j['condition']}" for j in join]
            join_clause = " ".join(join_clauses)

        # Construct the WHERE clause
        where_clause = ""
        params = ()
        if name_col and val:
            if multiple_where:
                where_conditions = " AND ".join(f"{col} = %s" for col in name_col)
                where_clause = f"WHERE {where_conditions}"
                params = tuple(val)
            else:
                where_clause = f"WHERE {name_col} = %s"
                params = (val,)

            if not_null_condition:
                where_clause += f" AND {columns_str} IS NOT NULL"

        # Construct the ORDER BY clause
        order_clause = ""
        if order_param:
            order_clause = f"ORDER BY {order_param}"

        # Construct the final SELECT query
        select_query = f"SELECT {columns_str} FROM {self._name} {join_clause} {where_clause} {order_clause};"

        # Execute the query
        try:
            cursor = self._db.cursor
            # print(select_query, params)
            cursor.execute(select_query, params)
            results = cursor.fetchall()
            return results
        except Exception as e:
            general_logger.error(f"Failed to select values from table: {self._name}. Reason: {e}")
            raise

class GeneralDataTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the GeneralDataTable with the provided db connection.

        Args:
            db (PioneerDatabase): The db connection object used to interact with the db.
        
        This constructor sets up the table name and its schema specific to general security device data.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the SecurityPolicyContainersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and its schema specific to security policy containers.
        """
        super().__init__(db)
        self._name = "security_policy_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class NATPolicyContainersTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the NATPolicyContainersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and its schema specific to NAT policy containers.
        """
        super().__init__(db)
        self._name = "nat_policy_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class ObjectContainersTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the ObjectContainersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and its schema specific to object containers.
        """
        super().__init__(db)
        self._name = "object_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class SecurityZoneContainersTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the SecurityZoneContainersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and its schema specific to security zone containers.
        """
        super().__init__(db)
        self._name = "security_zone_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class ManagedDeviceContainersTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the ManagedDeviceContainersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to managed device containers.
        """
        super().__init__(db)
        self._name = "managed_device_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class NATContainersTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the NATContainersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to managed device containers.
        """
        super().__init__(db)
        self._name = "nat_containers"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_device_uid", "TEXT"),
            ("parent", "TEXT"),
            ("CONSTRAINT fk_security_device FOREIGN KEY (security_device_uid)", "REFERENCES general_security_device_data (uid)"),
        ]

class ManagedDevicesTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the ManagedDevicesTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to managed devices, including constraints 
        for foreign key relationships and a unique constraint on the combination of name and container UID.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the SecurityPoliciesTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to security policies, including 
        constraints for foreign key relationships and a unique constraint on the combination of policy 
        name and container UID.
        """
        super().__init__(db)
        self._name = "security_policies"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_policy_container_uid", "TEXT NOT NULL"),
            ("index", "INT"),
            ("category", "TEXT"),
            ("status", "BOOLEAN NOT NULL"),
            ("log_start", "BOOLEAN NOT NULL"),
            ("log_end", "BOOLEAN NOT NULL"),
            ("log_to_manager", "BOOLEAN NOT NULL"),
            ("log_to_syslog", "BOOLEAN NOT NULL"),
            ("section", "TEXT"),
            ("action", "TEXT"),
            ("comments", "TEXT"),
            ("description", "TEXT"),
            ("target_device_uid", "TEXT"),
            ("CONSTRAINT fk_security_policy_container FOREIGN KEY(security_policy_container_uid)", "REFERENCES security_policy_containers(uid)"),
            ("CONSTRAINT uc_security_policy_container_uid123", "UNIQUE (name, security_policy_container_uid)")
        ]

#TODO: what should be done about target_device_uid? how do I retrieve it and map it properly?
# given the fact that managed_devices_table stores the assigned security policies
# how to track if interface is used for translation? maybe use a boolean and a new db col
class NATPoliciesTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the NATPoliciesTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to security policies, including 
        constraints for foreign key relationships and a unique constraint on the combination of policy 
        name and container UID.
        """
        super().__init__(db)
        self._name = "nat_policies"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("security_policy_container_uid", "TEXT NOT NULL"),
            # needed to track if interface is used for translation or not
            ("original_destination_interface", "BOOLEAN NOT NULL"),
            ("translated_destination_interface", "BOOLEAN NOT NULL"),
            ("index", "INT"),
            ("category", "TEXT"),
            ("status", "TEXT NOT NULL"),
            ("log_to_manager", "BOOLEAN NOT NULL"),
            ("log_to_syslog", "BOOLEAN NOT NULL"),
            ("section", "TEXT"),
            ("comments", "TEXT"),
            ("description", "TEXT"),
            ("static_or_dynamic", "TEXT"),
            ("single_or_twice", "TEXT"),
            ("target_device_uid", "TEXT"),
            ("CONSTRAINT fk_security_policy_container FOREIGN KEY(security_policy_container_uid)", "REFERENCES security_policy_containers(uid)"),
            ("CONSTRAINT uc_security_policy_container_uid1", "UNIQUE (name, security_policy_container_uid)")
        ]

        # needed for relationships tables
        # 'source_interface',
        # 'destination_interface',
        # 'original_source',
        # 'original_destination',
        # 'translated_source',
        # 'translated_destination',
        # 'original_source_port',
        # 'original_destination_port',
        # 'translated_source_port',
        # 'translated_destination_port',

class SecurityZonesTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the SecurityZonesTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to security zones, including 
        constraints for foreign key relationships and a unique constraint on the combination of zone 
        name and container UID.
        """
        super().__init__(db)
        self._name = "security_zones"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("zone_container_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_zone_container_uid FOREIGN KEY(zone_container_uid)", "REFERENCES security_zone_containers(uid)"),
            ("CONSTRAINT uc_zone_container_uid", "UNIQUE (name, zone_container_uid)")
        ]

class URLObjectsTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the URLObjectsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to URL objects, including constraints 
        for foreign key relationships and a unique constraint on the combination of name and object container UID.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the NetworkAddressObjectsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to network address objects, including constraints 
        for foreign key relationships and a unique constraint on the combination of name and object container UID.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the NetworkGroupObjectsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to network group objects, including constraints 
        for foreign key relationships and a unique constraint on the combination of name and object container UID.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the PortGroupObjectsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to port group objects, including constraints 
        for foreign key relationships and a unique constraint on the combination of name and object container UID.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the URLGroupObjectsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to URL group objects, including constraints 
        for foreign key relationships and a unique constraint on the combination of name and object container UID.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the NetworkGroupObjectsMembersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to network group object memberships, including a
        foreign key constraint that references the `network_group_objects` table to establish a relationship between
        network groups and their associated objects.
        """
        super().__init__(db)
        self._name = "network_group_objects_members"
        self._table_columns = [
            ("group_uid", "TEXT NOT NULL"),
            ("object_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_group FOREIGN KEY(group_uid)", "REFERENCES network_group_objects(uid)")
        ]

class PortGroupObjectsMembersTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the PortGroupObjectsMembersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to port group object memberships, including a
        foreign key constraint that references the `port_group_objects` table to establish a relationship between
        port groups and their associated objects.
        """
        super().__init__(db)
        self._name = "port_group_objects_members"
        self._table_columns = [
            ("group_uid", "TEXT NOT NULL"),
            ("object_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_group FOREIGN KEY(group_uid)", "REFERENCES port_group_objects(uid)")
        ]

class URLGroupObjectsMembersTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the URLGroupObjectsMembersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to URL group object memberships. It includes
        a foreign key constraint that links the `group_uid` column to the `url_group_objects` table, ensuring
        referential integrity between URL groups and their associated objects.
        """
        super().__init__(db)
        self._name = "url_group_objects_members"
        self._table_columns = [
            ("group_uid", "TEXT NOT NULL"),
            ("object_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_group FOREIGN KEY(group_uid)", "REFERENCES url_group_objects(uid)")
        ]

class GeolocationObjectsTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the GeolocationObjectsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to geolocation objects. It includes a foreign key 
        constraint that links the `object_container_uid` column to the `object_containers` table, ensuring referential
        integrity between geolocation objects and their containers. It also includes a unique constraint to ensure
        that each combination of name and object container UID is unique.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the CountryObjectsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to country objects. It includes a foreign key 
        constraint that links the `object_container_uid` column to the `object_containers` table, ensuring referential
        integrity between country objects and their containers. It also includes a unique constraint to ensure
        that each combination of name and object container UID is unique.
        """
        super().__init__(db)
        self._name = "country_objects"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid34", "UNIQUE (name, object_container_uid)")
        ]

class PortObjectsTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the PortObjectsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to port objects. It includes columns for various 
        attributes of port objects, including a foreign key constraint linking `object_container_uid` to the 
        `object_containers` table. It also includes a unique constraint to ensure that each combination of name 
        and object container UID is unique.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the ICMPObjectsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to ICMP objects. It includes columns for various 
        attributes of ICMP objects, such as type and code, along with constraints for foreign key relationships 
        and a unique constraint on the combination of name and object container UID.
        """
        super().__init__(db)
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

class ScheduleObjectsTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the ScheduleObjectsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to schedule objects, including constraints 
        for foreign key relationships and a unique constraint on the combination of name and object container UID.
        """
        super().__init__(db)
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
            # ("recurrence_type", "TEXT"),
            # ("daily_start", "TEXT"),
            # ("daily_end", "TEXT"),
            # ("week_day", "TEXT"),
            # ("week_day_start", "TEXT"),
            # ("week_day_end", "TEXT"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid15", "UNIQUE (name, object_container_uid)")
        ]

class PolicyUsersTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the PolicyUsersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to policy users, including constraints 
        for foreign key relationships and a unique constraint on the combination of name and object container UID.
        """
        super().__init__(db)
        self._name = "policy_users"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid20", "UNIQUE (name, object_container_uid)")
        ]

class L7AppsTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the L7AppsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to Layer 7 applications, including constraints 
        for foreign key relationships and a unique constraint on the combination of name and object container UID.
        """
        super().__init__(db)
        self._name = "l7_apps"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid19", "UNIQUE (name, object_container_uid)")
        ]

class L7AppFiltersTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the L7AppFiltersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to Layer 7 application filters, including constraints 
        for foreign key relationships and a unique constraint on the combination of name and object container UID.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the L7AppGroupsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to Layer 7 application groups, including constraints 
        for foreign key relationships and a unique constraint on the combination of name and object container UID.
        """
        super().__init__(db)
        self._name = "l7_app_groups"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid29", "UNIQUE (name, object_container_uid)")
        ]


class L7AppGroupMembersTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the L7AppGroupMembersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to Layer 7 application group members, including constraints 
        for foreign key relationships and a primary key constraint on the combination of group UID and object UID.
        """
        super().__init__(db)
        self._name = "l7_app_group_members"
        self._table_columns = [
            ("group_uid", "TEXT NOT NULL"),
            ("object_uid", "TEXT NOT NULL"),
            ("CONSTRAINT fk_group FOREIGN KEY(group_uid)", "REFERENCES l7_app_groups(uid)"),
            ("PRIMARY KEY(group_uid, object_uid)", "")
        ]

class URLCategoriesTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the URLCategoriesTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to URL categories, including constraints 
        for foreign key relationships and a unique constraint on the combination of name and object container UID.
        """
        super().__init__(db)
        self._name = "url_categories"
        self._table_columns = [
            ("uid", "TEXT PRIMARY KEY"),
            ("name", "TEXT NOT NULL"),
            ("object_container_uid", "TEXT NOT NULL"),
            ("reputation", "TEXT"),
            ("CONSTRAINT fk_object_container FOREIGN KEY(object_container_uid)", "REFERENCES object_containers(uid)"),
            ("CONSTRAINT uc_object_container_uid22", "UNIQUE (name, object_container_uid)")
        ]

# relationships tables between security policies and objects used to define the objects
# attached to the security policies
class SecurityPolicyZonesTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the SecurityPolicyZonesTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to security policy zones, including constraints 
        for foreign key relationships.
        """
        super().__init__(db)
        self._name = "security_policy_zones"
        self._table_columns = [
            ("security_policy_uid", "TEXT NOT NULL"),
            ("zone_uid", "TEXT"),
            ("flow", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)")
        ]

class SecurityPolicyNetworksTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the SecurityPolicyNetworksTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to security policy networks, including constraints 
        for foreign key relationships to various network-related tables.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the SecurityPolicyPortsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to security policy ports, including constraints 
        for foreign key relationships to various port-related and ICMP-related tables.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the SecurityPolicyUsersTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema specific to the association between security policies and users. 
        It includes constraints for foreign key relationships to the `security_policies` and `policy_users` tables.
        """
        super().__init__(db)
        self._name = "security_policy_users"
        self._table_columns = [
            ("security_policy_uid", "TEXT NOT NULL"),
            ("user_uid", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)"),
            ("CONSTRAINT fk_user_uid FOREIGN KEY (user_uid)", "REFERENCES policy_users (uid)")
        ]

class SecurityPolicyURLsTable(PioneerTable):
    def __init__(self, db):
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the SecurityPolicyL7AppsTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema for the association between security policies and Layer 7 (L7) applications. 
        It includes foreign key constraints linking to the `security_policies`, `l7_apps`, `l7_app_filters`, and `l7_app_groups` tables.
        """
        super().__init__(db)
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
    def __init__(self, db):
        """
        Initialize the SecurityPolicyScheduleTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema for associating security policies with schedules. 
        It includes foreign key constraints linking to the `security_policies` and `schedule_objects` tables.
        """
        super().__init__(db)
        self._name = "security_policy_schedule"
        self._table_columns = [
            ("security_policy_uid", "TEXT"),
            ("schedule_uid", "TEXT"),
            ("CONSTRAINT fk_security_policy_uid FOREIGN KEY (security_policy_uid)", "REFERENCES security_policies (uid)"),
            ("CONSTRAINT fk_schedule_uid FOREIGN KEY (schedule_uid)", "REFERENCES schedule_objects (uid)")
        ]

# migration projects table
class MigrationProjectGeneralDataTable(PioneerTable):
    def __init__(self, db) -> None:
        """
        Initialize the MigrationProjectGeneralDataTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema for storing general data related to migration projects. 
        The schema includes columns for the project name, description, and creation date.
        """
        super().__init__(db)
        self._name = "migration_project_general_data"
        self._table_columns = [
            ("name", "TEXT NOT NULL"),
            ("description", "TEXT"),
            ("creation_date", "TIMESTAMP")
        ]

class MigrationProjectDevicesTable(PioneerTable):
    def __init__(self, db):
        """
        Initialize the MigrationProjectDevicesTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema for tracking migration project devices. 
        The schema includes columns for source and target device UIDs and establishes a composite primary key 
        on the combination of these two columns to ensure uniqueness.
        """
        super().__init__(db)
        self._name = "migration_project_devices"
        self._table_columns = [
            ("source_device_uid", "TEXT NOT NULL"),
            ("target_device_uid", "TEXT NOT NULL"),
            ("PRIMARY KEY (source_device_uid, target_device_uid)", "")
        ]

class SecurityDeviceInterfaceMap(PioneerTable):
    def __init__(self, db) -> None:
        """
        Initialize the SecurityDeviceInterfaceMap table with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema for mapping security zones. 
        The schema includes columns for the source and target security zones and establishes foreign key constraints 
        to ensure that the values in these columns reference valid entries in the `security_zones` table.
        """
        super().__init__(db)
        self._name = "security_zones_map"
        self._table_columns = [
            ("source_security_zone", "TEXT"),
            ("target_security_zone", "TEXT"),
            ("CONSTRAINT fk_source_security_zone FOREIGN KEY (source_security_zone)", "REFERENCES security_zones (uid)"),
            ("CONSTRAINT fk_target_security_zone FOREIGN KEY (target_security_zone)", "REFERENCES security_zones (uid)")
        ]

class SecurityPolicyContainersMapTable(PioneerTable):
    def __init__(self, db) -> None:
        """
        Initialize the SecurityPolicyContainersMapTable with the provided database connection.

        Args:
            db (PioneerDatabase): The database connection object used to interact with the database.

        This constructor sets up the table name and schema for mapping security policy containers. 
        The schema includes columns for the source and target security policy containers and establishes foreign key constraints 
        to ensure that the values in these columns reference valid entries in the `security_policy_containers` table.
        """
        super().__init__(db)
        self._name = "security_policy_containers_map"
        self._table_columns = [
            ("source_security_policy_container_uid", "TEXT"),
            ("target_security_policy_container_uid", "TEXT"),
            ("CONSTRAINT fk_source_security_policy_container FOREIGN KEY (source_security_policy_container_uid)", "REFERENCES security_policy_containers (uid)"),
            ("CONSTRAINT fk_target_security_policy_container FOREIGN KEY (target_security_policy_container_uid)", "REFERENCES security_policy_containers (uid)")
        ]

# the following tables are very simplistic and limited and will be rewritten
# in the future. the feature they are trying to emulate is needed now
class LogSettingsTable(PioneerTable):
    def __init__(self, db) -> None:
        super().__init__(db)
        self._name = "log_settings"
        self._table_columns = [
            ("log_manager", "TEXT")
        ]

class SpecialSecurityPolicyParametersTable(PioneerTable):
    def __init__(self, db):
        super().__init__(db)
        self._name = "special_security_policy_parameters"
        self._table_columns = [
            ("security_profile", "TEXT")
        ]

class NetworkObjectTypesMapTable(PioneerTable):
    def __init__(self, db) -> None:
        super().__init__(db)
        self._name = "network_object_types_map"
        self._table_columns = [
            ("fmc_api", "TEXT"),
            ("panmc_api", "TEXT")
        ]

    def pre_insert_data(self):
        self.insert('Host', 'ip-netmask')
        self.insert('Network', 'ip-netmask')
        self.insert('Range', 'ip-range')
        self.insert('FQDN', 'fqdn')

class SecurityPolicyActionMapTable(PioneerTable):
    def __init__(self, db) -> None:
        super().__init__(db)
        self._name = "security_policy_actions_map"
        self._table_columns = [
            ("fmc_api", "TEXT"),
            ("panmc_api", "TEXT")
        ]

    def pre_insert_data(self):
        self.insert('ALLOW', 'allow')
        self.insert('TRUST', 'allow')
        self.insert('BLOCK', 'deny')
        self.insert('BLOCK_RESET', 'reset-client')

class SecurityPolicySectionMap(PioneerTable):
    def __init__(self, db) -> None:
        super().__init__(db)
        self._name = "seecurity_policy_section_map"
        self._table_columns = [
            ("fmc_api", "TEXT"),
            ("panmc_api", "TEXT")
        ]

    def pre_insert_data(self):
        self.insert('Mandatory', 'pre')
        self.insert('Default', 'post')
