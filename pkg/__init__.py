from abc import ABC, abstractmethod
import psycopg2
import sys
import utils.helper as helper

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
        helper.logging.debug(f"Called DBConnection::__init__()")
    
    def create_cursor(self):
        """
        Create a cursor for interacting with the database.

        Returns:
            cursor: The database cursor.
        """
        helper.logging.debug(f"Called DBConnection::create_cursor().")
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
            helper.logging.critical(f"Error connecting to PostgreSQL Platform: {err}.")
            sys.exit(1)
        
        # initialize the db cursor
        database_cursor = postgres_conn.cursor()
        helper.logging.debug(f"Succesfully created cursor {database_cursor}.")

        # return the cursor to the caller
        return database_cursor

#TODO: refactor these functions as well!
class PioneerDatabase():
    def __init__(self, cursor):
        self._cursor = cursor
        helper.logging.debug(f"Called PioneerDatabase::__init__().")
    
    @abstractmethod
    def create_specific_tables(self):
        pass

    @abstractmethod
    def table_factory(self):
        pass
    
    def create_database(self, name):
        # execute the request to create the database for the project. no need to specify the owner
        # as the owner will be the creator of the database.
        helper.logging.debug(f"Called PioneerDatabase::create_database().")
        try:
            # execute the query to create the database
            query = """CREATE DATABASE {};""".format(name)
            helper.logging.debug(f"Executing the following query: {query}.")
            self._cursor.execute(query)

            # inform the user that the execution succeeded
            # print(f"Created database {name}.")
            helper.logging.info(f"Succesfully created database: {name}")

        # catch the error and exit the program if database creation fails
        except psycopg2.Error as err:
            helper.logging.critical(f"Error creating database: {name}. Reason: {err}")
            sys.exit(1)

    
    def delete_database(self, name):
        helper.logging.debug(f"Called PioneerDatabase::delete_database().")
        try:
            query = """DROP DATABASE {};""".format(name)
            helper.logging.debug(f"Executing the following query: {query}.")
            self._cursor.execute(query)

            helper.logging.info(f"Succesfully deleted database: {name}")
        
        except psycopg2.Error as err:
            helper.logging.critical(f"Error deleting database: {name}. Reason: {err}")
            sys.exit(1)  
    

    def create_table(self, table_name, table_command):
        helper.logging.debug(f"Called PioneerDatabase::create_table().")
        try:
            self._cursor.execute(table_command)
            helper.logging.info(f"Succesfully created table {table_name}")
        
        except psycopg2.Error as err:
            helper.logging.critical(f"Error creating table: {table_name}. Reason: {err}")
            print(f"Failed to create table: {table_name}. Reason: {err}")
            sys.exit(1)
    

    def get_table_value(self, table_name, select_command, parameters=None):
        helper.logging.debug(f"Called PioneerDatabase::get_table_value().")
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
            helper.logging.error(f"Failed to select values from table {table_name}. Reason: {err}")
            # sys.exit(1)

        # Fetch the returned query values
        postgres_cursor_data = self._cursor.fetchall()
        helper.logging.info(f"Succesfully retrieved values from table {table_name}.")
        return postgres_cursor_data


    # this function inserts values into a table of a database
    def insert_table_value(self, table_name, insert_command, values=None):
        """
        Insert values into a specified table of the database.

        Parameters:
        - table_name (str): Name of the table.
        - insert_command (str): SQL command for insertion.
        - values (tuple): Values to be inserted into the table. Default is None.

        Returns:
        None
        """
        helper.logging.debug(f"Called PioneerDatabase::insert_table_value().")
        try:
            if values is not None:
                self._cursor.execute(insert_command, values)
            else:
                self._cursor.execute(insert_command)

            helper.logging.info(f"Succesfully inserted values into table {table_name}.")
        except psycopg2.Error as err:
            helper.logging.error(f"Failed to insert values {values} into: {table_name}. Reason: {err}")
            # sys.exit(1)


    # this function updates values into a table
    def update_table_value(self, table_name, update_command):
        try:
            self._cursor.execute(update_command)
            print(f"Inserted values into: {table_name}.")
        
        except psycopg2.Error as err:
            print(f"Failed to insert values into: {table_name}. Reason: {err}")
            sys.exit(1)


    def flatten_query_result(self, query_result):
        helper.logging.debug(f"Called PioneerDatabase::flatten_query_result().")
        # Flatten both lists within each tuple and handle any number of sublists
        flattened_list = [item for tuple_item in query_result for sublist_part in tuple_item for item in sublist_part]

        # Convert the list to a set to remove duplicate values and then back to a list
        unique_values_list = list(set(flattened_list))

        # Return the list with unique values
        helper.logging.info(f"Flattened the query result.")
        return unique_values_list



# Example usage
# query_result = [[['value1']], [['value2']], [['value3']], ...]
# result = flatten_query_result(query_result)
# print(result) # Output: ['value1', 'value2', 'value3', ...]


    
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
    

