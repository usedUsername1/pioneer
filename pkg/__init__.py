from abc import ABC, abstractmethod
import psycopg2
import sys
import utils.helper as helper

# there should still be functions in the helper module. the functions in helper will interact with postgres
# the function form here will interact with the objects databases
class DBConnection():
    def __init__(self, user, database, password, host, port):
        self._user = user,
        self._database = database,
        self._password = password,
        self._host = host,
        self._port = port
    
    def create_cursor(self):
        # self parameters are returned as a tuple, they need to be extracted
        try:
            postgres_conn = psycopg2.connect(
                user = self._user[0],
                database = self._database[0],
                password = self._password[0],
                host = self._host[0],
                port = self._port
            )
            # set autocommit to True
            postgres_conn.autocommit = True

        # if the connection fails, catch the error and exit the program
        except psycopg2.Error as err:
            print(self._user, self._database, self._password, self._host, self._port)
            print(f"Error connecting to PostgreSQL Platform: {err}")
            sys.exit(1)
        
        # initialize the db cursor
        database_cursor = postgres_conn.cursor()

        # return the cursor to the caller
        return database_cursor


class PioneerDatabase():
    def __init__(self, cursor):
        self._cursor = cursor
    
    @abstractmethod
    def create_specific_tables(self):
        pass

    @abstractmethod
    def table_factory(self):
        pass
    
    def create_database(self, name):
        # execute the request to create the database for the project. no need to specify the owner
        # as the owner will be the creator of the database.
        try:
            # execute the query to create the database
            self._cursor.execute(("""CREATE DATABASE {};""").format(name))

            # inform the user that the execution succeeded
            print(f"Created database {name}.")

        # catch the error and exit the program if database creation fails
        except psycopg2.Error as err:
            print(f"Error creating database: {name}. Reason: {err}")
            sys.exit(1)

    
    def delete_database(self, name):
        try:
            self._cursor.execute(("""DROP DATABASE {};""").format(name))

            print(f"Deleted database {name}.")
        
        except psycopg2.Error as err:
            print(f"Error deleting database: {name}. Reason: {err}")
            sys.exit(1)  
    

    def create_table(self, table_name, table_command):
        try:
            self._cursor.execute(table_command)
            print(f"Created table: {table_name}")
        
        except psycopg2.Error as err:
            print(f"Failed to create table: {table_name}. Reason: {err}")
            sys.exit(1)
    

    def get_table_value(self, table_name, select_command):
        try:
            self._cursor.execute(select_command)
        
        except psycopg2.Error as err:
            print(f"Failed to select values from table {table_name}. Reason: {err}")
            sys.exit(1)
        
        # fetch the returned query values
        postgres_cursor_data = self._cursor.fetchall()

        # extract the output returned from the select query. the returned value is a list of tuples
        # since there is only one tuple in the list, it makes sense to extract it like this
        return postgres_cursor_data[0][0]
    

    # this function inserts values into a table of a database
    def insert_table_value(self, table_name, insert_command):
        try:
            self._cursor.execute(insert_command)
            print(f"Inserted values into: {table_name}")
        
        except psycopg2.Error as err:
            print(f"Failed to insert values into: {table_name}. Reason: {err}")
            sys.exit(1)


    # this function updates values into a table
    def update_table_value(self, table_name, update_command):
        try:
            self._cursor.execute(update_command)
            print(f"Inserted values into: {table_name}.")
        
        except psycopg2.Error as err:
            print(f"Failed to insert values into: {table_name}. Reason: {err}")
            sys.exit(1)

    
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
    

